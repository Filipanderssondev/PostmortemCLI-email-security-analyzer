# launcher.py
# Registered as "postmortemcli" via pyproject.toml
# Runs on host: detects platform, finds runtime, starts container
# Runs in container: hands off to main.py

import os
import sys
import glob
import shutil
import subprocess


# Use APPDATA on Windows (avoids permission issues with dot-prefixed folders)
# On Linux/Mac: ~/.postmortemcli
# On Windows:   C:\Users\<user>\AppData\Roaming\postmortemcli
if sys.platform == 'win32':
    CONFIG_DIR = os.path.normpath(
        os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'postmortemcli')
    ).strip()
else:
    CONFIG_DIR = os.path.normpath(os.path.expanduser('~/.postmortemcli')).strip()
ENV_FILE   = os.path.normpath(os.path.join(CONFIG_DIR, '.env')).strip()
CA_CERT    = os.path.normpath(os.path.join(CONFIG_DIR, 'org-ca.pem')).strip()

# ── Environment detection ─────────────────────────────────────────────────────

def is_inside_container() -> bool:
    return os.environ.get('POSTMORTEM_CONTAINER') == '1'


def find_runtime() -> str:
    finder = 'where' if sys.platform == 'win32' else 'which'
    for candidate in ['podman', 'docker']:
        result = subprocess.run([finder, candidate], capture_output=True)
        if result.returncode == 0:
            return candidate
    return None


def get_image() -> str:
    image = _read_env_key('POSTMORTEM_IMAGE')
    if image:
        return image
    return os.environ.get(
        'POSTMORTEM_IMAGE',
        'docker.io/filipanderssondev/postmortemcli:latest'
    )


def is_private_registry() -> bool:
    """
    Detects if the configured image is from a private registry.
    Public registries are pulled automatically.
    Private registries require manual login and pull — local image is used.
    """
    public_registries = ['docker.io', 'ghcr.io', 'registry.hub.docker.com', 'quay.io']
    return not any(registry in get_image() for registry in public_registries)


def is_enterprise_environment() -> bool:
    """
    Detects enterprise environment.
    Signal: RHEL operating system + private registry configured.
    RHEL is common in enterprise environments. Private registry means POSTMORTEM_IMAGE
    points to an internal private registry, not Docker Hub.
    """
    is_rhel = os.path.exists('/etc/redhat-release')
    has_private_registry = is_private_registry()
    return is_rhel and has_private_registry


def get_mount_path() -> str:
    cwd = os.getcwd()
    if sys.platform == 'win32':
        drive, rest = os.path.splitdrive(cwd)
        return f'/{drive.replace(":", "").lower()}{rest.replace(chr(92), "/")}'
    return cwd


def _read_env_key(key: str) -> str:
    """Read a single key from ~/.postmortemcli/.env without loading full environment."""
    if not os.path.exists(ENV_FILE):
        return ''
    with open(ENV_FILE) as f:
        for line in f:
            line = line.strip()
            if line.startswith(f'{key}='):
                return line.split('=', 1)[1].strip()
    return ''


def _get_ca_flags() -> list:
    """
    If ~/.postmortemcli/org-ca.pem exists, mount it into the container
    and set REQUESTS_CA_BUNDLE so Python uses it automatically.

    This fixes SSL verification failures caused by enterprise SSL inspection
    proxies that intercept HTTPS traffic and re-sign certificates with an
    internal CA the container does not trust.

    The :z flag sets the correct SELinux label on Linux/RHEL.
    It is omitted on Windows where SELinux does not apply.
    """
    if not os.path.exists(CA_CERT):
        return []
    z = '' if sys.platform == 'win32' else ',z'
    return [
        '-v', f'{CA_CERT}:/etc/ssl/certs/org-ca.pem:ro{z}',
        '--env', 'REQUESTS_CA_BUNDLE=/etc/ssl/certs/org-ca.pem',
        '--env', 'SSL_CERT_FILE=/etc/ssl/certs/org-ca.pem',
    ]


# ── Setup ─────────────────────────────────────────────────────────────────────

def _find_system_ca_certs() -> list:
    """
    Searches standard system CA trust directories for organisation
    certificates added by IT during workstation onboarding.
    Returns list of found certificate file paths.
    """
    search_patterns = [
        '/etc/pki/ca-trust/source/anchors/*.pem',
        '/etc/pki/ca-trust/source/anchors/*.crt',
        '/usr/local/share/ca-certificates/*.pem',
        '/usr/local/share/ca-certificates/*.crt',
    ]
    found = []
    for pattern in search_patterns:
        found.extend(glob.glob(pattern))
    return found


def _copy_ca_cert(cert_path: str):
    """Copy a CA certificate to the local config directory."""
    shutil.copy2(cert_path, CA_CERT)


def _write_env_file(keys: dict):
    """
    Write API keys to ~/.postmortemcli/.env.
    Preserves existing values if user presses Enter without input.
    """
    existing = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    k, v = line.split('=', 1)
                    existing[k.strip()] = v.strip()

    merged = {**existing, **{k: v for k, v in keys.items() if v}}

    with open(ENV_FILE, 'w', encoding='utf-8') as f:
        f.write('# PostmortemCLI - local configuration\n')
        f.write('# Generated by: postmortemcli setup\n')
        f.write('# Location: postmortemcli config dir\n')
        f.write('#\n')
        f.write('# Format rules:\n')
        f.write('#   KEY=value          correct\n')
        f.write('#   KEY="value"        wrong - quotes become part of the value\n')
        f.write('#   KEY=value # note   wrong - comment becomes part of the value\n')
        f.write('#   export KEY=value   wrong - export prefix breaks --env-file\n')
        f.write('\n')
        f.write('# Threat intelligence API keys\n')
        for k, v in merged.items():
            f.write(f'{k}={v}\n')

    if sys.platform != 'win32':
        os.chmod(ENV_FILE, 0o600)


def _prompt_key(name: str, description: str, url: str, existing: str) -> str:
    display = '(already set — press Enter to keep)' if existing else '(press Enter to skip)'
    print(f'\n  {name}')
    print(f'  {description}')
    print(f'  {url}')
    val = input(f'  Value {display}: ').strip()
    return val if val else existing


def cmd_setup():
    """
    First-time setup. Run once per machine.
    Detects environment automatically — no flags needed.
    Safe to re-run: existing values are preserved.
    """
    print()
    print('  ════════════════════════════════════════════════')
    print('    PostmortemCLI — Setup')
    print('  ════════════════════════════════════════════════')

    print()
    print(f'  Platform:    {sys.platform}')
    print(f'  Config dir:  {CONFIG_DIR}')

    # Create config and reports directories
    os.makedirs(CONFIG_DIR, exist_ok=True)
    print(f'  ✓ Created {CONFIG_DIR}')
    reports_dir = os.path.join(CONFIG_DIR, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    print(f'  ✓ Created {reports_dir}')

    # Windows: add user Scripts directory to PATH permanently
    # Uses site.getuserbase() to find the correct user-level Scripts dir
    # where pip installs executables when running without admin rights
    if sys.platform == 'win32':
        import site
        scripts_dir = os.path.join(site.getuserbase(), 'Scripts')
        print(f'  Adding {scripts_dir} to user PATH...')
        try:
            result = subprocess.run([
                'powershell', '-Command',
                f'$current = [Environment]::GetEnvironmentVariable("PATH","User"); '
                f'if ($current -notlike "*{scripts_dir}*") {{ '
                f'[Environment]::SetEnvironmentVariable("PATH", $current + ";{scripts_dir}", "User") '
                f'}}'
            ], capture_output=True)
            print(f'  ✓ PATH updated — open a new terminal for the change to take effect.')
        except Exception:
            print(f'  ⚠  Could not set PATH automatically.')
            print(f'  Add manually to PATH: {scripts_dir}')

    enterprise = is_enterprise_environment()
    print(f'  Enterprise:  {enterprise}')

    if enterprise:
        print()
        print('  Enterprise environment detected.')

    # ── API keys ──────────────────────────────────────────────────────────────

    print()
    print('  ── API Keys ─────────────────────────────────────')
    print('  Optional. Press Enter to skip.')

    existing = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    k, v = line.split('=', 1)
                    existing[k.strip()] = v.strip()

    keys = {
        'ABUSE_CH_API_KEY': _prompt_key(
            'ABUSE_CH_API_KEY',
            'URLhaus, MalwareBazaar and ThreatFox (one key for all three)',
            'https://auth.abuse.ch',
            existing.get('ABUSE_CH_API_KEY', ''),
        ),
        'VIRUSTOTAL_API_KEY': _prompt_key(
            'VIRUSTOTAL_API_KEY',
            '70+ AV engines — URL and file scanning',
            'https://www.virustotal.com',
            existing.get('VIRUSTOTAL_API_KEY', ''),
        ),
        'ABUSEIPDB_API_KEY': _prompt_key(
            'ABUSEIPDB_API_KEY',
            'IP abuse confidence score',
            'https://www.abuseipdb.com/register',
            existing.get('ABUSEIPDB_API_KEY', ''),
        ),
        'GOOGLE_SAFE_BROWSING_KEY': _prompt_key(
            'GOOGLE_SAFE_BROWSING_KEY',
            'Google phishing and malware URL detection',
            'https://console.cloud.google.com',
            existing.get('GOOGLE_SAFE_BROWSING_KEY', ''),
        ),
        'EMAILREP_API_KEY': _prompt_key(
            'EMAILREP_API_KEY',
            'Sender email reputation (requires manual approval)',
            'https://emailrep.io',
            existing.get('EMAILREP_API_KEY', ''),
        ),
    }

    if enterprise:
        keys['POSTMORTEM_IMAGE'] = _prompt_key(
            'POSTMORTEM_IMAGE',
            'Full image path in private registry',
            'Contact your IT department',
            existing.get('POSTMORTEM_IMAGE', ''),
        )

    _write_env_file(keys)
    print(f'\n  ✓ Config saved to {ENV_FILE}')

    # ── CA certificate (enterprise only) ──────────────────────────────────────

    if enterprise:
        print()
        print('  ── SSL Certificate ──────────────────────────────')
        print('  Searching for organisation CA certificate...')

        if os.path.exists(CA_CERT):
            print('  ✓ Certificate already configured — skipping.')
        else:
            certs = _find_system_ca_certs()

            if len(certs) == 1:
                _copy_ca_cert(certs[0])
                print(f'  ✓ Certificate copied from {certs[0]}')

            elif len(certs) > 1:
                print()
                print('  Multiple certificates found:')
                for i, path in enumerate(certs, 1):
                    print(f'    [{i}] {os.path.basename(path)}')
                print()
                choice = input('  Which one is the organisation root CA? [number]: ').strip()
                try:
                    chosen = certs[int(choice) - 1]
                    _copy_ca_cert(chosen)
                    print('  ✓ Certificate copied — this will not be asked again.')
                except (ValueError, IndexError):
                    print('  ⚠  Invalid choice — skipping.')
                    print(f'  Re-run setup or copy manually to {CA_CERT}')
            else:
                print('  ⚠  No certificates found in system CA store.')
                print(f'  Copy the organisation root CA to {CA_CERT}')

        # ── bashrc ────────────────────────────────────────────────────────────
        bashrc = os.path.expanduser('~/.bashrc')
        try:
            content = open(bashrc).read()
            if 'postmortemcli-update' not in content:
                with open(bashrc, 'a') as f:
                    f.write('\n# PostmortemCLI\n')
                    f.write("alias postmortemcli-update='~/.postmortemcli/setup.sh'\n")
                print('  ✓ postmortemcli-update alias added to ~/.bashrc')
                print('  Run: source ~/.bashrc')
        except Exception:
            pass

    # ── Done ──────────────────────────────────────────────────────────────────

    print()
    print('  ════════════════════════════════════════════════')
    print('  Setup complete.')
    print()
    print('  Run: postmortemcli start')
    print('  ════════════════════════════════════════════════')
    print()



# ── Docker management ─────────────────────────────────────────────────────────

def _ensure_docker_running(runtime: str) -> bool:
    try:
        result = subprocess.run([runtime, 'info'], capture_output=True, timeout=5)
        if result.returncode == 0:
            return True
    except Exception:
        pass

    if sys.platform == 'win32' and runtime == 'docker':
        print('  [*] Docker not running -- starting Docker Desktop...')
        docker_paths = [
            os.path.join(os.environ.get('PROGRAMFILES', 'C:/Program Files'), 'Docker', 'Docker', 'Docker Desktop.exe'),
        ]
        started = False
        for path in docker_paths:
            if os.path.exists(path):
                subprocess.Popen([path])
                started = True
                break

        if not started:
            print('  [!] Docker Desktop not found.')
            print('      Install from: https://www.docker.com/products/docker-desktop')
            return False

        import time
        print('  [*] Waiting for Docker to start', end='', flush=True)
        for _ in range(30):
            time.sleep(2)
            print('.', end='', flush=True)
            try:
                result = subprocess.run([runtime, 'info'], capture_output=True, timeout=5)
                if result.returncode == 0:
                    print(' ready.')
                    return True
            except Exception:
                pass
        print()
        print('  [!] Docker did not start in time. Start Docker Desktop manually.')
        return False

    return False


def _update_image(runtime: str, version: str):
    image_name = 'filipanderssondev/postmortemcli'
    tag = version if version.startswith('v') else 'v' + version
    full_image = 'docker.io/' + image_name + ':' + tag

    print('  [1/3] Stopping running postmortemcli containers...')
    try:
        result = subprocess.run(
            [runtime, 'ps', '-q', '--filter', 'ancestor=' + image_name],
            capture_output=True, text=True
        )
        for cid in [c for c in result.stdout.strip().split() if c]:
            subprocess.run([runtime, 'stop', cid], capture_output=True)
            print('         Stopped ' + cid[:12])
    except Exception:
        pass

    print('  [2/3] Removing existing postmortemcli images...')
    try:
        result = subprocess.run(
            [runtime, 'images', '--format', '{{.ID}}', '--filter', 'reference=' + image_name + '*'],
            capture_output=True, text=True
        )
        for img_id in [i for i in result.stdout.strip().split() if i]:
            subprocess.run([runtime, 'rmi', '-f', img_id], capture_output=True)
            print('         Removed ' + img_id[:12])
    except Exception:
        pass

    print('  [3/3] Pulling ' + full_image + '...')
    result = subprocess.run([runtime, 'pull', full_image])
    if result.returncode == 0:
        print('  ✓ Image updated to ' + tag)
        try:
            env_content = open(ENV_FILE).read() if os.path.exists(ENV_FILE) else ''
            if 'POSTMORTEM_IMAGE=' in env_content:
                lines = [
                    'POSTMORTEM_IMAGE=' + full_image if l.startswith('POSTMORTEM_IMAGE=') else l
                    for l in env_content.splitlines()
                ]
                with open(ENV_FILE, 'w', encoding='utf-8') as f:
                    f.write(os.linesep.join(lines))
            else:
                with open(ENV_FILE, 'a') as f:
                    f.write(os.linesep + 'POSTMORTEM_IMAGE=' + full_image + os.linesep)
            print('  ✓ POSTMORTEM_IMAGE updated in .env')
        except Exception as e:
            print('  Warning: could not update .env: ' + str(e))
    else:
        print('  [!] Failed to pull image. Check your internet connection.')


def cmd_update(args: list):
    """
    Updates PostmortemCLI to a specific version.

    Enterprise (SMHI Linux):
      Delegates to ~/.postmortemcli/setup.sh which handles
      Image scanning, retagging, registry push and local pull.

    Standard (Windows / private Linux / Mac):
      1. pip install --force-reinstall from GitHub
      2. docker/podman pull from DockerHub
    """
    if not args:
        print('[ERROR] Provide a version.')
        print('Usage: postmortemcli update <version>')
        print('Example: postmortemcli update v0.3.0-beta')
        return

    version = args[0].lstrip('v')
    tag = 'v' + version

    print()
    print('  PostmortemCLI -- Update to ' + tag)
    print()

    # ── Enterprise (SMHI) — delegate to local setup.sh ───────────────────────
    if is_enterprise_environment():
        setup_script = os.path.join(CONFIG_DIR, 'update.sh')
        if not os.path.exists(setup_script):
            print('  [!] Enterprise update script not found: ' + setup_script)
            print('      Expected: ~/.postmortemcli/update.sh')
            return
        print('  Enterprise environment detected.')
        # Ensure script is executable
        import stat
        os.chmod(setup_script, os.stat(setup_script).st_mode | stat.S_IEXEC)
        print('  Running ' + setup_script + ' ' + tag + '...')
        print()
        result = subprocess.run([setup_script, tag])
        if result.returncode == 0:
            print()
            print('  ✓ Enterprise update complete. Run: postmortemcli start')
        else:
            print('  [!] Enterprise update script failed.')
        print()
        return

    # ── Standard (Windows / private Linux / Mac) ─────────────────────────────

    # Step 1: Update Python package
    print('  [1/2] Updating Python package...')
    repo = 'https://github.com/Filipanderssondev/PostmortemCLI-email-security-analyzer.git'
    result = subprocess.run([
        sys.executable, '-m', 'pip', 'install', '--force-reinstall',
        'git+' + repo + '@' + tag
    ])
    if result.returncode != 0:
        print('  [!] pip install failed.')
        return
    print('  ✓ Package updated.')

    # Step 2: Update container image
    print()
    print('  [2/2] Updating container image...')
    runtime = find_runtime()
    if not runtime:
        print('  [!] No container runtime found (docker/podman).')
        return

    if not _ensure_docker_running(runtime):
        return

    _update_image(runtime, tag)

    print()
    print('  ✓ Update complete. Run: postmortemcli start')
    print()

# ── Container lifecycle ───────────────────────────────────────────────────────

def _kill_existing(runtime: str):
    """Frees port 1025 before starting a new container."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if s.connect_ex(('127.0.0.1', 1025)) != 0:
            return

    print('  [*] Port 1025 in use — stopping existing container...')

    try:
        result = subprocess.run([runtime, 'ps', '-q'], capture_output=True, text=True)
        for cid in result.stdout.strip().split('\n'):
            if cid:
                port_result = subprocess.run(
                    [runtime, 'port', cid, '1025'], capture_output=True, text=True
                )
                if port_result.stdout.strip():
                    subprocess.run([runtime, 'stop', cid], capture_output=True)
                    print(f'  [*] Stopped container {cid[:12]}')
                    import time; time.sleep(1)
                    return
    except Exception:
        pass

    try:
        subprocess.run(['fuser', '-k', '1025/tcp'], capture_output=True)
        import time; time.sleep(0.5)
        print('  [*] Freed port 1025')
    except Exception:
        pass


def run_container(args: list):
    runtime = find_runtime()

    if not runtime:
        print('[ERROR] Neither podman nor docker found.')
        if sys.platform == 'win32':
            print('        Install Docker Desktop: https://www.docker.com/products/docker-desktop')
        else:
            print('        Install podman or docker.')
        sys.exit(1)

    if args and args[0] in ('start', 'listen'):
        if not _ensure_docker_running(runtime):
            sys.exit(1)
        _kill_existing(runtime)

    pull_flag  = ['--pull', 'never'] if is_private_registry() else []
    needs_port = args[0] in ('start', 'listen') if args else False
    env_flag   = ['--env-file', ENV_FILE] if os.path.exists(ENV_FILE) else []
    # Pass host reports path so sender.py can display correct path in output
    host_reports = os.path.join(CONFIG_DIR, 'reports')
    env_flag += ['--env', f'HOST_REPORTS_DIR={host_reports}']
    ca_flags   = _get_ca_flags()

    # Ensure reports directory exists on host
    reports_dir = os.path.join(CONFIG_DIR, 'reports')
    os.makedirs(reports_dir, exist_ok=True)

    # Mount CONFIG_DIR as /data so reports, config etc are accessible
    # On Linux/RHEL: :z sets SELinux label — omitted on Windows
    z = '' if sys.platform == 'win32' else ':z'

    # Mount CONFIG_DIR as /data (reports, env etc)
    # Mount cwd as /cwd so scan/send can access local email files
    # Convert Windows path to Docker-compatible Unix format
    # Uses same logic as get_mount_path(): C:\Users\... -> /c/Users/...
    def _to_docker_path(p: str) -> str:
        if sys.platform != 'win32':
            return p
        drive, rest = os.path.splitdrive(p)
        return f'/{drive.replace(":", "").lower()}{rest.replace(chr(92), "/")}'

    config_mount = _to_docker_path(CONFIG_DIR)
    cwd_mount    = get_mount_path()

    cmd = [
        runtime, 'run', '-it', '--rm',
        *pull_flag,
        *env_flag,
        *ca_flags,
        '-v', f'{config_mount}:/data{z}',
        '-v', f'{cwd_mount}:/cwd{z}',
        *(['-p', '1025:1025'] if needs_port else []),
        get_image(),
    ] + args

    if sys.platform == 'win32':
        sys.exit(subprocess.run(cmd).returncode)
    else:
        os.execvp(runtime, cmd)


def send_files(files: list):
    import smtplib
    from email import message_from_bytes
    from email.policy import SMTP as _smtp_policy
    from email.utils import parseaddr

    if not files:
        print('[ERROR] Provide at least one file.')
        print('Usage: postmortemcli send <file.eml> [files...]')
        sys.exit(1)

    for filepath in files:
        if not os.path.isfile(filepath):
            print(f'[ERROR] File not found: {filepath}')
            continue

        ext = os.path.splitext(filepath)[1].lower()

        try:
            if ext == '.msg':
                try:
                    import extract_msg
                except ImportError:
                    print('[ERROR] .msg support requires: pip install extract-msg')
                    continue
                msg_obj = extract_msg.openMsg(filepath)
                raw     = msg_obj.exportBytes()
            else:
                with open(filepath, 'rb') as f:
                    raw = f.read()

            message = message_from_bytes(raw, policy=_smtp_policy)

            _, from_addr = parseaddr(message.get('From', ''))
            if not from_addr or '@' not in from_addr:
                from_addr = 'postmortem@localhost'

            if not message.get('To'):
                message['To'] = 'postmortem@localhost'

            with smtplib.SMTP('127.0.0.1', 1025) as smtp:
                smtp.send_message(
                    message,
                    from_addr=from_addr,
                    to_addrs=['postmortem@localhost'],
                )

            print(f'[*] Sent: {filepath}')

        except ConnectionRefusedError:
            print('[ERROR] Nothing listening on port 1025.')
            print("        Run 'postmortemcli start' first.")
            sys.exit(1)
        except Exception as e:
            print(f'[ERROR] Send failed for {filepath}: {e}')


# ── Entry point ───────────────────────────────────────────────────────────────

USAGE = """
PostmortemCLI – Email Security Analysis Tool

Usage:
  postmortemcli setup                    First-time setup (run once per machine)
  postmortemcli update <version>         Update to a specific version
  postmortemcli start                    Start container + SMTP listener
  postmortemcli scan <file> [files...]   Scan email files directly
  postmortemcli send <file> [files...]   Send files to running SMTP listener
"""


def main():
    if is_inside_container():
        from main import main as cli_main
        cli_main()
        return

    args = sys.argv[1:]

    if not args:
        print(USAGE)
        sys.exit(0)

    command = args[0]

    if command == 'setup':
        cmd_setup()
    elif command == 'update':
        cmd_update(args[1:])
    elif command == 'send':
        send_files(args[1:])
    elif command in ('start', 'scan', 'listen'):
        run_container(args)
    else:
        print(f"[ERROR] Unknown command: '{command}'")
        print(USAGE)
        sys.exit(1)


if __name__ == '__main__':
    main()