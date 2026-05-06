# launcher.py
# Registered as "postmortemcli" via pyproject.toml
# Runs on host: detects platform, finds runtime, starts container
# Runs in container: hands off to main.py

import os
import sys
import subprocess


def is_inside_container() -> bool:
    return os.environ.get("POSTMORTEM_CONTAINER") == "1"


def find_runtime() -> str:
    finder = "where" if sys.platform == "win32" else "which"
    for candidate in ["podman", "docker"]:
        result = subprocess.run([finder, candidate], capture_output=True)
        if result.returncode == 0:
            return candidate
    return None


def get_image() -> str:
    return os.environ.get(
        "POSTMORTEM_IMAGE",
        "docker.io/filipanderssondev/postmortemcli:latest"
        # Override with: export POSTMORTEM_IMAGE=your-registry/image:tag
    )


def is_private_registry() -> bool:
    """
    Detects if the configured image is from a private registry.
    Public registries are pulled automatically.
    Private registries require manual login and pull – local image is used.
    """
    public_registries = ["docker.io", "ghcr.io", "registry.hub.docker.com", "quay.io"]
    return not any(registry in get_image() for registry in public_registries)


def get_mount_path() -> str:
    cwd = os.getcwd()
    if sys.platform == "win32":
        drive, rest = os.path.splitdrive(cwd)
        return f"/{drive.replace(':', '').lower()}{rest.replace(chr(92), '/')}"
    return cwd


def run_container(args: list):
    runtime = find_runtime()

    if not runtime:
        print("[ERROR] Neither podman nor docker found.")
        if sys.platform == "win32":
            print("        Install Docker Desktop: https://www.docker.com/products/docker-desktop")
        else:
            print("        Install podman or docker.")
        sys.exit(1)

    pull_flag = ["--pull", "never"] if is_private_registry() else []
    # Private registry: use local image only – manual pull required
    # Public registry: pull automatically on first run

    cmd = [
        runtime, "run", "-it", "--rm",
        *pull_flag,
        "-v", f"{get_mount_path()}:/data",
        "-p", "1025:1025",
        get_image(),
    ] + args

    if sys.platform == "win32":
        sys.exit(subprocess.run(cmd).returncode)
    else:
        os.execvp(runtime, cmd)


def send_files(files: list):
    import smtplib
    from email import message_from_bytes

    if not files:
        print("[ERROR] Provide at least one file.")
        print("Usage: postmortemcli send <file.eml> [files...]")
        sys.exit(1)

    for filepath in files:
        try:
            with open(filepath, "rb") as f:
                message = message_from_bytes(f.read())

            with smtplib.SMTP("localhost", 1025) as smtp:
                smtp.send_message(message)

            print(f"[*] Sent: {filepath}")

        except FileNotFoundError:
            print(f"[ERROR] File not found: {filepath}")

        except ConnectionRefusedError:
            print("[ERROR] Nothing listening on port 1025.")
            print("        Run 'postmortemcli start' first.")
            sys.exit(1)


USAGE = """
PostmortemCLI – Email Security Analysis Tool

Usage:
  postmortemcli start                    Start container + SMTP listener
  postmortemcli scan <file> [files...]   Scan email files directly
  postmortemcli send <file> [files...]   Send files to running SMTP listener

Configuration:
  Override image via environment variable:
  export POSTMORTEM_IMAGE=your-registry/image:tag
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

    if command == "send":
        send_files(args[1:])
    elif command in ("start", "scan", "listen"):
        run_container(args)
    else:
        print(f"[ERROR] Unknown command: '{command}'")
        print(USAGE)
        sys.exit(1)


if __name__ == "__main__":
    main()