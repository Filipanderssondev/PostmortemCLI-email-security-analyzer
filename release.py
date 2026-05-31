#!/usr/bin/env python3
# release.py
# Updates version across ALL files in the project, commits, and tags.
#
# Usage:
#   python release.py 0.2.2-beta
#   python release.py 1.0.0

import sys
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).parent

SKIP_DIRS  = {'.git', '.github', '__pycache__', '.venv', 'node_modules', '.pytest_cache'}
SKIP_FILES = {'release.py'}
SCAN_EXTENSIONS = {'.py', '.toml', '.txt', '.md', '.cfg', '.ini', '.yml', '.yaml', '.sh'}


def fail(msg: str):
    print(f'\n[ERROR] {msg}')
    sys.exit(1)


def run(cmd: list, check=True) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        fail(f'Command failed: {" ".join(cmd)}\n{result.stderr}')
    return result.stdout.strip()


def check_git_clean():
    status = run(['git', 'status', '--porcelain'])
    if status:
        fail(f'Working directory not clean. Commit or stash first:\n{status}')


def get_current_version() -> str:
    content = (ROOT / 'pyproject.toml').read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', content, re.MULTILINE)
    if not match:
        fail('Could not find version in pyproject.toml')
    return match.group(1)


def scan_and_update(old_version: str, new_version: str) -> list:
    updated = []

    for path in sorted(ROOT.rglob('*')):
        if path.is_dir():
            continue
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue
        if path.name in SKIP_FILES:
            continue
        if path.suffix not in SCAN_EXTENSIONS:
            continue

        try:
            content = path.read_text(encoding='utf-8')
        except (UnicodeDecodeError, PermissionError):
            continue

        new_content = content.replace(old_version, new_version)
        new_content = new_content.replace(f'v{old_version}', f'v{new_version}')

        if new_content != content:
            path.write_text(new_content, encoding='utf-8')
            rel = path.relative_to(ROOT)
            updated.append(str(rel))
            print(f'  [✓] {rel}')

    return updated


def git_commit_and_tag(version: str, updated_files: list):
    # Get commits since last tag for changelog
    last_tag = run(['git', 'describe', '--tags', '--abbrev=0'], check=False)
    if last_tag:
        changelog = run(['git', 'log', f'{last_tag}..HEAD', '--oneline', '--no-merges'], check=False)
    else:
        changelog = run(['git', 'log', '--oneline', '--no-merges', '-10'], check=False)

    commit_msg = f'chore: bump version to {version}'
    if changelog:
        commit_msg += f'\n\nChanges since {last_tag or "initial"}:\n{changelog}'

    if updated_files:
        run(['git', 'add', '-u'])
        run(['git', 'commit', '-m', commit_msg])
        print(f'  [✓] Committed {len(updated_files)} file(s)')
    else:
        print('  [~] No files needed updating')

    existing = run(['git', 'tag', '-l', f'v{version}'], check=False)
    if existing:
        fail(
            f'Tag v{version} already exists.\n'
            f'Delete it first:\n'
            f'  git tag -d v{version}\n'
            f'  git push origin --delete v{version}'
        )
    run(['git', 'tag', f'v{version}'])
    print(f'  [✓] Created tag v{version}')
    run(['git', 'push'])
    run(['git', 'push', 'origin', f'v{version}'])
    print(f'  [✓] Pushed → CI/CD is building the image')


def main():
    if len(sys.argv) != 2:
        print('Usage:   python release.py <version>')
        print('Example: python release.py 0.2.2-beta')
        sys.exit(1)

    new_version = sys.argv[1].lstrip('v')

    if not re.match(r'^\d+\.\d+\.\d+[\w.\-]*$', new_version):
        fail(
            f'Invalid version: {new_version}\n'
            f'Examples: 0.2.2-beta  1.0.0  0.3.0-alpha'
        )

    check_git_clean()

    old_version = get_current_version()

    if old_version == new_version:
        fail(f'New version is the same as current ({old_version})')

    print(f'\n  PostmortemCLI  {old_version} → {new_version}\n')
    print('  Scanning project files...')

    updated = scan_and_update(old_version, new_version)

    if not updated:
        print(f'  [!] No files contained "{old_version}" — check version in pyproject.toml')
        sys.exit(1)

    print()
    git_commit_and_tag(new_version, updated)

    print(f'\n  Done. v{new_version} is live.')
    print(f'  Run: postmortemcli update v{new_version}\n')


if __name__ == '__main__':
    main()