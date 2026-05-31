# src/sender.py
# Saves the Post-Mortem Incident Report to /data/reports/ inside the container.
# /data is mounted from the host — files written here persist outside the container.
#
# Usage:
#   from src.sender import save
#   save(report_text, report_id)
#
# Output: /data/reports/PMRT-YYYYMMDD-HHMMSS.txt
# Host:   ~/.postmortemcli/reports/PMRT-YYYYMMDD-HHMMSS.txt

import os
import sys
from src.logger import get_logger

logger   = get_logger(__name__)
# Inside container: /data/reports (mounted from the host config dir)
# Outside container (local testing): platform-specific config dir
def _get_reports_dir() -> str:
    if os.environ.get('POSTMORTEM_CONTAINER') == '1':
        return '/data/reports'
    if sys.platform == 'win32':
        base = os.environ.get('APPDATA', os.path.expanduser('~'))
        return os.path.normpath(os.path.join(base, 'postmortemcli', 'reports'))
    return os.path.expanduser('~/.postmortemcli/reports')

_OUT_DIR = _get_reports_dir()


def save(report_text: str, report_id: str) -> str:
    """
    Saves the report to /data/reports/ which is mounted from the host.
    Returns the file path, or empty string on failure.
    """
    try:
        os.makedirs(_OUT_DIR, exist_ok=True)
        path = os.path.join(_OUT_DIR, f'{report_id}.txt')
        with open(path, 'w', encoding='utf-8') as f:
            f.write(report_text)
        logger.info(f'Report saved → {path}')
        host_reports = os.environ.get('HOST_REPORTS_DIR', '/data/reports')
        host_path = os.path.join(host_reports, f'{report_id}.txt')
        print(f'\n  Report saved -> {host_path}\n')
        return path
    except Exception as e:
        logger.warning(f'Could not save report: {e}')
        return ''