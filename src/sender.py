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
from src.logger import get_logger

logger   = get_logger(__name__)
# Inside container: /data/reports (mounted from ~/.postmortemcli/reports)
# Outside container or local testing: ~/.postmortemcli/reports directly
_OUT_DIR = '/data/reports' if os.environ.get('POSTMORTEM_CONTAINER') == '1'            else os.path.expanduser('~/.postmortemcli/reports')


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
        print(f'\n  Report saved → ~/.postmortemcli/reports/{report_id}.txt\n')
        return path
    except Exception as e:
        logger.warning(f'Could not save report: {e}')
        return ''