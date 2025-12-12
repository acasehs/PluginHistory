"""
Configuration constants for the Nessus Historical Analysis System.
"""

from dataclasses import dataclass
from typing import Dict, List, Tuple


# Application version
VERSION = "2.0"

# Severity mappings
SEVERITY_MAPPING = {
    0: 'Info',
    1: 'Low',
    2: 'Medium',
    3: 'High',
    4: 'Critical'
}
SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info']

SEVERITY_COLORS = {
    'Critical': '#dc3545',
    'High': '#fd7e14',
    'Medium': '#ffc107',
    'Low': '#007bff',
    'Info': '#6c757d'
}

SEVERITY_WEIGHTS = {
    'Critical': 4,
    'High': 3,
    'Medium': 2,
    'Low': 1,
    'Info': 0
}

# CVSS score thresholds for severity mapping
CVSS_THRESHOLDS = {
    'Critical': (9.0, 10.0),
    'High': (7.0, 8.9),
    'Medium': (4.0, 6.9),
    'Low': (0.1, 3.9),
    'Info': (0.0, 0.0)
}

# Finding lifecycle settings
REAPPEARANCE_GAP_DAYS = 45  # Days gap to consider finding as reappeared

# Hostname structure configuration
@dataclass
class HostnameFormat:
    """Configuration for hostname structure parsing."""
    length: int
    location_start: int
    location_end: int
    tier_start: int
    tier_end: int
    cluster_pos: int
    environment_pos: int
    type_pos: int


# 9-character hostname format: LLLLTTCEP
# L=Location(4), T=Tier(2), C=Cluster(1), E=Environment(1), P=Physical/Virtual(1)
HOSTNAME_FORMAT_9 = HostnameFormat(
    length=9,
    location_start=0,
    location_end=4,
    tier_start=4,
    tier_end=6,
    cluster_pos=6,
    environment_pos=7,
    type_pos=8
)

# Host type indicators
HOST_TYPE_PHYSICAL = 'p'
HOST_TYPE_VIRTUAL = 'v'
HOST_TYPE_ILOM = 'ilom'

# OPDIR compliance status colors
OPDIR_STATUS_COLORS = {
    'On Track': '#28a745',
    'Due Soon': '#ffc107',
    'Overdue': '#dc3545',
    'Unknown': '#6c757d'
}

# Age buckets for finding age categorization
AGE_BUCKETS = [
    (0, 30, '0-30'),
    (31, 60, '31-60'),
    (61, 90, '61-90'),
    (91, 120, '91-120'),
    (121, float('inf'), '121+')
]

# GUI settings
GUI_WINDOW_SIZE = "1400x900"
GUI_DARK_THEME = {
    'bg': '#2b2b2b',
    'fg': 'white',
    'entry_bg': '#404040',
    'button_bg': '#404040',
    'button_active': '#505050',
    'text_bg': '#1e1e1e'
}

# Export settings
EXCEL_MAX_COLUMN_WIDTH = 50
SQLITE_INDEXES = {
    'historical_findings': ['hostname', 'plugin_id', 'scan_date', 'ip_address'],
    'finding_lifecycle': ['hostname', 'plugin_id', 'status', 'opdir_number', 'opdir_status'],
    'host_presence': ['hostname', 'status'],
    'scan_changes': ['scan_date']
}

# Date formats
DATE_FORMAT_DISPLAY = '%Y-%m-%d'
DATE_FORMAT_FULL = '%Y-%m-%d %H:%M:%S'
DATE_FORMAT_ISO = '%Y-%m-%dT%H:%M:%S'

# Scan date extraction patterns
DATE_PATTERNS = [
    r'(\d{4})[-_](\d{2})[-_](\d{2})',  # YYYY-MM-DD or YYYY_MM_DD
    r'(\d{2})[-_](\d{2})[-_](\d{4})',  # MM-DD-YYYY or MM_DD_YYYY
    r'(\d{8})',  # YYYYMMDD
    r'(\d{6})',  # YYMMDD or MMDDYY
]
