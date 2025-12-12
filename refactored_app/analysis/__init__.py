"""
Analysis modules for vulnerability lifecycle and host tracking.
"""

from .lifecycle import (
    analyze_finding_lifecycle,
    identify_reappearances,
    calculate_mttr
)

from .host_presence import (
    create_host_presence_analysis,
    identify_missing_hosts,
    calculate_scan_coverage
)

from .scan_changes import (
    analyze_scan_changes,
    calculate_host_churn
)

from .opdir_compliance import (
    load_opdir_mapping,
    enrich_with_opdir,
    calculate_opdir_compliance_status
)

__all__ = [
    'analyze_finding_lifecycle',
    'identify_reappearances',
    'calculate_mttr',
    'create_host_presence_analysis',
    'identify_missing_hosts',
    'calculate_scan_coverage',
    'analyze_scan_changes',
    'calculate_host_churn',
    'load_opdir_mapping',
    'enrich_with_opdir',
    'calculate_opdir_compliance_status'
]
