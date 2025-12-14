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
    calculate_opdir_compliance_status,
    get_opdir_compliance_summary,
    get_overdue_findings,
    get_opdir_by_year_report,
    extract_opdir_from_iavx,
    normalize_opdir_number,
    create_opdir_lookup,
    match_opdir
)

from .iavm_parser import (
    load_iavm_summaries,
    enrich_findings_with_iavm,
    normalize_iavm_number,
    create_iavm_lookup,
    get_iavm_summary_stats,
    merge_opdir_and_iavm
)

from .advanced_metrics import (
    get_all_advanced_metrics,
    calculate_reopen_rate,
    calculate_coverage_metrics,
    calculate_mttd,
    calculate_risk_reduction_trend,
    calculate_remediation_rate,
    calculate_sla_breach_tracking,
    calculate_normalized_metrics
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
    'calculate_opdir_compliance_status',
    'get_opdir_compliance_summary',
    'get_overdue_findings',
    'get_opdir_by_year_report',
    'extract_opdir_from_iavx',
    'normalize_opdir_number',
    'create_opdir_lookup',
    'match_opdir',
    'load_iavm_summaries',
    'enrich_findings_with_iavm',
    'normalize_iavm_number',
    'create_iavm_lookup',
    'get_iavm_summary_stats',
    'merge_opdir_and_iavm',
    'get_all_advanced_metrics',
    'calculate_reopen_rate',
    'calculate_coverage_metrics',
    'calculate_mttd',
    'calculate_risk_reduction_trend',
    'calculate_remediation_rate',
    'calculate_sla_breach_tracking',
    'calculate_normalized_metrics'
]
