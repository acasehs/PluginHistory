"""
Statistics modules for vulnerability and host analysis.
"""

from .plugin_stats import (
    get_plugin_occurrence_stats,
    get_plugin_timeline,
    get_plugin_severity_distribution,
    get_plugin_remediation_stats,
    get_most_persistent_plugins,
    get_reappearing_plugins
)

from .host_stats import (
    get_host_vulnerability_stats,
    get_host_risk_scores,
    get_hosts_by_severity,
    get_host_remediation_performance
)

from .trend_analysis import (
    calculate_trend_metrics,
    get_severity_trends,
    get_remediation_trends,
    forecast_vulnerability_count
)

from .aggregations import (
    aggregate_by_hostname_structure,
    create_summary_dashboard_data,
    get_top_n_summary
)

__all__ = [
    'get_plugin_occurrence_stats',
    'get_plugin_timeline',
    'get_plugin_severity_distribution',
    'get_plugin_remediation_stats',
    'get_most_persistent_plugins',
    'get_reappearing_plugins',
    'get_host_vulnerability_stats',
    'get_host_risk_scores',
    'get_hosts_by_severity',
    'get_host_remediation_performance',
    'calculate_trend_metrics',
    'get_severity_trends',
    'get_remediation_trends',
    'forecast_vulnerability_count',
    'aggregate_by_hostname_structure',
    'create_summary_dashboard_data',
    'get_top_n_summary'
]
