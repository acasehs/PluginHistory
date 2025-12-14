"""
Visualization modules for creating charts and dashboards.
"""

from .charts import (
    create_severity_pie_chart,
    create_timeline_chart,
    create_host_risk_bar_chart,
    create_cvss_distribution,
    create_remediation_chart,
    # Date interval grouping utilities
    get_date_interval,
    get_interval_label,
    get_period_format,
    get_date_format,
    format_period_label,
    group_by_interval,
    group_by_interval_column,
    get_period_labels,
    calculate_date_range_from_df,
    DATE_INTERVAL_WEEKLY,
    DATE_INTERVAL_MONTHLY,
    DATE_INTERVAL_QUARTERLY,
    DATE_INTERVAL_YEARLY
)

from .dashboards import (
    create_executive_dashboard,
    create_lifecycle_dashboard,
    create_host_analysis_dashboard,
    create_plugin_analysis_dashboard
)

from .export_visuals import (
    export_chart_to_file,
    export_dashboard_to_pdf
)

__all__ = [
    'create_severity_pie_chart',
    'create_timeline_chart',
    'create_host_risk_bar_chart',
    'create_cvss_distribution',
    'create_remediation_chart',
    'create_executive_dashboard',
    'create_lifecycle_dashboard',
    'create_host_analysis_dashboard',
    'create_plugin_analysis_dashboard',
    'export_chart_to_file',
    'export_dashboard_to_pdf',
    # Date interval utilities
    'get_date_interval',
    'get_interval_label',
    'get_period_format',
    'get_date_format',
    'format_period_label',
    'group_by_interval',
    'group_by_interval_column',
    'get_period_labels',
    'calculate_date_range_from_df',
    'DATE_INTERVAL_WEEKLY',
    'DATE_INTERVAL_MONTHLY',
    'DATE_INTERVAL_QUARTERLY',
    'DATE_INTERVAL_YEARLY'
]
