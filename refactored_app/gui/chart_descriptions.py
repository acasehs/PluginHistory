"""
Chart descriptions for vulnerability analysis visualizations.

Each chart has:
- title: Display name
- description: What the chart shows
- cyber_context: Security/risk management value
- inputs: Data required
- interpretation: How to read the results
"""

CHART_DESCRIPTIONS = {
    # ==================== Risk Tab ====================
    'cvss_distribution': {
        'title': 'CVSS Score Distribution',
        'description': 'Histogram showing the distribution of CVSS v3 base scores across all findings. Bars are color-coded by severity: Critical (red, 9.0+), High (orange, 7.0-8.9), Medium (yellow, 4.0-6.9), Low (green, 0-3.9).',
        'cyber_context': 'Helps identify the overall risk profile of your environment. A distribution skewed toward higher scores indicates systemic security issues requiring immediate attention. Use this to prioritize remediation efforts and justify security investments.',
        'inputs': 'cvss3_base_score from vulnerability scan data',
        'interpretation': 'Peak location shows typical vulnerability severity. Wide spread suggests diverse risk levels. Right-skewed distributions are concerning.',
        'filters': ['Severity', 'Status', 'Date Range', 'Environment']
    },
    'mttr_by_severity': {
        'title': 'Mean Time to Remediation (MTTR)',
        'description': 'Bar chart showing average days to resolve vulnerabilities grouped by severity level. Only includes resolved findings.',
        'cyber_context': 'Key metric for security operations effectiveness. Compare against SLA targets to identify compliance gaps. Critical and High MTTR exceeding SLAs indicates remediation process failures.',
        'inputs': 'days_open, severity_text, status (Resolved)',
        'interpretation': 'Lower bars = faster remediation. Critical should have lowest MTTR. Compare to your SLA targets (typically: Critical 15d, High 30d, Medium 60d, Low 90d).',
        'filters': ['Severity', 'Date Range', 'Environment']
    },
    'findings_by_age': {
        'title': 'Findings by Age',
        'description': 'Stacked bar chart showing active findings bucketed by age: 0-30 days, 31-60 days, 61-90 days, 90+ days.',
        'cyber_context': 'Aging vulnerabilities represent increased risk exposure. Findings over 90 days likely indicate process failures, lack of ownership, or technical barriers. Use for compliance reporting and risk acceptance decisions.',
        'inputs': 'days_open, status (Active)',
        'interpretation': 'Most findings should be in 0-30 day bucket. Large 90+ day bucket indicates remediation backlog requiring management attention.',
        'filters': ['Severity', 'Status', 'Environment']
    },
    'risky_hosts': {
        'title': 'Top Risky Hosts',
        'description': 'Horizontal bar chart showing hosts with highest cumulative risk scores, colored by environment type (Production=green, PSS=blue, Shared=yellow).',
        'cyber_context': 'Identifies assets requiring immediate security attention. Production hosts with high risk scores should be prioritized. Helps target penetration testing and security assessments.',
        'inputs': 'hostname, severity_value, environment_type',
        'interpretation': 'Focus remediation on top hosts. Consider isolating high-risk production systems. Environment coloring helps prioritize based on business impact.',
        'filters': ['Severity', 'Status', 'Environment', 'Host Type']
    },

    # ==================== Timeline Tab ====================
    'total_findings_trend': {
        'title': 'Total Findings by Period',
        'description': 'Line chart showing total vulnerability count over time, grouped by selected interval (daily, weekly, monthly). Includes trend indicator.',
        'cyber_context': 'Shows overall security posture trajectory. Increasing trend indicates growing attack surface or inadequate remediation. Flat or decreasing trend suggests security program effectiveness.',
        'inputs': 'scan_date, finding counts',
        'interpretation': 'Upward trend = increasing risk. Spikes may indicate new scans or vulnerability disclosures. Compare to security events or infrastructure changes.',
        'filters': ['Date Range', 'Severity', 'Environment']
    },
    'severity_timeline': {
        'title': 'Findings by Severity Over Time',
        'description': 'Multi-line chart tracking Critical, High, Medium, Low findings over time. Each severity has distinct color.',
        'cyber_context': 'Monitors severity distribution changes. Sudden Critical/High spikes may indicate zero-days or new attack vectors. Helps demonstrate remediation progress by severity tier.',
        'inputs': 'scan_date, severity_text',
        'interpretation': 'Critical/High lines should trend downward. Watch for correlation between severity levels. Diverging trends may indicate prioritization issues.',
        'filters': ['Date Range', 'Environment']
    },
    'new_vs_resolved': {
        'title': 'New / Closed / Unchanged',
        'description': 'Grouped bar chart showing weekly breakdown of finding states: New (appeared this period), Closed (resolved), and Unchanged (continuing from previous period).',
        'cyber_context': 'Core metric for security program health. Closed > New indicates reducing risk. Unchanged represents backlog that needs attention. Track ratio of all three for comprehensive program visibility.',
        'inputs': 'scan_changes (New/Resolved/Continuing events), historical finding counts',
        'interpretation': 'Green bars (closed) should exceed red bars (new). Gray bars (unchanged) show persistent backlog. Net change = New - Closed. Velocity ratio: Closed/New > 1.0 means improving posture.',
        'filters': ['Date Range', 'Severity', 'Environment']
    },
    'cumulative_risk': {
        'title': 'Cumulative Risk Score',
        'description': 'Area chart showing total severity-weighted risk score over time. Risk = sum of (severity_value for all active findings).',
        'cyber_context': 'Single metric capturing overall organizational risk. Use for executive reporting and risk trending. Enables comparison across time periods and business units.',
        'inputs': 'scan_date, severity_value',
        'interpretation': 'Downward slope = risk reduction. Plateaus indicate stagnation. Sharp increases require investigation.',
        'filters': ['Date Range', 'Environment']
    },

    # ==================== 8 Week Rolling Tab ====================
    'rolling_severity_totals': {
        'title': 'Total Findings by Severity (Weekly)',
        'description': 'Stacked bar chart showing total vulnerability count per week, broken down by severity level (Critical, High, Medium, Low). Each bar represents one week of the rolling 8-week window.',
        'cyber_context': 'Week-over-week trend analysis is essential for measuring remediation velocity and identifying emerging risks. Sudden increases may indicate new vulnerabilities or scan coverage changes.',
        'inputs': 'scan_date, severity_text, finding counts aggregated weekly',
        'interpretation': 'Decreasing total bar heights indicate risk reduction. Watch for Critical/High segments growing relative to others. Missing weeks appear as zero-height bars.',
        'filters': ['Environment', 'Severity']
    },
    'rolling_unique_plugins': {
        'title': 'Unique Plugins by Severity (Weekly)',
        'description': 'Stacked bar chart showing count of unique vulnerability types (plugin IDs) detected each week, grouped by severity. Measures vulnerability diversity rather than instance count.',
        'cyber_context': 'Unique plugin count reveals attack surface breadth. Decreasing unique plugins suggests successful patch management. New plugins appearing indicate emerging threats or expanded scan coverage.',
        'inputs': 'scan_date, plugin_id, severity_text',
        'interpretation': 'Lower unique counts = fewer distinct vulnerability types to address. Spikes may indicate new scan plugins or emerging CVEs. Compare to total findings to understand instance-to-type ratio.',
        'filters': ['Environment', 'Severity']
    },
    'rolling_env_findings': {
        'title': 'Findings by Environment (Weekly)',
        'description': 'Grouped bar chart showing unique findings per environment type for each week. NEW findings that appeared that week are shown in transparent (50% opacity) at the bottom of each bar, while existing/continuing findings are solid. Enables tracking of both total findings and weekly new arrivals per environment.',
        'cyber_context': 'Environment comparison highlights where security resources should focus. Transparent sections show NEW vulnerabilities appearing that week - high new counts indicate emerging risks. Solid sections represent backlog. Production environments typically require faster remediation.',
        'inputs': 'scan_date, environment_type, hostname, plugin_id (compared week-over-week)',
        'interpretation': 'Watch for large transparent (new) sections - indicates emerging risks. Solid sections (unchanged) represent persistent backlog. Total number shown at top, +N label shows new count. Production findings should trend downward.',
        'filters': ['Severity', 'Environment']
    },
    'rolling_env_totals': {
        'title': 'Environment Totals by Severity (Weekly)',
        'description': 'Grouped stacked bar chart showing total findings per environment, with severity breakdown. Each environment has its own bar group per week, stacked by severity.',
        'cyber_context': 'Combines environment segmentation with severity analysis. Critical findings in Production require immediate attention. Helps prioritize cross-environment remediation campaigns.',
        'inputs': 'scan_date, environment_type, severity_text',
        'interpretation': 'Focus on Critical/High segments in Production first. Consistent severity distribution across environments suggests systemic issues. Varying distributions may indicate environment-specific risks.',
        'filters': ['Environment']
    },

    # ==================== SLA Tab ====================
    'sla_compliance': {
        'title': 'SLA Compliance Overview',
        'description': 'Stacked bar chart showing compliant, at-risk, and breached findings by severity level.',
        'cyber_context': 'Critical for compliance reporting and audit evidence. SLA breaches may trigger contractual penalties or regulatory findings. Track for continuous improvement.',
        'inputs': 'severity_text, sla_status (calculated from days_open vs SLA targets)',
        'interpretation': 'Green = on track, Yellow = approaching deadline, Red = breached. Focus on reducing red segments, especially for Critical/High.',
        'filters': ['Severity', 'Environment']
    },
    'sla_breaches': {
        'title': 'SLA Breaches by Severity',
        'description': 'Bar chart showing count of SLA-breached findings per severity level.',
        'cyber_context': 'Direct compliance risk indicator. High breach counts require escalation and resource allocation. Document for audit trail.',
        'inputs': 'severity_text, days_open, sla_targets',
        'interpretation': 'Critical breaches are highest priority. Zero breaches is the goal. Track month-over-month improvement.',
        'filters': ['Date Range', 'Environment']
    },
    'sla_approaching': {
        'title': 'SLA Approaching Deadline',
        'description': 'List/bar of findings within warning threshold of SLA deadline (typically 25% remaining).',
        'cyber_context': 'Early warning system for potential breaches. Enables proactive remediation before SLA violation. Helps resource planning.',
        'inputs': 'severity_text, days_open, sla_targets, warning_threshold',
        'interpretation': 'These findings need immediate attention. Sort by days remaining. Assign owners and track daily.',
        'filters': ['Severity', 'Environment']
    },
    'sla_days_distribution': {
        'title': 'Days to SLA Deadline',
        'description': 'Distribution chart showing days remaining until SLA deadline. Negative values = overdue.',
        'cyber_context': 'Visualizes remediation urgency across portfolio. Helps identify systemic issues (e.g., all Critical findings overdue).',
        'inputs': 'sla_deadline, current_date',
        'interpretation': 'Distribution should be right-skewed (most findings have time remaining). Left tail (negative) represents breaches.',
        'filters': ['Severity', 'Status', 'Environment']
    },

    # ==================== OPDIR Tab ====================
    'opdir_coverage': {
        'title': 'OPDIR Coverage',
        'description': 'Pie chart showing findings mapped to OPDIR directives vs unmapped findings.',
        'cyber_context': 'OPDIR directives are authoritative remediation requirements. Unmapped findings may lack official guidance. Coverage indicates compliance posture.',
        'inputs': 'opdir_number (presence indicates mapping)',
        'interpretation': 'Higher mapped percentage = better compliance coverage. Unmapped findings need manual assessment.',
        'filters': ['Severity', 'Status']
    },
    'opdir_status': {
        'title': 'OPDIR Compliance Status',
        'description': 'Donut chart showing Overdue, Due Soon, and On Track status for OPDIR-mapped findings.',
        'cyber_context': 'Direct compliance measurement against authoritative directives. Overdue findings may result in audit findings or security incidents.',
        'inputs': 'opdir_due_date, current_date',
        'interpretation': 'Minimize red (overdue). Yellow indicates upcoming deadlines. Green shows compliant items.',
        'filters': ['Date Range', 'Environment']
    },
    'opdir_age': {
        'title': 'OPDIR Finding Age Distribution',
        'description': 'Histogram of days since discovery for OPDIR-mapped findings.',
        'cyber_context': 'Shows remediation velocity for mandated vulnerabilities. Long-standing OPDIR findings indicate serious compliance issues.',
        'inputs': 'first_seen, opdir_number',
        'interpretation': 'Distribution should skew left (newer findings). Long tail indicates remediation challenges.',
        'filters': ['OPDIR Status', 'Severity']
    },
    'opdir_by_year': {
        'title': 'Findings by OPDIR Year',
        'description': 'Grouped bar showing findings by OPDIR directive release year.',
        'cyber_context': 'Older directives with open findings suggest persistent compliance gaps. Helps identify historical remediation debt.',
        'inputs': 'opdir_number (year extracted)',
        'interpretation': 'Findings from older years indicate long-standing issues. Recent years should have fewer findings.',
        'filters': ['Status', 'Severity']
    },

    # ==================== Efficiency Tab ====================
    'scan_coverage': {
        'title': 'Scan Coverage Consistency',
        'description': 'Distribution of hosts by number of scans they appear in.',
        'cyber_context': 'Identifies gaps in vulnerability scanning program. Hosts scanned infrequently may harbor undetected vulnerabilities.',
        'inputs': 'hostname, scan_date (unique scans per host)',
        'interpretation': 'Peak should be at high scan counts. Left tail indicates under-scanned assets.',
        'filters': ['Date Range', 'Host Type']
    },
    'reappearance_rate': {
        'title': 'Vulnerability Reappearance',
        'description': 'Chart showing vulnerabilities that were resolved but reappeared in subsequent scans.',
        'cyber_context': 'Indicates ineffective remediation or regression. High reappearance suggests root cause not addressed or change management issues.',
        'inputs': 'scan_changes (status transitions)',
        'interpretation': 'Lower is better. Recurring findings need root cause analysis. May indicate patch rollback or configuration drift.',
        'filters': ['Severity', 'Date Range']
    },
    'host_burden': {
        'title': 'Vulnerabilities per Host',
        'description': 'Distribution showing how vulnerabilities are spread across hosts.',
        'cyber_context': 'Identifies concentration risk. Few hosts with many vulnerabilities are high-value targets for attackers.',
        'inputs': 'hostname, finding count per host',
        'interpretation': 'Right-skewed = few problematic hosts. Flat distribution = systemic issues.',
        'filters': ['Severity', 'Environment', 'Host Type']
    },
    'resolution_velocity': {
        'title': 'Resolution Velocity',
        'description': 'Distribution of time-to-resolution for remediated vulnerabilities.',
        'cyber_context': 'Measures remediation efficiency. Compare to industry benchmarks and SLA targets.',
        'inputs': 'days_open (for resolved findings)',
        'interpretation': 'Peak location shows typical remediation time. Long tail indicates outliers needing investigation.',
        'filters': ['Severity', 'Date Range', 'Environment']
    },

    # ==================== Network Tab ====================
    'top_subnets': {
        'title': 'Top Subnets by Vulnerability',
        'description': 'Horizontal bar chart showing network subnets with most vulnerabilities.',
        'cyber_context': 'Identifies network segments requiring security focus. May indicate vulnerable applications, outdated infrastructure, or inadequate segmentation.',
        'inputs': 'ip_address (subnet extracted)',
        'interpretation': 'Focus network security efforts on top subnets. Consider additional segmentation for high-risk segments.',
        'filters': ['Severity', 'Status', 'Environment']
    },
    'subnet_risk': {
        'title': 'Subnet Risk Scores',
        'description': 'Risk-weighted view of network segments using severity scoring.',
        'cyber_context': 'Prioritizes network segments by actual risk, not just count. Critical vulnerabilities weight higher than informational.',
        'inputs': 'ip_address, severity_value',
        'interpretation': 'High-risk subnets need immediate attention regardless of count. May justify network redesign.',
        'filters': ['Severity', 'Status']
    },
    'host_criticality': {
        'title': 'Host Criticality Distribution',
        'description': 'Distribution of cumulative risk scores across hosts.',
        'cyber_context': 'Visualizes risk concentration across infrastructure. Tail represents high-value targets.',
        'inputs': 'hostname, severity_value (summed)',
        'interpretation': 'Right tail hosts are critical. Average line shows typical risk level.',
        'filters': ['Environment', 'Host Type']
    },
    'environment_distribution': {
        'title': 'Environment Distribution',
        'description': 'Pie/bar chart showing findings by environment type (Production, PSS, Shared, etc.).',
        'cyber_context': 'Production vulnerabilities have highest business impact. Shared infrastructure affects multiple environments.',
        'inputs': 'hostname -> environment_type mapping',
        'interpretation': 'Production findings need prioritization. Shared findings may have broader impact.',
        'filters': ['Severity', 'Status']
    },

    # ==================== Plugin Tab ====================
    'top_plugins': {
        'title': 'Top 15 Most Common Plugins',
        'description': 'Horizontal bar chart showing most frequently detected vulnerability types (by Plugin ID).',
        'cyber_context': 'Identifies systemic vulnerabilities affecting many hosts. These are often misconfigurations or missing patches.',
        'inputs': 'plugin_id, plugin_name, count',
        'interpretation': 'Top plugins may have single remediation action affecting many hosts. High ROI for remediation.',
        'filters': ['Severity', 'Status', 'Environment']
    },
    'plugin_severity': {
        'title': 'Findings by Severity',
        'description': 'Bar chart showing total findings per severity level.',
        'cyber_context': 'Quick view of severity distribution. Critical and High counts drive risk posture.',
        'inputs': 'severity_text',
        'interpretation': 'Pyramid shape (more Low, fewer Critical) is healthy. Inverted pyramid indicates serious issues.',
        'filters': ['Status', 'Environment']
    },
    'plugins_by_hosts': {
        'title': 'Plugins Affecting Most Hosts',
        'description': 'Plugins ranked by number of unique hosts affected.',
        'cyber_context': 'Wide-spread vulnerabilities indicate systemic issues. High host count + high severity = critical priority.',
        'inputs': 'plugin_id, hostname (unique count)',
        'interpretation': 'Top plugins affect most of your infrastructure. Single fix can reduce risk across many assets.',
        'filters': ['Severity', 'Status']
    },
    'plugin_age': {
        'title': 'Plugins with Longest Average Age',
        'description': 'Plugins ranked by average days open. Color-coded: Red (>90d), Orange (>30d), Green (<30d).',
        'cyber_context': 'Long-standing vulnerability types may indicate remediation barriers or false positives.',
        'inputs': 'plugin_id, days_open (averaged)',
        'interpretation': 'Red items need investigation. May be unfixable or require significant effort.',
        'filters': ['Status', 'Environment']
    },

    # ==================== Priority Tab ====================
    'priority_matrix': {
        'title': 'Remediation Priority Matrix',
        'description': 'Scatter plot with CVSS score on X-axis and days open on Y-axis. Points colored by severity.',
        'cyber_context': 'Visual prioritization tool. Upper-right quadrant = high severity AND old = highest priority.',
        'inputs': 'cvss3_base_score, days_open, severity_text',
        'interpretation': 'Quadrants: UR=Critical priority, UL=Old but low severity, LR=New high severity, LL=Low priority.',
        'filters': ['Severity', 'Status', 'Environment']
    },
    'priority_distribution': {
        'title': 'Priority Distribution',
        'description': 'Pie chart showing findings by calculated priority bucket (Urgent, High, Medium, Low).',
        'cyber_context': 'Summary view for resource planning. Urgent items need immediate attention.',
        'inputs': 'priority_score (calculated from CVSS + age)',
        'interpretation': 'Track urgent reduction over time. Healthy distribution has small urgent slice.',
        'filters': ['Severity', 'Status']
    },
    'top_priority': {
        'title': 'Top 10 Priority Findings',
        'description': 'List of highest priority findings based on CVSS score and age combination.',
        'cyber_context': 'Action list for remediation teams. These should be assigned and tracked daily.',
        'inputs': 'priority_score, plugin_name, hostname',
        'interpretation': 'Start remediation from top. Check for common threads (same host, same vulnerability).',
        'filters': ['Environment', 'Host Type']
    },
    'priority_by_severity': {
        'title': 'Priority Score by Severity',
        'description': 'Average priority score grouped by severity level.',
        'cyber_context': 'Shows if high-severity items are being addressed quickly. Critical should have lower priority score (newer).',
        'inputs': 'priority_score, severity_text (averaged)',
        'interpretation': 'Higher bars for Critical/High indicates aging high-severity items - bad sign.',
        'filters': ['Status', 'Environment']
    },

    # ==================== Host Tracking Tab ====================
    'missing_hosts': {
        'title': 'Missing Hosts',
        'description': 'Hosts not seen in recent scans that previously appeared.',
        'cyber_context': 'Missing hosts may be decommissioned, renamed, or dropped from scan scope. Security risk if active but unscanned.',
        'inputs': 'hostname, last_seen_date',
        'interpretation': 'Verify status of each missing host. Update inventory or scan configuration as needed.',
        'filters': ['Date Range', 'Environment']
    },
    'host_presence': {
        'title': 'Hosts per Scan Over Time',
        'description': 'Line chart showing unique host count per scan over time.',
        'cyber_context': 'Monitors scan scope consistency. Drops may indicate infrastructure changes or scanner issues.',
        'inputs': 'scan_date, hostname (unique count)',
        'interpretation': 'Stable line is good. Sudden changes need investigation.',
        'filters': ['Date Range']
    },
    'declining_hosts': {
        'title': 'Declining Scan Coverage',
        'description': 'Hosts showing decreased scan frequency or intermittent coverage.',
        'cyber_context': 'Intermittent scanning creates blind spots. Attackers can exploit gaps in visibility.',
        'inputs': 'hostname, scan appearance frequency',
        'interpretation': 'Investigate cause for each declining host. May need scanner configuration changes.',
        'filters': ['Date Range', 'Environment']
    },
    'host_status': {
        'title': 'Host Status Overview',
        'description': 'Distribution of hosts by their scanning status (Active, Intermittent, Missing).',
        'cyber_context': 'Quick health check of vulnerability management program coverage.',
        'inputs': 'hostname, scan frequency classification',
        'interpretation': 'Maximize Active, minimize Missing. Set thresholds based on scan schedule.',
        'filters': ['Environment', 'Host Type']
    },

    # ==================== Metrics Tab ====================
    'remediation_metrics': {
        'title': 'Remediation vs Active by Severity',
        'description': 'Grouped bar comparing resolved and active findings per severity level.',
        'cyber_context': 'Shows remediation progress across severity tiers. Higher resolved:active ratio is better.',
        'inputs': 'severity_text, status',
        'interpretation': 'Green (resolved) should exceed red (active), especially for Critical/High.',
        'filters': ['Date Range', 'Environment']
    },
    'risk_trend': {
        'title': 'Organization Risk Trend',
        'description': 'Line chart showing overall risk score over time with trend line.',
        'cyber_context': 'Executive-level metric for security program effectiveness. Use for board reporting.',
        'inputs': 'scan_date, severity_value (summed)',
        'interpretation': 'Downward trend shows improvement. Flat or rising requires action.',
        'filters': ['Date Range']
    },
    'sla_metrics': {
        'title': 'SLA Compliance by Severity',
        'description': 'Stacked percentage bar showing SLA compliance rate per severity.',
        'cyber_context': 'Compliance metric for regulatory and contractual requirements.',
        'inputs': 'severity_text, sla_status',
        'interpretation': 'Target 100% compliance, especially for Critical. Track improvement over time.',
        'filters': ['Date Range', 'Environment']
    },
    'vulns_per_host_trend': {
        'title': 'Vulnerabilities per Host Trend',
        'description': 'Average vulnerabilities per host over time.',
        'cyber_context': 'Normalized metric accounting for infrastructure growth. Better for comparison across time.',
        'inputs': 'finding count / host count per scan',
        'interpretation': 'Decreasing trend shows per-asset risk reduction.',
        'filters': ['Date Range', 'Environment']
    },

    # ==================== Advanced Charts ====================
    'heatmap': {
        'title': 'Vulnerability Density Heatmap',
        'description': 'Grid showing vulnerability density by host and severity. Darker = more findings.',
        'cyber_context': 'Visual pattern recognition for concentrated risk areas.',
        'inputs': 'hostname, severity_text, count',
        'interpretation': 'Dark cells are priority. Look for patterns (all hosts same severity = systemic issue).',
        'filters': ['Severity', 'Status', 'Environment']
    },
    'bubble': {
        'title': 'Bubble Chart',
        'description': 'Multi-dimensional view: X=CVSS, Y=Age, Size=hosts affected, Color=severity.',
        'cyber_context': 'Rich visualization for executive presentations. Shows multiple risk dimensions.',
        'inputs': 'cvss3_base_score, days_open, host_count, severity',
        'interpretation': 'Large red bubbles in upper-right are critical priorities.',
        'filters': ['Severity', 'Status']
    },
    'sankey': {
        'title': 'Lifecycle Flow',
        'description': 'Flow diagram showing vulnerability progression from discovery to resolution.',
        'cyber_context': 'Process visualization for remediation workflow analysis.',
        'inputs': 'status transitions over time',
        'interpretation': 'Thick flows to Resolved is good. Thin flows indicate bottlenecks.',
        'filters': ['Date Range', 'Severity']
    },
    'treemap': {
        'title': 'Category Treemap',
        'description': 'Hierarchical view of vulnerabilities by plugin family/category.',
        'cyber_context': 'Identifies vulnerability categories requiring attention.',
        'inputs': 'plugin_family, count, severity',
        'interpretation': 'Large tiles represent significant vulnerability categories.',
        'filters': ['Severity', 'Status']
    },
    'sla_prediction': {
        'title': 'SLA Breach Prediction',
        'description': 'Forecast of upcoming SLA breaches based on current trajectory.',
        'cyber_context': 'Proactive risk management. Plan resources before breaches occur.',
        'inputs': 'days_to_sla, remediation velocity',
        'interpretation': 'Rising line indicates increasing future breaches. Take action early.',
        'filters': ['Severity']
    },
    'period_comparison': {
        'title': 'Period Comparison',
        'description': 'Side-by-side comparison of metrics between two time periods.',
        'cyber_context': 'Demonstrates program improvement for reporting and audits.',
        'inputs': 'All metrics calculated for each period',
        'interpretation': 'Green indicators show improvement. Red indicates regression.',
        'filters': ['Date Range Selection']
    },
}

def get_chart_description(chart_key: str) -> dict:
    """Get description for a specific chart."""
    return CHART_DESCRIPTIONS.get(chart_key, {
        'title': chart_key,
        'description': 'No description available.',
        'cyber_context': '',
        'inputs': '',
        'interpretation': '',
        'filters': []
    })

def get_all_chart_descriptions() -> dict:
    """Get all chart descriptions."""
    return CHART_DESCRIPTIONS
