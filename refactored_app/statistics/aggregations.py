"""
Aggregation Functions Module
Functions for aggregating and summarizing vulnerability data.
"""

import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any

from ..config import SEVERITY_ORDER, SEVERITY_WEIGHTS
from ..filters.hostname_parser import parse_hostname


def aggregate_by_hostname_structure(historical_df: pd.DataFrame, attribute: str = 'location') -> pd.DataFrame:
    """
    Aggregate findings by hostname structure attribute.

    Args:
        historical_df: DataFrame with historical findings
        attribute: Attribute to aggregate by ('location', 'tier', 'environment', 'cluster', 'host_type')

    Returns:
        DataFrame with aggregated statistics
    """
    if historical_df.empty:
        return pd.DataFrame()

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    # Use latest scan
    latest_scan = historical_df['scan_date'].max()
    latest_data = historical_df[historical_df['scan_date'] == latest_scan].copy()

    # Extract attribute from hostname
    def get_attribute(hostname):
        parsed = parse_hostname(hostname)
        if attribute == 'location':
            return parsed.location or 'Unknown'
        elif attribute == 'tier':
            return parsed.tier or 'Unknown'
        elif attribute == 'environment':
            return parsed.environment or 'Unknown'
        elif attribute == 'cluster':
            return parsed.cluster or 'Unknown'
        elif attribute == 'host_type':
            return parsed.host_type.value
        else:
            return 'Unknown'

    latest_data['_group_key'] = latest_data['hostname'].apply(get_attribute)

    # Aggregate
    aggregated = latest_data.groupby('_group_key').agg({
        'hostname': 'nunique',
        'plugin_id': 'nunique',
        'ip_address': 'nunique',
        'severity_value': 'sum',
        'cvss3_base_score': lambda x: pd.to_numeric(x, errors='coerce').mean()
    }).reset_index()

    aggregated.columns = [attribute, 'host_count', 'unique_plugins', 'unique_ips',
                          'total_severity_score', 'avg_cvss']

    # Finding count
    finding_counts = latest_data.groupby('_group_key').size().reset_index(name='finding_count')
    aggregated = aggregated.merge(finding_counts, left_on=attribute, right_on='_group_key', how='left')
    aggregated = aggregated.drop(columns=['_group_key'], errors='ignore')

    # Add severity breakdown
    severity_pivot = latest_data.groupby(['_group_key', 'severity_text']).size().unstack(fill_value=0)
    severity_pivot = severity_pivot.reset_index()
    severity_pivot = severity_pivot.rename(columns={'_group_key': attribute})

    aggregated = aggregated.merge(severity_pivot, on=attribute, how='left')

    # Fill missing severity columns
    for severity in SEVERITY_ORDER:
        if severity not in aggregated.columns:
            aggregated[severity] = 0

    # Calculate risk score
    aggregated['risk_score'] = (
        aggregated.get('Critical', 0) * SEVERITY_WEIGHTS['Critical'] * 2 +
        aggregated.get('High', 0) * SEVERITY_WEIGHTS['High'] * 1.5 +
        aggregated.get('Medium', 0) * SEVERITY_WEIGHTS['Medium'] +
        aggregated.get('Low', 0) * SEVERITY_WEIGHTS['Low'] * 0.5
    ).round(1)

    # Sort by risk score
    aggregated = aggregated.sort_values('risk_score', ascending=False)

    return aggregated


def create_summary_dashboard_data(historical_df: pd.DataFrame, lifecycle_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Create summary data for a dashboard view.

    Args:
        historical_df: DataFrame with historical findings
        lifecycle_df: DataFrame from analyze_finding_lifecycle

    Returns:
        Dictionary with dashboard summary data
    """
    if historical_df.empty:
        return {}

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    latest_scan = historical_df['scan_date'].max()
    latest_data = historical_df[historical_df['scan_date'] == latest_scan]

    # Key metrics
    total_findings = len(latest_data)
    unique_hosts = latest_data['hostname'].nunique()
    unique_plugins = latest_data['plugin_id'].nunique()
    unique_ips = latest_data['ip_address'].nunique()

    # Severity breakdown
    severity_counts = latest_data['severity_text'].value_counts().to_dict()

    # Critical and high count
    critical_high = severity_counts.get('Critical', 0) + severity_counts.get('High', 0)

    # Lifecycle metrics
    lifecycle_metrics = {}
    if lifecycle_df is not None and not lifecycle_df.empty:
        active = lifecycle_df[lifecycle_df['status'] == 'Active']
        resolved = lifecycle_df[lifecycle_df['status'] == 'Resolved']

        lifecycle_metrics = {
            'active_findings': len(active),
            'resolved_findings': len(resolved),
            'resolution_rate': round((len(resolved) / len(lifecycle_df) * 100), 1) if len(lifecycle_df) > 0 else 0,
            'avg_days_open': round(active['days_open'].mean(), 1) if not active.empty else 0,
            'reappearing_findings': len(lifecycle_df[lifecycle_df['reappearances'] > 0])
        }

    # Scan history
    scan_dates = sorted(historical_df['scan_date'].unique())
    total_scans = len(scan_dates)

    return {
        'current_metrics': {
            'total_findings': total_findings,
            'unique_hosts': unique_hosts,
            'unique_plugins': unique_plugins,
            'unique_ips': unique_ips,
            'critical_high_count': critical_high,
            'scan_date': latest_scan.strftime('%Y-%m-%d')
        },
        'severity_breakdown': severity_counts,
        'lifecycle_metrics': lifecycle_metrics,
        'scan_info': {
            'total_scans': total_scans,
            'first_scan': scan_dates[0].strftime('%Y-%m-%d'),
            'latest_scan': scan_dates[-1].strftime('%Y-%m-%d'),
            'date_range_days': (scan_dates[-1] - scan_dates[0]).days
        }
    }


def get_top_n_summary(historical_df: pd.DataFrame, n: int = 10) -> Dict[str, List[Dict]]:
    """
    Get top N items for various categories.

    Args:
        historical_df: DataFrame with historical findings
        n: Number of top items to return

    Returns:
        Dictionary with top N lists for each category
    """
    if historical_df.empty:
        return {}

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    latest_scan = historical_df['scan_date'].max()
    latest_data = historical_df[historical_df['scan_date'] == latest_scan]

    result = {}

    # Top hosts by finding count
    top_hosts = latest_data.groupby('hostname').agg({
        'plugin_id': 'count',
        'ip_address': 'first',
        'severity_value': 'sum'
    }).reset_index()
    top_hosts.columns = ['hostname', 'finding_count', 'ip_address', 'severity_score']
    top_hosts = top_hosts.nlargest(n, 'finding_count')
    result['top_hosts'] = top_hosts.to_dict('records')

    # Top plugins by occurrence
    top_plugins = latest_data.groupby(['plugin_id', 'name']).agg({
        'hostname': 'nunique',
        'severity_text': 'first',
        'severity_value': 'first'
    }).reset_index()
    top_plugins.columns = ['plugin_id', 'plugin_name', 'affected_hosts', 'severity', 'severity_value']
    top_plugins = top_plugins.nlargest(n, 'affected_hosts')
    result['top_plugins'] = top_plugins.to_dict('records')

    # Top CVEs (if available)
    if 'cves' in latest_data.columns:
        cve_list = []
        for cves in latest_data['cves'].dropna():
            if cves:
                cve_list.extend([cve.strip() for cve in cves.split('\n') if cve.strip()])

        if cve_list:
            cve_counts = pd.Series(cve_list).value_counts().head(n)
            result['top_cves'] = [{'cve': cve, 'count': int(count)} for cve, count in cve_counts.items()]

    # Highest risk hosts (by severity score)
    risk_hosts = latest_data.groupby('hostname').agg({
        'severity_value': 'sum',
        'cvss3_base_score': lambda x: pd.to_numeric(x, errors='coerce').max(),
        'ip_address': 'first'
    }).reset_index()
    risk_hosts.columns = ['hostname', 'severity_score', 'max_cvss', 'ip_address']
    risk_hosts['risk_score'] = risk_hosts['severity_score'] + (risk_hosts['max_cvss'].fillna(0) * 5)
    risk_hosts = risk_hosts.nlargest(n, 'risk_score')
    result['highest_risk_hosts'] = risk_hosts.to_dict('records')

    return result


def create_comparison_matrix(historical_df: pd.DataFrame, group_col: str = 'hostname') -> pd.DataFrame:
    """
    Create a comparison matrix showing findings across scans.

    Args:
        historical_df: DataFrame with historical findings
        group_col: Column to group by (e.g., 'hostname', 'plugin_id')

    Returns:
        DataFrame with matrix of counts per scan
    """
    if historical_df.empty:
        return pd.DataFrame()

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    # Create pivot table
    matrix = pd.crosstab(
        historical_df[group_col],
        historical_df['scan_date'].dt.strftime('%Y-%m-%d')
    )

    # Add totals
    matrix['Total'] = matrix.sum(axis=1)
    matrix = matrix.sort_values('Total', ascending=False)

    return matrix
