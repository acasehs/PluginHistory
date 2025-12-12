"""
Plugin Statistics Module
Statistics and analytics for Nessus plugins across historical scans.
"""

import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any

from ..config import SEVERITY_ORDER


def get_plugin_occurrence_stats(historical_df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate plugin occurrence statistics across all scans.

    Args:
        historical_df: DataFrame with historical findings

    Returns:
        DataFrame with plugin occurrence statistics
    """
    if historical_df.empty:
        return pd.DataFrame()

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    # Get total scans and dates
    scan_dates = sorted(historical_df['scan_date'].unique())
    total_scans = len(scan_dates)

    # Calculate stats per plugin
    plugin_stats = historical_df.groupby(['plugin_id', 'name']).agg({
        'hostname': 'nunique',
        'scan_date': ['nunique', 'min', 'max'],
        'severity_text': 'first',
        'severity_value': 'first',
        'cvss3_base_score': 'first'
    }).reset_index()

    plugin_stats.columns = [
        'plugin_id', 'plugin_name', 'unique_hosts', 'scans_present',
        'first_seen', 'last_seen', 'severity_text', 'severity_value', 'cvss3_base_score'
    ]

    # Calculate additional metrics
    plugin_stats['presence_percentage'] = (plugin_stats['scans_present'] / total_scans * 100).round(1)
    plugin_stats['days_present'] = (plugin_stats['last_seen'] - plugin_stats['first_seen']).dt.days

    # Total findings per plugin
    finding_counts = historical_df.groupby('plugin_id').size().reset_index(name='total_findings')
    plugin_stats = plugin_stats.merge(finding_counts, on='plugin_id')

    # Average hosts per scan
    plugin_stats['avg_hosts_per_scan'] = (plugin_stats['total_findings'] / plugin_stats['scans_present']).round(1)

    # Sort by total findings
    plugin_stats = plugin_stats.sort_values('total_findings', ascending=False)

    return plugin_stats


def get_plugin_timeline(historical_df: pd.DataFrame, plugin_id: str = None) -> pd.DataFrame:
    """
    Get plugin occurrence timeline.

    Args:
        historical_df: DataFrame with historical findings
        plugin_id: Optional specific plugin to analyze

    Returns:
        DataFrame with plugin counts over time
    """
    if historical_df.empty:
        return pd.DataFrame()

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    if plugin_id:
        historical_df = historical_df[historical_df['plugin_id'] == plugin_id]

    timeline = historical_df.groupby('scan_date').agg({
        'plugin_id': 'nunique',
        'hostname': 'nunique'
    }).reset_index()

    timeline.columns = ['scan_date', 'unique_plugins', 'affected_hosts']

    # Add total findings count
    finding_counts = historical_df.groupby('scan_date').size().reset_index(name='total_findings')
    timeline = timeline.merge(finding_counts, on='scan_date')

    return timeline.sort_values('scan_date')


def get_plugin_severity_distribution(historical_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Get plugin count and finding count by severity.

    Args:
        historical_df: DataFrame with historical findings

    Returns:
        Dictionary with severity distribution data
    """
    if historical_df.empty:
        return {}

    # Unique plugins by severity
    plugin_severity = historical_df.groupby('severity_text')['plugin_id'].nunique()

    # Finding counts by severity
    finding_severity = historical_df.groupby('severity_text').size()

    # Host counts by severity
    host_severity = historical_df.groupby('severity_text')['hostname'].nunique()

    return {
        'plugins_by_severity': plugin_severity.to_dict(),
        'findings_by_severity': finding_severity.to_dict(),
        'hosts_by_severity': host_severity.to_dict(),
        'severity_order': [s for s in SEVERITY_ORDER if s in plugin_severity.index]
    }


def get_plugin_remediation_stats(lifecycle_df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate remediation statistics per plugin.

    Args:
        lifecycle_df: DataFrame from analyze_finding_lifecycle

    Returns:
        DataFrame with per-plugin remediation statistics
    """
    if lifecycle_df.empty:
        return pd.DataFrame()

    # Group by plugin
    plugin_remediation = lifecycle_df.groupby(['plugin_id', 'plugin_name']).agg({
        'days_open': ['mean', 'median', 'min', 'max', 'std'],
        'status': lambda x: (x == 'Resolved').sum(),
        'hostname': 'count',
        'reappearances': 'sum',
        'severity_text': 'first',
        'severity_value': 'first'
    })

    plugin_remediation.columns = [
        'mean_days_open', 'median_days_open', 'min_days_open', 'max_days_open', 'std_days_open',
        'resolved_count', 'total_findings', 'total_reappearances',
        'severity_text', 'severity_value'
    ]

    plugin_remediation = plugin_remediation.reset_index()

    # Calculate resolution rate
    plugin_remediation['resolution_rate'] = (
        plugin_remediation['resolved_count'] / plugin_remediation['total_findings'] * 100
    ).round(1)

    # Calculate reappearance rate
    plugin_remediation['reappearance_rate'] = (
        plugin_remediation['total_reappearances'] / plugin_remediation['total_findings'] * 100
    ).round(1)

    # Sort by mean days open
    plugin_remediation = plugin_remediation.sort_values('mean_days_open', ascending=False)

    return plugin_remediation


def get_most_persistent_plugins(lifecycle_df: pd.DataFrame, top_n: int = 20) -> pd.DataFrame:
    """
    Get the most persistent plugins (longest average time open).

    Args:
        lifecycle_df: DataFrame from analyze_finding_lifecycle
        top_n: Number of top plugins to return

    Returns:
        DataFrame with most persistent plugins
    """
    if lifecycle_df.empty:
        return pd.DataFrame()

    # Filter to active findings only
    active = lifecycle_df[lifecycle_df['status'] == 'Active'].copy()

    if active.empty:
        return pd.DataFrame()

    persistent = active.groupby(['plugin_id', 'plugin_name']).agg({
        'days_open': 'mean',
        'hostname': 'nunique',
        'severity_text': 'first',
        'severity_value': 'first'
    }).reset_index()

    persistent.columns = ['plugin_id', 'plugin_name', 'avg_days_open', 'affected_hosts',
                          'severity_text', 'severity_value']

    persistent = persistent.sort_values('avg_days_open', ascending=False).head(top_n)

    return persistent


def get_reappearing_plugins(lifecycle_df: pd.DataFrame) -> pd.DataFrame:
    """
    Get plugins that frequently reappear after remediation.

    Args:
        lifecycle_df: DataFrame from analyze_finding_lifecycle

    Returns:
        DataFrame with reappearing plugins
    """
    if lifecycle_df.empty:
        return pd.DataFrame()

    reappearing = lifecycle_df[lifecycle_df['reappearances'] > 0].copy()

    if reappearing.empty:
        return pd.DataFrame()

    plugin_reappearance = reappearing.groupby(['plugin_id', 'plugin_name']).agg({
        'reappearances': 'sum',
        'hostname': 'nunique',
        'severity_text': 'first',
        'severity_value': 'first'
    }).reset_index()

    plugin_reappearance.columns = ['plugin_id', 'plugin_name', 'total_reappearances',
                                    'affected_hosts', 'severity_text', 'severity_value']

    plugin_reappearance = plugin_reappearance.sort_values('total_reappearances', ascending=False)

    return plugin_reappearance


def get_new_plugins_per_scan(historical_df: pd.DataFrame) -> pd.DataFrame:
    """
    Track when new plugins first appeared.

    Args:
        historical_df: DataFrame with historical findings

    Returns:
        DataFrame showing new plugins per scan
    """
    if historical_df.empty:
        return pd.DataFrame()

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    # Get first appearance date for each plugin
    first_seen = historical_df.groupby('plugin_id')['scan_date'].min().reset_index()
    first_seen.columns = ['plugin_id', 'first_seen']

    # Count new plugins per scan
    new_plugins_per_scan = first_seen.groupby('first_seen').size().reset_index(name='new_plugins')
    new_plugins_per_scan.columns = ['scan_date', 'new_plugins']

    # Merge with all scan dates
    all_dates = pd.DataFrame({'scan_date': sorted(historical_df['scan_date'].unique())})
    new_plugins_per_scan = all_dates.merge(new_plugins_per_scan, on='scan_date', how='left')
    new_plugins_per_scan['new_plugins'] = new_plugins_per_scan['new_plugins'].fillna(0).astype(int)

    # Add cumulative count
    new_plugins_per_scan['cumulative_plugins'] = new_plugins_per_scan['new_plugins'].cumsum()

    return new_plugins_per_scan


def get_plugin_host_matrix(historical_df: pd.DataFrame, top_n_plugins: int = 20) -> pd.DataFrame:
    """
    Create a matrix showing which plugins affect which hosts.

    Args:
        historical_df: DataFrame with historical findings
        top_n_plugins: Number of top plugins to include

    Returns:
        DataFrame with plugin-host matrix (latest scan only)
    """
    if historical_df.empty:
        return pd.DataFrame()

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    # Use latest scan
    latest_scan = historical_df['scan_date'].max()
    latest_data = historical_df[historical_df['scan_date'] == latest_scan]

    # Get top plugins by host count
    top_plugins = latest_data.groupby('plugin_id')['hostname'].nunique().nlargest(top_n_plugins).index

    latest_data = latest_data[latest_data['plugin_id'].isin(top_plugins)]

    # Create pivot table
    matrix = pd.crosstab(
        latest_data['plugin_id'],
        latest_data['hostname']
    )

    return matrix
