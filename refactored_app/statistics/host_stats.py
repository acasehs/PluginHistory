"""
Host Statistics Module
Statistics and analytics for hosts across historical scans.
"""

import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any

from ..config import SEVERITY_ORDER, SEVERITY_WEIGHTS
from ..filters.hostname_parser import parse_hostname, HostType


def get_host_vulnerability_stats(historical_df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate vulnerability statistics per host.

    Args:
        historical_df: DataFrame with historical findings

    Returns:
        DataFrame with per-host vulnerability statistics
    """
    if historical_df.empty:
        return pd.DataFrame()

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    # Get latest scan
    latest_scan = historical_df['scan_date'].max()
    latest_data = historical_df[historical_df['scan_date'] == latest_scan]

    # Calculate stats per host
    host_stats = latest_data.groupby(['hostname', 'ip_address']).agg({
        'plugin_id': 'nunique',
        'severity_text': 'count',
        'cvss3_base_score': lambda x: pd.to_numeric(x, errors='coerce').mean()
    }).reset_index()

    host_stats.columns = ['hostname', 'ip_address', 'unique_plugins', 'total_findings', 'avg_cvss']

    # Add severity breakdown
    severity_pivot = latest_data.groupby(['hostname', 'severity_text']).size().unstack(fill_value=0)
    severity_pivot = severity_pivot.reset_index()

    host_stats = host_stats.merge(severity_pivot, on='hostname', how='left')

    # Fill missing severity columns
    for severity in SEVERITY_ORDER:
        if severity not in host_stats.columns:
            host_stats[severity] = 0

    # Calculate risk score
    host_stats['risk_score'] = (
        host_stats.get('Critical', 0) * SEVERITY_WEIGHTS['Critical'] +
        host_stats.get('High', 0) * SEVERITY_WEIGHTS['High'] +
        host_stats.get('Medium', 0) * SEVERITY_WEIGHTS['Medium'] +
        host_stats.get('Low', 0) * SEVERITY_WEIGHTS['Low']
    )

    # Add host type classification
    host_stats['host_type'] = host_stats['hostname'].apply(
        lambda h: parse_hostname(h).host_type.value
    )

    # Add location info
    host_stats['location'] = host_stats['hostname'].apply(
        lambda h: parse_hostname(h).location
    )

    # Sort by risk score
    host_stats = host_stats.sort_values('risk_score', ascending=False)

    return host_stats


def get_host_risk_scores(historical_df: pd.DataFrame, lifecycle_df: pd.DataFrame = None) -> pd.DataFrame:
    """
    Calculate comprehensive risk scores for each host.

    Risk score components:
    - Severity-weighted vulnerability count
    - Average CVSS score
    - Age factor (older vulnerabilities increase risk)
    - Reappearance penalty

    Args:
        historical_df: DataFrame with historical findings
        lifecycle_df: Optional lifecycle DataFrame for age and reappearance data

    Returns:
        DataFrame with host risk scores
    """
    if historical_df.empty:
        return pd.DataFrame()

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    latest_scan = historical_df['scan_date'].max()
    latest_data = historical_df[historical_df['scan_date'] == latest_scan]

    # Base severity score
    hosts = latest_data.groupby('hostname').agg({
        'ip_address': 'first',
        'severity_value': 'sum',
        'cvss3_base_score': lambda x: pd.to_numeric(x, errors='coerce').mean()
    }).reset_index()

    hosts.columns = ['hostname', 'ip_address', 'severity_score', 'avg_cvss']

    # Add lifecycle metrics if available
    if lifecycle_df is not None and not lifecycle_df.empty:
        active_lifecycle = lifecycle_df[lifecycle_df['status'] == 'Active']

        if not active_lifecycle.empty:
            lifecycle_metrics = active_lifecycle.groupby('hostname').agg({
                'days_open': 'mean',
                'reappearances': 'sum'
            }).reset_index()

            lifecycle_metrics.columns = ['hostname', 'avg_days_open', 'total_reappearances']
            hosts = hosts.merge(lifecycle_metrics, on='hostname', how='left')

            hosts['avg_days_open'] = hosts['avg_days_open'].fillna(0)
            hosts['total_reappearances'] = hosts['total_reappearances'].fillna(0)

            # Age factor (normalize to 0-1 scale, max at 365 days)
            hosts['age_factor'] = (hosts['avg_days_open'] / 365).clip(0, 1)

            # Reappearance factor
            hosts['reappearance_factor'] = (hosts['total_reappearances'] / 10).clip(0, 1)
        else:
            hosts['age_factor'] = 0
            hosts['reappearance_factor'] = 0
    else:
        hosts['age_factor'] = 0
        hosts['reappearance_factor'] = 0

    # Calculate composite risk score (0-100 scale)
    hosts['risk_score'] = (
        hosts['severity_score'] * 0.5 +
        hosts['avg_cvss'].fillna(0) * 5 +
        hosts['age_factor'] * 20 +
        hosts['reappearance_factor'] * 10
    ).round(1)

    # Classify risk level
    def classify_risk(score):
        if score >= 80:
            return 'Critical'
        elif score >= 50:
            return 'High'
        elif score >= 25:
            return 'Medium'
        elif score > 0:
            return 'Low'
        else:
            return 'None'

    hosts['risk_level'] = hosts['risk_score'].apply(classify_risk)

    # Sort by risk score
    hosts = hosts.sort_values('risk_score', ascending=False)

    return hosts


def get_hosts_by_severity(historical_df: pd.DataFrame, severity: str) -> pd.DataFrame:
    """
    Get hosts with findings of a specific severity.

    Args:
        historical_df: DataFrame with historical findings
        severity: Severity level to filter by

    Returns:
        DataFrame with hosts having the specified severity
    """
    if historical_df.empty:
        return pd.DataFrame()

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    latest_scan = historical_df['scan_date'].max()
    latest_data = historical_df[
        (historical_df['scan_date'] == latest_scan) &
        (historical_df['severity_text'] == severity)
    ]

    if latest_data.empty:
        return pd.DataFrame()

    host_severity = latest_data.groupby(['hostname', 'ip_address']).agg({
        'plugin_id': 'nunique',
        'severity_text': 'count',
        'cvss3_base_score': lambda x: pd.to_numeric(x, errors='coerce').max()
    }).reset_index()

    host_severity.columns = ['hostname', 'ip_address', 'unique_plugins', 'finding_count', 'max_cvss']

    return host_severity.sort_values('finding_count', ascending=False)


def get_host_remediation_performance(lifecycle_df: pd.DataFrame) -> pd.DataFrame:
    """
    Analyze remediation performance per host.

    Args:
        lifecycle_df: DataFrame from analyze_finding_lifecycle

    Returns:
        DataFrame with host remediation performance metrics
    """
    if lifecycle_df.empty:
        return pd.DataFrame()

    host_performance = lifecycle_df.groupby('hostname').agg({
        'ip_address': 'first',
        'status': lambda x: (x == 'Resolved').sum(),
        'plugin_id': 'count',
        'days_open': 'mean',
        'reappearances': 'sum',
        'severity_value': 'mean'
    }).reset_index()

    host_performance.columns = [
        'hostname', 'ip_address', 'resolved_count', 'total_findings',
        'avg_days_to_resolve', 'total_reappearances', 'avg_severity'
    ]

    # Calculate resolution rate
    host_performance['resolution_rate'] = (
        host_performance['resolved_count'] / host_performance['total_findings'] * 100
    ).round(1)

    # Active findings count
    active_counts = lifecycle_df[lifecycle_df['status'] == 'Active'].groupby('hostname').size()
    host_performance = host_performance.merge(
        active_counts.reset_index(name='active_findings'),
        on='hostname',
        how='left'
    )
    host_performance['active_findings'] = host_performance['active_findings'].fillna(0).astype(int)

    # Performance score (higher is better)
    host_performance['performance_score'] = (
        host_performance['resolution_rate'] -
        (host_performance['avg_days_to_resolve'] / 10).clip(0, 50) -
        host_performance['total_reappearances'] * 2
    ).round(1)

    # Sort by performance score
    host_performance = host_performance.sort_values('performance_score', ascending=False)

    return host_performance


def get_host_type_breakdown(historical_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Get finding breakdown by host type (physical/virtual/ilom).

    Args:
        historical_df: DataFrame with historical findings

    Returns:
        Dictionary with host type statistics
    """
    if historical_df.empty:
        return {}

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    latest_scan = historical_df['scan_date'].max()
    latest_data = historical_df[historical_df['scan_date'] == latest_scan].copy()

    # Add host type
    latest_data['host_type'] = latest_data['hostname'].apply(
        lambda h: parse_hostname(h).host_type.value
    )

    # Statistics by host type
    type_stats = latest_data.groupby('host_type').agg({
        'hostname': 'nunique',
        'plugin_id': 'nunique',
        'severity_value': 'sum'
    }).reset_index()

    type_stats.columns = ['host_type', 'host_count', 'unique_plugins', 'severity_score']

    # Finding counts by type
    finding_counts = latest_data.groupby('host_type').size().reset_index(name='finding_count')
    type_stats = type_stats.merge(finding_counts, on='host_type')

    # Average findings per host
    type_stats['avg_findings_per_host'] = (
        type_stats['finding_count'] / type_stats['host_count']
    ).round(1)

    return {
        'type_stats': type_stats.to_dict('records'),
        'types': type_stats['host_type'].tolist(),
        'host_counts': dict(zip(type_stats['host_type'], type_stats['host_count'])),
        'finding_counts': dict(zip(type_stats['host_type'], type_stats['finding_count']))
    }


def get_location_breakdown(historical_df: pd.DataFrame) -> pd.DataFrame:
    """
    Get finding breakdown by location (from hostname structure).

    Args:
        historical_df: DataFrame with historical findings

    Returns:
        DataFrame with location statistics
    """
    if historical_df.empty:
        return pd.DataFrame()

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    latest_scan = historical_df['scan_date'].max()
    latest_data = historical_df[historical_df['scan_date'] == latest_scan].copy()

    # Extract location from hostname
    latest_data['location'] = latest_data['hostname'].apply(
        lambda h: parse_hostname(h).location or 'Unknown'
    )

    # Statistics by location
    location_stats = latest_data.groupby('location').agg({
        'hostname': 'nunique',
        'plugin_id': 'nunique',
        'severity_value': ['sum', 'mean'],
        'cvss3_base_score': lambda x: pd.to_numeric(x, errors='coerce').mean()
    }).reset_index()

    location_stats.columns = [
        'location', 'host_count', 'unique_plugins',
        'total_severity', 'avg_severity', 'avg_cvss'
    ]

    # Finding counts by location
    finding_counts = latest_data.groupby('location').size().reset_index(name='finding_count')
    location_stats = location_stats.merge(finding_counts, on='location')

    # Sort by total severity
    location_stats = location_stats.sort_values('total_severity', ascending=False)

    return location_stats
