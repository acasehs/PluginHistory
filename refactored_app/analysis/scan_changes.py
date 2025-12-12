"""
Scan Changes Analysis Module
Tracks changes between consecutive scans.
"""

import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, List, Tuple, Optional


def analyze_scan_changes(historical_df: pd.DataFrame) -> pd.DataFrame:
    """
    Analyze changes between consecutive scans.

    Args:
        historical_df: DataFrame with historical findings

    Returns:
        DataFrame with scan-to-scan change analysis
    """
    if historical_df.empty:
        return pd.DataFrame()

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    scan_dates = sorted(historical_df['scan_date'].unique())

    if len(scan_dates) < 2:
        return pd.DataFrame()

    change_records = []

    for i in range(1, len(scan_dates)):
        prev_scan = scan_dates[i-1]
        curr_scan = scan_dates[i]

        prev_hosts = set(historical_df[historical_df['scan_date'] == prev_scan]['hostname'].unique())
        curr_hosts = set(historical_df[historical_df['scan_date'] == curr_scan]['hostname'].unique())

        added_hosts = curr_hosts - prev_hosts
        removed_hosts = prev_hosts - curr_hosts
        unchanged_hosts = curr_hosts & prev_hosts

        change_records.append({
            'scan_date': curr_scan,
            'previous_scan': prev_scan,
            'days_between_scans': (curr_scan - prev_scan).days,
            'hosts_added': len(added_hosts),
            'hosts_removed': len(removed_hosts),
            'hosts_unchanged': len(unchanged_hosts),
            'total_hosts_current': len(curr_hosts),
            'total_hosts_previous': len(prev_hosts),
            'net_change': len(curr_hosts) - len(prev_hosts),
            'added_host_list': ', '.join(sorted(added_hosts)) if added_hosts else '',
            'removed_host_list': ', '.join(sorted(removed_hosts)) if removed_hosts else ''
        })

    changes_df = pd.DataFrame(change_records)

    return changes_df


def analyze_finding_changes(historical_df: pd.DataFrame) -> pd.DataFrame:
    """
    Analyze finding changes between consecutive scans.

    Args:
        historical_df: DataFrame with historical findings

    Returns:
        DataFrame with finding change analysis
    """
    if historical_df.empty:
        return pd.DataFrame()

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    historical_df['finding_key'] = historical_df['hostname'].astype(str) + '|' + historical_df['plugin_id'].astype(str)

    scan_dates = sorted(historical_df['scan_date'].unique())

    if len(scan_dates) < 2:
        return pd.DataFrame()

    change_records = []

    for i in range(1, len(scan_dates)):
        prev_scan = scan_dates[i-1]
        curr_scan = scan_dates[i]

        prev_findings = set(historical_df[historical_df['scan_date'] == prev_scan]['finding_key'].unique())
        curr_findings = set(historical_df[historical_df['scan_date'] == curr_scan]['finding_key'].unique())

        new_findings = curr_findings - prev_findings
        resolved_findings = prev_findings - curr_findings
        persistent_findings = curr_findings & prev_findings

        # Calculate severity breakdown for new findings
        new_findings_df = historical_df[
            (historical_df['scan_date'] == curr_scan) &
            (historical_df['finding_key'].isin(new_findings))
        ]

        severity_breakdown = {}
        if not new_findings_df.empty and 'severity_text' in new_findings_df.columns:
            severity_breakdown = new_findings_df['severity_text'].value_counts().to_dict()

        change_records.append({
            'scan_date': curr_scan,
            'previous_scan': prev_scan,
            'new_findings': len(new_findings),
            'resolved_findings': len(resolved_findings),
            'persistent_findings': len(persistent_findings),
            'total_findings_current': len(curr_findings),
            'total_findings_previous': len(prev_findings),
            'net_change': len(curr_findings) - len(prev_findings),
            'new_critical': severity_breakdown.get('Critical', 0),
            'new_high': severity_breakdown.get('High', 0),
            'new_medium': severity_breakdown.get('Medium', 0),
            'new_low': severity_breakdown.get('Low', 0)
        })

    changes_df = pd.DataFrame(change_records)

    return changes_df


def calculate_host_churn(changes_df: pd.DataFrame) -> Dict[str, float]:
    """
    Calculate host churn statistics.

    Args:
        changes_df: DataFrame from analyze_scan_changes

    Returns:
        Dictionary with churn statistics
    """
    if changes_df.empty:
        return {
            'avg_hosts_added': 0.0,
            'avg_hosts_removed': 0.0,
            'avg_net_change': 0.0,
            'total_hosts_added': 0,
            'total_hosts_removed': 0,
            'churn_rate': 0.0
        }

    stats = {
        'avg_hosts_added': round(changes_df['hosts_added'].mean(), 1),
        'avg_hosts_removed': round(changes_df['hosts_removed'].mean(), 1),
        'avg_net_change': round(changes_df['net_change'].mean(), 1),
        'total_hosts_added': int(changes_df['hosts_added'].sum()),
        'total_hosts_removed': int(changes_df['hosts_removed'].sum()),
    }

    # Calculate churn rate (turnover)
    avg_hosts = changes_df['total_hosts_current'].mean()
    if avg_hosts > 0:
        total_turnover = stats['total_hosts_added'] + stats['total_hosts_removed']
        stats['churn_rate'] = round((total_turnover / (2 * avg_hosts * len(changes_df))) * 100, 1)
    else:
        stats['churn_rate'] = 0.0

    return stats


def get_scan_summary(historical_df: pd.DataFrame) -> pd.DataFrame:
    """
    Get summary statistics per scan.

    Args:
        historical_df: DataFrame with historical findings

    Returns:
        DataFrame with per-scan summary
    """
    if historical_df.empty:
        return pd.DataFrame()

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    summary = historical_df.groupby('scan_date').agg({
        'hostname': 'nunique',
        'plugin_id': 'nunique',
        'ip_address': 'nunique'
    }).reset_index()

    summary.columns = ['scan_date', 'unique_hosts', 'unique_plugins', 'unique_ips']

    # Add total findings count
    finding_counts = historical_df.groupby('scan_date').size().reset_index(name='total_findings')
    summary = summary.merge(finding_counts, on='scan_date')

    # Add severity breakdown
    if 'severity_text' in historical_df.columns:
        severity_pivot = historical_df.groupby(['scan_date', 'severity_text']).size().unstack(fill_value=0)
        summary = summary.merge(severity_pivot.reset_index(), on='scan_date', how='left')

    return summary.sort_values('scan_date')
