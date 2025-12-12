"""
Finding Lifecycle Analysis Module
Tracks vulnerabilities from first appearance through resolution or persistence.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
import json

from ..config import REAPPEARANCE_GAP_DAYS, SEVERITY_ORDER


def analyze_finding_lifecycle(historical_df: pd.DataFrame) -> pd.DataFrame:
    """
    Analyze finding lifecycle across multiple scans.

    Tracks each unique finding (hostname + plugin_id) across all scans to determine:
    - First/last seen dates
    - Duration open
    - Number of observations
    - Reappearances (gaps in detection)
    - Current status (Active/Resolved)

    Args:
        historical_df: DataFrame with historical findings across multiple scans.
                       Must have columns: hostname, plugin_id, scan_date, name,
                       severity_text, severity_value, ip_address, cvss3_base_score, cves, iavx

    Returns:
        DataFrame with lifecycle analysis for each unique finding
    """
    if historical_df.empty:
        return pd.DataFrame()

    # Ensure scan_date is datetime
    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    # Create unique finding key
    historical_df['finding_key'] = historical_df['hostname'].astype(str) + '|' + historical_df['plugin_id'].astype(str)

    lifecycle_records = []
    latest_scan_date = historical_df['scan_date'].max()

    for finding_key, group in historical_df.groupby('finding_key'):
        hostname, plugin_id = finding_key.split('|')
        group = group.sort_values('scan_date')
        latest = group.iloc[-1]

        scan_dates = sorted(group['scan_date'].unique())
        first_seen = scan_dates[0]
        last_seen = scan_dates[-1]

        # Calculate reappearances (gaps > threshold)
        reappearances = 0
        gap_details = []

        if len(scan_dates) > 1:
            for i in range(1, len(scan_dates)):
                days_gap = (scan_dates[i] - scan_dates[i-1]).days
                if days_gap > REAPPEARANCE_GAP_DAYS:
                    reappearances += 1
                    gap_details.append({
                        'gap_start': scan_dates[i-1].strftime('%Y-%m-%d'),
                        'gap_end': scan_dates[i].strftime('%Y-%m-%d'),
                        'days': days_gap
                    })

        # Determine status
        status = 'Active' if last_seen == latest_scan_date else 'Resolved'

        # Calculate days open
        days_open = (last_seen - first_seen).days

        lifecycle_records.append({
            'hostname': hostname,
            'ip_address': latest.get('ip_address', ''),
            'plugin_id': plugin_id,
            'plugin_name': latest.get('name', 'Unknown'),
            'severity_text': latest.get('severity_text', 'Unknown'),
            'severity_value': latest.get('severity_value', 0),
            'first_seen': first_seen,
            'last_seen': last_seen,
            'days_open': days_open,
            'total_observations': len(scan_dates),
            'reappearances': reappearances,
            'status': status,
            'cvss3_base_score': latest.get('cvss3_base_score'),
            'cves': latest.get('cves', ''),
            'iavx': latest.get('iavx', ''),
            'gap_details': json.dumps(gap_details) if gap_details else ''
        })

    lifecycle_df = pd.DataFrame(lifecycle_records)

    # Sort by severity and days open
    lifecycle_df = lifecycle_df.sort_values(
        ['severity_value', 'days_open'],
        ascending=[False, False]
    )

    return lifecycle_df


def identify_reappearances(lifecycle_df: pd.DataFrame) -> pd.DataFrame:
    """
    Filter to findings that have reappeared after apparent resolution.

    Args:
        lifecycle_df: DataFrame from analyze_finding_lifecycle

    Returns:
        DataFrame with only findings that have reappeared
    """
    if lifecycle_df.empty:
        return pd.DataFrame()

    return lifecycle_df[lifecycle_df['reappearances'] > 0].copy()


def calculate_mttr(lifecycle_df: pd.DataFrame, group_by: Optional[str] = None) -> pd.DataFrame:
    """
    Calculate Mean Time to Remediation (MTTR) statistics.

    Args:
        lifecycle_df: DataFrame from analyze_finding_lifecycle
        group_by: Optional column to group by (e.g., 'severity_text', 'hostname')

    Returns:
        DataFrame with MTTR statistics
    """
    if lifecycle_df.empty:
        return pd.DataFrame()

    resolved = lifecycle_df[lifecycle_df['status'] == 'Resolved'].copy()

    if resolved.empty:
        return pd.DataFrame()

    if group_by and group_by in resolved.columns:
        mttr_stats = resolved.groupby(group_by).agg({
            'days_open': ['mean', 'median', 'min', 'max', 'std', 'count']
        }).round(1)
        mttr_stats.columns = ['mean_days', 'median_days', 'min_days', 'max_days', 'std_days', 'count']
        mttr_stats = mttr_stats.reset_index()
    else:
        mttr_stats = pd.DataFrame([{
            'mean_days': resolved['days_open'].mean(),
            'median_days': resolved['days_open'].median(),
            'min_days': resolved['days_open'].min(),
            'max_days': resolved['days_open'].max(),
            'std_days': resolved['days_open'].std(),
            'count': len(resolved)
        }]).round(1)

    return mttr_stats


def get_findings_by_age(lifecycle_df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
    """
    Categorize findings by age buckets.

    Args:
        lifecycle_df: DataFrame from analyze_finding_lifecycle

    Returns:
        Dictionary mapping age bucket names to DataFrames
    """
    if lifecycle_df.empty:
        return {}

    active = lifecycle_df[lifecycle_df['status'] == 'Active'].copy()

    buckets = {
        '0-30 days': active[active['days_open'] <= 30],
        '31-60 days': active[(active['days_open'] > 30) & (active['days_open'] <= 60)],
        '61-90 days': active[(active['days_open'] > 60) & (active['days_open'] <= 90)],
        '91-120 days': active[(active['days_open'] > 90) & (active['days_open'] <= 120)],
        '121+ days': active[active['days_open'] > 120]
    }

    return buckets


def get_severity_timeline(historical_df: pd.DataFrame) -> pd.DataFrame:
    """
    Get finding counts by severity over time.

    Args:
        historical_df: DataFrame with historical findings

    Returns:
        DataFrame with severity counts per scan date
    """
    if historical_df.empty:
        return pd.DataFrame()

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    timeline = historical_df.groupby(['scan_date', 'severity_text']).size().unstack(fill_value=0)

    # Reorder columns by severity
    available_cols = [col for col in SEVERITY_ORDER if col in timeline.columns]
    if available_cols:
        timeline = timeline[available_cols]

    timeline['Total'] = timeline.sum(axis=1)

    return timeline.reset_index()


def calculate_resolution_rate(lifecycle_df: pd.DataFrame, time_period_days: int = 30) -> Dict[str, float]:
    """
    Calculate resolution rate statistics.

    Args:
        lifecycle_df: DataFrame from analyze_finding_lifecycle
        time_period_days: Number of days to consider "recently resolved"

    Returns:
        Dictionary with resolution statistics
    """
    if lifecycle_df.empty:
        return {'total_findings': 0, 'resolved': 0, 'active': 0, 'resolution_rate': 0.0}

    total = len(lifecycle_df)
    resolved = len(lifecycle_df[lifecycle_df['status'] == 'Resolved'])
    active = len(lifecycle_df[lifecycle_df['status'] == 'Active'])

    resolution_rate = (resolved / total * 100) if total > 0 else 0.0

    # Calculate recently resolved
    now = datetime.now()
    cutoff = now - timedelta(days=time_period_days)

    recently_resolved = lifecycle_df[
        (lifecycle_df['status'] == 'Resolved') &
        (lifecycle_df['last_seen'] >= cutoff)
    ]

    return {
        'total_findings': total,
        'resolved': resolved,
        'active': active,
        'resolution_rate': round(resolution_rate, 1),
        'recently_resolved': len(recently_resolved),
        'reappeared': len(lifecycle_df[lifecycle_df['reappearances'] > 0])
    }
