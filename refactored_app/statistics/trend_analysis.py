"""
Trend Analysis Module
Time-series analysis and trend calculations for vulnerability data.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any

from ..config import SEVERITY_ORDER


def calculate_trend_metrics(historical_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Calculate overall trend metrics for vulnerability data.

    Args:
        historical_df: DataFrame with historical findings

    Returns:
        Dictionary with trend metrics
    """
    if historical_df.empty:
        return {}

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    scan_dates = sorted(historical_df['scan_date'].unique())

    if len(scan_dates) < 2:
        return {'insufficient_data': True}

    # Get counts per scan
    scan_stats = historical_df.groupby('scan_date').agg({
        'plugin_id': 'count',
        'hostname': 'nunique'
    }).reset_index()

    scan_stats.columns = ['scan_date', 'finding_count', 'host_count']
    scan_stats = scan_stats.sort_values('scan_date')

    # Calculate changes
    scan_stats['finding_change'] = scan_stats['finding_count'].diff()
    scan_stats['finding_pct_change'] = scan_stats['finding_count'].pct_change() * 100
    scan_stats['host_change'] = scan_stats['host_count'].diff()

    # Overall trends
    first_scan = scan_stats.iloc[0]
    last_scan = scan_stats.iloc[-1]

    overall_change = last_scan['finding_count'] - first_scan['finding_count']
    overall_pct_change = (overall_change / first_scan['finding_count'] * 100) if first_scan['finding_count'] > 0 else 0

    # Trend direction
    if overall_pct_change > 5:
        trend_direction = 'increasing'
    elif overall_pct_change < -5:
        trend_direction = 'decreasing'
    else:
        trend_direction = 'stable'

    # Recent trend (last 3 scans)
    if len(scan_stats) >= 3:
        recent = scan_stats.tail(3)
        recent_change = recent['finding_count'].iloc[-1] - recent['finding_count'].iloc[0]
        recent_pct = (recent_change / recent['finding_count'].iloc[0] * 100) if recent['finding_count'].iloc[0] > 0 else 0

        if recent_pct > 5:
            recent_trend = 'increasing'
        elif recent_pct < -5:
            recent_trend = 'decreasing'
        else:
            recent_trend = 'stable'
    else:
        recent_trend = trend_direction
        recent_pct = overall_pct_change

    return {
        'total_scans': len(scan_dates),
        'date_range': {
            'start': scan_dates[0].strftime('%Y-%m-%d'),
            'end': scan_dates[-1].strftime('%Y-%m-%d'),
            'days': (scan_dates[-1] - scan_dates[0]).days
        },
        'findings': {
            'initial': int(first_scan['finding_count']),
            'current': int(last_scan['finding_count']),
            'change': int(overall_change),
            'pct_change': round(overall_pct_change, 1),
            'average': round(scan_stats['finding_count'].mean(), 1),
            'min': int(scan_stats['finding_count'].min()),
            'max': int(scan_stats['finding_count'].max())
        },
        'hosts': {
            'initial': int(first_scan['host_count']),
            'current': int(last_scan['host_count']),
            'average': round(scan_stats['host_count'].mean(), 1)
        },
        'trend_direction': trend_direction,
        'recent_trend': recent_trend,
        'recent_pct_change': round(recent_pct, 1),
        'scan_timeline': scan_stats.to_dict('records')
    }


def get_severity_trends(historical_df: pd.DataFrame) -> pd.DataFrame:
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

    # Pivot by severity
    severity_trends = historical_df.groupby(['scan_date', 'severity_text']).size().unstack(fill_value=0)

    # Ensure all severity columns exist
    for severity in SEVERITY_ORDER:
        if severity not in severity_trends.columns:
            severity_trends[severity] = 0

    # Reorder columns
    severity_trends = severity_trends[SEVERITY_ORDER]

    # Add total
    severity_trends['Total'] = severity_trends.sum(axis=1)

    severity_trends = severity_trends.reset_index()

    return severity_trends.sort_values('scan_date')


def get_remediation_trends(lifecycle_df: pd.DataFrame, historical_df: pd.DataFrame) -> pd.DataFrame:
    """
    Track remediation progress over time.

    Args:
        lifecycle_df: DataFrame from analyze_finding_lifecycle
        historical_df: DataFrame with historical findings

    Returns:
        DataFrame with remediation metrics per scan date
    """
    if historical_df.empty:
        return pd.DataFrame()

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    historical_df['finding_key'] = historical_df['hostname'].astype(str) + '|' + historical_df['plugin_id'].astype(str)

    scan_dates = sorted(historical_df['scan_date'].unique())
    remediation_data = []

    for i, scan_date in enumerate(scan_dates):
        current_findings = set(
            historical_df[historical_df['scan_date'] == scan_date]['finding_key'].unique()
        )

        if i == 0:
            # First scan - no previous to compare
            remediation_data.append({
                'scan_date': scan_date,
                'total_findings': len(current_findings),
                'new_findings': len(current_findings),
                'resolved_findings': 0,
                'persistent_findings': 0
            })
        else:
            prev_findings = set(
                historical_df[historical_df['scan_date'] == scan_dates[i-1]]['finding_key'].unique()
            )

            new_findings = current_findings - prev_findings
            resolved_findings = prev_findings - current_findings
            persistent_findings = current_findings & prev_findings

            remediation_data.append({
                'scan_date': scan_date,
                'total_findings': len(current_findings),
                'new_findings': len(new_findings),
                'resolved_findings': len(resolved_findings),
                'persistent_findings': len(persistent_findings)
            })

    remediation_df = pd.DataFrame(remediation_data)

    # Calculate cumulative metrics
    remediation_df['cumulative_resolved'] = remediation_df['resolved_findings'].cumsum()
    remediation_df['cumulative_new'] = remediation_df['new_findings'].cumsum()

    # Resolution rate (resolved vs new)
    remediation_df['net_change'] = remediation_df['new_findings'] - remediation_df['resolved_findings']
    remediation_df['resolution_ratio'] = (
        remediation_df['resolved_findings'] / remediation_df['new_findings'].replace(0, 1)
    ).round(2)

    return remediation_df


def forecast_vulnerability_count(historical_df: pd.DataFrame, periods_ahead: int = 3) -> Dict[str, Any]:
    """
    Simple forecast of future vulnerability counts based on trend.

    Uses linear regression on historical data to project future counts.

    Args:
        historical_df: DataFrame with historical findings
        periods_ahead: Number of future periods to forecast

    Returns:
        Dictionary with forecast data
    """
    if historical_df.empty:
        return {'error': 'No data'}

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    # Get counts per scan
    counts = historical_df.groupby('scan_date').size().reset_index(name='count')
    counts = counts.sort_values('scan_date')

    if len(counts) < 3:
        return {'error': 'Insufficient data for forecasting'}

    # Simple linear regression
    x = np.arange(len(counts))
    y = counts['count'].values

    # Calculate slope and intercept
    slope = np.polyfit(x, y, 1)[0]
    intercept = np.polyfit(x, y, 1)[1]

    # Forecast
    forecasts = []
    last_date = counts['scan_date'].max()
    avg_interval = (counts['scan_date'].diff().mean()).days

    for i in range(1, periods_ahead + 1):
        future_x = len(counts) + i - 1
        future_y = slope * future_x + intercept
        future_date = last_date + timedelta(days=avg_interval * i)

        forecasts.append({
            'period': i,
            'date': future_date.strftime('%Y-%m-%d'),
            'forecast': max(0, round(future_y)),  # Can't have negative findings
            'confidence': 'low' if i > 1 else 'medium'
        })

    return {
        'trend_slope': round(slope, 2),
        'trend_direction': 'increasing' if slope > 0 else 'decreasing' if slope < 0 else 'stable',
        'avg_scan_interval_days': avg_interval,
        'forecasts': forecasts,
        'historical_counts': counts.to_dict('records')
    }


def compare_periods(historical_df: pd.DataFrame, period1_start: datetime, period1_end: datetime,
                   period2_start: datetime, period2_end: datetime) -> Dict[str, Any]:
    """
    Compare vulnerability metrics between two time periods.

    Args:
        historical_df: DataFrame with historical findings
        period1_start: Start of first period
        period1_end: End of first period
        period2_start: Start of second period
        period2_end: End of second period

    Returns:
        Dictionary with comparison metrics
    """
    if historical_df.empty:
        return {}

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    # Filter periods
    period1 = historical_df[
        (historical_df['scan_date'] >= period1_start) &
        (historical_df['scan_date'] <= period1_end)
    ]
    period2 = historical_df[
        (historical_df['scan_date'] >= period2_start) &
        (historical_df['scan_date'] <= period2_end)
    ]

    def get_period_stats(df):
        if df.empty:
            return {}
        return {
            'total_findings': len(df),
            'unique_hosts': df['hostname'].nunique(),
            'unique_plugins': df['plugin_id'].nunique(),
            'scans': df['scan_date'].nunique(),
            'avg_findings_per_scan': len(df) / df['scan_date'].nunique() if df['scan_date'].nunique() > 0 else 0,
            'severity_breakdown': df['severity_text'].value_counts().to_dict() if 'severity_text' in df.columns else {}
        }

    period1_stats = get_period_stats(period1)
    period2_stats = get_period_stats(period2)

    # Calculate changes
    changes = {}
    for key in ['total_findings', 'unique_hosts', 'unique_plugins', 'avg_findings_per_scan']:
        if key in period1_stats and key in period2_stats and period1_stats.get(key, 0) > 0:
            change = period2_stats.get(key, 0) - period1_stats.get(key, 0)
            pct_change = (change / period1_stats[key]) * 100
            changes[key] = {
                'absolute': round(change, 1),
                'percentage': round(pct_change, 1)
            }

    return {
        'period1': {
            'start': period1_start.strftime('%Y-%m-%d'),
            'end': period1_end.strftime('%Y-%m-%d'),
            'stats': period1_stats
        },
        'period2': {
            'start': period2_start.strftime('%Y-%m-%d'),
            'end': period2_end.strftime('%Y-%m-%d'),
            'stats': period2_stats
        },
        'changes': changes
    }
