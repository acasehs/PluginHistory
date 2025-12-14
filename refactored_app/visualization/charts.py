"""
Chart Creation Module
Functions for creating individual charts using matplotlib.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any, Callable
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
import matplotlib.dates as mdates

from ..config import SEVERITY_COLORS, SEVERITY_ORDER, OPDIR_STATUS_COLORS


# Date interval constants
DATE_INTERVAL_WEEKLY = 'weekly'
DATE_INTERVAL_MONTHLY = 'monthly'
DATE_INTERVAL_QUARTERLY = 'quarterly'
DATE_INTERVAL_YEARLY = 'yearly'


def get_date_interval(start_date: datetime, end_date: datetime) -> str:
    """
    Determine the appropriate date interval for visualizations based on date range.

    Rules:
    - ≤60 days: weekly intervals
    - >60 and ≤180 days: monthly intervals
    - >180 and ≤540 days: quarterly intervals
    - >540 days: yearly intervals

    Args:
        start_date: Start of date range
        end_date: End of date range

    Returns:
        Interval type string: 'weekly', 'monthly', 'quarterly', or 'yearly'
    """
    if pd.isna(start_date) or pd.isna(end_date):
        return DATE_INTERVAL_MONTHLY

    # Ensure datetime objects
    if isinstance(start_date, str):
        start_date = pd.to_datetime(start_date)
    if isinstance(end_date, str):
        end_date = pd.to_datetime(end_date)

    days_range = (end_date - start_date).days

    if days_range <= 60:
        return DATE_INTERVAL_WEEKLY
    elif days_range <= 180:
        return DATE_INTERVAL_MONTHLY
    elif days_range <= 540:
        return DATE_INTERVAL_QUARTERLY
    else:
        return DATE_INTERVAL_YEARLY


def get_interval_label(interval: str) -> str:
    """Get human-readable label for interval type."""
    labels = {
        DATE_INTERVAL_WEEKLY: 'Week',
        DATE_INTERVAL_MONTHLY: 'Month',
        DATE_INTERVAL_QUARTERLY: 'Quarter',
        DATE_INTERVAL_YEARLY: 'Year'
    }
    return labels.get(interval, 'Period')


def get_period_format(interval: str) -> str:
    """Get pandas period format string for interval type."""
    formats = {
        DATE_INTERVAL_WEEKLY: 'W',
        DATE_INTERVAL_MONTHLY: 'M',
        DATE_INTERVAL_QUARTERLY: 'Q',
        DATE_INTERVAL_YEARLY: 'Y'
    }
    return formats.get(interval, 'M')


def get_date_format(interval: str) -> str:
    """Get matplotlib date format string for interval type."""
    formats = {
        DATE_INTERVAL_WEEKLY: '%m/%d',
        DATE_INTERVAL_MONTHLY: '%b %Y',
        DATE_INTERVAL_QUARTERLY: 'Q%q %Y',
        DATE_INTERVAL_YEARLY: '%Y'
    }
    return formats.get(interval, '%Y-%m')


def format_period_label(period, interval: str) -> str:
    """Format a period object to a display label based on interval."""
    if interval == DATE_INTERVAL_WEEKLY:
        # Week format: "Jan 01" or "W01"
        start = period.start_time
        return start.strftime('%b %d')
    elif interval == DATE_INTERVAL_MONTHLY:
        return str(period)  # 2024-01 format
    elif interval == DATE_INTERVAL_QUARTERLY:
        return f"Q{period.quarter} {period.year}"
    elif interval == DATE_INTERVAL_YEARLY:
        return str(period.year)
    return str(period)


def group_by_interval(df: pd.DataFrame, date_column: str, interval: str,
                      agg_func: str = 'size') -> pd.Series:
    """
    Group DataFrame by date interval and aggregate.

    Args:
        df: DataFrame to group
        date_column: Name of date column
        interval: Interval type from get_date_interval()
        agg_func: Aggregation function ('size', 'sum', 'mean', 'count')

    Returns:
        Grouped and aggregated Series
    """
    if df.empty or date_column not in df.columns:
        return pd.Series()

    df = df.copy()
    df[date_column] = pd.to_datetime(df[date_column])

    period_format = get_period_format(interval)
    grouped = df.groupby(df[date_column].dt.to_period(period_format))

    if agg_func == 'size':
        return grouped.size()
    elif agg_func == 'sum':
        return grouped.sum()
    elif agg_func == 'mean':
        return grouped.mean()
    elif agg_func == 'count':
        return grouped.count()
    else:
        return grouped.size()


def group_by_interval_column(df: pd.DataFrame, date_column: str, value_column: str,
                             interval: str, agg_func: str = 'sum') -> pd.Series:
    """
    Group DataFrame by date interval and aggregate a specific column.

    Args:
        df: DataFrame to group
        date_column: Name of date column
        value_column: Name of column to aggregate
        interval: Interval type from get_date_interval()
        agg_func: Aggregation function

    Returns:
        Grouped and aggregated Series
    """
    if df.empty or date_column not in df.columns or value_column not in df.columns:
        return pd.Series()

    df = df.copy()
    df[date_column] = pd.to_datetime(df[date_column])

    period_format = get_period_format(interval)
    grouped = df.groupby(df[date_column].dt.to_period(period_format))[value_column]

    if agg_func == 'sum':
        return grouped.sum()
    elif agg_func == 'mean':
        return grouped.mean()
    elif agg_func == 'count':
        return grouped.count()
    elif agg_func == 'max':
        return grouped.max()
    elif agg_func == 'min':
        return grouped.min()
    else:
        return grouped.sum()


def get_period_labels(periods: pd.PeriodIndex, interval: str) -> List[str]:
    """
    Get formatted labels for period index.

    Args:
        periods: PeriodIndex from groupby
        interval: Interval type

    Returns:
        List of formatted label strings
    """
    return [format_period_label(p, interval) for p in periods]


def calculate_date_range_from_df(df: pd.DataFrame, date_column: str) -> Tuple[Optional[datetime], Optional[datetime]]:
    """
    Calculate the date range from a DataFrame's date column.

    Args:
        df: DataFrame
        date_column: Name of date column

    Returns:
        Tuple of (start_date, end_date)
    """
    if df.empty or date_column not in df.columns:
        return (None, None)

    dates = pd.to_datetime(df[date_column])
    return (dates.min(), dates.max())


def get_dark_style():
    """Apply dark theme styling to plots."""
    return {
        'figure.facecolor': '#2b2b2b',
        'axes.facecolor': '#2b2b2b',
        'axes.edgecolor': 'white',
        'axes.labelcolor': 'white',
        'text.color': 'white',
        'xtick.color': 'white',
        'ytick.color': 'white',
        'grid.color': '#555555',
        'legend.facecolor': '#2b2b2b',
        'legend.edgecolor': 'white'
    }


def create_severity_pie_chart(df: pd.DataFrame, title: str = "Findings by Severity",
                              figsize: Tuple[int, int] = (8, 6)) -> Figure:
    """
    Create a pie chart showing finding distribution by severity.

    Args:
        df: DataFrame with severity_text column
        title: Chart title
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig, ax = plt.subplots(figsize=figsize)

        if df.empty or 'severity_text' not in df.columns:
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center',
                   fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        # Count by severity
        severity_counts = df['severity_text'].value_counts()

        # Order by severity
        ordered_severities = [s for s in SEVERITY_ORDER if s in severity_counts.index]
        severity_counts = severity_counts.reindex(ordered_severities)
        severity_counts = severity_counts.dropna()

        if severity_counts.empty:
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center',
                   fontsize=14, color='white')
            return fig

        colors = [SEVERITY_COLORS.get(s, 'gray') for s in severity_counts.index]

        wedges, texts, autotexts = ax.pie(
            severity_counts.values,
            labels=severity_counts.index,
            colors=colors,
            autopct='%1.1f%%',
            startangle=90,
            textprops={'color': 'white'}
        )

        ax.set_title(title, fontsize=14, fontweight='bold', color='white')

        return fig


def create_timeline_chart(df: pd.DataFrame, date_column: str = 'scan_date',
                         value_columns: List[str] = None,
                         title: str = "Findings Over Time",
                         figsize: Tuple[int, int] = (12, 6)) -> Figure:
    """
    Create a timeline chart showing values over time.

    Args:
        df: DataFrame with date and value columns
        date_column: Name of date column
        value_columns: List of columns to plot
        title: Chart title
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig, ax = plt.subplots(figsize=figsize)

        if df.empty:
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center',
                   fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        df = df.copy()
        df[date_column] = pd.to_datetime(df[date_column])
        df = df.sort_values(date_column)

        if value_columns is None:
            # Default: plot severity breakdown
            value_columns = [s for s in SEVERITY_ORDER if s in df.columns]

        for col in value_columns:
            if col in df.columns:
                color = SEVERITY_COLORS.get(col, None)
                ax.plot(df[date_column], df[col], marker='o', label=col, color=color, linewidth=2)

        ax.set_xlabel('Scan Date', color='white')
        ax.set_ylabel('Count', color='white')
        ax.set_title(title, fontsize=14, fontweight='bold', color='white')

        ax.legend(loc='upper left', facecolor='#2b2b2b', edgecolor='white')
        ax.grid(True, alpha=0.3)
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
        plt.xticks(rotation=45, ha='right')

        fig.tight_layout()
        return fig


def create_host_risk_bar_chart(df: pd.DataFrame, top_n: int = 15,
                               title: str = "Top Hosts by Risk Score",
                               figsize: Tuple[int, int] = (12, 8)) -> Figure:
    """
    Create a horizontal bar chart showing hosts ranked by risk score.

    Args:
        df: DataFrame with hostname and risk_score columns
        top_n: Number of top hosts to show
        title: Chart title
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig, ax = plt.subplots(figsize=figsize)

        if df.empty or 'hostname' not in df.columns:
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center',
                   fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        # Sort and get top N
        score_col = 'risk_score' if 'risk_score' in df.columns else 'severity_value'
        if score_col not in df.columns:
            score_col = df.select_dtypes(include=[np.number]).columns[0] if len(df.select_dtypes(include=[np.number]).columns) > 0 else None

        if score_col is None:
            ax.text(0.5, 0.5, 'No numeric data available', ha='center', va='center',
                   fontsize=14, color='white')
            return fig

        top_hosts = df.nlargest(top_n, score_col)

        # Create color gradient based on risk
        colors = plt.cm.RdYlGn_r(np.linspace(0.2, 0.8, len(top_hosts)))

        bars = ax.barh(range(len(top_hosts)), top_hosts[score_col].values, color=colors)
        ax.set_yticks(range(len(top_hosts)))
        ax.set_yticklabels(top_hosts['hostname'].values, color='white')

        ax.set_xlabel('Risk Score', color='white')
        ax.set_title(title, fontsize=14, fontweight='bold', color='white')
        ax.grid(True, alpha=0.3, axis='x')

        # Add value labels
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax.text(width + 0.5, bar.get_y() + bar.get_height()/2,
                   f'{width:.1f}', va='center', color='white', fontsize=9)

        ax.invert_yaxis()
        fig.tight_layout()
        return fig


def create_cvss_distribution(df: pd.DataFrame, cvss_column: str = 'cvss3_base_score',
                            title: str = "CVSS Score Distribution",
                            figsize: Tuple[int, int] = (10, 6)) -> Figure:
    """
    Create a histogram showing CVSS score distribution.

    Args:
        df: DataFrame with CVSS score column
        cvss_column: Name of CVSS column
        title: Chart title
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig, ax = plt.subplots(figsize=figsize)

        if df.empty or cvss_column not in df.columns:
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center',
                   fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        scores = pd.to_numeric(df[cvss_column], errors='coerce').dropna()

        if scores.empty:
            ax.text(0.5, 0.5, 'No CVSS scores available', ha='center', va='center',
                   fontsize=14, color='white')
            return fig

        # Create bins for CVSS ranges
        bins = [0, 0.1, 4.0, 7.0, 9.0, 10.0]
        bin_labels = ['None', 'Low', 'Medium', 'High', 'Critical']
        bin_colors = ['#6c757d', '#007bff', '#ffc107', '#fd7e14', '#dc3545']

        # Calculate counts for each bin
        counts = []
        for i in range(len(bins) - 1):
            count = len(scores[(scores >= bins[i]) & (scores < bins[i+1])])
            if i == len(bins) - 2:  # Last bin includes upper bound
                count = len(scores[(scores >= bins[i]) & (scores <= bins[i+1])])
            counts.append(count)

        bars = ax.bar(bin_labels, counts, color=bin_colors, edgecolor='white', linewidth=1)

        ax.set_xlabel('CVSS Severity Range', color='white')
        ax.set_ylabel('Number of Findings', color='white')
        ax.set_title(title, fontsize=14, fontweight='bold', color='white')
        ax.grid(True, alpha=0.3, axis='y')

        # Add value labels
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                   f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')

        fig.tight_layout()
        return fig


def create_remediation_chart(df: pd.DataFrame,
                            title: str = "New vs Resolved Findings",
                            figsize: Tuple[int, int] = (12, 6)) -> Figure:
    """
    Create a chart showing new vs resolved findings over time.

    Args:
        df: DataFrame with scan_date, new_findings, resolved_findings columns
        title: Chart title
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig, ax = plt.subplots(figsize=figsize)

        if df.empty:
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center',
                   fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        df = df.copy()
        df['scan_date'] = pd.to_datetime(df['scan_date'])
        df = df.sort_values('scan_date')

        x = range(len(df))
        width = 0.35

        if 'new_findings' in df.columns:
            bars1 = ax.bar([i - width/2 for i in x], df['new_findings'], width,
                          label='New Findings', color='#dc3545')

        if 'resolved_findings' in df.columns:
            bars2 = ax.bar([i + width/2 for i in x], df['resolved_findings'], width,
                          label='Resolved Findings', color='#28a745')

        ax.set_xlabel('Scan Date', color='white')
        ax.set_ylabel('Count', color='white')
        ax.set_title(title, fontsize=14, fontweight='bold', color='white')
        ax.set_xticks(x)
        ax.set_xticklabels([d.strftime('%Y-%m-%d') for d in df['scan_date']], rotation=45, ha='right')
        ax.legend(loc='upper right', facecolor='#2b2b2b', edgecolor='white')
        ax.grid(True, alpha=0.3, axis='y')

        fig.tight_layout()
        return fig


def create_host_type_chart(data: Dict[str, int], title: str = "Hosts by Type",
                          figsize: Tuple[int, int] = (8, 6)) -> Figure:
    """
    Create a chart showing host distribution by type (physical/virtual/ilom).

    Args:
        data: Dictionary mapping host type to count
        title: Chart title
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig, ax = plt.subplots(figsize=figsize)

        if not data:
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center',
                   fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        type_colors = {
            'physical': '#007bff',
            'virtual': '#28a745',
            'ilom': '#fd7e14',
            'unknown': '#6c757d'
        }

        labels = list(data.keys())
        values = list(data.values())
        colors = [type_colors.get(t.lower(), '#6c757d') for t in labels]

        wedges, texts, autotexts = ax.pie(
            values,
            labels=labels,
            colors=colors,
            autopct='%1.1f%%',
            startangle=90,
            textprops={'color': 'white'}
        )

        ax.set_title(title, fontsize=14, fontweight='bold', color='white')

        return fig


def create_opdir_status_chart(df: pd.DataFrame, title: str = "OPDIR Compliance Status",
                             figsize: Tuple[int, int] = (8, 6)) -> Figure:
    """
    Create a chart showing OPDIR compliance status breakdown.

    Args:
        df: DataFrame with opdir_status column
        title: Chart title
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig, ax = plt.subplots(figsize=figsize)

        if df.empty or 'opdir_status' not in df.columns:
            ax.text(0.5, 0.5, 'No OPDIR data available', ha='center', va='center',
                   fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        # Filter to findings with OPDIR status
        opdir_data = df[df['opdir_status'] != '']

        if opdir_data.empty:
            ax.text(0.5, 0.5, 'No OPDIR mappings', ha='center', va='center',
                   fontsize=14, color='white')
            return fig

        status_counts = opdir_data['opdir_status'].value_counts()
        colors = [OPDIR_STATUS_COLORS.get(s, '#6c757d') for s in status_counts.index]

        wedges, texts, autotexts = ax.pie(
            status_counts.values,
            labels=status_counts.index,
            colors=colors,
            autopct='%1.1f%%',
            startangle=90,
            textprops={'color': 'white'}
        )

        ax.set_title(title, fontsize=14, fontweight='bold', color='white')

        return fig
