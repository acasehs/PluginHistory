"""
Dashboard Creation Module
Functions for creating multi-chart dashboards.
"""

import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
import matplotlib.gridspec as gridspec

from ..config import SEVERITY_COLORS, SEVERITY_ORDER
from .charts import get_dark_style


def create_executive_dashboard(historical_df: pd.DataFrame,
                               lifecycle_df: pd.DataFrame,
                               figsize: Tuple[int, int] = (16, 12)) -> Figure:
    """
    Create an executive summary dashboard with key metrics.

    Includes:
    - Severity pie chart
    - Finding trend over time
    - Top hosts by risk
    - Key metrics summary

    Args:
        historical_df: DataFrame with historical findings
        lifecycle_df: DataFrame from analyze_finding_lifecycle
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig = plt.figure(figsize=figsize)
        gs = gridspec.GridSpec(3, 3, figure=fig, hspace=0.3, wspace=0.3)

        # Prepare data
        historical_df = historical_df.copy()
        if 'scan_date' in historical_df.columns:
            historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])
            latest_scan = historical_df['scan_date'].max()
            latest_data = historical_df[historical_df['scan_date'] == latest_scan]
        else:
            latest_data = historical_df

        # 1. Key Metrics Panel (top left)
        ax_metrics = fig.add_subplot(gs[0, 0])
        ax_metrics.set_facecolor('#2b2b2b')
        ax_metrics.axis('off')

        total_findings = len(latest_data)
        unique_hosts = latest_data['hostname'].nunique() if 'hostname' in latest_data.columns else 0
        critical_high = len(latest_data[latest_data['severity_text'].isin(['Critical', 'High'])]) if 'severity_text' in latest_data.columns else 0

        metrics_text = f"""
        KEY METRICS

        Total Findings: {total_findings:,}
        Unique Hosts: {unique_hosts:,}
        Critical/High: {critical_high:,}
        """

        if not lifecycle_df.empty:
            active = len(lifecycle_df[lifecycle_df['status'] == 'Active'])
            resolved = len(lifecycle_df[lifecycle_df['status'] == 'Resolved'])
            metrics_text += f"""
        Active: {active:,}
        Resolved: {resolved:,}
            """

        ax_metrics.text(0.1, 0.9, metrics_text, transform=ax_metrics.transAxes,
                       fontsize=12, color='white', verticalalignment='top',
                       fontfamily='monospace')
        ax_metrics.set_title('Summary', fontsize=14, fontweight='bold', color='white')

        # 2. Severity Pie Chart (top center)
        ax_pie = fig.add_subplot(gs[0, 1])
        if 'severity_text' in latest_data.columns and not latest_data.empty:
            severity_counts = latest_data['severity_text'].value_counts()
            ordered_sev = [s for s in SEVERITY_ORDER if s in severity_counts.index]
            severity_counts = severity_counts.reindex(ordered_sev).dropna()

            if not severity_counts.empty:
                colors = [SEVERITY_COLORS.get(s, 'gray') for s in severity_counts.index]
                ax_pie.pie(severity_counts.values, labels=severity_counts.index,
                          colors=colors, autopct='%1.1f%%', startangle=90,
                          textprops={'color': 'white', 'fontsize': 9})
        ax_pie.set_title('Severity Distribution', fontsize=14, fontweight='bold', color='white')

        # 3. Status breakdown (top right)
        ax_status = fig.add_subplot(gs[0, 2])
        if not lifecycle_df.empty:
            status_counts = lifecycle_df['status'].value_counts()
            colors = ['#dc3545' if s == 'Active' else '#28a745' for s in status_counts.index]
            ax_status.barh(status_counts.index, status_counts.values, color=colors)
            ax_status.set_xlabel('Count', color='white')
            for i, v in enumerate(status_counts.values):
                ax_status.text(v + 1, i, str(v), va='center', color='white')
        ax_status.set_title('Finding Status', fontsize=14, fontweight='bold', color='white')
        ax_status.set_facecolor('#2b2b2b')
        ax_status.tick_params(colors='white')
        ax_status.grid(True, alpha=0.3, axis='x')

        # 4. Timeline Chart (middle row, spans all columns)
        ax_timeline = fig.add_subplot(gs[1, :])
        if 'scan_date' in historical_df.columns:
            timeline_data = historical_df.groupby(['scan_date', 'severity_text']).size().unstack(fill_value=0)

            for severity in SEVERITY_ORDER:
                if severity in timeline_data.columns:
                    ax_timeline.plot(timeline_data.index, timeline_data[severity],
                                   marker='o', label=severity,
                                   color=SEVERITY_COLORS.get(severity), linewidth=2)

            ax_timeline.legend(loc='upper left', facecolor='#2b2b2b', edgecolor='white')
            ax_timeline.set_xlabel('Scan Date', color='white')
            ax_timeline.set_ylabel('Finding Count', color='white')
            plt.setp(ax_timeline.xaxis.get_majorticklabels(), rotation=45, ha='right')

        ax_timeline.set_title('Findings Over Time', fontsize=14, fontweight='bold', color='white')
        ax_timeline.set_facecolor('#2b2b2b')
        ax_timeline.tick_params(colors='white')
        ax_timeline.grid(True, alpha=0.3)

        # 5. Top Hosts (bottom left)
        ax_hosts = fig.add_subplot(gs[2, 0:2])
        if 'hostname' in latest_data.columns:
            host_counts = latest_data.groupby('hostname').size().nlargest(10)
            colors = plt.cm.RdYlGn_r(np.linspace(0.2, 0.8, len(host_counts)))
            ax_hosts.barh(range(len(host_counts)), host_counts.values, color=colors)
            ax_hosts.set_yticks(range(len(host_counts)))
            ax_hosts.set_yticklabels(host_counts.index, fontsize=9)
            ax_hosts.invert_yaxis()
            ax_hosts.set_xlabel('Finding Count', color='white')

        ax_hosts.set_title('Top 10 Hosts by Finding Count', fontsize=14, fontweight='bold', color='white')
        ax_hosts.set_facecolor('#2b2b2b')
        ax_hosts.tick_params(colors='white')
        ax_hosts.grid(True, alpha=0.3, axis='x')

        # 6. Age Distribution (bottom right)
        ax_age = fig.add_subplot(gs[2, 2])
        if not lifecycle_df.empty and 'days_open' in lifecycle_df.columns:
            active = lifecycle_df[lifecycle_df['status'] == 'Active']
            if not active.empty:
                bins = [0, 30, 60, 90, 120, float('inf')]
                labels = ['0-30', '31-60', '61-90', '91-120', '121+']
                active['age_bucket'] = pd.cut(active['days_open'], bins=bins, labels=labels)
                age_counts = active['age_bucket'].value_counts().reindex(labels)
                ax_age.bar(labels, age_counts.values, color=['#28a745', '#ffc107', '#fd7e14', '#dc3545', '#8b0000'])
                ax_age.set_xlabel('Days Open', color='white')
                ax_age.set_ylabel('Count', color='white')

        ax_age.set_title('Active Findings by Age', fontsize=14, fontweight='bold', color='white')
        ax_age.set_facecolor('#2b2b2b')
        ax_age.tick_params(colors='white')
        ax_age.grid(True, alpha=0.3, axis='y')

        fig.suptitle('Executive Summary Dashboard', fontsize=16, fontweight='bold', color='white', y=0.98)

        return fig


def create_lifecycle_dashboard(lifecycle_df: pd.DataFrame,
                               figsize: Tuple[int, int] = (16, 10)) -> Figure:
    """
    Create a finding lifecycle analysis dashboard.

    Args:
        lifecycle_df: DataFrame from analyze_finding_lifecycle
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig = plt.figure(figsize=figsize)
        gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.3, wspace=0.3)

        if lifecycle_df.empty:
            ax = fig.add_subplot(111)
            ax.text(0.5, 0.5, 'No lifecycle data available', ha='center', va='center',
                   fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        # 1. Status Distribution
        ax1 = fig.add_subplot(gs[0, 0])
        status_counts = lifecycle_df['status'].value_counts()
        colors = ['#dc3545' if s == 'Active' else '#28a745' for s in status_counts.index]
        ax1.pie(status_counts.values, labels=status_counts.index, colors=colors,
               autopct='%1.1f%%', startangle=90, textprops={'color': 'white'})
        ax1.set_title('Active vs Resolved', fontsize=12, fontweight='bold', color='white')

        # 2. MTTR by Severity
        ax2 = fig.add_subplot(gs[0, 1])
        resolved = lifecycle_df[lifecycle_df['status'] == 'Resolved']
        if not resolved.empty:
            mttr = resolved.groupby('severity_text')['days_open'].mean()
            mttr = mttr.reindex([s for s in SEVERITY_ORDER if s in mttr.index])
            colors = [SEVERITY_COLORS.get(s, 'gray') for s in mttr.index]
            ax2.bar(mttr.index, mttr.values, color=colors)
            ax2.set_ylabel('Average Days', color='white')
            plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45, ha='right')
        ax2.set_title('MTTR by Severity', fontsize=12, fontweight='bold', color='white')
        ax2.set_facecolor('#2b2b2b')
        ax2.tick_params(colors='white')
        ax2.grid(True, alpha=0.3, axis='y')

        # 3. Reappearances
        ax3 = fig.add_subplot(gs[0, 2])
        reappeared = lifecycle_df[lifecycle_df['reappearances'] > 0]
        non_reappeared = len(lifecycle_df) - len(reappeared)
        ax3.pie([len(reappeared), non_reappeared],
               labels=['Reappeared', 'Single Occurrence'],
               colors=['#fd7e14', '#6c757d'],
               autopct='%1.1f%%', startangle=90, textprops={'color': 'white'})
        ax3.set_title('Reappearance Rate', fontsize=12, fontweight='bold', color='white')

        # 4. Days Open Distribution
        ax4 = fig.add_subplot(gs[1, 0:2])
        active = lifecycle_df[lifecycle_df['status'] == 'Active']
        if not active.empty:
            ax4.hist(active['days_open'], bins=20, color='#007bff', edgecolor='white', alpha=0.7)
            ax4.axvline(active['days_open'].mean(), color='#dc3545', linestyle='--',
                       label=f'Mean: {active["days_open"].mean():.0f} days')
            ax4.axvline(active['days_open'].median(), color='#ffc107', linestyle='--',
                       label=f'Median: {active["days_open"].median():.0f} days')
            ax4.legend(loc='upper right', facecolor='#2b2b2b', edgecolor='white')
        ax4.set_xlabel('Days Open', color='white')
        ax4.set_ylabel('Number of Findings', color='white')
        ax4.set_title('Distribution of Days Open (Active Findings)', fontsize=12, fontweight='bold', color='white')
        ax4.set_facecolor('#2b2b2b')
        ax4.tick_params(colors='white')
        ax4.grid(True, alpha=0.3)

        # 5. Severity of Active Findings
        ax5 = fig.add_subplot(gs[1, 2])
        if not active.empty:
            sev_counts = active['severity_text'].value_counts()
            sev_counts = sev_counts.reindex([s for s in SEVERITY_ORDER if s in sev_counts.index])
            colors = [SEVERITY_COLORS.get(s, 'gray') for s in sev_counts.index]
            ax5.barh(sev_counts.index, sev_counts.values, color=colors)
            ax5.set_xlabel('Count', color='white')
        ax5.set_title('Active by Severity', fontsize=12, fontweight='bold', color='white')
        ax5.set_facecolor('#2b2b2b')
        ax5.tick_params(colors='white')
        ax5.grid(True, alpha=0.3, axis='x')

        fig.suptitle('Finding Lifecycle Dashboard', fontsize=16, fontweight='bold', color='white', y=0.98)

        return fig


def create_host_analysis_dashboard(historical_df: pd.DataFrame,
                                   host_stats_df: pd.DataFrame = None,
                                   figsize: Tuple[int, int] = (16, 10)) -> Figure:
    """
    Create a host-focused analysis dashboard.

    Args:
        historical_df: DataFrame with historical findings
        host_stats_df: DataFrame with host statistics
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig = plt.figure(figsize=figsize)
        gs = gridspec.GridSpec(2, 2, figure=fig, hspace=0.3, wspace=0.3)

        if historical_df.empty:
            ax = fig.add_subplot(111)
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center',
                   fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        historical_df = historical_df.copy()
        if 'scan_date' in historical_df.columns:
            historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])
            latest_data = historical_df[historical_df['scan_date'] == historical_df['scan_date'].max()]
        else:
            latest_data = historical_df

        # 1. Top hosts by finding count
        ax1 = fig.add_subplot(gs[0, 0])
        host_counts = latest_data.groupby('hostname').size().nlargest(15)
        colors = plt.cm.RdYlGn_r(np.linspace(0.2, 0.8, len(host_counts)))
        ax1.barh(range(len(host_counts)), host_counts.values, color=colors)
        ax1.set_yticks(range(len(host_counts)))
        ax1.set_yticklabels(host_counts.index, fontsize=8)
        ax1.invert_yaxis()
        ax1.set_xlabel('Finding Count', color='white')
        ax1.set_title('Top 15 Hosts', fontsize=12, fontweight='bold', color='white')
        ax1.set_facecolor('#2b2b2b')
        ax1.tick_params(colors='white')
        ax1.grid(True, alpha=0.3, axis='x')

        # 2. Host count over time
        ax2 = fig.add_subplot(gs[0, 1])
        if 'scan_date' in historical_df.columns:
            host_timeline = historical_df.groupby('scan_date')['hostname'].nunique()
            ax2.plot(host_timeline.index, host_timeline.values, marker='o', color='#007bff', linewidth=2)
            ax2.fill_between(host_timeline.index, host_timeline.values, alpha=0.3, color='#007bff')
            plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45, ha='right')
        ax2.set_xlabel('Scan Date', color='white')
        ax2.set_ylabel('Host Count', color='white')
        ax2.set_title('Hosts Over Time', fontsize=12, fontweight='bold', color='white')
        ax2.set_facecolor('#2b2b2b')
        ax2.tick_params(colors='white')
        ax2.grid(True, alpha=0.3)

        # 3. Findings per host distribution
        ax3 = fig.add_subplot(gs[1, 0])
        findings_per_host = latest_data.groupby('hostname').size()
        ax3.hist(findings_per_host, bins=30, color='#28a745', edgecolor='white', alpha=0.7)
        ax3.axvline(findings_per_host.mean(), color='#dc3545', linestyle='--',
                   label=f'Mean: {findings_per_host.mean():.1f}')
        ax3.legend(loc='upper right', facecolor='#2b2b2b', edgecolor='white')
        ax3.set_xlabel('Findings per Host', color='white')
        ax3.set_ylabel('Number of Hosts', color='white')
        ax3.set_title('Finding Distribution', fontsize=12, fontweight='bold', color='white')
        ax3.set_facecolor('#2b2b2b')
        ax3.tick_params(colors='white')
        ax3.grid(True, alpha=0.3)

        # 4. Host severity breakdown
        ax4 = fig.add_subplot(gs[1, 1])
        if 'severity_text' in latest_data.columns:
            sev_per_host = latest_data.groupby(['hostname', 'severity_text']).size().unstack(fill_value=0)
            sev_per_host = sev_per_host.reindex(columns=[s for s in SEVERITY_ORDER if s in sev_per_host.columns])
            # Show top 10 hosts by total
            sev_per_host['Total'] = sev_per_host.sum(axis=1)
            top_hosts = sev_per_host.nlargest(10, 'Total').drop(columns=['Total'])

            bottom = np.zeros(len(top_hosts))
            for severity in top_hosts.columns:
                ax4.barh(range(len(top_hosts)), top_hosts[severity].values, left=bottom,
                        label=severity, color=SEVERITY_COLORS.get(severity, 'gray'))
                bottom += top_hosts[severity].values

            ax4.set_yticks(range(len(top_hosts)))
            ax4.set_yticklabels(top_hosts.index, fontsize=8)
            ax4.legend(loc='lower right', facecolor='#2b2b2b', edgecolor='white', fontsize=8)
            ax4.invert_yaxis()

        ax4.set_xlabel('Finding Count', color='white')
        ax4.set_title('Host Severity Breakdown', fontsize=12, fontweight='bold', color='white')
        ax4.set_facecolor('#2b2b2b')
        ax4.tick_params(colors='white')
        ax4.grid(True, alpha=0.3, axis='x')

        fig.suptitle('Host Analysis Dashboard', fontsize=16, fontweight='bold', color='white', y=0.98)

        return fig


def create_plugin_analysis_dashboard(historical_df: pd.DataFrame,
                                     figsize: Tuple[int, int] = (16, 10)) -> Figure:
    """
    Create a plugin-focused analysis dashboard.

    Args:
        historical_df: DataFrame with historical findings
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig = plt.figure(figsize=figsize)
        gs = gridspec.GridSpec(2, 2, figure=fig, hspace=0.3, wspace=0.3)

        if historical_df.empty:
            ax = fig.add_subplot(111)
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center',
                   fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        historical_df = historical_df.copy()
        if 'scan_date' in historical_df.columns:
            historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])
            latest_data = historical_df[historical_df['scan_date'] == historical_df['scan_date'].max()]
        else:
            latest_data = historical_df

        # 1. Top plugins by host count
        ax1 = fig.add_subplot(gs[0, 0])
        plugin_hosts = latest_data.groupby(['plugin_id', 'name'])['hostname'].nunique().reset_index()
        plugin_hosts = plugin_hosts.nlargest(15, 'hostname')
        labels = [f"{row['plugin_id'][:8]}..." if len(str(row['plugin_id'])) > 8 else row['plugin_id']
                 for _, row in plugin_hosts.iterrows()]

        ax1.barh(range(len(plugin_hosts)), plugin_hosts['hostname'].values, color='#007bff')
        ax1.set_yticks(range(len(plugin_hosts)))
        ax1.set_yticklabels(labels, fontsize=8)
        ax1.invert_yaxis()
        ax1.set_xlabel('Affected Hosts', color='white')
        ax1.set_title('Top 15 Plugins by Reach', fontsize=12, fontweight='bold', color='white')
        ax1.set_facecolor('#2b2b2b')
        ax1.tick_params(colors='white')
        ax1.grid(True, alpha=0.3, axis='x')

        # 2. Plugin severity distribution
        ax2 = fig.add_subplot(gs[0, 1])
        if 'severity_text' in latest_data.columns:
            plugin_severity = latest_data.groupby('severity_text')['plugin_id'].nunique()
            plugin_severity = plugin_severity.reindex([s for s in SEVERITY_ORDER if s in plugin_severity.index])
            colors = [SEVERITY_COLORS.get(s, 'gray') for s in plugin_severity.index]
            ax2.bar(plugin_severity.index, plugin_severity.values, color=colors)
            ax2.set_ylabel('Unique Plugins', color='white')
            plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45, ha='right')
        ax2.set_title('Plugins by Severity', fontsize=12, fontweight='bold', color='white')
        ax2.set_facecolor('#2b2b2b')
        ax2.tick_params(colors='white')
        ax2.grid(True, alpha=0.3, axis='y')

        # 3. New plugins over time
        ax3 = fig.add_subplot(gs[1, 0])
        if 'scan_date' in historical_df.columns:
            first_seen = historical_df.groupby('plugin_id')['scan_date'].min().reset_index()
            first_seen.columns = ['plugin_id', 'first_seen']
            new_plugins = first_seen.groupby('first_seen').size()
            ax3.bar(new_plugins.index, new_plugins.values, color='#28a745', edgecolor='white')
            ax3.plot(new_plugins.index, new_plugins.cumsum(), color='#dc3545', marker='o', linewidth=2)
            plt.setp(ax3.xaxis.get_majorticklabels(), rotation=45, ha='right')
        ax3.set_xlabel('Scan Date', color='white')
        ax3.set_ylabel('Count', color='white')
        ax3.set_title('New Plugins Over Time', fontsize=12, fontweight='bold', color='white')
        ax3.set_facecolor('#2b2b2b')
        ax3.tick_params(colors='white')
        ax3.grid(True, alpha=0.3)

        # 4. Plugin persistence (plugins appearing in most scans)
        ax4 = fig.add_subplot(gs[1, 1])
        if 'scan_date' in historical_df.columns:
            total_scans = historical_df['scan_date'].nunique()
            plugin_scans = historical_df.groupby('plugin_id')['scan_date'].nunique()
            plugin_persistence = (plugin_scans / total_scans * 100).round(1)
            top_persistent = plugin_persistence.nlargest(15)

            ax4.barh(range(len(top_persistent)), top_persistent.values, color='#fd7e14')
            ax4.set_yticks(range(len(top_persistent)))
            labels = [p[:8] + '...' if len(str(p)) > 8 else str(p) for p in top_persistent.index]
            ax4.set_yticklabels(labels, fontsize=8)
            ax4.invert_yaxis()
            ax4.set_xlabel('% Scans Present', color='white')

        ax4.set_title('Most Persistent Plugins', fontsize=12, fontweight='bold', color='white')
        ax4.set_facecolor('#2b2b2b')
        ax4.tick_params(colors='white')
        ax4.grid(True, alpha=0.3, axis='x')

        fig.suptitle('Plugin Analysis Dashboard', fontsize=16, fontweight='bold', color='white', y=0.98)

        return fig
