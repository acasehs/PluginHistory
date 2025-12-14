"""
Remediation Dashboard Module

Creates comprehensive dashboards for package version impact analysis
and remediation prioritization.
"""

import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
import matplotlib.gridspec as gridspec
from matplotlib.patches import Patch

from ..config import SEVERITY_COLORS, SEVERITY_ORDER
from .charts import get_dark_style


def create_remediation_impact_dashboard(
    plan,  # RemediationPlan from package_version_impact
    figsize: Tuple[int, int] = (18, 14)
) -> Figure:
    """
    Create a comprehensive remediation impact dashboard.

    Includes:
    - Key metrics summary
    - Top packages by impact
    - Cumulative impact curve
    - Severity breakdown
    - Quick wins identification

    Args:
        plan: RemediationPlan object from package_version_impact analysis
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig = plt.figure(figsize=figsize)
        gs = gridspec.GridSpec(3, 3, figure=fig, hspace=0.35, wspace=0.3)

        if not plan.packages:
            ax = fig.add_subplot(111)
            ax.text(0.5, 0.5, 'No package data available\n\nPlease load version extraction data first.',
                   ha='center', va='center', fontsize=16, color='white')
            ax.set_facecolor('#2b2b2b')
            ax.axis('off')
            return fig

        # 1. Key Metrics Panel (top left)
        ax_metrics = fig.add_subplot(gs[0, 0])
        ax_metrics.set_facecolor('#2b2b2b')
        ax_metrics.axis('off')

        # Calculate metrics
        total_packages = len(plan.packages)
        total_findings = plan.total_findings_resolved
        total_hosts = plan.total_hosts_affected
        total_cves = plan.total_unique_cves

        # Calculate 80% threshold
        cumulative = 0
        packages_for_80 = total_packages
        for i, pkg in enumerate(plan.packages):
            cumulative += pkg.total_impact
            if cumulative >= total_findings * 0.8:
                packages_for_80 = i + 1
                break

        # Severity breakdown
        severity_totals = {sev: 0 for sev in SEVERITY_ORDER}
        for pkg in plan.packages:
            for sev, count in pkg.severity_breakdown.items():
                if sev in severity_totals:
                    severity_totals[sev] += count

        metrics_text = f"""
        REMEDIATION SUMMARY

        Total Packages: {total_packages:,}
        Total Findings: {total_findings:,}
        Total Hosts: {total_hosts:,}
        Total CVEs: {total_cves:,}

        80% Coverage: Top {packages_for_80} packages

        BY SEVERITY:
        Critical: {severity_totals['Critical']:,}
        High: {severity_totals['High']:,}
        Medium: {severity_totals['Medium']:,}
        Low: {severity_totals['Low']:,}
        """

        ax_metrics.text(0.05, 0.95, metrics_text, transform=ax_metrics.transAxes,
                       fontsize=11, color='white', verticalalignment='top',
                       fontfamily='monospace')
        ax_metrics.set_title('Key Metrics', fontsize=12, fontweight='bold', color='white')

        # 2. Top Packages Bar Chart (top center + right, spans 2 columns)
        ax_top = fig.add_subplot(gs[0, 1:])
        top_packages = plan.packages[:10]

        if top_packages:
            package_names = [p.package_name[:25] + ('...' if len(p.package_name) > 25 else '')
                           for p in top_packages]
            impact_scores = [p.impact_score for p in top_packages]

            # Color by severity composition
            colors = []
            for pkg in top_packages:
                critical = pkg.severity_breakdown.get('Critical', 0)
                high = pkg.severity_breakdown.get('High', 0)
                total = sum(pkg.severity_breakdown.values()) or 1
                if critical / total > 0.3:
                    colors.append(SEVERITY_COLORS['Critical'])
                elif high / total > 0.3:
                    colors.append(SEVERITY_COLORS['High'])
                else:
                    colors.append(SEVERITY_COLORS['Medium'])

            y_pos = range(len(top_packages))
            bars = ax_top.barh(y_pos, impact_scores, color=colors, edgecolor='white')
            ax_top.set_yticks(y_pos)
            ax_top.set_yticklabels(package_names, fontsize=9, color='white')

            for i, (bar, pkg) in enumerate(zip(bars, top_packages)):
                width = bar.get_width()
                label = f'{int(width):,} ({pkg.total_impact}F/{pkg.affected_hosts}H)'
                ax_top.text(width * 1.01, bar.get_y() + bar.get_height()/2,
                           label, va='center', color='white', fontsize=8)

            ax_top.invert_yaxis()
            ax_top.set_xlabel('Impact Score', color='white')
            ax_top.grid(True, alpha=0.3, axis='x')

        ax_top.set_title('Top 10 Packages by Impact', fontsize=12, fontweight='bold', color='white')
        ax_top.set_facecolor('#2b2b2b')
        ax_top.tick_params(colors='white')

        # 3. Cumulative Impact Curve (middle left + center)
        ax_cumulative = fig.add_subplot(gs[1, 0:2])

        cumulative_findings = 0
        y_cumulative = []
        y_pct = []

        for pkg in plan.packages:
            cumulative_findings += pkg.total_impact
            y_cumulative.append(cumulative_findings)
            y_pct.append(cumulative_findings / total_findings * 100 if total_findings > 0 else 0)

        x_pos = range(1, len(plan.packages) + 1)

        ax_cumulative.fill_between(x_pos, y_cumulative, alpha=0.3, color='#007bff')
        line1, = ax_cumulative.plot(x_pos, y_cumulative, color='#007bff', linewidth=2, label='Findings')

        ax_cumulative2 = ax_cumulative.twinx()
        line2, = ax_cumulative2.plot(x_pos, y_pct, color='#28a745', linewidth=2,
                                     linestyle='--', label='Percentage')
        ax_cumulative2.axhline(y=80, color='#ffc107', linestyle=':', linewidth=2, alpha=0.7)
        ax_cumulative2.text(len(plan.packages) * 0.85, 82, '80%', color='#ffc107', fontsize=9)

        ax_cumulative.set_xlabel('Number of Packages Remediated', color='white')
        ax_cumulative.set_ylabel('Cumulative Findings', color='#007bff')
        ax_cumulative2.set_ylabel('Percentage (%)', color='#28a745')
        ax_cumulative.tick_params(axis='y', labelcolor='#007bff')
        ax_cumulative2.tick_params(axis='y', labelcolor='#28a745')

        ax_cumulative.legend([line1, line2], ['Findings', 'Percentage'], loc='lower right',
                            facecolor='#2b2b2b', edgecolor='white')

        ax_cumulative.set_title(f'Cumulative Impact (80% at {packages_for_80} packages)',
                               fontsize=12, fontweight='bold', color='white')
        ax_cumulative.set_facecolor('#2b2b2b')
        ax_cumulative.tick_params(colors='white')
        ax_cumulative.grid(True, alpha=0.3)

        # 4. Severity Pie Chart (middle right)
        ax_severity = fig.add_subplot(gs[1, 2])

        severity_values = [severity_totals[s] for s in SEVERITY_ORDER if severity_totals[s] > 0]
        severity_labels = [s for s in SEVERITY_ORDER if severity_totals[s] > 0]
        severity_colors = [SEVERITY_COLORS[s] for s in severity_labels]

        if severity_values:
            wedges, texts, autotexts = ax_severity.pie(
                severity_values, labels=severity_labels, colors=severity_colors,
                autopct='%1.1f%%', startangle=90, textprops={'color': 'white', 'fontsize': 9}
            )
            for autotext in autotexts:
                autotext.set_fontsize(8)

        ax_severity.set_title('Findings by Severity', fontsize=12, fontweight='bold', color='white')

        # 5. Quick Wins Chart (bottom left)
        ax_quickwins = fig.add_subplot(gs[2, 0])

        quick_wins = [p for p in plan.packages if p.affected_hosts <= 10 and p.total_impact >= 5]
        quick_wins = sorted(quick_wins, key=lambda x: x.total_impact / max(x.affected_hosts, 1), reverse=True)[:8]

        if quick_wins:
            qw_names = [p.package_name[:15] + ('...' if len(p.package_name) > 15 else '')
                       for p in quick_wins]
            qw_efficiency = [p.total_impact / max(p.affected_hosts, 1) for p in quick_wins]

            y_pos = range(len(quick_wins))
            colors = plt.cm.Greens(np.linspace(0.4, 0.9, len(quick_wins)))

            ax_quickwins.barh(y_pos, qw_efficiency, color=colors, edgecolor='white')
            ax_quickwins.set_yticks(y_pos)
            ax_quickwins.set_yticklabels(qw_names, fontsize=8, color='white')
            ax_quickwins.invert_yaxis()
            ax_quickwins.set_xlabel('Findings/Host', color='white', fontsize=9)
        else:
            ax_quickwins.text(0.5, 0.5, 'No quick wins found', ha='center', va='center',
                            fontsize=12, color='white')

        ax_quickwins.set_title('Quick Wins (Low Effort, High Impact)', fontsize=11, fontweight='bold', color='white')
        ax_quickwins.set_facecolor('#2b2b2b')
        ax_quickwins.tick_params(colors='white')
        ax_quickwins.grid(True, alpha=0.3, axis='x')

        # 6. Version Consolidation (bottom center)
        ax_versions = fig.add_subplot(gs[2, 1])

        sorted_by_versions = sorted(plan.packages, key=lambda x: len(x.current_versions), reverse=True)[:8]

        if sorted_by_versions:
            v_names = [p.package_name[:15] + ('...' if len(p.package_name) > 15 else '')
                      for p in sorted_by_versions]
            v_counts = [len(p.current_versions) for p in sorted_by_versions]

            y_pos = range(len(sorted_by_versions))
            colors = plt.cm.Oranges(np.linspace(0.4, 0.9, len(sorted_by_versions)))

            ax_versions.barh(y_pos, v_counts, color=colors, edgecolor='white')
            ax_versions.set_yticks(y_pos)
            ax_versions.set_yticklabels(v_names, fontsize=8, color='white')
            ax_versions.invert_yaxis()
            ax_versions.set_xlabel('Version Count', color='white', fontsize=9)

        ax_versions.set_title('Consolidation Opportunities', fontsize=11, fontweight='bold', color='white')
        ax_versions.set_facecolor('#2b2b2b')
        ax_versions.tick_params(colors='white')
        ax_versions.grid(True, alpha=0.3, axis='x')

        # 7. CVE Coverage (bottom right)
        ax_cves = fig.add_subplot(gs[2, 2])

        packages_with_cves = sorted([p for p in plan.packages if p.cves],
                                   key=lambda x: len(x.cves), reverse=True)[:8]

        if packages_with_cves:
            cve_names = [p.package_name[:15] + ('...' if len(p.package_name) > 15 else '')
                        for p in packages_with_cves]
            cve_counts = [len(p.cves) for p in packages_with_cves]

            y_pos = range(len(packages_with_cves))

            ax_cves.barh(y_pos, cve_counts, color='#dc3545', edgecolor='white')
            ax_cves.set_yticks(y_pos)
            ax_cves.set_yticklabels(cve_names, fontsize=8, color='white')
            ax_cves.invert_yaxis()
            ax_cves.set_xlabel('CVE Count', color='white', fontsize=9)
        else:
            ax_cves.text(0.5, 0.5, 'No CVE data', ha='center', va='center',
                        fontsize=12, color='white')

        ax_cves.set_title('CVE Coverage by Package', fontsize=11, fontweight='bold', color='white')
        ax_cves.set_facecolor('#2b2b2b')
        ax_cves.tick_params(colors='white')
        ax_cves.grid(True, alpha=0.3, axis='x')

        fig.suptitle('Package Version Remediation Dashboard',
                    fontsize=16, fontweight='bold', color='white', y=0.98)

        return fig


def create_executive_remediation_summary(
    plan,  # RemediationPlan
    figsize: Tuple[int, int] = (16, 10)
) -> Figure:
    """
    Create an executive-level summary dashboard.

    Focuses on high-level metrics and actionable insights.

    Args:
        plan: RemediationPlan object
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig = plt.figure(figsize=figsize)
        gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.35, wspace=0.3)

        if not plan.packages:
            ax = fig.add_subplot(111)
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center',
                   fontsize=16, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        # Calculate key metrics
        total_findings = plan.total_findings_resolved
        total_hosts = plan.total_hosts_affected
        total_cves = plan.total_unique_cves
        total_packages = len(plan.packages)

        # Calculate severity breakdown
        critical_findings = sum(p.severity_breakdown.get('Critical', 0) for p in plan.packages)
        high_findings = sum(p.severity_breakdown.get('High', 0) for p in plan.packages)

        # Calculate 80% threshold
        cumulative = 0
        packages_for_80 = total_packages
        for i, pkg in enumerate(plan.packages):
            cumulative += pkg.total_impact
            if cumulative >= total_findings * 0.8:
                packages_for_80 = i + 1
                break

        # 1. Big Numbers Panel (top row, spans all columns)
        ax_big = fig.add_subplot(gs[0, :])
        ax_big.set_facecolor('#2b2b2b')
        ax_big.axis('off')

        # Create big number display
        metrics = [
            (f"{total_findings:,}", "Total Findings", '#007bff'),
            (f"{total_hosts:,}", "Affected Hosts", '#28a745'),
            (f"{total_packages:,}", "Packages to Update", '#ffc107'),
            (f"{critical_findings + high_findings:,}", "Critical/High", '#dc3545'),
            (f"{packages_for_80}", "80% Coverage", '#17a2b8')
        ]

        for i, (value, label, color) in enumerate(metrics):
            x_pos = 0.1 + i * 0.18
            ax_big.text(x_pos, 0.7, value, fontsize=32, fontweight='bold',
                       color=color, ha='center', transform=ax_big.transAxes)
            ax_big.text(x_pos, 0.3, label, fontsize=11, color='white',
                       ha='center', transform=ax_big.transAxes)

        ax_big.set_title('Remediation Overview', fontsize=14, fontweight='bold',
                        color='white', pad=20)

        # 2. Top 5 Priority Packages (bottom left)
        ax_priority = fig.add_subplot(gs[1, 0])

        top5 = plan.packages[:5]
        if top5:
            names = [f"{i+1}. {p.package_name[:18]}..." if len(p.package_name) > 18
                    else f"{i+1}. {p.package_name}"
                    for i, p in enumerate(top5)]
            impacts = [p.total_impact for p in top5]

            colors = [SEVERITY_COLORS['Critical'] if p.severity_breakdown.get('Critical', 0) > 0
                     else SEVERITY_COLORS['High'] if p.severity_breakdown.get('High', 0) > 0
                     else SEVERITY_COLORS['Medium']
                     for p in top5]

            y_pos = range(len(top5))
            ax_priority.barh(y_pos, impacts, color=colors, edgecolor='white')
            ax_priority.set_yticks(y_pos)
            ax_priority.set_yticklabels(names, fontsize=10, color='white')
            ax_priority.invert_yaxis()

            for i, (imp, pkg) in enumerate(zip(impacts, top5)):
                ax_priority.text(imp + max(impacts) * 0.02, i,
                               f"{pkg.affected_hosts}H", va='center',
                               color='white', fontsize=9)

        ax_priority.set_xlabel('Findings Resolved', color='white')
        ax_priority.set_title('Top 5 Priority Packages', fontsize=12,
                             fontweight='bold', color='white')
        ax_priority.set_facecolor('#2b2b2b')
        ax_priority.tick_params(colors='white')
        ax_priority.grid(True, alpha=0.3, axis='x')

        # 3. Severity Distribution Donut (bottom center)
        ax_donut = fig.add_subplot(gs[1, 1])

        severity_totals = {}
        for sev in SEVERITY_ORDER:
            severity_totals[sev] = sum(p.severity_breakdown.get(sev, 0) for p in plan.packages)

        values = [severity_totals[s] for s in SEVERITY_ORDER if severity_totals[s] > 0]
        labels = [s for s in SEVERITY_ORDER if severity_totals[s] > 0]
        colors = [SEVERITY_COLORS[s] for s in labels]

        if values:
            wedges, texts, autotexts = ax_donut.pie(
                values, labels=labels, colors=colors,
                autopct='%1.0f%%', startangle=90, pctdistance=0.75,
                textprops={'color': 'white', 'fontsize': 10},
                wedgeprops=dict(width=0.5)
            )

            # Add center text
            ax_donut.text(0, 0, f'{sum(values):,}\nFindings',
                         ha='center', va='center', fontsize=14,
                         fontweight='bold', color='white')

        ax_donut.set_title('Severity Distribution', fontsize=12, fontweight='bold', color='white')

        # 4. Recommendations Panel (bottom right)
        ax_recs = fig.add_subplot(gs[1, 2])
        ax_recs.set_facecolor('#2b2b2b')
        ax_recs.axis('off')

        recommendations = []

        # Priority 1: Critical packages
        critical_pkgs = [p for p in plan.packages if p.severity_breakdown.get('Critical', 0) > 0]
        if critical_pkgs:
            top_crit = critical_pkgs[0].package_name[:20]
            recommendations.append(f"1. URGENT: {len(critical_pkgs)} package(s) with\n   critical findings. Start: {top_crit}")

        # Priority 2: Quick wins
        quick_wins = [p for p in plan.packages if p.affected_hosts <= 5 and p.total_impact >= 10]
        if quick_wins:
            recommendations.append(f"2. QUICK WIN: {len(quick_wins)} package(s)\n   affect few hosts but high impact")

        # Priority 3: 80% coverage
        recommendations.append(f"3. GOAL: Remediate top {packages_for_80} packages\n   for 80% coverage")

        # Priority 4: Consolidation
        high_version_variance = [p for p in plan.packages if len(p.current_versions) > 3]
        if high_version_variance:
            recommendations.append(f"4. CONSOLIDATE: {len(high_version_variance)} package(s)\n   have 4+ versions in use")

        rec_text = "RECOMMENDATIONS\n\n" + "\n\n".join(recommendations)

        ax_recs.text(0.05, 0.95, rec_text, transform=ax_recs.transAxes,
                    fontsize=10, color='white', verticalalignment='top',
                    fontfamily='monospace', wrap=True)
        ax_recs.set_title('Action Items', fontsize=12, fontweight='bold', color='white')

        fig.suptitle('Executive Remediation Summary',
                    fontsize=16, fontweight='bold', color='white', y=0.98)

        return fig


def create_host_impact_dashboard(
    plan,  # RemediationPlan
    figsize: Tuple[int, int] = (16, 10)
) -> Figure:
    """
    Create a host-focused impact dashboard.

    Shows which hosts benefit most from remediation.

    Args:
        plan: RemediationPlan object
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig = plt.figure(figsize=figsize)
        gs = gridspec.GridSpec(2, 2, figure=fig, hspace=0.3, wspace=0.3)

        if not plan.packages:
            ax = fig.add_subplot(111)
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center',
                   fontsize=16, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        # Aggregate host data
        host_data = {}
        for pkg in plan.packages:
            for host in pkg.hosts_list:
                if host not in host_data:
                    host_data[host] = {
                        'packages': 0,
                        'findings': 0,
                        'severity_score': 0
                    }
                host_data[host]['packages'] += 1
                host_data[host]['findings'] += pkg.total_impact / max(pkg.affected_hosts, 1)
                # Add severity score
                for sev, count in pkg.severity_breakdown.items():
                    weight = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}.get(sev, 0)
                    host_data[host]['severity_score'] += (count / max(pkg.affected_hosts, 1)) * weight

        # Sort hosts by severity score
        sorted_hosts = sorted(host_data.items(), key=lambda x: x[1]['severity_score'], reverse=True)

        # 1. Top Hosts by Finding Count (top left)
        ax1 = fig.add_subplot(gs[0, 0])

        top_hosts = sorted_hosts[:15]
        if top_hosts:
            names = [h[0][:20] + ('...' if len(h[0]) > 20 else '') for h in top_hosts]
            findings = [h[1]['findings'] for h in top_hosts]

            colors = plt.cm.RdYlGn_r(np.linspace(0.2, 0.8, len(top_hosts)))
            ax1.barh(range(len(top_hosts)), findings, color=colors, edgecolor='white')
            ax1.set_yticks(range(len(top_hosts)))
            ax1.set_yticklabels(names, fontsize=9, color='white')
            ax1.invert_yaxis()

        ax1.set_xlabel('Estimated Findings', color='white')
        ax1.set_title('Top 15 Hosts by Finding Impact', fontsize=12, fontweight='bold', color='white')
        ax1.set_facecolor('#2b2b2b')
        ax1.tick_params(colors='white')
        ax1.grid(True, alpha=0.3, axis='x')

        # 2. Host Distribution by Package Count (top right)
        ax2 = fig.add_subplot(gs[0, 1])

        package_counts = [h[1]['packages'] for h in sorted_hosts]
        if package_counts:
            bins = [1, 2, 3, 5, 10, 20, max(package_counts) + 1]
            labels = ['1', '2', '3-4', '5-9', '10-19', '20+']

            hist_data = []
            for count in package_counts:
                for i, (low, high) in enumerate(zip(bins[:-1], bins[1:])):
                    if low <= count < high:
                        hist_data.append(labels[i])
                        break

            from collections import Counter
            hist_counts = Counter(hist_data)
            x_labels = [l for l in labels if l in hist_counts]
            y_values = [hist_counts[l] for l in x_labels]

            ax2.bar(x_labels, y_values, color='#17a2b8', edgecolor='white')
            ax2.set_xlabel('Packages to Remediate', color='white')
            ax2.set_ylabel('Number of Hosts', color='white')

        ax2.set_title('Host Distribution by Package Count', fontsize=12, fontweight='bold', color='white')
        ax2.set_facecolor('#2b2b2b')
        ax2.tick_params(colors='white')
        ax2.grid(True, alpha=0.3, axis='y')

        # 3. Remediation Effort by Host (bottom left)
        ax3 = fig.add_subplot(gs[1, 0])

        if sorted_hosts:
            x = [h[1]['packages'] for h in sorted_hosts[:50]]
            y = [h[1]['findings'] for h in sorted_hosts[:50]]
            sizes = [max(20, min(200, h[1]['severity_score'] * 5)) for h in sorted_hosts[:50]]

            scatter = ax3.scatter(x, y, s=sizes, c='#007bff', alpha=0.6, edgecolors='white')

            ax3.set_xlabel('Packages to Update', color='white')
            ax3.set_ylabel('Findings Resolved', color='white')

        ax3.set_title('Host Remediation Effort vs Benefit', fontsize=12, fontweight='bold', color='white')
        ax3.set_facecolor('#2b2b2b')
        ax3.tick_params(colors='white')
        ax3.grid(True, alpha=0.3)

        # 4. Summary Statistics (bottom right)
        ax4 = fig.add_subplot(gs[1, 1])
        ax4.set_facecolor('#2b2b2b')
        ax4.axis('off')

        total_hosts = len(sorted_hosts)
        avg_packages = np.mean([h[1]['packages'] for h in sorted_hosts]) if sorted_hosts else 0
        max_packages = max([h[1]['packages'] for h in sorted_hosts]) if sorted_hosts else 0
        hosts_gt_5_pkgs = len([h for h in sorted_hosts if h[1]['packages'] > 5])

        summary_text = f"""
        HOST STATISTICS

        Total Affected Hosts: {total_hosts:,}
        Average Packages/Host: {avg_packages:.1f}
        Max Packages on Single Host: {max_packages}
        Hosts with 5+ Packages: {hosts_gt_5_pkgs}

        REMEDIATION NOTES:

        - {hosts_gt_5_pkgs} hosts require significant
          remediation effort (5+ packages)

        - Consider prioritizing hosts with
          high severity scores first

        - Quick wins: Target hosts with
          1-2 packages and high impact
        """

        ax4.text(0.05, 0.95, summary_text, transform=ax4.transAxes,
                fontsize=10, color='white', verticalalignment='top',
                fontfamily='monospace')
        ax4.set_title('Host Analysis Summary', fontsize=12, fontweight='bold', color='white')

        fig.suptitle('Host-Level Remediation Impact',
                    fontsize=16, fontweight='bold', color='white', y=0.98)

        return fig
