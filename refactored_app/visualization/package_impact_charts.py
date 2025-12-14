"""
Package Version Impact Visualization Module

Creates charts and visualizations for package version impact analysis,
showing remediation priorities, impact distribution, and cumulative benefits.
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


def create_package_impact_bar_chart(
    plan,  # RemediationPlan
    top_n: int = 15,
    title: str = "Top Packages by Remediation Impact",
    figsize: Tuple[int, int] = (12, 8)
) -> Figure:
    """
    Create a horizontal bar chart showing packages ranked by impact score.

    Args:
        plan: RemediationPlan object
        top_n: Number of top packages to show
        title: Chart title
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig, ax = plt.subplots(figsize=figsize)

        if not plan.packages:
            ax.text(0.5, 0.5, 'No package data available', ha='center', va='center',
                   fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        # Get top N packages by impact score
        top_packages = plan.packages[:top_n]

        # Prepare data
        package_names = [p.package_name[:30] + ('...' if len(p.package_name) > 30 else '')
                        for p in top_packages]
        impact_scores = [p.impact_score for p in top_packages]
        findings_counts = [p.total_impact for p in top_packages]
        host_counts = [p.affected_hosts for p in top_packages]

        # Create color gradient based on severity composition
        colors = []
        for pkg in top_packages:
            critical = pkg.severity_breakdown.get('Critical', 0)
            high = pkg.severity_breakdown.get('High', 0)
            medium = pkg.severity_breakdown.get('Medium', 0)
            total = sum(pkg.severity_breakdown.values()) or 1

            # Weighted color (more red for critical/high)
            if critical / total > 0.3:
                colors.append(SEVERITY_COLORS['Critical'])
            elif high / total > 0.3:
                colors.append(SEVERITY_COLORS['High'])
            elif medium / total > 0.3:
                colors.append(SEVERITY_COLORS['Medium'])
            else:
                colors.append(SEVERITY_COLORS['Low'])

        y_pos = range(len(top_packages))

        bars = ax.barh(y_pos, impact_scores, color=colors, edgecolor='white', linewidth=0.5)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(package_names, fontsize=9, color='white')

        ax.set_xlabel('Impact Score (Severity × Hosts × Findings)', color='white', fontsize=10)
        ax.set_title(title, fontsize=14, fontweight='bold', color='white')
        ax.grid(True, alpha=0.3, axis='x')

        # Add value labels with findings/hosts info
        for i, (bar, findings, hosts) in enumerate(zip(bars, findings_counts, host_counts)):
            width = bar.get_width()
            label = f'{int(width):,} ({findings}F/{hosts}H)'
            ax.text(width + max(impact_scores) * 0.01, bar.get_y() + bar.get_height()/2,
                   label, va='center', color='white', fontsize=8)

        ax.invert_yaxis()

        # Add legend
        legend_elements = [
            Patch(facecolor=SEVERITY_COLORS['Critical'], label='Critical-heavy'),
            Patch(facecolor=SEVERITY_COLORS['High'], label='High-heavy'),
            Patch(facecolor=SEVERITY_COLORS['Medium'], label='Medium-heavy'),
            Patch(facecolor=SEVERITY_COLORS['Low'], label='Low/Info')
        ]
        ax.legend(handles=legend_elements, loc='lower right',
                 facecolor='#2b2b2b', edgecolor='white', fontsize=8)

        fig.tight_layout()
        return fig


def create_cumulative_impact_chart(
    plan,  # RemediationPlan
    title: str = "Cumulative Remediation Impact",
    figsize: Tuple[int, int] = (12, 6)
) -> Figure:
    """
    Create a chart showing cumulative impact as packages are remediated.

    Shows the "80/20" effect - how much impact the top packages provide.

    Args:
        plan: RemediationPlan object
        title: Chart title
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig, ax1 = plt.subplots(figsize=figsize)

        if not plan.packages:
            ax1.text(0.5, 0.5, 'No package data available', ha='center', va='center',
                    fontsize=14, color='white')
            ax1.set_facecolor('#2b2b2b')
            return fig

        # Calculate cumulative data
        cumulative_findings = 0
        x_labels = []
        y_findings = []
        y_pct = []

        total_findings = plan.total_findings_resolved or 1

        for i, pkg in enumerate(plan.packages):
            cumulative_findings += pkg.total_impact
            x_labels.append(f"{i+1}")
            y_findings.append(cumulative_findings)
            y_pct.append(cumulative_findings / total_findings * 100)

        x_pos = range(len(plan.packages))

        # Area chart for cumulative findings
        ax1.fill_between(x_pos, y_findings, alpha=0.4, color='#007bff')
        ax1.plot(x_pos, y_findings, color='#007bff', linewidth=2, marker='o',
                markersize=4, label='Cumulative Findings')

        ax1.set_xlabel('Number of Packages Remediated', color='white', fontsize=10)
        ax1.set_ylabel('Cumulative Findings Resolved', color='#007bff', fontsize=10)
        ax1.tick_params(axis='y', labelcolor='#007bff')

        # Secondary y-axis for percentage
        ax2 = ax1.twinx()
        ax2.plot(x_pos, y_pct, color='#28a745', linewidth=2, linestyle='--',
                marker='s', markersize=4, label='Percentage')
        ax2.set_ylabel('Percentage of Total (%)', color='#28a745', fontsize=10)
        ax2.tick_params(axis='y', labelcolor='#28a745')

        # Add 80% line
        ax2.axhline(y=80, color='#ffc107', linestyle=':', linewidth=2, alpha=0.7)
        ax2.text(len(plan.packages) * 0.7, 82, '80% Target', color='#ffc107', fontsize=9)

        # Find where 80% is reached
        packages_for_80 = next((i + 1 for i, pct in enumerate(y_pct) if pct >= 80), len(plan.packages))
        ax1.axvline(x=packages_for_80 - 1, color='#ffc107', linestyle=':', linewidth=2, alpha=0.7)

        ax1.set_title(f"{title}\n(80% coverage with top {packages_for_80} packages)",
                     fontsize=14, fontweight='bold', color='white')
        ax1.grid(True, alpha=0.3)
        ax1.set_facecolor('#2b2b2b')

        # Set x-ticks
        if len(x_pos) > 20:
            step = max(1, len(x_pos) // 10)
            ax1.set_xticks(x_pos[::step])
        else:
            ax1.set_xticks(x_pos)

        # Combined legend
        lines1, labels1 = ax1.get_legend_handles_labels()
        lines2, labels2 = ax2.get_legend_handles_labels()
        ax1.legend(lines1 + lines2, labels1 + labels2, loc='lower right',
                  facecolor='#2b2b2b', edgecolor='white')

        fig.tight_layout()
        return fig


def create_severity_breakdown_chart(
    plan,  # RemediationPlan
    top_n: int = 10,
    title: str = "Package Severity Breakdown",
    figsize: Tuple[int, int] = (12, 8)
) -> Figure:
    """
    Create a stacked bar chart showing severity breakdown per package.

    Args:
        plan: RemediationPlan object
        top_n: Number of packages to show
        title: Chart title
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig, ax = plt.subplots(figsize=figsize)

        if not plan.packages:
            ax.text(0.5, 0.5, 'No package data available', ha='center', va='center',
                   fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        top_packages = plan.packages[:top_n]
        package_names = [p.package_name[:25] + ('...' if len(p.package_name) > 25 else '')
                        for p in top_packages]

        y_pos = range(len(top_packages))

        # Create stacked bars
        left_pos = np.zeros(len(top_packages))

        for severity in SEVERITY_ORDER:
            counts = [p.severity_breakdown.get(severity, 0) for p in top_packages]
            if sum(counts) > 0:
                ax.barh(y_pos, counts, left=left_pos, label=severity,
                       color=SEVERITY_COLORS.get(severity, 'gray'), edgecolor='white', linewidth=0.5)
                left_pos = [l + c for l, c in zip(left_pos, counts)]

        ax.set_yticks(y_pos)
        ax.set_yticklabels(package_names, fontsize=9, color='white')
        ax.set_xlabel('Number of Findings', color='white', fontsize=10)
        ax.set_title(title, fontsize=14, fontweight='bold', color='white')
        ax.grid(True, alpha=0.3, axis='x')

        ax.legend(loc='lower right', facecolor='#2b2b2b', edgecolor='white')
        ax.invert_yaxis()

        fig.tight_layout()
        return fig


def create_host_distribution_chart(
    plan,  # RemediationPlan
    top_n: int = 10,
    title: str = "Hosts Affected by Package",
    figsize: Tuple[int, int] = (12, 6)
) -> Figure:
    """
    Create a chart showing host distribution across packages.

    Args:
        plan: RemediationPlan object
        top_n: Number of packages to show
        title: Chart title
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig, ax = plt.subplots(figsize=figsize)

        if not plan.packages:
            ax.text(0.5, 0.5, 'No package data available', ha='center', va='center',
                   fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        top_packages = plan.packages[:top_n]
        package_names = [p.package_name[:20] + ('...' if len(p.package_name) > 20 else '')
                        for p in top_packages]
        host_counts = [p.affected_hosts for p in top_packages]
        findings_per_host = [p.total_impact / p.affected_hosts if p.affected_hosts > 0 else 0
                           for p in top_packages]

        x_pos = range(len(top_packages))
        width = 0.35

        bars1 = ax.bar([x - width/2 for x in x_pos], host_counts, width,
                      label='Hosts Affected', color='#007bff', edgecolor='white')
        bars2 = ax.bar([x + width/2 for x in x_pos], findings_per_host, width,
                      label='Findings/Host', color='#fd7e14', edgecolor='white')

        ax.set_xlabel('Package', color='white', fontsize=10)
        ax.set_ylabel('Count', color='white', fontsize=10)
        ax.set_title(title, fontsize=14, fontweight='bold', color='white')
        ax.set_xticks(x_pos)
        ax.set_xticklabels(package_names, rotation=45, ha='right', fontsize=9, color='white')
        ax.legend(loc='upper right', facecolor='#2b2b2b', edgecolor='white')
        ax.grid(True, alpha=0.3, axis='y')

        fig.tight_layout()
        return fig


def create_version_consolidation_chart(
    plan,  # RemediationPlan
    top_n: int = 10,
    title: str = "Version Consolidation Opportunities",
    figsize: Tuple[int, int] = (12, 6)
) -> Figure:
    """
    Create a chart showing packages with many different versions.

    Highlights consolidation opportunities.

    Args:
        plan: RemediationPlan object
        top_n: Number of packages to show
        title: Chart title
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig, ax = plt.subplots(figsize=figsize)

        if not plan.packages:
            ax.text(0.5, 0.5, 'No package data available', ha='center', va='center',
                   fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        # Sort by number of current versions
        sorted_packages = sorted(plan.packages, key=lambda x: len(x.current_versions), reverse=True)
        top_packages = sorted_packages[:top_n]

        package_names = [f"{p.package_name[:18]}... → {p.target_version[:8]}"
                        if len(p.package_name) > 18 else f"{p.package_name} → {p.target_version[:8]}"
                        for p in top_packages]
        version_counts = [len(p.current_versions) for p in top_packages]

        y_pos = range(len(top_packages))

        # Color by version count (more versions = more red)
        colors = plt.cm.RdYlGn_r(np.linspace(0.2, 0.8, len(top_packages)))

        bars = ax.barh(y_pos, version_counts, color=colors, edgecolor='white', linewidth=0.5)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(package_names, fontsize=9, color='white')

        ax.set_xlabel('Number of Different Versions in Environment', color='white', fontsize=10)
        ax.set_title(title, fontsize=14, fontweight='bold', color='white')
        ax.grid(True, alpha=0.3, axis='x')

        # Add value labels
        for bar in bars:
            width = bar.get_width()
            ax.text(width + 0.1, bar.get_y() + bar.get_height()/2,
                   f'{int(width)} versions', va='center', color='white', fontsize=8)

        ax.invert_yaxis()

        fig.tight_layout()
        return fig


def create_cve_coverage_chart(
    plan,  # RemediationPlan
    top_n: int = 10,
    title: str = "CVE Coverage by Package Remediation",
    figsize: Tuple[int, int] = (12, 6)
) -> Figure:
    """
    Create a chart showing CVE coverage per package.

    Args:
        plan: RemediationPlan object
        top_n: Number of packages to show
        title: Chart title
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig, ax = plt.subplots(figsize=figsize)

        if not plan.packages:
            ax.text(0.5, 0.5, 'No package data available', ha='center', va='center',
                   fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        # Filter packages with CVEs and sort by CVE count
        packages_with_cves = [p for p in plan.packages if p.cves]
        if not packages_with_cves:
            ax.text(0.5, 0.5, 'No CVE data available', ha='center', va='center',
                   fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        sorted_packages = sorted(packages_with_cves, key=lambda x: len(x.cves), reverse=True)
        top_packages = sorted_packages[:top_n]

        package_names = [p.package_name[:25] + ('...' if len(p.package_name) > 25 else '')
                        for p in top_packages]
        cve_counts = [len(p.cves) for p in top_packages]

        y_pos = range(len(top_packages))

        bars = ax.barh(y_pos, cve_counts, color='#dc3545', edgecolor='white', linewidth=0.5)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(package_names, fontsize=9, color='white')

        ax.set_xlabel('Number of CVEs Addressed', color='white', fontsize=10)
        ax.set_title(title, fontsize=14, fontweight='bold', color='white')
        ax.grid(True, alpha=0.3, axis='x')

        # Add value labels with example CVEs
        for i, (bar, pkg) in enumerate(zip(bars, top_packages)):
            width = bar.get_width()
            example_cve = pkg.cves[0] if pkg.cves else ""
            label = f'{int(width)} ({example_cve[:15]}...)' if len(example_cve) > 15 else f'{int(width)}'
            ax.text(width + 0.1, bar.get_y() + bar.get_height()/2,
                   label, va='center', color='white', fontsize=8)

        ax.invert_yaxis()

        fig.tight_layout()
        return fig


def create_impact_bubble_chart(
    plan,  # RemediationPlan
    top_n: int = 20,
    title: str = "Package Impact Overview (Bubble Size = Impact Score)",
    figsize: Tuple[int, int] = (14, 10)
) -> Figure:
    """
    Create a bubble chart showing hosts vs findings with impact as bubble size.

    Args:
        plan: RemediationPlan object
        top_n: Number of packages to show
        title: Chart title
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig, ax = plt.subplots(figsize=figsize)

        if not plan.packages:
            ax.text(0.5, 0.5, 'No package data available', ha='center', va='center',
                   fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        top_packages = plan.packages[:top_n]

        x = [p.affected_hosts for p in top_packages]
        y = [p.total_impact for p in top_packages]
        sizes = [max(50, min(2000, p.impact_score / 10)) for p in top_packages]
        labels = [p.package_name for p in top_packages]

        # Color by primary severity
        colors = []
        for pkg in top_packages:
            critical = pkg.severity_breakdown.get('Critical', 0)
            high = pkg.severity_breakdown.get('High', 0)
            total = sum(pkg.severity_breakdown.values()) or 1

            if critical / total > 0.2:
                colors.append(SEVERITY_COLORS['Critical'])
            elif high / total > 0.2:
                colors.append(SEVERITY_COLORS['High'])
            elif pkg.severity_breakdown.get('Medium', 0) / total > 0.3:
                colors.append(SEVERITY_COLORS['Medium'])
            else:
                colors.append(SEVERITY_COLORS['Low'])

        scatter = ax.scatter(x, y, s=sizes, c=colors, alpha=0.6, edgecolors='white', linewidth=1)

        # Add labels for top packages
        for i, (xi, yi, label) in enumerate(zip(x, y, labels)):
            if i < 5:  # Label top 5
                short_label = label[:15] + '...' if len(label) > 15 else label
                ax.annotate(short_label, (xi, yi), xytext=(5, 5),
                           textcoords='offset points', fontsize=8, color='white')

        ax.set_xlabel('Affected Hosts', color='white', fontsize=11)
        ax.set_ylabel('Findings Resolved', color='white', fontsize=11)
        ax.set_title(title, fontsize=14, fontweight='bold', color='white')
        ax.grid(True, alpha=0.3)

        # Add legend
        legend_elements = [
            Patch(facecolor=SEVERITY_COLORS['Critical'], label='Critical-heavy'),
            Patch(facecolor=SEVERITY_COLORS['High'], label='High-heavy'),
            Patch(facecolor=SEVERITY_COLORS['Medium'], label='Medium-heavy'),
            Patch(facecolor=SEVERITY_COLORS['Low'], label='Low/Info')
        ]
        ax.legend(handles=legend_elements, loc='upper left',
                 facecolor='#2b2b2b', edgecolor='white')

        fig.tight_layout()
        return fig


def create_quick_wins_chart(
    plan,  # RemediationPlan
    max_hosts: int = 10,
    min_findings: int = 5,
    title: str = "Quick Wins: High Impact, Low Effort",
    figsize: Tuple[int, int] = (12, 6)
) -> Figure:
    """
    Create a chart showing "quick win" packages (few hosts, many findings).

    Args:
        plan: RemediationPlan object
        max_hosts: Maximum hosts for quick win
        min_findings: Minimum findings for quick win
        title: Chart title
        figsize: Figure size tuple

    Returns:
        matplotlib Figure object
    """
    with plt.rc_context(get_dark_style()):
        fig, ax = plt.subplots(figsize=figsize)

        if not plan.packages:
            ax.text(0.5, 0.5, 'No package data available', ha='center', va='center',
                   fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        # Find quick wins
        quick_wins = [p for p in plan.packages
                     if p.affected_hosts <= max_hosts and p.total_impact >= min_findings]

        if not quick_wins:
            ax.text(0.5, 0.5, f'No quick wins found\n(hosts <= {max_hosts}, findings >= {min_findings})',
                   ha='center', va='center', fontsize=14, color='white')
            ax.set_facecolor('#2b2b2b')
            return fig

        # Sort by findings/host ratio
        quick_wins = sorted(quick_wins, key=lambda x: x.total_impact / max(x.affected_hosts, 1), reverse=True)[:15]

        package_names = [p.package_name[:20] + ('...' if len(p.package_name) > 20 else '')
                        for p in quick_wins]
        efficiency = [p.total_impact / max(p.affected_hosts, 1) for p in quick_wins]

        y_pos = range(len(quick_wins))

        colors = plt.cm.Greens(np.linspace(0.4, 0.9, len(quick_wins)))

        bars = ax.barh(y_pos, efficiency, color=colors, edgecolor='white', linewidth=0.5)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(package_names, fontsize=9, color='white')

        ax.set_xlabel('Findings Resolved per Host', color='white', fontsize=10)
        ax.set_title(title, fontsize=14, fontweight='bold', color='white')
        ax.grid(True, alpha=0.3, axis='x')

        # Add value labels
        for i, (bar, pkg) in enumerate(zip(bars, quick_wins)):
            width = bar.get_width()
            label = f'{width:.1f} ({pkg.total_impact}F/{pkg.affected_hosts}H)'
            ax.text(width + 0.1, bar.get_y() + bar.get_height()/2,
                   label, va='center', color='white', fontsize=8)

        ax.invert_yaxis()

        fig.tight_layout()
        return fig
