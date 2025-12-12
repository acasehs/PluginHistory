"""
Visual Export Module
Functions for exporting charts and dashboards to files.
"""

import os
from datetime import datetime
from typing import Optional, List
from matplotlib.figure import Figure


def export_chart_to_file(fig: Figure, filepath: str, dpi: int = 150,
                         transparent: bool = False) -> bool:
    """
    Export a matplotlib figure to a file.

    Args:
        fig: matplotlib Figure object
        filepath: Output file path (extension determines format)
        dpi: Resolution in dots per inch
        transparent: Whether to use transparent background

    Returns:
        True if successful
    """
    try:
        fig.savefig(filepath, dpi=dpi, bbox_inches='tight',
                   facecolor=fig.get_facecolor() if not transparent else 'none',
                   edgecolor='none', transparent=transparent)
        print(f"Chart exported to: {filepath}")
        return True
    except Exception as e:
        print(f"Error exporting chart: {e}")
        return False


def export_dashboard_to_pdf(figures: List[Figure], filepath: str,
                           title: str = "Vulnerability Analysis Report") -> bool:
    """
    Export multiple figures to a single PDF file.

    Args:
        figures: List of matplotlib Figure objects
        filepath: Output PDF file path
        title: Report title

    Returns:
        True if successful
    """
    try:
        from matplotlib.backends.backend_pdf import PdfPages

        with PdfPages(filepath) as pdf:
            # Add title page
            import matplotlib.pyplot as plt
            title_fig = plt.figure(figsize=(11, 8.5))
            title_fig.set_facecolor('#2b2b2b')
            ax = title_fig.add_subplot(111)
            ax.axis('off')
            ax.set_facecolor('#2b2b2b')
            ax.text(0.5, 0.6, title, fontsize=24, fontweight='bold',
                   color='white', ha='center', va='center')
            ax.text(0.5, 0.4, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                   fontsize=12, color='white', ha='center', va='center')
            pdf.savefig(title_fig, facecolor=title_fig.get_facecolor())
            plt.close(title_fig)

            # Add each figure
            for fig in figures:
                pdf.savefig(fig, facecolor=fig.get_facecolor(), bbox_inches='tight')

        print(f"PDF exported to: {filepath}")
        return True

    except Exception as e:
        print(f"Error exporting PDF: {e}")
        return False


def export_all_charts(historical_df, lifecycle_df, output_dir: str,
                     prefix: str = "nessus") -> List[str]:
    """
    Export all standard charts to a directory.

    Args:
        historical_df: DataFrame with historical findings
        lifecycle_df: DataFrame from analyze_finding_lifecycle
        output_dir: Output directory
        prefix: Filename prefix

    Returns:
        List of exported file paths
    """
    from .dashboards import (
        create_executive_dashboard,
        create_lifecycle_dashboard,
        create_host_analysis_dashboard,
        create_plugin_analysis_dashboard
    )

    os.makedirs(output_dir, exist_ok=True)
    exported_files = []
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    # Export each dashboard
    dashboards = [
        ('executive', create_executive_dashboard, [historical_df, lifecycle_df]),
        ('lifecycle', create_lifecycle_dashboard, [lifecycle_df]),
        ('host_analysis', create_host_analysis_dashboard, [historical_df]),
        ('plugin_analysis', create_plugin_analysis_dashboard, [historical_df])
    ]

    for name, create_func, args in dashboards:
        try:
            fig = create_func(*args)
            filepath = os.path.join(output_dir, f"{prefix}_{name}_{timestamp}.png")
            if export_chart_to_file(fig, filepath):
                exported_files.append(filepath)
            import matplotlib.pyplot as plt
            plt.close(fig)
        except Exception as e:
            print(f"Error creating {name} dashboard: {e}")

    return exported_files


def create_report_package(historical_df, lifecycle_df, host_presence_df,
                         output_dir: str, report_name: str = "vulnerability_report") -> str:
    """
    Create a complete report package with charts and summary.

    Args:
        historical_df: DataFrame with historical findings
        lifecycle_df: DataFrame from analyze_finding_lifecycle
        host_presence_df: DataFrame from create_host_presence_analysis
        output_dir: Output directory
        report_name: Name for the report

    Returns:
        Path to the report directory
    """
    from .dashboards import (
        create_executive_dashboard,
        create_lifecycle_dashboard,
        create_host_analysis_dashboard,
        create_plugin_analysis_dashboard
    )

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_dir = os.path.join(output_dir, f"{report_name}_{timestamp}")
    os.makedirs(report_dir, exist_ok=True)

    # Create subdirectories
    charts_dir = os.path.join(report_dir, "charts")
    os.makedirs(charts_dir, exist_ok=True)

    # Export individual charts
    figures = []
    chart_names = []

    try:
        exec_fig = create_executive_dashboard(historical_df, lifecycle_df)
        figures.append(exec_fig)
        chart_names.append("executive_summary")
        export_chart_to_file(exec_fig, os.path.join(charts_dir, "01_executive_summary.png"))
    except Exception as e:
        print(f"Error creating executive dashboard: {e}")

    try:
        life_fig = create_lifecycle_dashboard(lifecycle_df)
        figures.append(life_fig)
        chart_names.append("lifecycle_analysis")
        export_chart_to_file(life_fig, os.path.join(charts_dir, "02_lifecycle_analysis.png"))
    except Exception as e:
        print(f"Error creating lifecycle dashboard: {e}")

    try:
        host_fig = create_host_analysis_dashboard(historical_df)
        figures.append(host_fig)
        chart_names.append("host_analysis")
        export_chart_to_file(host_fig, os.path.join(charts_dir, "03_host_analysis.png"))
    except Exception as e:
        print(f"Error creating host analysis dashboard: {e}")

    try:
        plugin_fig = create_plugin_analysis_dashboard(historical_df)
        figures.append(plugin_fig)
        chart_names.append("plugin_analysis")
        export_chart_to_file(plugin_fig, os.path.join(charts_dir, "04_plugin_analysis.png"))
    except Exception as e:
        print(f"Error creating plugin analysis dashboard: {e}")

    # Create PDF with all figures
    if figures:
        pdf_path = os.path.join(report_dir, f"{report_name}.pdf")
        export_dashboard_to_pdf(figures, pdf_path, title="Vulnerability Analysis Report")

    # Clean up figures
    import matplotlib.pyplot as plt
    for fig in figures:
        plt.close(fig)

    # Create summary text file
    summary_path = os.path.join(report_dir, "summary.txt")
    with open(summary_path, 'w') as f:
        f.write(f"Vulnerability Analysis Report\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"{'='*50}\n\n")

        if not historical_df.empty:
            f.write(f"Total Findings: {len(historical_df)}\n")
            f.write(f"Unique Hosts: {historical_df['hostname'].nunique()}\n")
            f.write(f"Unique Plugins: {historical_df['plugin_id'].nunique()}\n\n")

        if not lifecycle_df.empty:
            active = len(lifecycle_df[lifecycle_df['status'] == 'Active'])
            resolved = len(lifecycle_df[lifecycle_df['status'] == 'Resolved'])
            f.write(f"Active Findings: {active}\n")
            f.write(f"Resolved Findings: {resolved}\n")
            f.write(f"Resolution Rate: {(resolved/(active+resolved)*100):.1f}%\n")

    print(f"Report package created: {report_dir}")
    return report_dir
