"""
Generate screenshots for the user guide documentation.
Creates sample data and generates all visualization screenshots.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for headless generation
import matplotlib.pyplot as plt

# Create sample version extraction data
def create_sample_version_data():
    """Create sample version extraction data similar to Tenable output."""
    packages = [
        ('openssl', ['1.0.2k', '1.0.2g', '1.0.2e'], '1.1.1w'),
        ('java-openjdk', ['1.8.0_292', '1.8.0_275', '11.0.9'], '17.0.9'),
        ('apache-httpd', ['2.4.37', '2.4.29', '2.4.25'], '2.4.58'),
        ('nginx', ['1.14.1', '1.12.2'], '1.25.3'),
        ('openssh', ['7.4p1', '7.6p1', '8.0p1'], '9.5p1'),
        ('kernel', ['3.10.0-1160', '4.18.0-348', '5.4.0'], '6.6.8'),
        ('python', ['2.7.18', '3.6.8', '3.8.10'], '3.12.1'),
        ('postgresql', ['9.6.24', '10.23', '12.17'], '16.1'),
        ('mysql-community', ['5.7.42', '8.0.32'], '8.0.35'),
        ('nodejs', ['12.22.12', '14.21.3', '16.20.2'], '20.10.0'),
        ('curl', ['7.29.0', '7.61.1', '7.79.1'], '8.5.0'),
        ('libxml2', ['2.9.1', '2.9.7', '2.9.10'], '2.12.3'),
        ('openldap', ['2.4.44', '2.4.46'], '2.6.6'),
        ('bind', ['9.11.4', '9.11.26', '9.16.23'], '9.18.21'),
        ('zlib', ['1.2.7', '1.2.11'], '1.3.1'),
    ]

    hosts = [f'server{i:03d}.example.com' for i in range(1, 51)]
    severities = ['Critical', 'High', 'Medium', 'Low']
    severity_weights = [0.1, 0.25, 0.4, 0.25]  # Distribution

    cves = [
        'CVE-2023-44487', 'CVE-2023-38545', 'CVE-2023-4911', 'CVE-2023-38408',
        'CVE-2023-32233', 'CVE-2023-2650', 'CVE-2023-0286', 'CVE-2022-40674',
        'CVE-2022-3602', 'CVE-2022-3786', 'CVE-2022-22965', 'CVE-2021-44228',
        'CVE-2021-45046', 'CVE-2021-3449', 'CVE-2021-3156', 'CVE-2020-1938',
    ]

    data = []
    np.random.seed(42)

    for pkg_name, installed_versions, target_version in packages:
        # Assign random hosts to this package (5-30 hosts affected)
        num_hosts = np.random.randint(5, min(31, len(hosts)))
        affected_hosts = np.random.choice(hosts, num_hosts, replace=False)

        # Assign CVEs (1-4 per package)
        num_cves = np.random.randint(1, 5)
        pkg_cves = np.random.choice(cves, num_cves, replace=False).tolist()

        for host in affected_hosts:
            installed = np.random.choice(installed_versions)
            severity = np.random.choice(severities, p=severity_weights)

            data.append({
                'Plugin_ID': str(np.random.randint(10000, 99999)),
                'Hostname': host,
                'IP_Address': f'10.{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}',
                'Component_Name': pkg_name,
                'Installed_Version': f'{pkg_name}-{installed}',
                'Should_Be_Version': target_version,
                'Fixed_Version': target_version,
                'Version_Type': 'fixed',
                'CVEs': ', '.join(pkg_cves),
                'Severity': severity
            })

    return pd.DataFrame(data)


def create_sample_findings_data():
    """Create sample findings data for enrichment."""
    np.random.seed(42)

    data = []
    hosts = [f'server{i:03d}.example.com' for i in range(1, 51)]

    for i in range(500):
        data.append({
            'plugin_id': str(np.random.randint(10000, 99999)),
            'hostname': np.random.choice(hosts),
            'severity_text': np.random.choice(['Critical', 'High', 'Medium', 'Low'], p=[0.1, 0.25, 0.4, 0.25]),
            'cvss3_base_score': np.random.uniform(3.0, 10.0),
            'scan_date': datetime.now() - timedelta(days=np.random.randint(1, 90)),
            'status': np.random.choice(['Active', 'Resolved'], p=[0.6, 0.4])
        })

    return pd.DataFrame(data)


def generate_all_screenshots(output_dir='screenshots'):
    """Generate all screenshots for the user guide."""
    os.makedirs(output_dir, exist_ok=True)

    print("Creating sample data...")
    version_df = create_sample_version_data()
    findings_df = create_sample_findings_data()

    print("Analyzing package version impact...")
    from refactored_app.analysis.package_version_impact import (
        analyze_package_version_impact,
        create_remediation_summary_df,
        calculate_cumulative_impact,
        estimate_remediation_effort
    )

    plan = analyze_package_version_impact(version_df, findings_df)

    print(f"Found {len(plan.packages)} packages affecting {plan.total_hosts_affected} hosts")

    # Generate screenshots
    from refactored_app.visualization.package_impact_charts import (
        create_package_impact_bar_chart,
        create_cumulative_impact_chart,
        create_severity_breakdown_chart,
        create_host_distribution_chart,
        create_version_consolidation_chart,
        create_quick_wins_chart,
        create_impact_bubble_chart
    )
    from refactored_app.visualization.remediation_dashboard import (
        create_remediation_impact_dashboard,
        create_executive_remediation_summary,
        create_host_impact_dashboard
    )

    charts = [
        ('01_remediation_dashboard', create_remediation_impact_dashboard, (plan,), (18, 14)),
        ('02_executive_summary', create_executive_remediation_summary, (plan,), (16, 10)),
        ('03_package_impact_ranking', create_package_impact_bar_chart, (plan,), (12, 8)),
        ('04_cumulative_impact', create_cumulative_impact_chart, (plan,), (12, 6)),
        ('05_severity_breakdown', create_severity_breakdown_chart, (plan,), (12, 8)),
        ('06_host_distribution', create_host_distribution_chart, (plan,), (12, 6)),
        ('07_version_consolidation', create_version_consolidation_chart, (plan,), (12, 6)),
        ('08_quick_wins', create_quick_wins_chart, (plan,), (12, 6)),
        ('09_impact_bubble', create_impact_bubble_chart, (plan,), (14, 10)),
        ('10_host_impact_dashboard', create_host_impact_dashboard, (plan,), (16, 10)),
    ]

    for name, func, args, figsize in charts:
        print(f"Generating {name}...")
        try:
            fig = func(*args)
            fig.savefig(
                os.path.join(output_dir, f'{name}.png'),
                dpi=150,
                bbox_inches='tight',
                facecolor='#2b2b2b',
                edgecolor='none'
            )
            plt.close(fig)
            print(f"  Saved {name}.png")
        except Exception as e:
            print(f"  Error generating {name}: {e}")

    # Generate summary table screenshot
    print("Generating summary table...")
    summary_df = create_remediation_summary_df(plan)

    fig, ax = plt.subplots(figsize=(16, 8))
    ax.set_facecolor('#2b2b2b')
    fig.patch.set_facecolor('#2b2b2b')
    ax.axis('off')

    # Show top 10 rows
    table_data = summary_df.head(10)[['Package', 'Target_Version', 'Affected_Hosts', 'Findings_Resolved', 'Impact_Score', 'Critical', 'High', 'CVE_Count']].values.tolist()
    headers = ['Package', 'Target Version', 'Hosts', 'Findings', 'Impact Score', 'Critical', 'High', 'CVEs']

    table = ax.table(
        cellText=table_data,
        colLabels=headers,
        loc='center',
        cellLoc='center'
    )
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1.2, 1.8)

    # Style the table
    for i in range(len(headers)):
        table[(0, i)].set_facecolor('#404040')
        table[(0, i)].set_text_props(color='white', fontweight='bold')

    for i in range(1, len(table_data) + 1):
        for j in range(len(headers)):
            table[(i, j)].set_facecolor('#2b2b2b' if i % 2 == 0 else '#363636')
            table[(i, j)].set_text_props(color='white')

    ax.set_title('Prioritized Remediation List (Top 10)', fontsize=14, fontweight='bold', color='white', pad=20)

    fig.savefig(
        os.path.join(output_dir, '11_remediation_list.png'),
        dpi=150,
        bbox_inches='tight',
        facecolor='#2b2b2b',
        edgecolor='none'
    )
    plt.close(fig)
    print("  Saved 11_remediation_list.png")

    # Generate effort estimate
    print("Generating effort estimate...")
    effort = estimate_remediation_effort(plan)

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.set_facecolor('#2b2b2b')
    fig.patch.set_facecolor('#2b2b2b')
    ax.axis('off')

    effort_text = f"""
    REMEDIATION EFFORT ESTIMATE
    {'='*50}

    Total Packages to Update:  {effort['total_packages']}
    Total Hosts Affected:      {effort['total_hosts']}
    Total Findings Resolved:   {effort['total_findings']}
    Total CVEs Addressed:      {effort['total_cves']}

    Effort Level:              {effort['effort_level']}

    BY SEVERITY:
    - Critical Packages:       {effort['critical_packages']}
    - High Packages:           {effort['high_packages']}
    - Medium Packages:         {effort['medium_packages']}
    - Low Packages:            {effort['low_packages']}
    """

    ax.text(0.1, 0.9, effort_text, transform=ax.transAxes,
           fontsize=12, color='white', verticalalignment='top',
           fontfamily='monospace')

    fig.savefig(
        os.path.join(output_dir, '12_effort_estimate.png'),
        dpi=150,
        bbox_inches='tight',
        facecolor='#2b2b2b',
        edgecolor='none'
    )
    plt.close(fig)
    print("  Saved 12_effort_estimate.png")

    print(f"\nAll screenshots saved to {output_dir}/")
    return True


if __name__ == '__main__':
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'screenshots')
    generate_all_screenshots(output_dir)
