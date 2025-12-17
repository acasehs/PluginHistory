# Excel Visualization Export Specification

This document defines the data requirements and Excel chart mappings for exporting all application visualizations as native Excel charts.

---

## Overview

| Category | Python Chart Types | Excel Equivalents |
|----------|-------------------|-------------------|
| Bar Charts | `ax.bar()` | `BarChart` / `BarChart3D` |
| Horizontal Bar | `ax.barh()` | `BarChart` (horizontal) |
| Line Charts | `ax.plot()` | `LineChart` / `LineChart3D` |
| Pie Charts | `ax.pie()` | `PieChart` / `PieChart3D` |
| Area Charts | `ax.fill_between()` | `AreaChart` |
| Scatter/Bubble | `ax.scatter()` | `ScatterChart` / `BubbleChart` |
| Stacked Bar | `ax.bar(bottom=...)` | `BarChart` (stacked) |
| Histogram | `ax.hist()` / binned `ax.bar()` | `BarChart` with binned data |
| Dual-Axis | Two y-axes | `LineChart` + secondary axis |
| Heatmap | `ax.imshow()` | Conditional formatting on cells |

---

## 1. PDF REPORT VISUALIZATIONS

### 1.1 Executive Summary PDF (`_export_executive_summary_pdf`)

#### Chart 1: Severity Distribution Pie
```python
# DATA REQUIRED
data = {
    'severity': ['Critical', 'High', 'Medium', 'Low'],
    'count': [df[df['severity_text'] == sev].shape[0] for sev in severities]
}

# EXCEL IMPLEMENTATION
from openpyxl.chart import PieChart, Reference
chart = PieChart()
chart.title = "Active Findings by Severity"
data_ref = Reference(ws, min_col=2, min_row=1, max_row=5)
labels = Reference(ws, min_col=1, min_row=2, max_row=5)
chart.add_data(data_ref, titles_from_data=True)
chart.set_categories(labels)
# Colors: Critical=#dc3545, High=#fd7e14, Medium=#ffc107, Low=#28a745
```

#### Chart 2: Top 10 Hosts Bar Chart
```python
# DATA REQUIRED
data = {
    'hostname': top_hosts.index[:10],
    'finding_count': top_hosts.values[:10]
}

# EXCEL IMPLEMENTATION
from openpyxl.chart import BarChart, Reference
chart = BarChart()
chart.type = "bar"  # Horizontal
chart.title = "Top 10 Hosts by Findings"
data_ref = Reference(ws, min_col=2, min_row=1, max_row=11)
cats = Reference(ws, min_col=1, min_row=2, max_row=11)
chart.add_data(data_ref, titles_from_data=True)
chart.set_categories(cats)
chart.shape = 4  # Flat bars
```

#### Chart 3: Environment Distribution Pie
```python
# DATA REQUIRED
data = {
    'environment': df['environment_type'].value_counts().index,
    'count': df['environment_type'].value_counts().values
}

# EXCEL IMPLEMENTATION
# Same as severity pie, different data source
```

#### Chart 4: Top 8 Vulnerabilities Bar Chart
```python
# DATA REQUIRED
data = {
    'plugin_name': top_vulns.index[:8],
    'host_count': top_vulns.values[:8]
}

# EXCEL IMPLEMENTATION
chart = BarChart()
chart.type = "bar"  # Horizontal
chart.title = "Top 8 Vulnerabilities"
```

#### Chart 5: Monthly Discovery Trend Line
```python
# DATA REQUIRED
data = {
    'month': monthly.index.astype(str),  # Period labels
    'new_findings': monthly.values
}

# EXCEL IMPLEMENTATION
from openpyxl.chart import LineChart, Reference
chart = LineChart()
chart.title = "Monthly Vulnerability Discovery"
chart.y_axis.title = "New Findings"
chart.x_axis.title = "Month"
data_ref = Reference(ws, min_col=2, min_row=1, max_row=len(data)+1)
cats = Reference(ws, min_col=1, min_row=2, max_row=len(data)+1)
chart.add_data(data_ref, titles_from_data=True)
chart.set_categories(cats)
series = chart.series[0]
series.marker.symbol = "circle"
series.graphicalProperties.line.width = 25000  # 2pt
```

#### Chart 6: Severity Trend Over Time (Multi-Line)
```python
# DATA REQUIRED
data = {
    'month': monthly_dates,
    'Critical': sev_monthly['Critical'].values,
    'High': sev_monthly['High'].values,
    'Medium': sev_monthly['Medium'].values,
    'Low': sev_monthly['Low'].values
}

# EXCEL IMPLEMENTATION
chart = LineChart()
chart.title = "All Severities Over Time"
# Add 4 data series, one per severity
for col in range(2, 6):
    data_ref = Reference(ws, min_col=col, min_row=1, max_row=len(data)+1)
    chart.add_data(data_ref, titles_from_data=True)
# Set colors per series
colors = ['dc3545', 'fd7e14', 'ffc107', '28a745']
for i, series in enumerate(chart.series):
    series.graphicalProperties.line.solidFill = colors[i]
```

---

### 1.2 Resolution Report PDF (`_export_resolution_pdf`)

#### Chart 1: Period Activity Overview (Stacked Bar)
```python
# DATA REQUIRED
data = {
    'week': week_labels,
    'new': [w['new'] for w in weekly_data],
    'closed': [w['closed'] for w in weekly_data],
    'active': [w['total_active'] for w in weekly_data]
}

# EXCEL IMPLEMENTATION
chart = BarChart()
chart.type = "col"
chart.grouping = "stacked"
chart.title = "Period Activity Overview"
# Add each series (new, closed, active)
```

#### Chart 2: New vs Closed Bar Chart
```python
# DATA REQUIRED
data = {
    'week': weeks,
    'new': new_counts,
    'closed': closed_counts
}

# EXCEL IMPLEMENTATION
chart = BarChart()
chart.type = "col"
chart.grouping = "clustered"
chart.title = "New vs Closed Findings by Week"
```

#### Chart 3: Active Findings Trend Line
```python
# DATA REQUIRED
data = {
    'week': weeks,
    'total_active': active_counts
}

# EXCEL IMPLEMENTATION
chart = LineChart()
chart.title = "Total Active Findings Trend"
# Add fill_between equivalent using AreaChart
from openpyxl.chart import AreaChart
area = AreaChart()
area.grouping = "standard"
```

#### Chart 4: Severity Trends (Grouped Bar)
```python
# DATA REQUIRED
data = {
    'week': weeks,
    'crit_new': crit_new,
    'high_new': high_new,
    'med_new': med_new,
    'low_new': low_new
}

# EXCEL IMPLEMENTATION
chart = BarChart()
chart.type = "col"
chart.grouping = "clustered"
chart.title = "New Findings by Severity"
```

#### Chart 5: Environment Breakdown (Per-Environment Bar)
```python
# DATA REQUIRED - One dataset per environment
for env in environments:
    data[env] = {
        'week': weeks,
        'new': env_new_counts,
        'closed': env_closed_counts
    }

# EXCEL IMPLEMENTATION - Create chart per environment or combined
```

---

### 1.3 Host Risk Assessment PDF (`_export_host_risk_pdf`)

#### Chart 1: Severity Breakdown Bar
```python
# DATA REQUIRED (per host)
data = {
    'severity': sev_counts.index,
    'count': sev_counts.values
}

# EXCEL IMPLEMENTATION
chart = BarChart()
chart.type = "col"
chart.title = "Active Findings by Severity"
```

#### Chart 2: Risk Score Gauge (Text/Number Display)
```python
# DATA REQUIRED
data = {
    'risk_score': calculated_risk_score,
    'risk_level': risk_level_text
}

# EXCEL IMPLEMENTATION
# No native gauge chart - use conditional formatting on cell
# Or create a semi-circle pie chart hack
```

#### Chart 3: Discovery Timeline Bar
```python
# DATA REQUIRED
data = {
    'month': monthly.index.astype(str),
    'new_findings': monthly.values
}

# EXCEL IMPLEMENTATION
chart = BarChart()
chart.title = "Discovery Timeline"
```

#### Chart 4: Top Vulnerabilities Horizontal Bar
```python
# DATA REQUIRED
data = {
    'plugin_name': top_vulns.index[:8],
    'count': top_vulns.values[:8]
}

# EXCEL IMPLEMENTATION
chart = BarChart()
chart.type = "bar"  # Horizontal
chart.title = "Top Vulnerabilities"
```

---

### 1.4 Vulnerability Aging PDF (`_export_aging_report_pdf`)

#### Chart 1: Aging Distribution Bar
```python
# DATA REQUIRED
data = {
    'bucket': ['0-30 days', '31-60 days', '61-90 days', '91-180 days', '180+ days'],
    'count': bucket_counts.values
}

# EXCEL IMPLEMENTATION
chart = BarChart()
chart.title = "Findings by Age"
# Apply gradient colors: green -> red
```

#### Chart 2: SLA Compliance Bar
```python
# DATA REQUIRED
data = {
    'severity': ['Critical', 'High', 'Medium', 'Low'],
    'compliance_rate': [rate for rate in compliance_rates]
}

# EXCEL IMPLEMENTATION
chart = BarChart()
chart.title = "SLA Compliance by Severity"
# Add 80% target line using secondary data series or shape
```

#### Chart 3: Oldest Findings Horizontal Bar
```python
# DATA REQUIRED
data = {
    'plugin_name': oldest['plugin_name'].values[:10],
    'age_days': oldest['age_days'].values[:10]
}

# EXCEL IMPLEMENTATION
chart = BarChart()
chart.type = "bar"
chart.title = "Oldest Active Findings"
```

---

### 1.5 Remediation Priority PDF (`_export_remediation_priority_pdf`)

#### Chart 1: Top 15 by Impact Horizontal Bar
```python
# DATA REQUIRED
data = {
    'plugin_name': top_impact['plugin_name'].values[:15],
    'impact_score': top_impact['impact_score'].values[:15],
    'severity': top_impact['severity'].values[:15]  # For color coding
}

# EXCEL IMPLEMENTATION
chart = BarChart()
chart.type = "bar"
chart.title = "Top 15 by Impact"
# Apply conditional colors based on severity column
```

#### Chart 2: Quick Wins Horizontal Bar
```python
# DATA REQUIRED
data = {
    'plugin_name': quick_wins['plugin_name'].values[:10],
    'affected_hosts': quick_wins['affected_hosts'].values[:10]
}

# EXCEL IMPLEMENTATION
chart = BarChart()
chart.type = "bar"
chart.title = "Quick Wins (3+ Hosts, Single Fix)"
```

#### Chart 3: Critical/High Priority Items
```python
# DATA REQUIRED
data = {
    'plugin_name': ch_counts['plugin_name'].values[:12],
    'count': ch_counts['count'].values[:12],
    'severity_text': ch_counts['severity_text'].values[:12]
}

# EXCEL IMPLEMENTATION
chart = BarChart()
chart.type = "bar"
chart.title = "Critical/High Priority Items"
```

---

### 1.6 Monthly Metrics PDF (`_export_monthly_metrics_pdf`)

#### Chart 1: New Findings by Month Bar
```python
# DATA REQUIRED
data = {
    'month': monthly_new.index.astype(str),
    'new_findings': monthly_new.values
}

# EXCEL IMPLEMENTATION
chart = BarChart()
chart.title = "New Findings by Month"
```

#### Chart 2: Resolved by Month Bar
```python
# DATA REQUIRED
data = {
    'month': monthly_resolved.index.astype(str),
    'resolved': monthly_resolved.values
}

# EXCEL IMPLEMENTATION
chart = BarChart()
chart.title = "Resolved by Month"
```

#### Chart 3: Net Change Bar (Positive/Negative)
```python
# DATA REQUIRED
data = {
    'month': months_labels,
    'net_change': net_change  # Can be positive or negative
}

# EXCEL IMPLEMENTATION
chart = BarChart()
chart.title = "Net Change (New - Resolved)"
# Apply conditional colors: red for positive, green for negative
```

#### Chart 4: Severity Trends Multi-Line
```python
# DATA REQUIRED
data = {
    'month': severity_monthly.index.astype(str),
    'Critical': severity_monthly['Critical'].values,
    'High': severity_monthly['High'].values,
    'Medium': severity_monthly['Medium'].values,
    'Low': severity_monthly['Low'].values
}

# EXCEL IMPLEMENTATION
chart = LineChart()
chart.title = "New Findings by Severity"
```

#### Chart 5: Critical/High Ratio Line
```python
# DATA REQUIRED
data = {
    'month': ratio.index.astype(str),
    'percentage': ratio.values
}

# EXCEL IMPLEMENTATION
chart = AreaChart()  # or LineChart with fill
chart.title = "Critical/High as % of Total"
```

---

### 1.7 Compliance Status PDF (`_export_compliance_status_pdf`)

#### Chart 1: STIG Compliance Pie
```python
# DATA REQUIRED
data = {
    'category': ['Compliant', 'Non-Compliant', 'Not Reviewed'],
    'count': [compliant, non_compliant, not_reviewed]
}

# EXCEL IMPLEMENTATION
chart = PieChart()
chart.title = "STIG Compliance"
```

#### Chart 2: Open STIG Findings by Category Bar
```python
# DATA REQUIRED
data = {
    'severity': cat_counts.index,  # high, medium, low
    'count': cat_counts.values
}

# EXCEL IMPLEMENTATION
chart = BarChart()
chart.title = "Open STIG Findings by Category"
```

#### Chart 3: POAM Status Bar
```python
# DATA REQUIRED
data = {
    'status': poam_status.index,
    'count': poam_status.values
}

# EXCEL IMPLEMENTATION
chart = BarChart()
chart.title = "POAM Status"
```

---

## 2. GUI TAB VISUALIZATIONS

### 2.1 Weekly Resolution Report Tab

#### Main Data Structure
```python
weekly_resolution_data = {
    'start_date': datetime,
    'end_date': datetime,
    'weekly_data': [
        {
            'week_label': 'Week 1 (2024-01-01)',
            'total_active': 150,
            'new': 25,
            'new_crit': 5,
            'new_high': 10,
            'new_med': 8,
            'new_low': 2,
            'closed': 20,
            'unchanged': 130,
            'previous_total': 145
        },
        # ... more weeks
    ],
    'weekly_by_env': {
        'Production': [...],
        'PSS': [...],
        'Shared': [...]
    },
    'fully_closed': [...],
    'repops': [...],
    'new_findings': [...],
    'closed_findings': [...],
    'environments': ['Production', 'PSS', 'Shared']
}
```

---

### 2.2 Trends Tab Charts

#### Chart: New vs Resolved Line/Bar
```python
# DATA REQUIRED
data = {
    'date': scan_dates,
    'new': new_counts,
    'resolved': resolved_counts
}

# EXCEL COLUMNS
# A: Date, B: New, C: Resolved
```

---

### 2.3 Timeline Analysis Tab (4 Charts)

#### Chart 1: Total Findings Line + Area
```python
data = {
    'period': period_labels,
    'total': total_counts
}
```

#### Chart 2: Severity Timeline (Multi-Line)
```python
data = {
    'period': period_labels,
    'Critical': crit_counts,
    'High': high_counts,
    'Medium': med_counts,
    'Low': low_counts
}
```

#### Chart 3: New vs Resolved Bar
```python
data = {
    'period': period_labels,
    'new': new_counts,
    'resolved': resolved_counts
}
```

#### Chart 4: Cumulative Risk Line + Area
```python
data = {
    'day': days,
    'cumulative_risk': cumulative_values
}
```

---

### 2.4 Rolling Analysis Tab (4 Charts)

#### Chart 1: Rolling Severity Totals (Stacked Bar)
```python
data = {
    'week': week_labels,
    'Critical': crit_rolling,
    'High': high_rolling,
    'Medium': med_rolling,
    'Low': low_rolling
}
```

#### Chart 2: Rolling Unique Plugins Bar
```python
data = {
    'week': week_labels,
    'unique_plugins': plugin_counts
}
```

#### Chart 3: Rolling Environment Findings (Grouped Bar)
```python
data = {
    'week': week_labels,
    'Production': prod_counts,
    'PSS': pss_counts,
    'Shared': shared_counts
}
```

---

### 2.5 Risk Analysis Tab (4 Charts)

#### Chart 1: CVSS Distribution Bar
```python
data = {
    'range': ['None (0)', 'Low (0.1-3.9)', 'Medium (4-6.9)', 'High (7-8.9)', 'Critical (9-10)'],
    'count': cvss_bin_counts
}
```

#### Chart 2: MTTR by Severity Bar
```python
data = {
    'severity': ['Critical', 'High', 'Medium', 'Low'],
    'mean_days': mttr_values
}
```

#### Chart 3: Age of Active Histogram
```python
data = {
    'bin': age_bin_edges,
    'count': age_bin_counts
}
```

#### Chart 4: Risk Score Ranking Horizontal Bar
```python
data = {
    'hostname': top_hosts[:10],
    'risk_score': risk_scores[:10]
}
```

---

## 3. EXCEL EXPORT IMPLEMENTATION

### 3.1 Core Export Function Structure

```python
from openpyxl import Workbook
from openpyxl.chart import (
    BarChart, LineChart, PieChart, AreaChart,
    ScatterChart, BubbleChart, Reference
)
from openpyxl.chart.series import DataPoint
from openpyxl.drawing.fill import PatternFillProperties, ColorChoice
from openpyxl.utils.dataframe import dataframe_to_rows

def export_visualization_to_excel(
    data: pd.DataFrame,
    chart_type: str,
    chart_config: dict,
    output_path: str
) -> bool:
    """
    Export a visualization to Excel with native chart.

    Args:
        data: DataFrame with chart data
        chart_type: 'bar', 'line', 'pie', 'area', 'scatter', 'bubble'
        chart_config: {
            'title': str,
            'x_axis_title': str,
            'y_axis_title': str,
            'colors': list[str],  # Hex colors
            'stacked': bool,
            'horizontal': bool,
            'show_labels': bool,
            'width': int,  # Chart width in cells
            'height': int  # Chart height in cells
        }
        output_path: Path for Excel file

    Returns:
        True if successful
    """
    wb = Workbook()
    ws = wb.active
    ws.title = "Chart Data"

    # Write data to worksheet
    for r_idx, row in enumerate(dataframe_to_rows(data, index=False, header=True), 1):
        for c_idx, value in enumerate(row, 1):
            ws.cell(row=r_idx, column=c_idx, value=value)

    # Create chart based on type
    if chart_type == 'bar':
        chart = create_bar_chart(ws, data, chart_config)
    elif chart_type == 'line':
        chart = create_line_chart(ws, data, chart_config)
    elif chart_type == 'pie':
        chart = create_pie_chart(ws, data, chart_config)
    # ... etc

    # Position chart
    ws.add_chart(chart, f"A{len(data) + 5}")

    wb.save(output_path)
    return True
```

### 3.2 Bar Chart Creator

```python
def create_bar_chart(ws, data: pd.DataFrame, config: dict) -> BarChart:
    """Create a bar chart from worksheet data."""
    chart = BarChart()
    chart.type = "bar" if config.get('horizontal', False) else "col"
    chart.grouping = "stacked" if config.get('stacked', False) else "clustered"
    chart.title = config.get('title', '')

    if config.get('y_axis_title'):
        chart.y_axis.title = config['y_axis_title']
    if config.get('x_axis_title'):
        chart.x_axis.title = config['x_axis_title']

    # Data references
    num_rows = len(data) + 1
    num_cols = len(data.columns)

    # First column is categories
    cats = Reference(ws, min_col=1, min_row=2, max_row=num_rows)

    # Remaining columns are data series
    for col in range(2, num_cols + 1):
        data_ref = Reference(ws, min_col=col, min_row=1, max_row=num_rows)
        chart.add_data(data_ref, titles_from_data=True)

    chart.set_categories(cats)

    # Apply colors
    if 'colors' in config:
        for i, color in enumerate(config['colors']):
            if i < len(chart.series):
                chart.series[i].graphicalProperties.solidFill = color.replace('#', '')

    # Add data labels if requested
    if config.get('show_labels', True):
        chart.dataLabels = DataLabelList()
        chart.dataLabels.showVal = True

    chart.width = config.get('width', 15)
    chart.height = config.get('height', 10)

    return chart
```

### 3.3 Line Chart Creator

```python
def create_line_chart(ws, data: pd.DataFrame, config: dict) -> LineChart:
    """Create a line chart from worksheet data."""
    chart = LineChart()
    chart.title = config.get('title', '')
    chart.style = 10  # Dark style

    if config.get('y_axis_title'):
        chart.y_axis.title = config['y_axis_title']
    if config.get('x_axis_title'):
        chart.x_axis.title = config['x_axis_title']

    num_rows = len(data) + 1
    num_cols = len(data.columns)

    cats = Reference(ws, min_col=1, min_row=2, max_row=num_rows)

    for col in range(2, num_cols + 1):
        data_ref = Reference(ws, min_col=col, min_row=1, max_row=num_rows)
        chart.add_data(data_ref, titles_from_data=True)

    chart.set_categories(cats)

    # Apply colors and markers
    colors = config.get('colors', ['dc3545', 'fd7e14', 'ffc107', '28a745'])
    for i, series in enumerate(chart.series):
        if i < len(colors):
            series.graphicalProperties.line.solidFill = colors[i]
        series.marker.symbol = "circle"
        series.marker.size = 7

    chart.width = config.get('width', 15)
    chart.height = config.get('height', 10)

    return chart
```

### 3.4 Pie Chart Creator

```python
def create_pie_chart(ws, data: pd.DataFrame, config: dict) -> PieChart:
    """Create a pie chart from worksheet data."""
    chart = PieChart()
    chart.title = config.get('title', '')

    num_rows = len(data) + 1

    data_ref = Reference(ws, min_col=2, min_row=1, max_row=num_rows)
    cats = Reference(ws, min_col=1, min_row=2, max_row=num_rows)

    chart.add_data(data_ref, titles_from_data=True)
    chart.set_categories(cats)

    # Apply colors to slices
    if 'colors' in config:
        for i, color in enumerate(config['colors']):
            pt = DataPoint(idx=i)
            pt.graphicalProperties.solidFill = color.replace('#', '')
            chart.series[0].data_points.append(pt)

    # Show percentages
    chart.dataLabels = DataLabelList()
    chart.dataLabels.showPercent = True
    chart.dataLabels.showVal = False
    chart.dataLabels.showCatName = True

    chart.width = config.get('width', 10)
    chart.height = config.get('height', 10)

    return chart
```

---

## 4. COMPLETE EXPORT CONFIGURATIONS

### 4.1 PDF Report Configurations

```python
EXECUTIVE_SUMMARY_CHARTS = [
    {
        'name': 'severity_pie',
        'type': 'pie',
        'data_source': 'df.severity_text.value_counts()',
        'config': {
            'title': 'Active Findings by Severity',
            'colors': ['#dc3545', '#fd7e14', '#ffc107', '#28a745'],
            'show_labels': True
        }
    },
    {
        'name': 'top_hosts_bar',
        'type': 'bar',
        'data_source': 'df.hostname.value_counts().head(10)',
        'config': {
            'title': 'Top 10 Hosts by Findings',
            'horizontal': True,
            'colors': ['#17a2b8'],
            'show_labels': True
        }
    },
    {
        'name': 'environment_pie',
        'type': 'pie',
        'data_source': 'df.environment_type.value_counts()',
        'config': {
            'title': 'Findings by Environment',
            'colors': ['#28a745', '#007bff', '#ffc107', '#6c757d']
        }
    },
    {
        'name': 'top_vulns_bar',
        'type': 'bar',
        'data_source': 'df.plugin_name.value_counts().head(8)',
        'config': {
            'title': 'Top 8 Vulnerabilities',
            'horizontal': True,
            'colors': ['#fd7e14']
        }
    },
    {
        'name': 'monthly_trend_line',
        'type': 'line',
        'data_source': 'df.groupby(df.first_seen.dt.to_period("M")).size()',
        'config': {
            'title': 'Monthly Vulnerability Discovery',
            'x_axis_title': 'Month',
            'y_axis_title': 'New Findings',
            'colors': ['#17a2b8']
        }
    },
    {
        'name': 'severity_trend_multi',
        'type': 'line',
        'data_source': 'df.groupby([df.first_seen.dt.to_period("M"), "severity_text"]).size().unstack()',
        'config': {
            'title': 'All Severities Over Time',
            'x_axis_title': 'Month',
            'y_axis_title': 'Finding Count',
            'colors': ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
        }
    }
]

RESOLUTION_REPORT_CHARTS = [
    {
        'name': 'new_vs_closed_bar',
        'type': 'bar',
        'data_source': 'weekly_data[["week_label", "new", "closed"]]',
        'config': {
            'title': 'New vs Closed Findings by Week',
            'colors': ['#FF8C00', '#4CAF50'],
            'stacked': False
        }
    },
    {
        'name': 'active_trend_line',
        'type': 'area',
        'data_source': 'weekly_data[["week_label", "total_active"]]',
        'config': {
            'title': 'Total Active Findings Trend',
            'colors': ['#2196F3']
        }
    },
    {
        'name': 'severity_breakdown_bar',
        'type': 'bar',
        'data_source': 'weekly_data[["week_label", "new_crit", "new_high", "new_med", "new_low"]]',
        'config': {
            'title': 'New Findings by Severity',
            'stacked': False,
            'colors': ['#FF4444', '#FF8C00', '#FFD700', '#4CAF50']
        }
    }
]
```

---

## 5. IMPLEMENTATION CHECKLIST

### Phase 1: Core Infrastructure
- [ ] Create `excel_chart_exporter.py` module
- [ ] Implement base chart creation functions (bar, line, pie, area)
- [ ] Implement data transformation helpers
- [ ] Create chart configuration schema

### Phase 2: PDF Report Charts
- [ ] Executive Summary (6 charts)
- [ ] Resolution Report (4+ charts)
- [ ] Host Risk Assessment (4 charts per host)
- [ ] Vulnerability Aging (3 charts)
- [ ] Remediation Priority (3 charts)
- [ ] Monthly Metrics (5 charts)
- [ ] Compliance Status (3 charts)

### Phase 3: GUI Tab Charts
- [ ] Trends Tab (2 charts)
- [ ] Timeline Analysis (4 charts)
- [ ] Rolling Analysis (4 charts)
- [ ] Risk Analysis (4 charts)
- [ ] OPDIR Compliance (4 charts)
- [ ] Efficiency (4 charts)
- [ ] Network Analysis (4 charts)
- [ ] Plugin Analysis (4 charts)
- [ ] Priority Analysis (4 charts)
- [ ] SLA Compliance (4 charts)
- [ ] Host Tracking (4 charts)

### Phase 4: Advanced Features
- [ ] Dual-axis charts
- [ ] Conditional color formatting
- [ ] Sparklines for inline charts
- [ ] Dashboard layout worksheets
- [ ] Interactive slicers (Excel 2013+)

---

## 6. COLOR REFERENCE

### Severity Colors
| Severity | Hex | RGB |
|----------|-----|-----|
| Critical | #dc3545 | 220, 53, 69 |
| High | #fd7e14 | 253, 126, 20 |
| Medium | #ffc107 | 255, 193, 7 |
| Low | #28a745 | 40, 167, 69 |
| Info | #6c757d | 108, 117, 125 |

### Status Colors
| Status | Hex | RGB |
|--------|-----|-----|
| Active | #dc3545 | 220, 53, 69 |
| Resolved | #28a745 | 40, 167, 69 |
| New | #FF8C00 | 255, 140, 0 |
| Closed | #4CAF50 | 76, 175, 80 |

### Environment Colors
| Environment | Hex | RGB |
|-------------|-----|-----|
| Production | #28a745 | 40, 167, 69 |
| PSS | #007bff | 0, 123, 255 |
| Shared | #ffc107 | 255, 193, 7 |
| Unknown | #6c757d | 108, 117, 125 |

### Chart Accent Colors
| Purpose | Hex |
|---------|-----|
| Primary | #17a2b8 |
| Secondary | #6c757d |
| Success | #28a745 |
| Warning | #ffc107 |
| Danger | #dc3545 |
| Info | #007bff |
