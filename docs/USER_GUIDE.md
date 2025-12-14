# Nessus History Tracker - User Guide

A comprehensive guide to using the Plugin History Analysis Tool for vulnerability management and tracking.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Loading Data](#loading-data)
4. [Main Interface Overview](#main-interface-overview)
5. [Using Filters](#using-filters)
6. [Dashboard and Visualization Tabs](#dashboard-and-visualization-tabs)
7. [Finding Details View](#finding-details-view)
8. [Host and Lifecycle Views](#host-and-lifecycle-views)
9. [Exporting Data](#exporting-data)
10. [Configuration and Settings](#configuration-and-settings)
11. [OPDIR and IAVM Integration](#opdir-and-iavm-integration)
12. [Environment Classification](#environment-classification)
13. [Smart Filtering](#smart-filtering)
14. [Troubleshooting](#troubleshooting)
15. [Keyboard Shortcuts](#keyboard-shortcuts)

---

## Introduction

### Purpose

The Nessus History Tracker is a powerful vulnerability analysis tool designed to:

- **Track vulnerability lifecycles** across multiple scan periods
- **Calculate remediation metrics** including MTTR (Mean Time to Remediation)
- **Monitor compliance** with SLA targets and OPDIR directives
- **Visualize trends** through interactive charts and dashboards
- **Identify priority findings** based on severity, age, and business impact
- **Generate reports** for executive briefings and audit requirements

### Key Features

| Feature | Description |
|---------|-------------|
| Historical Tracking | Track findings across unlimited scan periods |
| Lifecycle Analysis | Monitor finding states: New, Active, Remediated, Reappeared |
| Environment Classification | Categorize hosts by Production, PSS, Shared |
| OPDIR Integration | Map findings to compliance directives |
| IAVM Enrichment | Enhance findings with IAVM notice details |
| Smart Filtering | Automatic filter adjustment for accurate metrics |
| Multiple Export Formats | SQLite, Excel, JSON export options |

### System Requirements

- Python 3.8 or higher
- Windows, macOS, or Linux
- 4GB RAM minimum (8GB recommended for large datasets)
- Screen resolution: 1920x1080 or higher recommended

---

## Getting Started

### First Launch

1. Navigate to the application directory
2. Run the application:
   ```
   python run_app.py
   ```
3. The main window will open with an empty dashboard

[Screenshot: Initial application window with empty dashboard]

### Recommended First Steps

1. **Load Plugin Database** - Provides plugin names and descriptions
2. **Load Existing Database** or **Process New Archives** - Import vulnerability data
3. **Load OPDIR Mapping** (optional) - For compliance tracking
4. **Load IAVM Notices** (optional) - For enhanced IAVM details
5. **Configure Environment Settings** - Map hostnames to environments

---

## Loading Data

### Loading Plugin Database

The plugin database provides human-readable names and descriptions for Nessus plugin IDs.

1. Click **File → Load Plugins XML**
2. Select your `plugins.xml` file (exported from Nessus)
3. Wait for loading to complete (progress shown in status bar)

[Screenshot: File menu with Load Plugins XML highlighted]

**Supported Format:** Nessus plugin export XML file containing `<nasl_plugins>` or `<nasl>` elements.

**Note:** Plugin loading can take 30-60 seconds for large files (250,000+ plugins).

### Loading Existing Database

To continue working with previously processed data:

1. Click **File → Load Existing Database**
2. Select your `.db` file (SQLite database)
3. Data loads automatically including:
   - Historical findings
   - Lifecycle analysis
   - Host presence data
   - OPDIR mappings (if previously saved)
   - IAVM notices (if previously saved)

[Screenshot: Load database dialog]

### Processing New Archives

To import new Nessus scan data:

1. Click **File → Add Archive(s)**
2. Select one or more files:
   - `.nessus` files (individual scan results)
   - `.zip` files (containing multiple .nessus files)
3. Selected files appear in the archive list
4. Click **Process** to begin analysis

[Screenshot: Archive selection with multiple files queued]

**Processing Steps:**
1. Extract archives (if ZIP)
2. Parse Nessus XML files
3. Enrich with plugin data
4. Perform lifecycle analysis
5. Calculate host presence
6. Apply OPDIR/IAVM enrichment
7. Update visualizations

**Progress:** Processing status displays in the status bar at the bottom of the window.

### Loading OPDIR Mapping

OPDIR (Operational Directive) mapping enables compliance tracking:

1. Click **File → Load OPDIR Mapping**
2. Select your OPDIR Excel or CSV file

**Expected Columns:**
| Column | Description | Example |
|--------|-------------|---------|
| OPDIR NUMBER | Directive ID (XXXX-YY format) | 0001-24 |
| IAVA/B | IAVA/IAVB reference | B-0201 or 2024-B-0201 |
| POA&M DUE DATE | Intermediate deadline | 2024-06-15 |
| FINAL DUE DATE | Final compliance deadline | 2024-07-15 |
| SUBJECT | Directive title | Apache Log4j Vulnerability |

[Screenshot: OPDIR file loaded with column mapping]

### Loading IAVM Notices

IAVM (Information Assurance Vulnerability Management) notices provide additional context:

1. Click **File → Load IAVM Notices**
2. Select your IAVM Excel or CSV file

**IAVM data enriches findings with:**
- STIG severity ratings
- Vulnerability state and status
- Supersedence information
- Release and mitigation dates

---

## Main Interface Overview

### Window Layout

[Screenshot: Full application window with labeled regions]

The interface consists of these main areas:

| Area | Location | Purpose |
|------|----------|---------|
| Menu Bar | Top | File operations, settings, help |
| Filter Panel | Below menu | Date range, severity, status, environment filters |
| Tab Bar | Below filters | Switch between visualization tabs |
| Main Content | Center | Charts, tables, and data views |
| Status Bar | Bottom | Processing status and current action |

### Menu Bar

**File Menu:**
- Load Plugins XML
- Load Existing Database
- Add Archive(s)
- Load OPDIR Mapping
- Load IAVM Notices
- Save Database
- Export to Excel
- Export to JSON
- Exit

**Settings Menu:**
- Environment Configuration
- SLA Targets
- Display Options
- Data Labels Toggle

**Help Menu:**
- Documentation
- About

### Tab Navigation

The application organizes visualizations into tabs:

| Tab | Content |
|-----|---------|
| Dashboard | Summary metrics and overview charts |
| Risk | CVSS distribution, MTTR, age analysis, risky hosts |
| Timeline | Trends over time, new vs resolved |
| SLA | Compliance status, breaches, approaching deadlines |
| OPDIR | OPDIR coverage and compliance |
| Efficiency | Scan coverage, reappearance, resolution velocity |
| Network | Subnet analysis, host criticality |
| Plugin | Top plugins, severity distribution |
| Priority | Prioritization matrix, urgent findings |
| Host Tracking | Missing hosts, coverage trends |
| Metrics | KPIs, remediation rates, risk trends |
| Lifecycle | Detailed finding list with filters |
| Hosts | Host-centric view with presence data |
| Logging | Processing log and system messages |

---

## Using Filters

### Filter Panel Overview

[Screenshot: Filter panel with all controls visible]

The filter panel controls which data appears in all views:

| Filter | Options | Default |
|--------|---------|---------|
| Date Range | Start/End date pickers | Last 180 days |
| Severity | All, Critical, High, Medium, Low | All |
| Status | All, Active, Remediated | All |
| Environment | All, Production, PSS, Shared, Unknown | All |
| OPDIR Status | All, Mapped, Not Mapped | All |

### Date Range Filter

**Setting Date Range:**
1. Click the **Start Date** field
2. Select date from calendar popup
3. Click the **End Date** field
4. Select end date
5. Filters apply automatically

**Quick Ranges:**
- Default: Last 180 days from most recent scan
- Full Range: All available data

[Screenshot: Date picker calendar popup]

### Severity Filter

Filter findings by CVSS-based severity:

| Severity | CVSS Range | Color |
|----------|------------|-------|
| Critical | 9.0 - 10.0 | Red |
| High | 7.0 - 8.9 | Orange |
| Medium | 4.0 - 6.9 | Yellow |
| Low | 0.1 - 3.9 | Blue |

### Status Filter

| Status | Description |
|--------|-------------|
| Active | Currently open findings |
| Remediated | Previously resolved findings |
| All | Both active and remediated |

**Note:** Some metrics use [Smart Filtering](#smart-filtering) to ensure accurate calculations regardless of this setting.

### Environment Filter

Filter by host environment classification:

| Environment | Typical Hosts |
|-------------|---------------|
| Production | Live business systems |
| PSS | Pre-production, staging, test |
| Shared | Infrastructure serving multiple environments |
| Unknown | Unclassified hosts |

**Configure environments:** Click the gear icon (⚙) next to the Environment dropdown.

### Applying Filters

- Filters apply automatically when changed
- All visualizations update to reflect filtered data
- Lifecycle and Host tables refresh
- Filter state persists during session

---

## Dashboard and Visualization Tabs

### Dashboard Tab

The Dashboard provides an executive summary:

[Screenshot: Dashboard tab with all summary widgets]

**Summary Metrics:**
- Total Findings (Active)
- Critical Count
- High Count
- Average Age (days)
- Hosts Affected

**Quick Charts:**
- Severity distribution pie
- Status breakdown
- Environment distribution
- Recent trend sparkline

### Risk Tab

[Screenshot: Risk tab with 4-chart grid]

**Charts:**

1. **CVSS Score Distribution** - Histogram of vulnerability scores
2. **Mean Time to Remediation** - Average fix time by severity
3. **Findings by Age** - Age buckets showing remediation backlog
4. **Top Risky Hosts by Environment** - Highest risk hosts color-coded

**Interaction:**
- Double-click any chart to open enlarged pop-out view
- Pop-out includes zoom, pan, and export options

### Timeline Tab

[Screenshot: Timeline tab showing trends]

**Charts:**

1. **Total Findings Over Time** - Overall trend with direction indicator
2. **Findings by Severity Over Time** - Stacked area by severity
3. **New vs Resolved** - Bar comparison showing remediation velocity
4. **Cumulative Risk Score** - Weighted risk trend

### SLA Tab

[Screenshot: SLA tab with compliance metrics]

**Charts:**

1. **SLA Compliance Overview** - Stacked bar (Compliant/At-Risk/Breached)
2. **SLA Breaches by Severity** - Count of breached findings
3. **Approaching Deadline** - Findings nearing SLA breach
4. **Days to SLA** - Distribution of time remaining

**SLA Targets (Default):**
| Severity | Days |
|----------|------|
| Critical | 15 |
| High | 30 |
| Medium | 60 |
| Low | 90 |

Configure targets via **Settings → SLA Targets**.

### OPDIR Tab

[Screenshot: OPDIR tab with compliance charts]

**Charts:**

1. **OPDIR Coverage** - Pie showing mapped vs unmapped
2. **Compliance Status** - Overdue/Due Soon/On Track
3. **Finding Age (OPDIR Mapped)** - Age distribution for OPDIR findings
4. **Compliance by OPDIR Year** - Stacked bar by directive year

**Requirements:** Load OPDIR mapping file to enable these visualizations.

### Additional Tabs

See the [Visualization Guide](VISUALIZATION_GUIDE.md) for detailed documentation of all charts including:
- Efficiency Tab
- Network Tab
- Plugin Tab
- Priority Tab
- Host Tracking Tab
- Metrics Tab

---

## Finding Details View

### Opening Finding Details

From the Lifecycle tab:
1. Locate finding in the table
2. Double-click the row
3. Finding Detail modal opens

[Screenshot: Finding detail modal with all sections]

### Detail Sections

**Basic Information:**
| Field | Description |
|-------|-------------|
| Hostname | Affected system |
| IP Address | Network address |
| Plugin ID | Nessus plugin identifier |
| Severity | Critical/High/Medium/Low |
| CVSS v3 Score | Numeric severity score |
| Status | Active or Remediated |
| Port/Protocol | Service information |

**Timeline:**
| Field | Description |
|-------|-------------|
| First Observed | Initial detection date |
| Last Seen | Most recent scan appearance |
| Days Open | Exposure duration |
| Total Observations | Scan appearances |
| Reappearances | Times returned after remediation |

**CVE & IAVX References:**
- CVE identifiers displayed in 4-column grid
- IAVX references in 3-column grid

**OPDIR Information** (if mapped):
- OPDIR Number
- OPDIR Title
- Due Date
- Compliance Status

**Technical Details:**
- Synopsis - Brief description
- Description - Full vulnerability details (expandable)
- Solution - Remediation guidance (expandable)
- Plugin Output - Scan evidence (expandable)
- References - External links

### Actions

- **Copy to Clipboard** - Copy formatted details
- **Close** - Return to main view

---

## Host and Lifecycle Views

### Lifecycle Tab

[Screenshot: Lifecycle tab with table and columns]

The Lifecycle tab shows individual findings with filtering and sorting:

**Columns:**
| Column | Description |
|--------|-------------|
| Hostname | Affected system |
| Plugin ID | Vulnerability identifier |
| Plugin Name | Human-readable name |
| Severity | Critical/High/Medium/Low |
| Status | Active/Remediated |
| First Seen | Initial detection |
| Last Seen | Most recent appearance |
| Days Open | Exposure time |
| OPDIR | Mapped directive (if any) |

**Features:**
- Click column headers to sort
- Use filter panel to narrow results
- Double-click row for full details
- Right-click for context menu

### Hosts Tab

[Screenshot: Hosts tab with host-centric view]

The Hosts tab provides asset-focused analysis:

**Columns:**
| Column | Description |
|--------|-------------|
| Hostname | System identifier |
| IP Address | Network address |
| Finding Count | Total vulnerabilities |
| Critical | Critical severity count |
| High | High severity count |
| Presence % | Scan coverage percentage |
| Last Seen | Most recent scan |
| Environment | Classification |

**Use Cases:**
- Identify highest-risk assets
- Find hosts with coverage gaps
- Track remediation by system

---

## Exporting Data

### Save to Database

Preserve all processed data for future sessions:

1. Click **File → Save Database**
2. Choose location and filename
3. SQLite database saves all:
   - Historical findings
   - Lifecycle analysis
   - Host presence data
   - Scan changes
   - OPDIR mappings
   - IAVM notices

**Recommended:** Save after each major import session.

### Export to Excel

Generate Excel workbook for reporting:

1. Click **File → Export to Excel**
2. Choose location and filename
3. Workbook includes sheets:
   - Summary Dashboard
   - Finding Lifecycle
   - Historical Findings
   - Host Presence
   - Scan Changes

[Screenshot: Excel export with multiple sheets]

### Export to JSON

Export structured data for integration:

1. Click **File → Export to JSON**
2. Choose location and filename
3. JSON includes all data collections

**Use Cases:**
- Integration with other tools
- Custom reporting scripts
- Data archival

---

## Configuration and Settings

### Environment Configuration

Access via gear icon (⚙) next to Environment filter or **Settings → Environment Configuration**.

[Screenshot: Environment configuration modal]

**Tabs:**

**1. Environment Types**
Define available environment categories:
```
Production
PSS
Shared
Unknown
```

**2. Hostname Mappings**
Explicitly assign hosts to environments:
- Filter list by text or environment
- Select hosts with checkboxes
- Bulk assign using dropdown
- Changes take effect immediately

**3. Pattern Mappings**
Use regex patterns for automatic classification:
```
^prod-.* = Production
^dev-.* = PSS
^shared-.* = Shared
```

**4. Auto-Detection**
Configure hostname format detection:
- Expected hostname length
- Position-based rules (e.g., position 8 indicates environment)

### SLA Target Configuration

Access via **Settings → SLA Targets**.

[Screenshot: SLA settings dialog]

**Configure per-severity targets:**
| Setting | Default | Description |
|---------|---------|-------------|
| Critical SLA | 15 days | Maximum time to remediate Critical |
| High SLA | 30 days | Maximum time for High severity |
| Medium SLA | 60 days | Maximum time for Medium |
| Low SLA | 90 days | Maximum time for Low |

### Display Options

Access via **Settings → Display Options**.

**Options:**
- **Show Data Labels** - Toggle chart value labels
- **Date Format** - Configure date display format
- **Theme** - Dark mode (default)

---

## OPDIR and IAVM Integration

### OPDIR Overview

OPDIR (Operational Directive) integration maps vulnerabilities to compliance requirements:

**How Matching Works:**
1. Extract IAVX references from scan findings
2. Parse OPDIR file for IAVA/B mappings
3. Match by full reference (2024-B-0201) or suffix (B-0201)
4. Apply due dates and titles from OPDIR

**Year Inference:**
- OPDIR NUMBER format: `XXXX-YY` where YY is year suffix
- Example: `0001-24` → Year 2024
- Suffix-only IAVA/B references inherit year from OPDIR NUMBER

### OPDIR Compliance Status

| Status | Description | Color |
|--------|-------------|-------|
| On Track | More than 14 days until deadline | Green |
| Due Soon | Within 14 days of deadline | Yellow |
| Overdue | Past final due date | Red |

### IAVM Integration

IAVM notices provide enhanced vulnerability context:

**Enrichment Data:**
- STIG Severity (CAT I, CAT II, CAT III)
- Vulnerability State
- Supersedence Chain
- Release and Acknowledgment Dates

**Loading IAVM:**
1. Click **File → Load IAVM Notices**
2. Select IAVM Excel/CSV file
3. Enrichment applies automatically to matching findings

---

## Environment Classification

### Automatic Detection

Hostnames are classified automatically based on format:

**Standard Format: LLLLTTCEP (9 characters)**
- Positions 1-4: Location code
- Positions 5-6: Tier/type
- Position 7: Cluster
- Position 8: Environment indicator
  - Letter (A-Z) = Production
  - Number (0-9) = PSS
- Position 9: Host type (p=physical, v=virtual)

### Manual Override

Override auto-detection with explicit mappings:

1. Open Environment Configuration (gear icon)
2. Go to **Hostname Mappings** tab
3. Filter to "Unknown" to see unclassified hosts
4. Select hosts and assign environment
5. Click **Save** to apply

[Screenshot: Hostname mapping with Unknown filter]

### Bulk Assignment Workflow

To efficiently classify many hosts:

1. Set Environment filter to "Unknown"
2. Select multiple hosts with checkboxes
3. Choose target environment from dropdown
4. Click **Apply**
5. Hosts are assigned and removed from filtered view
6. Repeat until Unknown list is empty

---

## Smart Filtering

### What is Smart Filtering?

Smart filtering automatically ensures accurate metrics regardless of UI filter settings.

**Problem Solved:**
If you filter to "Active" status only, remediation rate would show 0% (no remediated findings visible). This is misleading for metrics that need both statuses.

**Solution:**
Specific visualizations automatically include both statuses when calculating metrics, while still respecting other filters (date, severity, environment).

### Affected Visualizations

| Visualization | Smart Filter Applied | Reason |
|---------------|---------------------|--------|
| MTTR by Severity | Remediated Only | Need resolved findings to calculate fix time |
| Remediation Rate | Both Statuses | Need both to calculate percentage |
| Remediation Status by Severity | Both Statuses | Comparing Active vs Remediated counts |
| Reopen Rate | Both Statuses | Tracking findings that returned |
| Resolution Velocity | Remediated Only | Distribution of time-to-fix |

### User Experience

- Smart filtering is automatic - no action required
- Other filters (date, severity, environment) still apply
- Metrics remain accurate regardless of Status filter setting
- Useful when triaging Active findings while maintaining accurate dashboards

---

## Troubleshooting

### Common Issues

**Issue: Plugin names not showing**
- **Cause:** Plugin database not loaded
- **Solution:** Load plugins.xml via File → Load Plugins XML

**Issue: OPDIR charts empty despite mapping**
- **Cause:** Column name mismatch or date parsing issue
- **Solution:**
  1. Check console for debug output
  2. Verify OPDIR file has expected columns
  3. Re-load OPDIR mapping

**Issue: Findings show 0 days open**
- **Cause:** Missing first_observed_date in scan data
- **Solution:** Ensure scans include plugin first observed timestamps

**Issue: Environment filter shows all Unknown**
- **Cause:** Hostname format doesn't match auto-detection
- **Solution:** Configure manual hostname mappings in Environment Configuration

**Issue: Charts not updating after filter change**
- **Cause:** Large dataset processing delay
- **Solution:** Wait for status bar to show "Ready"

### Performance Tips

1. **Large Datasets:**
   - Process archives in batches
   - Save database frequently
   - Use date filters to limit visible data

2. **Memory Usage:**
   - Close pop-out chart windows when not needed
   - Export and restart for very large datasets

3. **Scan Coverage:**
   - Include all scans for accurate trend analysis
   - Consistent scan scheduling improves metrics

### Log Review

Check the **Logging** tab for:
- Processing progress
- Error messages
- Data loading confirmation
- Enrichment results

[Screenshot: Logging tab with sample output]

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+O | Load database |
| Ctrl+S | Save database |
| Ctrl+E | Export to Excel |
| Escape | Close modal/popup |
| Double-click | Open finding details / Enlarge chart |

---

## Appendix

### Data Field Reference

**Finding Fields:**
| Field | Source | Description |
|-------|--------|-------------|
| plugin_id | Scan | Nessus plugin identifier |
| plugin_name | Plugin DB | Human-readable name |
| hostname | Scan | Affected system |
| ip_address | Scan | Network address |
| severity_text | Scan | Critical/High/Medium/Low |
| cvss3_base_score | Scan | CVSS v3 base score |
| first_seen | Calculated | First detection date |
| last_seen | Calculated | Most recent appearance |
| days_open | Calculated | current_date - first_seen |
| status | Calculated | Active/Remediated |
| iavx | Scan | IAVA/IAVB references |
| cves | Scan | CVE identifiers |

**Lifecycle States:**
| State | Meaning |
|-------|---------|
| New | First appearance in current scan |
| Active | Open finding |
| Remediated | No longer appearing in scans |
| Reappeared | Returned after remediation |

### File Formats

**Supported Input:**
- `.nessus` - Nessus scan export XML
- `.zip` - Archive containing .nessus files
- `.xml` - Plugin database export
- `.xlsx` / `.csv` - OPDIR and IAVM data

**Export Formats:**
- `.db` - SQLite database (full data preservation)
- `.xlsx` - Excel workbook (reporting)
- `.json` - JSON (integration)

### Getting Help

- **Documentation:** See docs/ folder
- **Visualization Guide:** [VISUALIZATION_GUIDE.md](VISUALIZATION_GUIDE.md)
- **Issues:** Report bugs at project repository

---

*Document Version: 1.0*
*Last Updated: December 2024*
