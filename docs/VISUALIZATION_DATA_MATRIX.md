# Visualization Data Element Matrix

This document provides a complete reference of all visualizations, their data sources, required columns, smart filtering behavior, and equivalent SQL queries.

---

## Quick Reference

### Data Sources

| Source | Table | Description |
|--------|-------|-------------|
| lifecycle | `finding_lifecycle` | Unique findings with status tracking |
| historical | `historical_findings` | All scan observations |
| scan_changes | `scan_changes` | New/Resolved transitions |
| host | `host_presence` | Host scan coverage |

### Smart Filter Modes

| Mode | Status Filter Behavior |
|------|----------------------|
| None | Respects UI status filter |
| `all_statuses` | Always includes Active + Remediated |
| `remediated_only` | Always uses Remediated only |
| `active_only` | Always uses Active only |

---

## Risk Tab Visualizations

### CVSS Score Distribution (Embedded)

| Property | Value |
|----------|-------|
| **Function** | `_update_risk_charts` (Chart 1) |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `cvss3_base_score` |
| **Grouping** | Histogram bins (0-10 by 0.5) |

```sql
SELECT cvss3_base_score, COUNT(*) as count
FROM finding_lifecycle
WHERE cvss3_base_score IS NOT NULL
  AND status = '{status_filter}'  -- or omit for All
  AND first_seen BETWEEN '{start_date}' AND '{end_date}'
GROUP BY ROUND(cvss3_base_score * 2) / 2
ORDER BY cvss3_base_score;
```

### CVSS Score Distribution (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_cvss_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `cvss3_base_score` |
| **Additional Features** | Severity threshold lines at 4.0, 7.0, 9.0 |

```sql
-- Same as embedded, with additional severity annotations
SELECT
    cvss3_base_score,
    CASE
        WHEN cvss3_base_score >= 9.0 THEN 'Critical'
        WHEN cvss3_base_score >= 7.0 THEN 'High'
        WHEN cvss3_base_score >= 4.0 THEN 'Medium'
        ELSE 'Low'
    END as severity_band,
    COUNT(*) as count
FROM finding_lifecycle
WHERE cvss3_base_score IS NOT NULL
GROUP BY ROUND(cvss3_base_score * 2) / 2
ORDER BY cvss3_base_score;
```

---

### Mean Time to Remediation (Embedded)

| Property | Value |
|----------|-------|
| **Function** | `_update_risk_charts` (Chart 2) |
| **Data Source** | lifecycle |
| **Smart Filter** | Filters to `status = 'Resolved'` internally |
| **Required Columns** | `severity_text`, `days_open`, `status` |
| **Grouping** | By severity_text |

```sql
SELECT
    severity_text,
    AVG(days_open) as mttr,
    COUNT(*) as count
FROM finding_lifecycle
WHERE status = 'Remediated'
  AND days_open IS NOT NULL
GROUP BY severity_text
ORDER BY
    CASE severity_text
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3
        WHEN 'Low' THEN 4
    END;
```

### Mean Time to Remediation (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_mttr_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | `remediated_only` |
| **Required Columns** | `severity_text`, `days_open` |
| **Note** | Always shows remediated data regardless of UI filter |

```sql
-- Smart filtered: Always uses Remediated status
SELECT
    severity_text,
    AVG(days_open) as mttr,
    MIN(days_open) as min_days,
    MAX(days_open) as max_days,
    COUNT(*) as count
FROM finding_lifecycle
WHERE status = 'Remediated'
  AND days_open IS NOT NULL
  AND first_seen BETWEEN '{start_date}' AND '{end_date}'
  AND ('{severity_filter}' = 'All' OR severity_text = '{severity_filter}')
GROUP BY severity_text;
```

---

### Findings by Age (Embedded)

| Property | Value |
|----------|-------|
| **Function** | `_update_risk_charts` (Chart 3) |
| **Data Source** | lifecycle |
| **Smart Filter** | Filters to `status = 'Active'` internally |
| **Required Columns** | `days_open`, `status` |
| **Buckets** | 0-30, 31-60, 61-90, 91-120, 121+ |

```sql
SELECT
    CASE
        WHEN days_open <= 30 THEN '0-30'
        WHEN days_open <= 60 THEN '31-60'
        WHEN days_open <= 90 THEN '61-90'
        WHEN days_open <= 120 THEN '91-120'
        ELSE '121+'
    END as age_bucket,
    COUNT(*) as count
FROM finding_lifecycle
WHERE status = 'Active'
  AND days_open IS NOT NULL
GROUP BY age_bucket
ORDER BY
    CASE age_bucket
        WHEN '0-30' THEN 1
        WHEN '31-60' THEN 2
        WHEN '61-90' THEN 3
        WHEN '91-120' THEN 4
        ELSE 5
    END;
```

### Findings by Age (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_age_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None (uses Active internally) |
| **Required Columns** | `days_open`, `status` |

```sql
-- Same as embedded with filter parameters
SELECT
    CASE
        WHEN days_open <= 30 THEN '0-30'
        WHEN days_open <= 60 THEN '31-60'
        WHEN days_open <= 90 THEN '61-90'
        WHEN days_open <= 120 THEN '91-120'
        ELSE '121+'
    END as age_bucket,
    COUNT(*) as count
FROM finding_lifecycle
WHERE status = 'Active'
  AND days_open IS NOT NULL
  AND first_seen BETWEEN '{start_date}' AND '{end_date}'
GROUP BY age_bucket;
```

---

### Top Risky Hosts by Environment (Embedded)

| Property | Value |
|----------|-------|
| **Function** | `_update_risk_charts` (Chart 4) |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `hostname`, `severity_value` |
| **Grouping** | By hostname, colored by environment |
| **Limit** | Top 5 per environment |

```sql
SELECT
    hostname,
    SUM(severity_value) as risk_score,
    COUNT(*) as finding_count
FROM finding_lifecycle
WHERE status = 'Active'
GROUP BY hostname
ORDER BY risk_score DESC
LIMIT 15;
```

### Top Risky Hosts (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_risky_hosts_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `hostname`, `severity_value` |
| **Limit** | Top 10 per environment |

```sql
-- For each environment type
SELECT
    hostname,
    SUM(severity_value) as risk_score,
    COUNT(*) as finding_count,
    SUM(CASE WHEN severity_text = 'Critical' THEN 1 ELSE 0 END) as critical_count,
    SUM(CASE WHEN severity_text = 'High' THEN 1 ELSE 0 END) as high_count
FROM finding_lifecycle
WHERE status = 'Active'
GROUP BY hostname
ORDER BY risk_score DESC;
```

---

## Timeline Tab Visualizations

### Total Findings Over Time (Embedded & Popout)

| Property | Value |
|----------|-------|
| **Function** | `_update_timeline_charts` / `_draw_total_findings_popout` |
| **Data Source** | historical |
| **Smart Filter** | None |
| **Required Columns** | `scan_date` |
| **Grouping** | By scan_date (daily/weekly/monthly) |

```sql
SELECT
    DATE(scan_date) as period,
    COUNT(*) as total_findings
FROM historical_findings
WHERE scan_date BETWEEN '{start_date}' AND '{end_date}'
GROUP BY DATE(scan_date)
ORDER BY period;
```

### Findings by Severity Over Time (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_severity_timeline_popout` |
| **Data Source** | historical |
| **Smart Filter** | None |
| **Required Columns** | `scan_date`, `severity_text` |

```sql
SELECT
    DATE(scan_date) as period,
    severity_text,
    COUNT(*) as count
FROM historical_findings
WHERE scan_date BETWEEN '{start_date}' AND '{end_date}'
GROUP BY DATE(scan_date), severity_text
ORDER BY period, severity_text;
```

### New vs Resolved (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_new_vs_resolved_popout` |
| **Data Source** | scan_changes |
| **Smart Filter** | None |
| **Required Columns** | `scan_date`, `change_type` |

```sql
SELECT
    DATE(scan_date) as period,
    SUM(CASE WHEN change_type = 'New' THEN 1 ELSE 0 END) as new_count,
    SUM(CASE WHEN change_type = 'Resolved' THEN 1 ELSE 0 END) as resolved_count
FROM scan_changes
WHERE scan_date BETWEEN '{start_date}' AND '{end_date}'
GROUP BY DATE(scan_date)
ORDER BY period;
```

### Cumulative Risk Score (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_cumulative_risk_popout` |
| **Data Source** | historical |
| **Smart Filter** | None |
| **Required Columns** | `scan_date`, `severity_value` |

```sql
SELECT
    DATE(scan_date) as period,
    SUM(severity_value) as total_risk_score
FROM historical_findings
WHERE scan_date BETWEEN '{start_date}' AND '{end_date}'
GROUP BY DATE(scan_date)
ORDER BY period;
```

---

## SLA Tab Visualizations

### SLA Compliance Overview (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_sla_compliance_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `severity_text`, `days_open`, `status` |
| **SLA Targets** | Critical: 15, High: 30, Medium: 60, Low: 90 |

```sql
SELECT
    severity_text,
    SUM(CASE
        WHEN days_open > sla_days THEN 1
        ELSE 0
    END) as breached,
    SUM(CASE
        WHEN days_open > sla_days * 0.75 AND days_open <= sla_days THEN 1
        ELSE 0
    END) as at_risk,
    SUM(CASE
        WHEN days_open <= sla_days * 0.75 THEN 1
        ELSE 0
    END) as on_track
FROM finding_lifecycle fl
CROSS JOIN (
    SELECT 'Critical' as sev, 15 as sla_days UNION ALL
    SELECT 'High', 30 UNION ALL
    SELECT 'Medium', 60 UNION ALL
    SELECT 'Low', 90
) sla ON fl.severity_text = sla.sev
WHERE status = 'Active'
GROUP BY severity_text;
```

### SLA Overdue Findings (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_sla_overdue_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `severity_text`, `days_open` |

```sql
SELECT
    severity_text,
    COUNT(*) as overdue_count
FROM finding_lifecycle
WHERE status = 'Active'
  AND (
    (severity_text = 'Critical' AND days_open > 15) OR
    (severity_text = 'High' AND days_open > 30) OR
    (severity_text = 'Medium' AND days_open > 60) OR
    (severity_text = 'Low' AND days_open > 90)
  )
GROUP BY severity_text;
```

### SLA Approaching Deadline (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_sla_approaching_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `severity_text`, `days_open` |

```sql
-- Findings within 25% of SLA deadline
SELECT
    severity_text,
    hostname,
    plugin_name,
    days_open,
    CASE severity_text
        WHEN 'Critical' THEN 15 - days_open
        WHEN 'High' THEN 30 - days_open
        WHEN 'Medium' THEN 60 - days_open
        WHEN 'Low' THEN 90 - days_open
    END as days_remaining
FROM finding_lifecycle
WHERE status = 'Active'
  AND (
    (severity_text = 'Critical' AND days_open BETWEEN 11 AND 15) OR
    (severity_text = 'High' AND days_open BETWEEN 22 AND 30) OR
    (severity_text = 'Medium' AND days_open BETWEEN 45 AND 60) OR
    (severity_text = 'Low' AND days_open BETWEEN 67 AND 90)
  )
ORDER BY days_remaining ASC;
```

---

## OPDIR Tab Visualizations

### OPDIR Coverage (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_opdir_coverage_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `opdir_number` |

```sql
SELECT
    CASE
        WHEN opdir_number IS NOT NULL AND opdir_number != '' THEN 'Mapped'
        ELSE 'Unmapped'
    END as mapping_status,
    COUNT(*) as count
FROM finding_lifecycle
WHERE status = 'Active'
GROUP BY mapping_status;
```

### OPDIR Compliance Status (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_opdir_status_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `opdir_status` |

```sql
SELECT
    opdir_status,
    COUNT(*) as count
FROM finding_lifecycle
WHERE opdir_status IS NOT NULL
  AND opdir_status != ''
GROUP BY opdir_status;
```

### OPDIR Finding Age (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_opdir_age_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `opdir_number`, `days_open` |

```sql
SELECT
    CASE
        WHEN days_open <= 7 THEN '0-7'
        WHEN days_open <= 30 THEN '8-30'
        WHEN days_open <= 60 THEN '31-60'
        WHEN days_open <= 90 THEN '61-90'
        WHEN days_open <= 180 THEN '91-180'
        ELSE '180+'
    END as age_bucket,
    COUNT(*) as count
FROM finding_lifecycle
WHERE opdir_number IS NOT NULL
  AND opdir_number != ''
GROUP BY age_bucket;
```

### Compliance by OPDIR Year (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_opdir_year_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `opdir_year`, `opdir_status` |

```sql
SELECT
    opdir_year,
    opdir_status,
    COUNT(*) as count
FROM finding_lifecycle
WHERE opdir_year IS NOT NULL
GROUP BY opdir_year, opdir_status
ORDER BY opdir_year;
```

---

## Efficiency Tab Visualizations

### Scan Coverage Consistency (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_scan_coverage_popout` |
| **Data Source** | host |
| **Smart Filter** | None |
| **Required Columns** | `presence_percentage` |

```sql
SELECT
    ROUND(presence_percentage / 10) * 10 as coverage_bucket,
    COUNT(*) as host_count
FROM host_presence
GROUP BY coverage_bucket
ORDER BY coverage_bucket;
```

### Vulnerability Reappearance (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_reappearance_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `reappearances` |

```sql
SELECT
    reappearances,
    COUNT(*) as count
FROM finding_lifecycle
WHERE reappearances > 0
GROUP BY reappearances
ORDER BY reappearances;
```

### Resolution Velocity (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_resolution_velocity_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | `remediated_only` (implicit) |
| **Required Columns** | `days_open`, `status` |

```sql
SELECT
    CASE
        WHEN days_open <= 7 THEN '0-7 days'
        WHEN days_open <= 14 THEN '8-14 days'
        WHEN days_open <= 30 THEN '15-30 days'
        WHEN days_open <= 60 THEN '31-60 days'
        WHEN days_open <= 90 THEN '61-90 days'
        ELSE '90+ days'
    END as resolution_bucket,
    COUNT(*) as count
FROM finding_lifecycle
WHERE status = 'Remediated'
GROUP BY resolution_bucket;
```

---

## Network Tab Visualizations

### Top Subnets by Vulnerability (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_top_subnets_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `ip_address` |

```sql
SELECT
    SUBSTR(ip_address, 1, INSTR(ip_address || '.', '.') +
           INSTR(SUBSTR(ip_address, INSTR(ip_address, '.') + 1) || '.', '.') +
           INSTR(SUBSTR(ip_address, INSTR(ip_address, '.') + 1 +
                 INSTR(SUBSTR(ip_address, INSTR(ip_address, '.') + 1), '.') + 1) || '.', '.') - 1
    ) || '.0/24' as subnet,
    COUNT(*) as finding_count
FROM finding_lifecycle
WHERE ip_address IS NOT NULL
GROUP BY subnet
ORDER BY finding_count DESC
LIMIT 15;
```

### Subnet Risk Scores (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_subnet_risk_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `ip_address`, `severity_value` |

```sql
SELECT
    -- Extract first 3 octets as subnet
    SUBSTR(ip_address, 1, LENGTH(ip_address) - LENGTH(REPLACE(ip_address, '.', '')) +
           INSTR(REVERSE(ip_address), '.')) as subnet,
    SUM(severity_value) as risk_score,
    COUNT(*) as finding_count
FROM finding_lifecycle
WHERE ip_address IS NOT NULL
GROUP BY subnet
ORDER BY risk_score DESC
LIMIT 15;
```

### Environment Distribution (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_environment_breakdown_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `hostname` (environment derived) |

```sql
-- Environment determined by hostname pattern at application level
SELECT
    environment_type,
    COUNT(*) as finding_count
FROM finding_lifecycle
GROUP BY environment_type;
```

---

## Plugin Tab Visualizations

### Top Plugins (Embedded & Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_top_plugins_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `plugin_id`, `plugin_name` |
| **Limit** | Top 10 per environment (popout), Top 5 (embedded) |

```sql
SELECT
    plugin_id,
    plugin_name,
    COUNT(*) as occurrence_count,
    COUNT(DISTINCT hostname) as hosts_affected
FROM finding_lifecycle
WHERE status = 'Active'
GROUP BY plugin_id, plugin_name
ORDER BY occurrence_count DESC
LIMIT 15;
```

### Plugin Severity Distribution (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_plugin_severity_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `severity_text` |

```sql
SELECT
    severity_text,
    COUNT(*) as count
FROM finding_lifecycle
WHERE status = 'Active'
GROUP BY severity_text
ORDER BY
    CASE severity_text
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3
        WHEN 'Low' THEN 4
    END;
```

### Plugins by Hosts Affected (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_plugins_by_hosts_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `plugin_id`, `plugin_name`, `hostname` |

```sql
SELECT
    plugin_id,
    plugin_name,
    COUNT(DISTINCT hostname) as hosts_affected
FROM finding_lifecycle
WHERE status = 'Active'
GROUP BY plugin_id, plugin_name
ORDER BY hosts_affected DESC
LIMIT 15;
```

### Plugins with Longest Average Age (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_plugin_age_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `plugin_id`, `plugin_name`, `days_open` |

```sql
SELECT
    plugin_id,
    plugin_name,
    AVG(days_open) as avg_age,
    COUNT(*) as count
FROM finding_lifecycle
WHERE status = 'Active'
  AND days_open IS NOT NULL
GROUP BY plugin_id, plugin_name
HAVING COUNT(*) >= 3  -- Minimum occurrences for meaningful average
ORDER BY avg_age DESC
LIMIT 15;
```

---

## Priority Tab Visualizations

### Priority Matrix (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_priority_matrix_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `cvss3_base_score`, `days_open`, `severity_text` |

```sql
SELECT
    plugin_id,
    hostname,
    cvss3_base_score,
    days_open,
    severity_text,
    (cvss3_base_score * 10) + (days_open / 10) as priority_score
FROM finding_lifecycle
WHERE status = 'Active'
  AND cvss3_base_score IS NOT NULL
  AND days_open IS NOT NULL;
```

### Priority Distribution (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_priority_distribution_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `cvss3_base_score`, `days_open` |

```sql
SELECT
    CASE
        WHEN cvss3_base_score >= 7.0 AND days_open > 30 THEN 'Urgent'
        WHEN cvss3_base_score >= 7.0 OR days_open > 60 THEN 'High'
        WHEN cvss3_base_score >= 4.0 OR days_open > 30 THEN 'Medium'
        ELSE 'Low'
    END as priority_bucket,
    COUNT(*) as count
FROM finding_lifecycle
WHERE status = 'Active'
GROUP BY priority_bucket;
```

### Top Priority Findings (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_top_priority_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `plugin_name`, `hostname`, `cvss3_base_score`, `days_open` |

```sql
SELECT
    plugin_name,
    hostname,
    severity_text,
    cvss3_base_score,
    days_open,
    (cvss3_base_score * 10) + (days_open / 5) as priority_score
FROM finding_lifecycle
WHERE status = 'Active'
ORDER BY priority_score DESC
LIMIT 10;
```

---

## Host Tracking Tab Visualizations

### Missing Hosts (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_missing_hosts_popout` |
| **Data Source** | host |
| **Smart Filter** | None |
| **Required Columns** | `hostname`, `last_seen` |

```sql
SELECT
    hostname,
    last_seen,
    JULIANDAY('now') - JULIANDAY(last_seen) as days_missing
FROM host_presence
WHERE last_seen < DATE('now', '-14 days')
ORDER BY last_seen ASC;
```

### Hosts Per Scan Over Time (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_host_presence_popout` |
| **Data Source** | historical |
| **Smart Filter** | None |
| **Required Columns** | `scan_date`, `hostname` |

```sql
SELECT
    DATE(scan_date) as scan_period,
    COUNT(DISTINCT hostname) as host_count
FROM historical_findings
GROUP BY DATE(scan_date)
ORDER BY scan_period;
```

### Declining Scan Coverage (Popout)

| Property | Value |
|----------|-------|
| **Function** | `_draw_declining_hosts_popout` |
| **Data Source** | host |
| **Smart Filter** | None |
| **Required Columns** | `hostname`, `presence_percentage` |

```sql
SELECT
    hostname,
    presence_percentage,
    scan_count,
    first_seen,
    last_seen
FROM host_presence
WHERE presence_percentage < 80
ORDER BY presence_percentage ASC
LIMIT 20;
```

---

## Metrics Tab Visualizations

### Remediation Status by Severity

| Property | Value |
|----------|-------|
| **Function** | `_update_metrics_charts` (Chart 1) |
| **Data Source** | lifecycle |
| **Smart Filter** | `all_statuses` |
| **Required Columns** | `severity_text`, `status` |

```sql
-- Smart filtered: Always includes both Active and Remediated
SELECT
    severity_text,
    SUM(CASE WHEN status = 'Active' THEN 1 ELSE 0 END) as active_count,
    SUM(CASE WHEN status = 'Remediated' THEN 1 ELSE 0 END) as remediated_count
FROM finding_lifecycle
WHERE status IN ('Active', 'Remediated')
GROUP BY severity_text;
```

### Risk Score Trend

| Property | Value |
|----------|-------|
| **Function** | `_update_metrics_charts` (Chart 2) |
| **Data Source** | historical |
| **Smart Filter** | None |
| **Required Columns** | `scan_date`, `severity_value` |

```sql
SELECT
    DATE(scan_date) as period,
    SUM(severity_value) as total_risk_score
FROM historical_findings
GROUP BY DATE(scan_date)
ORDER BY period;
```

### SLA Status by Severity

| Property | Value |
|----------|-------|
| **Function** | `_update_metrics_charts` (Chart 3) |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `severity_text`, `days_open` |

```sql
-- Similar to SLA Compliance query
SELECT
    severity_text,
    SUM(CASE WHEN days_open > sla_days THEN 1 ELSE 0 END) as breached,
    SUM(CASE WHEN days_open > sla_days * 0.75 AND days_open <= sla_days THEN 1 ELSE 0 END) as at_risk,
    SUM(CASE WHEN days_open <= sla_days * 0.75 THEN 1 ELSE 0 END) as on_track
FROM finding_lifecycle fl
JOIN sla_targets st ON fl.severity_text = st.severity
WHERE status = 'Active'
GROUP BY severity_text;
```

---

## Advanced Charts

### Vulnerability Density Heatmap

| Property | Value |
|----------|-------|
| **Function** | `_draw_heatmap_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `hostname`, `severity_text` |

```sql
SELECT
    hostname,
    severity_text,
    COUNT(*) as count
FROM finding_lifecycle
WHERE status = 'Active'
GROUP BY hostname, severity_text
ORDER BY hostname, severity_text;
```

### Bubble Chart

| Property | Value |
|----------|-------|
| **Function** | `_draw_bubble_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `cvss3_base_score`, `days_open`, `hostname` |

```sql
SELECT
    cvss3_base_score,
    days_open,
    severity_text,
    COUNT(DISTINCT hostname) as hosts_affected,
    COUNT(*) as finding_count
FROM finding_lifecycle
WHERE status = 'Active'
  AND cvss3_base_score IS NOT NULL
GROUP BY cvss3_base_score, days_open, severity_text;
```

### Category Treemap

| Property | Value |
|----------|-------|
| **Function** | `_draw_treemap_popout` |
| **Data Source** | lifecycle |
| **Smart Filter** | None |
| **Required Columns** | `plugin_family` (or derived category) |

```sql
SELECT
    COALESCE(plugin_family, 'Unknown') as category,
    COUNT(*) as count,
    SUM(severity_value) as risk_score
FROM finding_lifecycle
WHERE status = 'Active'
GROUP BY category
ORDER BY count DESC;
```

---

## KPI Calculations

### Remediation Rate

```sql
SELECT
    ROUND(
        CAST(SUM(CASE WHEN status = 'Remediated' THEN 1 ELSE 0 END) AS FLOAT) /
        CAST(COUNT(*) AS FLOAT) * 100,
    1) as remediation_rate_pct
FROM finding_lifecycle
WHERE status IN ('Active', 'Remediated');
```

### Reopen Rate

```sql
SELECT
    ROUND(
        CAST(SUM(CASE WHEN reappearances > 0 THEN 1 ELSE 0 END) AS FLOAT) /
        CAST(COUNT(*) AS FLOAT) * 100,
    1) as reopen_rate_pct
FROM finding_lifecycle;
```

### SLA Breach Rate

```sql
SELECT
    ROUND(
        CAST(SUM(CASE
            WHEN (severity_text = 'Critical' AND days_open > 15) OR
                 (severity_text = 'High' AND days_open > 30) OR
                 (severity_text = 'Medium' AND days_open > 60) OR
                 (severity_text = 'Low' AND days_open > 90)
            THEN 1 ELSE 0
        END) AS FLOAT) /
        CAST(COUNT(*) AS FLOAT) * 100,
    1) as breach_rate_pct
FROM finding_lifecycle
WHERE status = 'Active';
```

### Vulnerabilities Per Host

```sql
SELECT
    ROUND(
        CAST(COUNT(*) AS FLOAT) /
        CAST(COUNT(DISTINCT hostname) AS FLOAT),
    1) as vulns_per_host
FROM finding_lifecycle
WHERE status = 'Active';
```

---

## Filter Parameter Reference

All queries support these filter parameters:

| Parameter | Description | Example |
|-----------|-------------|---------|
| `{start_date}` | Filter start date | '2024-01-01' |
| `{end_date}` | Filter end date | '2024-12-31' |
| `{severity_filter}` | Severity level or 'All' | 'Critical' |
| `{status_filter}` | Status or 'All' | 'Active' |
| `{environment_filter}` | Environment or 'All' | 'Production' |

---

*Document Version: 1.0*
*Last Updated: December 2024*
