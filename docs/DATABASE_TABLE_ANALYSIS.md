# Database Table Dependency Analysis

## Table Overview

| Table | Purpose | Records Typical | Can Drop Safely? |
|-------|---------|-----------------|------------------|
| `historical_findings` | Raw scan data from Nessus exports | 10K-500K | ⚠️ PRIMARY - will lose all scan history |
| `finding_lifecycle` | Calculated finding status/tracking | 1K-50K | ✅ YES - Can regenerate from historical |
| `host_presence` | Host scanning history | 100-5K | ✅ YES - Can regenerate from historical |
| `scan_changes` | Delta between scans | 10-500 | ✅ YES - Can regenerate from historical |
| `opdir_mapping` | OPDIR/IAVA reference data | 1K-5K | ✅ YES - External reference, re-importable |
| `iavm_notices` | IAVM notice reference | 1K-10K | ✅ YES - External reference, re-importable |
| `stig_findings` | STIG checklist results | 1K-100K | ✅ YES - Re-import from .cklb files |
| `poam_entries` | POAM tracking items | 100-5K | ⚠️ CAUTION - May have manual entries |
| `host_overrides` | Manual host property edits | 0-500 | ⚠️ CAUTION - User-entered data |
| `export_summary` | Metadata about export | 1 | ✅ YES - Auto-regenerated on export |

---

## Dependency Graph

```
                    ┌─────────────────────┐
                    │ historical_findings │  ← PRIMARY SOURCE
                    │   (Raw Scan Data)   │
                    └──────────┬──────────┘
                               │
            ┌──────────────────┼──────────────────┐
            │                  │                  │
            ▼                  ▼                  ▼
    ┌───────────────┐  ┌──────────────┐  ┌──────────────┐
    │finding_lifecycle│  │ host_presence │  │ scan_changes │
    │  (Calculated)   │  │ (Calculated)  │  │ (Calculated) │
    └───────────────┘  └──────────────┘  └──────────────┘
            │
            │ (enriched by)
            ▼
    ┌───────────────┐
    │ opdir_mapping │  ← External reference (re-importable)
    │ iavm_notices  │
    └───────────────┘

    ┌───────────────┐     ┌───────────────┐
    │ stig_findings │     │  poam_entries │
    │   (Imported)  │     │   (Imported)  │
    └───────────────┘     └───────────────┘
           │                      │
           └──────────┬───────────┘
                      │ (linked by hostname/plugin)
                      ▼
              ┌───────────────┐
              │host_overrides │  ← User-entered
              └───────────────┘
```

---

## Table Drop Safety Assessment

### ✅ SAFE TO DROP (Regenerable)

#### `finding_lifecycle`
- **Dependencies:** None downstream
- **Regeneration:** Run lifecycle analysis on `historical_findings`
- **Data Loss Risk:** LOW - All data derivable from scans
- **Recommendation:** Safe to drop, will regenerate on next analysis

#### `host_presence`
- **Dependencies:** None downstream
- **Regeneration:** Run host presence analysis on `historical_findings`
- **Data Loss Risk:** LOW - All data derivable from scans
- **Recommendation:** Safe to drop, will regenerate on next analysis

#### `scan_changes`
- **Dependencies:** None downstream
- **Regeneration:** Run scan change analysis on `historical_findings`
- **Data Loss Risk:** LOW - All data derivable from scans
- **Recommendation:** Safe to drop, will regenerate on next analysis

#### `opdir_mapping`
- **Dependencies:** Enriches `finding_lifecycle` but not required
- **Regeneration:** Re-import OPDIR Excel file
- **Data Loss Risk:** LOW - External reference data
- **Recommendation:** Safe to drop, re-import from source file

#### `iavm_notices`
- **Dependencies:** Reference only
- **Regeneration:** Re-import IAVM XML file
- **Data Loss Risk:** LOW - External reference data
- **Recommendation:** Safe to drop, re-import from source file

#### `export_summary`
- **Dependencies:** None
- **Regeneration:** Auto-created on next export
- **Data Loss Risk:** NONE - Metadata only
- **Recommendation:** Safe to drop

### ⚠️ CAUTION (User Data)

#### `stig_findings`
- **Dependencies:** May link to `poam_entries`
- **Regeneration:** Re-import .cklb checklist files
- **Data Loss Risk:** MEDIUM - Need source files to regenerate
- **Recommendation:** Prompt for backup, ensure source files available

#### `poam_entries`
- **Dependencies:** May have manual status updates
- **Regeneration:** Re-import POAM Excel file
- **Data Loss Risk:** MEDIUM - Manual edits may be lost
- **Recommendation:** ALWAYS backup before drop

#### `host_overrides`
- **Dependencies:** None
- **Regeneration:** Cannot regenerate - user-entered data
- **Data Loss Risk:** HIGH - User manually entered this data
- **Recommendation:** ALWAYS backup before drop, warn user strongly

### ⛔ PRIMARY DATA (Critical)

#### `historical_findings`
- **Dependencies:** ALL other tables depend on this
- **Regeneration:** Re-import all .nessus files
- **Data Loss Risk:** CRITICAL - Source of all analysis
- **Recommendation:** Strongly discourage, require confirmation

---

## Deduplication Strategy

### What Constitutes a Duplicate?

Each table has different deduplication criteria:

| Table | Unique Key (Exclude import_date) |
|-------|----------------------------------|
| `historical_findings` | `plugin_id + hostname + scan_date + ip_address` |
| `finding_lifecycle` | `plugin_id + hostname + first_seen` |
| `host_presence` | `hostname` |
| `scan_changes` | `scan_date` |
| `stig_findings` | `hostname + stig_id + sv_id_base + stig_version + release_number` |
| `poam_entries` | `poam_id` or `control_id + hostname` |
| `host_overrides` | `hostname` |

### Deduplication SQL Templates

```sql
-- historical_findings deduplication
DELETE FROM historical_findings
WHERE rowid NOT IN (
    SELECT MIN(rowid) FROM historical_findings
    GROUP BY plugin_id, hostname, scan_date, ip_address
);

-- stig_findings deduplication (keep latest by version, not import_date)
DELETE FROM stig_findings
WHERE rowid NOT IN (
    SELECT MIN(rowid) FROM stig_findings
    GROUP BY hostname, stig_id, sv_id_base, stig_version, release_number
);

-- finding_lifecycle deduplication
DELETE FROM finding_lifecycle
WHERE rowid NOT IN (
    SELECT MIN(rowid) FROM finding_lifecycle
    GROUP BY plugin_id, hostname, first_seen
);
```

---

## Backup & Rollback Strategy

### Backup Process
1. Create timestamped backup file: `{table_name}_backup_{YYYYMMDD_HHMMSS}.db`
2. Copy entire table to backup database
3. Store backup path in memory for rollback option
4. Show backup location to user

### Rollback Process
1. User selects "Rollback" option
2. Read backed-up table from backup database
3. DROP current table
4. Recreate table from backup
5. Verify row counts match

### Backup Storage
```
{database_dir}/
├── main_database.db
└── backups/
    ├── historical_findings_backup_20241215_143022.db
    ├── stig_findings_backup_20241215_143156.db
    └── host_overrides_backup_20241215_144532.db
```

---

## Implementation Recommendations

### Drop Table UI Flow
```
1. User clicks "Drop Table" on selected table
2. System checks table type:
   - If CRITICAL (historical_findings):
     "⚠️ WARNING: This is your primary data source.
      Dropping will require re-importing all scan files.
      Are you absolutely sure? Type 'DELETE' to confirm."
   - If USER DATA (host_overrides, poam_entries):
     "⚠️ This table contains user-entered data that
      cannot be regenerated. Create backup first?"
     [Backup & Drop] [Cancel]
   - If REGENERABLE:
     "This table can be regenerated from source data.
      Create backup anyway?"
     [Backup & Drop] [Drop Only] [Cancel]
3. Create backup if requested
4. Drop table
5. Show success with rollback option
```

### Deduplication UI Flow
```
1. User clicks "Deduplicate" on selected table
2. System analyzes table:
   "Found {N} duplicate records out of {TOTAL}
    Deduplication will keep the earliest record for each unique key.

    Unique key: {columns used}

    Create backup before proceeding?"
3. Create backup
4. Run deduplication
5. Show results: "Removed {N} duplicates. {REMAINING} records remain."
6. Offer rollback if needed
```
