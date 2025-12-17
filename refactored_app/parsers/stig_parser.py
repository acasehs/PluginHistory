"""
STIG Checklist Parser for .cklb (JSON) files.

Parses DISA STIG Viewer 3 checklist files and extracts findings.
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import pandas as pd

logger = logging.getLogger(__name__)


# CAT severity mapping (DISA uses high/medium/low, we map to CAT I/II/III)
SEVERITY_TO_CAT = {
    'high': 'CAT I',
    'medium': 'CAT II',
    'low': 'CAT III',
    'unknown': 'Unknown'
}

# Status normalization
STATUS_MAPPING = {
    'not_reviewed': 'Not Reviewed',
    'not_applicable': 'Not Applicable',
    'open': 'Open',
    'not_a_finding': 'Not a Finding'
}


@dataclass
class ChecklistMetadata:
    """Tracks checklist identity and version for deduplication and history."""
    hostname: str  # Extended hostname (e.g., server01_PRODDB)
    stig_id: str  # STIG benchmark ID
    stig_version: str  # e.g., "2"
    release_number: str  # e.g., "6"
    benchmark_date: str  # e.g., "02 Apr 2025"
    source_file: str  # Path to .cklb file
    file_mtime: Optional[float] = None  # File modification time
    checklist_id: str = ""  # UUID from checklist
    checklist_date: Optional[datetime] = None  # Date from filename or file creation
    import_date: Optional[datetime] = None  # When this was imported

    @property
    def checklist_key(self) -> str:
        """Composite key for identifying same host+STIG combination."""
        return f"{self.hostname}|{self.stig_id}"

    @property
    def version_key(self) -> str:
        """Unique key including version for history tracking."""
        return f"{self.hostname}|{self.stig_id}|V{self.stig_version}R{self.release_number}"

    def is_newer_than(self, other: 'ChecklistMetadata') -> bool:
        """
        Determine if this checklist is newer than another.

        Comparison order:
        1. STIG version (higher = newer)
        2. Release number (higher = newer)
        3. Benchmark date (later = newer)
        4. File modification time (later = newer)
        """
        # Compare STIG version
        try:
            self_ver = int(self.stig_version) if self.stig_version else 0
            other_ver = int(other.stig_version) if other.stig_version else 0
            if self_ver != other_ver:
                return self_ver > other_ver
        except ValueError:
            pass

        # Compare release number
        try:
            self_rel = int(self.release_number) if self.release_number else 0
            other_rel = int(other.release_number) if other.release_number else 0
            if self_rel != other_rel:
                return self_rel > other_rel
        except ValueError:
            pass

        # Compare benchmark date
        self_date = parse_benchmark_date(self.benchmark_date)
        other_date = parse_benchmark_date(other.benchmark_date)
        if self_date and other_date and self_date != other_date:
            return self_date > other_date

        # Compare file modification time
        if self.file_mtime and other.file_mtime:
            return self.file_mtime > other.file_mtime

        return False


def parse_benchmark_date(date_str: str) -> Optional[datetime]:
    """Parse benchmark date string to datetime."""
    if not date_str:
        return None

    # Common formats: "02 Apr 2025", "2025-04-02", "04/02/2025"
    formats = [
        "%d %b %Y",  # 02 Apr 2025
        "%Y-%m-%d",  # 2025-04-02
        "%m/%d/%Y",  # 04/02/2025
        "%d-%b-%Y",  # 02-Apr-2025
    ]

    for fmt in formats:
        try:
            return datetime.strptime(date_str.strip(), fmt)
        except ValueError:
            continue

    return None


def extract_date_from_filename(file_path: str) -> Optional[datetime]:
    """
    Extract date from filename using common patterns.

    Standard format: mmddyyyy (e.g., 12152024)
    Also handles: mm-dd-yyyy, mm_dd_yyyy, yyyy-mm-dd, yyyymmdd

    Falls back to file creation/modification date if no date found in name.
    """
    filename = os.path.basename(file_path)
    name_without_ext = os.path.splitext(filename)[0]

    # Date patterns to try (ordered by preference)
    date_patterns = [
        # mmddyyyy (standard) - e.g., 12152024
        (r'(\d{2})(\d{2})(\d{4})', lambda m: f"{m.group(1)}/{m.group(2)}/{m.group(3)}", "%m/%d/%Y"),
        # mm-dd-yyyy or mm_dd_yyyy
        (r'(\d{2})[-_](\d{2})[-_](\d{4})', lambda m: f"{m.group(1)}/{m.group(2)}/{m.group(3)}", "%m/%d/%Y"),
        # yyyy-mm-dd or yyyy_mm_dd
        (r'(\d{4})[-_](\d{2})[-_](\d{2})', lambda m: f"{m.group(1)}-{m.group(2)}-{m.group(3)}", "%Y-%m-%d"),
        # yyyymmdd - e.g., 20241215
        (r'(\d{4})(\d{2})(\d{2})', lambda m: f"{m.group(1)}-{m.group(2)}-{m.group(3)}", "%Y-%m-%d"),
        # mm/dd/yyyy in filename (rare but possible)
        (r'(\d{2})/(\d{2})/(\d{4})', lambda m: f"{m.group(1)}/{m.group(2)}/{m.group(3)}", "%m/%d/%Y"),
    ]

    for pattern, formatter, date_fmt in date_patterns:
        match = re.search(pattern, name_without_ext)
        if match:
            try:
                date_str = formatter(match)
                parsed = datetime.strptime(date_str, date_fmt)
                # Sanity check: year should be reasonable (2000-2100)
                if 2000 <= parsed.year <= 2100:
                    return parsed
            except ValueError:
                continue

    # No date in filename - fall back to file dates
    try:
        # Try creation time first (Windows), then modification time
        stat = os.stat(file_path)
        # Use the earlier of ctime or mtime as "checklist date"
        file_time = min(stat.st_ctime, stat.st_mtime)
        return datetime.fromtimestamp(file_time)
    except OSError:
        return None


@dataclass
class STIGRule:
    """Represents a single STIG rule/finding."""
    # Identifiers
    stig_id: str  # Benchmark ID (e.g., "Windows_Server_2019_STIG")
    group_id: str  # V-ID (e.g., "V-205625")
    rule_id: str  # SV-ID with rule (e.g., "SV-205625r569188_rule")
    rule_version: str  # Rule version (e.g., "WN19-00-000010")

    # Base SV ID without rule suffix (for tracking across revisions)
    sv_id_base: str  # Just "SV-205625"

    # Content
    rule_title: str
    severity: str  # high, medium, low
    cat_severity: str  # CAT I, CAT II, CAT III
    status: str  # Open, Not a Finding, Not Applicable, Not Reviewed

    # Reference content
    check_content: str
    fix_text: str
    discussion: str

    # Finding details (user-entered)
    finding_details: str
    comments: str

    # Target system
    hostname: str
    ip_address: str

    # STIG metadata
    stig_name: str
    stig_display_name: str
    release_info: str
    stig_version: str  # e.g., "2"
    release_number: str  # e.g., "6"
    benchmark_date: str  # e.g., "02 Apr 2025"

    # CCI references
    ccis: List[str] = field(default_factory=list)
    legacy_ids: List[str] = field(default_factory=list)

    # Timestamps
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    # Source file
    source_file: str = ""
    checklist_id: str = ""

    # History tracking fields
    checklist_date: Optional[datetime] = None  # Date from filename or file creation
    import_date: Optional[datetime] = None  # When this record was imported
    is_current: bool = True  # True if this is the latest version for this host+STIG
    is_superseded: bool = False  # True if a newer STIG version exists


@dataclass
class STIGChecklist:
    """Represents a complete STIG checklist file."""
    title: str
    checklist_id: str
    cklb_version: str

    # Target system info
    hostname: str
    ip_address: str
    mac_address: str
    fqdn: str
    target_type: str
    role: str
    comments: str

    # STIGs in this checklist
    stigs: List[Dict[str, Any]] = field(default_factory=list)

    # All rules
    rules: List[STIGRule] = field(default_factory=list)

    # Source
    source_file: str = ""


def extract_sv_base_id(rule_id: str) -> str:
    """
    Extract base SV ID from rule_id, removing revision and rule suffix.

    Examples:
        'SV-205625r569188_rule' -> 'SV-205625'
        'SV-205625r1_rule' -> 'SV-205625'
        'SV-205625' -> 'SV-205625'
    """
    if not rule_id:
        return ""

    # Match SV-NNNNN pattern at the start
    match = re.match(r'(SV-\d+)', rule_id)
    if match:
        return match.group(1)

    return rule_id


def parse_datetime(dt_string: Optional[str]) -> Optional[datetime]:
    """Parse datetime string from STIG file."""
    if not dt_string:
        return None

    try:
        # Try ISO format first
        return datetime.fromisoformat(dt_string.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        pass

    try:
        # Try common formats
        for fmt in ['%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d']:
            try:
                return datetime.strptime(dt_string, fmt)
            except ValueError:
                continue
    except Exception:
        pass

    return None


def parse_release_info(release_info: str) -> Dict[str, str]:
    """
    Parse the release_info field to extract release number and benchmark date.

    Example input: "Release: 6 Benchmark Date: 02 Apr 2025"
    Returns: {'release': '6', 'benchmark_date': '02 Apr 2025'}
    """
    result = {'release': '', 'benchmark_date': ''}

    if not release_info:
        return result

    # Extract release number
    release_match = re.search(r'Release:\s*(\d+)', release_info, re.IGNORECASE)
    if release_match:
        result['release'] = release_match.group(1)

    # Extract benchmark date
    date_match = re.search(r'Benchmark Date:\s*(.+?)(?:$|\s*Release)', release_info, re.IGNORECASE)
    if date_match:
        result['benchmark_date'] = date_match.group(1).strip()
    else:
        # Try alternate pattern - date at end
        date_match = re.search(r'Benchmark Date:\s*(.+)$', release_info, re.IGNORECASE)
        if date_match:
            result['benchmark_date'] = date_match.group(1).strip()

    return result


def parse_cklb_file(file_path: str) -> Optional[STIGChecklist]:
    """
    Parse a .cklb (JSON) STIG checklist file.

    Args:
        file_path: Path to the .cklb file

    Returns:
        STIGChecklist object or None if parsing fails
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Extract checklist date from filename or file creation
        checklist_date = extract_date_from_filename(file_path)
        import_date = datetime.now()

        # Extract target data
        target_data = data.get('target_data', {})

        checklist = STIGChecklist(
            title=data.get('title', ''),
            checklist_id=data.get('id', ''),
            cklb_version=data.get('cklb_version', '1.0'),
            hostname=target_data.get('host_name', ''),
            ip_address=target_data.get('ip_address', ''),
            mac_address=target_data.get('mac_address', ''),
            fqdn=target_data.get('fqdn', ''),
            target_type=target_data.get('target_type', ''),
            role=target_data.get('role', ''),
            comments=target_data.get('comments', ''),
            source_file=str(file_path)
        )

        # Parse each STIG in the checklist
        for stig in data.get('stigs', []):
            stig_info = {
                'stig_name': stig.get('stig_name', ''),
                'display_name': stig.get('display_name', ''),
                'stig_id': stig.get('stig_id', ''),
                'release_info': stig.get('release_info', ''),
                'uuid': stig.get('uuid', ''),
                'size': stig.get('size', 0)
            }
            checklist.stigs.append(stig_info)

            # Parse release info for this STIG
            release_info = stig.get('release_info', '')
            parsed_release = parse_release_info(release_info)
            stig_version = str(stig.get('version', ''))

            # Parse rules within this STIG
            for rule in stig.get('rules', []):
                severity = rule.get('severity', 'unknown')
                cat_severity = SEVERITY_TO_CAT.get(severity.lower(), 'Unknown')

                raw_status = rule.get('status', 'not_reviewed')
                status = STATUS_MAPPING.get(raw_status, raw_status)

                rule_id = rule.get('rule_id', '')
                sv_base = extract_sv_base_id(rule_id)

                stig_rule = STIGRule(
                    stig_id=stig.get('stig_id', ''),
                    group_id=rule.get('group_id', ''),
                    rule_id=rule_id,
                    rule_version=rule.get('rule_version', ''),
                    sv_id_base=sv_base,
                    rule_title=rule.get('rule_title', ''),
                    severity=severity,
                    cat_severity=cat_severity,
                    status=status,
                    check_content=rule.get('check_content', '') or '',
                    fix_text=rule.get('fix_text', '') or '',
                    discussion=rule.get('discussion', '') or '',
                    finding_details=rule.get('finding_details', '') or '',
                    comments=rule.get('comments', '') or '',
                    hostname=checklist.hostname,
                    ip_address=checklist.ip_address,
                    stig_name=stig.get('stig_name', ''),
                    stig_display_name=stig.get('display_name', ''),
                    release_info=release_info,
                    stig_version=stig_version,
                    release_number=parsed_release['release'],
                    benchmark_date=parsed_release['benchmark_date'],
                    ccis=rule.get('ccis', []) or [],
                    legacy_ids=rule.get('legacy_ids', []) or [],
                    created_at=parse_datetime(rule.get('createdAt')),
                    updated_at=parse_datetime(rule.get('updatedAt')),
                    source_file=str(file_path),
                    checklist_id=checklist.checklist_id,
                    checklist_date=checklist_date,
                    import_date=import_date,
                    is_current=True,  # Will be updated by parse_multiple_cklb_files
                    is_superseded=False  # Will be updated by parse_multiple_cklb_files
                )

                checklist.rules.append(stig_rule)

        logger.info(f"Parsed {len(checklist.rules)} rules from {file_path}")
        return checklist

    except json.JSONDecodeError as e:
        logger.error(f"JSON parse error in {file_path}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error parsing STIG checklist {file_path}: {e}")
        return None


def extract_checklist_metadata(checklist: STIGChecklist, file_path: str) -> List[ChecklistMetadata]:
    """
    Extract metadata for each STIG in a checklist file.

    A single .cklb file can contain multiple STIGs (e.g., Windows Server + IIS).
    Returns one ChecklistMetadata per STIG in the file.
    """
    metadata_list = []

    # Get file modification time
    try:
        file_mtime = os.path.getmtime(file_path)
    except OSError:
        file_mtime = None

    for stig_info in checklist.stigs:
        # Parse release info for this specific STIG
        release_info = stig_info.get('release_info', '')
        parsed = parse_release_info(release_info)

        metadata = ChecklistMetadata(
            hostname=checklist.hostname,
            stig_id=stig_info.get('stig_id', ''),
            stig_version=str(stig_info.get('version', '')),
            release_number=parsed['release'],
            benchmark_date=parsed['benchmark_date'],
            source_file=file_path,
            file_mtime=file_mtime,
            checklist_id=checklist.checklist_id
        )
        metadata_list.append(metadata)

    return metadata_list


def parse_multiple_cklb_files(file_paths: List[str],
                              existing_df: pd.DataFrame = None,
                              keep_history: bool = True
                              ) -> Tuple[pd.DataFrame, List[STIGChecklist], Dict[str, Any]]:
    """
    Parse multiple .cklb files and return consolidated DataFrame with history tracking.

    Keeps all versions for history tracking, marking older versions as superseded.
    Tracks changes between versions for impact analysis.

    Args:
        file_paths: List of paths to .cklb files
        existing_df: Optional existing DataFrame to merge with (for incremental imports)
        keep_history: If True, keep all versions; if False, only keep latest

    Returns:
        Tuple of:
        - DataFrame with all findings (with history if enabled)
        - List of STIGChecklist objects
        - Dict with import statistics and impact analysis
    """
    all_checklists = []
    all_rules: List[STIGRule] = []

    # Statistics
    stats = {
        'files_processed': 0,
        'files_skipped_duplicate': 0,
        'checklists_new': 0,
        'checklists_historical': 0,
        'skipped_details': [],
        'impact_analysis': {
            'findings_changed': [],  # List of (hostname, stig_id, rule_id, old_status, new_status)
            'new_findings': 0,
            'remediated': 0,
            'regressed': 0,
            'unchanged': 0
        }
    }

    # Track seen version keys to prevent exact duplicates
    seen_version_keys = set()

    # If we have existing data, track what we already have
    existing_rules_by_key = {}
    if existing_df is not None and not existing_df.empty:
        for _, row in existing_df.iterrows():
            # Create version key: hostname|stig_id|version|release
            ver_key = f"{row['hostname']}|{row['stig_id']}|V{row['stig_version']}R{row['release_number']}"
            seen_version_keys.add(ver_key)

            # Track by rule key for impact analysis
            rule_key = f"{row['hostname']}|{row['stig_id']}|{row['sv_id_base']}"
            if rule_key not in existing_rules_by_key:
                existing_rules_by_key[rule_key] = []
            existing_rules_by_key[rule_key].append(row)

    # Parse all files
    for file_path in file_paths:
        checklist = parse_cklb_file(file_path)
        if not checklist:
            continue

        stats['files_processed'] += 1
        all_checklists.append(checklist)

        # Check for duplicate CHECKLISTS (not rules) by version key
        # Build checklist-level keys from the first rule or STIG info
        checklist_is_duplicate = False
        checklist_ver_keys = set()

        # Get version keys for each STIG in this checklist
        for stig_info in checklist.stigs:
            parsed = parse_release_info(stig_info.get('release_info', ''))
            ver_key = f"{checklist.hostname}|{stig_info.get('stig_id', '')}|V{stig_info.get('version', '')}R{parsed['release']}"
            checklist_ver_keys.add(ver_key)

            if ver_key in seen_version_keys:
                checklist_is_duplicate = True

        if checklist_is_duplicate:
            stats['files_skipped_duplicate'] += 1
            stats['skipped_details'].append(f"Duplicate: {file_path}")
            continue

        # Add all version keys for this checklist
        seen_version_keys.update(checklist_ver_keys)

        # Add ALL rules from this non-duplicate checklist
        for rule in checklist.rules:
            all_rules.append(rule)

            # Track if this is a new checklist or historical
            rule_key = f"{rule.hostname}|{rule.stig_id}|{rule.sv_id_base}"
            if rule_key in existing_rules_by_key:
                stats['checklists_historical'] += 1

                # Impact analysis - check for status changes
                existing = existing_rules_by_key[rule_key]
                # Find the most recent existing entry for this rule
                latest_existing = max(existing, key=lambda r: (
                    int(r.get('stig_version', 0) or 0),
                    int(r.get('release_number', 0) or 0)
                ))

                old_status = latest_existing.get('status', '')
                new_status = rule.status

                if old_status != new_status:
                    stats['impact_analysis']['findings_changed'].append({
                        'hostname': rule.hostname,
                        'stig_id': rule.stig_id,
                        'rule_id': rule.rule_id,
                        'rule_title': rule.rule_title[:50] + '...' if len(rule.rule_title) > 50 else rule.rule_title,
                        'old_status': old_status,
                        'new_status': new_status,
                        'old_version': f"V{latest_existing.get('stig_version')}R{latest_existing.get('release_number')}",
                        'new_version': f"V{rule.stig_version}R{rule.release_number}"
                    })

                    # Categorize the change
                    if old_status == 'Open' and new_status in ('Not a Finding', 'Not Applicable'):
                        stats['impact_analysis']['remediated'] += 1
                    elif old_status in ('Not a Finding', 'Not Applicable') and new_status == 'Open':
                        stats['impact_analysis']['regressed'] += 1
                else:
                    stats['impact_analysis']['unchanged'] += 1
            else:
                stats['checklists_new'] += 1
                stats['impact_analysis']['new_findings'] += 1

    if not all_rules:
        return pd.DataFrame(), all_checklists, stats

    # Determine is_current and is_superseded for all rules
    # Group rules by hostname|stig_id to find latest versions
    rules_by_checklist_key: Dict[str, List[STIGRule]] = {}
    for rule in all_rules:
        key = f"{rule.hostname}|{rule.stig_id}"
        if key not in rules_by_checklist_key:
            rules_by_checklist_key[key] = []
        rules_by_checklist_key[key].append(rule)

    # Mark is_current and is_superseded
    for key, rules in rules_by_checklist_key.items():
        # Sort by version (newest first)
        rules.sort(key=lambda r: (
            int(r.stig_version) if r.stig_version else 0,
            int(r.release_number) if r.release_number else 0
        ), reverse=True)

        # Find the max version/release
        max_version = max(int(r.stig_version) if r.stig_version else 0 for r in rules)
        max_release_for_version = {}
        for r in rules:
            ver = int(r.stig_version) if r.stig_version else 0
            rel = int(r.release_number) if r.release_number else 0
            if ver not in max_release_for_version:
                max_release_for_version[ver] = rel
            else:
                max_release_for_version[ver] = max(max_release_for_version[ver], rel)

        # Update flags
        for rule in rules:
            ver = int(rule.stig_version) if rule.stig_version else 0
            rel = int(rule.release_number) if rule.release_number else 0

            # is_current: True if this is the latest version+release
            rule.is_current = (ver == max_version and rel == max_release_for_version.get(ver, 0))

            # is_superseded: True if a newer version exists
            rule.is_superseded = not rule.is_current

    # Convert to DataFrame
    data = []
    for rule in all_rules:
        data.append({
            'stig_id': rule.stig_id,
            'group_id': rule.group_id,
            'rule_id': rule.rule_id,
            'sv_id_base': rule.sv_id_base,
            'rule_version': rule.rule_version,
            'rule_title': rule.rule_title,
            'severity': rule.severity,
            'cat_severity': rule.cat_severity,
            'status': rule.status,
            'check_content': rule.check_content,
            'fix_text': rule.fix_text,
            'discussion': rule.discussion,
            'finding_details': rule.finding_details,
            'comments': rule.comments,
            'hostname': rule.hostname,
            'ip_address': rule.ip_address,
            'stig_name': rule.stig_name,
            'stig_display_name': rule.stig_display_name,
            'release_info': rule.release_info,
            'stig_version': rule.stig_version,
            'release_number': rule.release_number,
            'benchmark_date': rule.benchmark_date,
            'ccis': ','.join(rule.ccis) if rule.ccis else '',
            'legacy_ids': ','.join(rule.legacy_ids) if rule.legacy_ids else '',
            'created_at': rule.created_at,
            'updated_at': rule.updated_at,
            'source_file': rule.source_file,
            'checklist_id': rule.checklist_id,
            'checklist_date': rule.checklist_date,
            'import_date': rule.import_date,
            'is_current': rule.is_current,
            'is_superseded': rule.is_superseded
        })

    df = pd.DataFrame(data)

    # If we have existing data and keep_history, merge
    if existing_df is not None and not existing_df.empty and keep_history:
        # Add history columns to existing if missing
        for col in ['checklist_date', 'import_date', 'is_current', 'is_superseded']:
            if col not in existing_df.columns:
                if col in ['is_current']:
                    existing_df[col] = False  # Old data is no longer current
                elif col in ['is_superseded']:
                    existing_df[col] = True  # Old data is superseded
                else:
                    existing_df[col] = None

        # Mark existing data as superseded if we have newer versions
        existing_df['is_superseded'] = True
        existing_df['is_current'] = False

        # Merge
        df = pd.concat([existing_df, df], ignore_index=True)

        # Re-calculate is_current across all data
        df = _recalculate_current_flags(df)

    # Log summary
    impact = stats['impact_analysis']
    logger.info(
        f"STIG Import: {stats['files_processed']} files, "
        f"{stats['checklists_new']} new findings, {stats['checklists_historical']} historical"
    )
    if impact['findings_changed']:
        logger.info(
            f"Impact: {impact['remediated']} remediated, {impact['regressed']} regressed, "
            f"{len(impact['findings_changed'])} status changes"
        )

    return df, all_checklists, stats


def _recalculate_current_flags(df: pd.DataFrame) -> pd.DataFrame:
    """Recalculate is_current and is_superseded flags across entire DataFrame."""
    if df.empty:
        return df

    df = df.copy()
    df['is_current'] = False
    df['is_superseded'] = True

    # Group by hostname|stig_id|sv_id_base (same rule on same host)
    for (hostname, stig_id, sv_id_base), group in df.groupby(['hostname', 'stig_id', 'sv_id_base']):
        if len(group) == 0:
            continue

        # Find the latest version
        latest_idx = group.apply(
            lambda r: (int(r['stig_version']) if r['stig_version'] else 0,
                      int(r['release_number']) if r['release_number'] else 0),
            axis=1
        ).idxmax()

        df.loc[latest_idx, 'is_current'] = True
        df.loc[latest_idx, 'is_superseded'] = False

    return df


def get_stig_summary(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Generate summary statistics for STIG findings.

    Args:
        df: DataFrame with STIG findings

    Returns:
        Dictionary with summary statistics
    """
    if df.empty:
        return {
            'total_findings': 0,
            'by_status': {},
            'by_cat': {},
            'by_stig': {},
            'unique_hosts': 0,
            'unique_rules': 0,
            'open_findings': 0
        }

    # Filter to only Open findings for "findings" count
    open_df = df[df['status'] == 'Open']

    summary = {
        'total_rules': len(df),
        'total_findings': len(open_df),  # Only count Open as actual findings
        'by_status': df['status'].value_counts().to_dict(),
        'by_cat': df['cat_severity'].value_counts().to_dict(),
        'by_stig': df['stig_id'].value_counts().to_dict(),
        'unique_hosts': df['hostname'].nunique(),
        'unique_rules': df['sv_id_base'].nunique(),
        'open_by_cat': open_df['cat_severity'].value_counts().to_dict() if not open_df.empty else {}
    }

    return summary


def get_consolidated_findings(df: pd.DataFrame, status_filter: Optional[List[str]] = None) -> pd.DataFrame:
    """
    Get consolidated unique findings across all hosts.

    Groups by SV base ID to track unique settings regardless of rule revision.

    Args:
        df: DataFrame with STIG findings
        status_filter: Optional list of statuses to include (default: ['Open'])

    Returns:
        DataFrame with consolidated findings
    """
    if df.empty:
        return pd.DataFrame()

    if status_filter is None:
        status_filter = ['Open']

    # Filter by status
    filtered = df[df['status'].isin(status_filter)].copy()

    if filtered.empty:
        return pd.DataFrame()

    # Group by sv_id_base (unique setting across revisions)
    consolidated = filtered.groupby('sv_id_base').agg({
        'group_id': 'first',
        'rule_id': 'first',  # Keep newest rule_id
        'rule_version': 'first',
        'rule_title': 'first',
        'severity': 'first',
        'cat_severity': 'first',
        'check_content': 'first',
        'fix_text': 'first',
        'discussion': 'first',
        'stig_id': 'first',
        'stig_name': 'first',
        'release_info': 'first',
        'hostname': lambda x: list(x.unique()),
        'ccis': 'first',
        'status': 'first'
    }).reset_index()

    # Add host count
    consolidated['host_count'] = consolidated['hostname'].apply(len)
    consolidated['total_instances'] = filtered.groupby('sv_id_base').size().values

    return consolidated


def export_stig_findings_to_excel(df: pd.DataFrame, output_path: str) -> bool:
    """
    Export STIG findings to Excel with multiple sheets.

    Args:
        df: DataFrame with STIG findings
        output_path: Path for output Excel file

    Returns:
        True if successful, False otherwise
    """
    try:
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            # All findings
            df.to_excel(writer, sheet_name='All Findings', index=False)

            # Open findings only
            open_df = df[df['status'] == 'Open']
            if not open_df.empty:
                open_df.to_excel(writer, sheet_name='Open Findings', index=False)

            # Consolidated unique settings
            consolidated = get_consolidated_findings(df)
            if not consolidated.empty:
                # Convert hostname list to string for Excel
                consolidated_export = consolidated.copy()
                consolidated_export['hostname'] = consolidated_export['hostname'].apply(
                    lambda x: ', '.join(x) if isinstance(x, list) else x
                )
                consolidated_export.to_excel(writer, sheet_name='Unique Settings', index=False)

            # Summary by CAT
            if not df.empty:
                cat_summary = df.groupby(['cat_severity', 'status']).size().unstack(fill_value=0)
                cat_summary.to_excel(writer, sheet_name='CAT Summary')

            # Summary by STIG
            if not df.empty:
                stig_summary = df.groupby(['stig_id', 'status']).size().unstack(fill_value=0)
                stig_summary.to_excel(writer, sheet_name='STIG Summary')

        logger.info(f"Exported STIG findings to {output_path}")
        return True

    except Exception as e:
        logger.error(f"Error exporting STIG findings: {e}")
        return False
