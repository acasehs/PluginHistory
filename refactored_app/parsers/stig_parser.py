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
    """Tracks checklist identity and version for deduplication."""
    hostname: str  # Extended hostname (e.g., server01_PRODDB)
    stig_id: str  # STIG benchmark ID
    stig_version: str  # e.g., "2"
    release_number: str  # e.g., "6"
    benchmark_date: str  # e.g., "02 Apr 2025"
    source_file: str  # Path to .cklb file
    file_mtime: Optional[float] = None  # File modification time
    checklist_id: str = ""  # UUID from checklist

    @property
    def checklist_key(self) -> str:
        """Composite key for identifying same host+STIG combination."""
        return f"{self.hostname}|{self.stig_id}"

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
                    checklist_id=checklist.checklist_id
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
                              existing_metadata: Dict[str, ChecklistMetadata] = None
                              ) -> Tuple[pd.DataFrame, List[STIGChecklist], Dict[str, Any]]:
    """
    Parse multiple .cklb files and return consolidated DataFrame with deduplication.

    Handles duplicate checklists by keeping only the newest version based on:
    1. STIG version
    2. Release number
    3. Benchmark date
    4. File modification time

    Args:
        file_paths: List of paths to .cklb files
        existing_metadata: Optional dict of existing checklist metadata (key -> metadata)
                          for incremental imports

    Returns:
        Tuple of:
        - DataFrame with all findings (deduplicated)
        - List of STIGChecklist objects (deduplicated)
        - Dict with import statistics (skipped, updated, new counts)
    """
    # Track metadata by checklist key (hostname|stig_id)
    metadata_tracker: Dict[str, ChecklistMetadata] = existing_metadata.copy() if existing_metadata else {}
    checklist_tracker: Dict[str, STIGChecklist] = {}
    rules_tracker: Dict[str, List[STIGRule]] = {}

    # Statistics
    stats = {
        'files_processed': 0,
        'files_skipped_older': 0,
        'files_skipped_duplicate': 0,
        'checklists_new': 0,
        'checklists_updated': 0,
        'skipped_details': []  # List of (file, reason) tuples
    }

    for file_path in file_paths:
        checklist = parse_cklb_file(file_path)
        if not checklist:
            continue

        stats['files_processed'] += 1

        # Extract metadata for each STIG in this checklist
        meta_list = extract_checklist_metadata(checklist, file_path)

        # Group rules by STIG ID for this checklist
        rules_by_stig: Dict[str, List[STIGRule]] = {}
        for rule in checklist.rules:
            if rule.stig_id not in rules_by_stig:
                rules_by_stig[rule.stig_id] = []
            rules_by_stig[rule.stig_id].append(rule)

        # Check each STIG in this file
        for meta in meta_list:
            key = meta.checklist_key

            if key in metadata_tracker:
                existing_meta = metadata_tracker[key]

                # Check if this is the exact same file (duplicate import)
                if meta.source_file == existing_meta.source_file:
                    stats['files_skipped_duplicate'] += 1
                    stats['skipped_details'].append((
                        os.path.basename(file_path),
                        f"Duplicate: already loaded"
                    ))
                    continue

                # Compare versions to see if new file is newer
                if meta.is_newer_than(existing_meta):
                    # New file is newer - update
                    logger.info(
                        f"Updating {key}: V{existing_meta.stig_version}R{existing_meta.release_number} "
                        f"-> V{meta.stig_version}R{meta.release_number}"
                    )
                    metadata_tracker[key] = meta
                    rules_tracker[key] = rules_by_stig.get(meta.stig_id, [])
                    stats['checklists_updated'] += 1
                else:
                    # Existing is newer or same - skip
                    stats['files_skipped_older'] += 1
                    stats['skipped_details'].append((
                        os.path.basename(file_path),
                        f"Older version: V{meta.stig_version}R{meta.release_number} "
                        f"(have V{existing_meta.stig_version}R{existing_meta.release_number})"
                    ))
                    logger.info(
                        f"Skipping older checklist for {key}: "
                        f"V{meta.stig_version}R{meta.release_number} "
                        f"(have V{existing_meta.stig_version}R{existing_meta.release_number})"
                    )
                    continue
            else:
                # New checklist
                metadata_tracker[key] = meta
                rules_tracker[key] = rules_by_stig.get(meta.stig_id, [])
                stats['checklists_new'] += 1

        # Track the checklist object (may contain multiple STIGs)
        checklist_tracker[file_path] = checklist

    # Collect all rules from tracked checklists
    all_rules = []
    for rules in rules_tracker.values():
        all_rules.extend(rules)

    if not all_rules:
        return pd.DataFrame(), list(checklist_tracker.values()), stats

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
            'checklist_id': rule.checklist_id
        })

    df = pd.DataFrame(data)

    # Log summary
    logger.info(
        f"STIG Import: {stats['files_processed']} files processed, "
        f"{stats['checklists_new']} new, {stats['checklists_updated']} updated, "
        f"{stats['files_skipped_older']} skipped (older), "
        f"{stats['files_skipped_duplicate']} skipped (duplicate)"
    )
    logger.info(f"Total: {len(df)} STIG findings from {len(checklist_tracker)} checklists")

    return df, list(checklist_tracker.values()), stats


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
