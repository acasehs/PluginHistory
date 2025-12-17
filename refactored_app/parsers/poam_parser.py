"""
POAM (Plan of Action and Milestones) Parser Module
Parses POAM Excel exports and provides matching to findings/STIGs.
"""

import pandas as pd
import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# Known POAM status values (allow custom values)
KNOWN_POAM_STATUSES = [
    'Not Started',
    'Started',
    'Complete',
    'Ongoing',
    'Risk Accepted',
    'Delayed',
    'Closed',
    'Open'
]

# Severity mappings
SEVERITY_LEVELS = ['Critical', 'High', 'Medium', 'Low', 'CAT I', 'CAT II', 'CAT III']

# Risk level mappings
RISK_LEVELS = ['Very High', 'High', 'Moderate', 'Low', 'Very Low']


@dataclass
class POAMEntry:
    """Represents a single POAM entry."""
    # Core identifiers
    poam_id: str
    gpm_uid: str  # Composite key: rule_id.hostname

    # Authorization and ownership
    authorization_package: str = ''
    poam_owner: str = ''
    name: str = ''

    # Dates
    date_identified: Optional[datetime] = None
    estimated_start_date: Optional[datetime] = None
    estimated_completion_date: Optional[datetime] = None
    actual_start_date: Optional[datetime] = None
    actual_completion_date: Optional[datetime] = None

    # Source and status
    source_identifying_weakness: str = ''
    poam_status: str = 'Not Started'

    # Severity and risk
    severity: str = ''
    mitigated_severity: str = ''
    calculated_risk_level: str = ''
    mitigated_risk_level: str = ''
    subjective_mitigated_risk_level: str = ''

    # Vulnerability mapping
    vulnerability_library_rule_id: str = ''  # Plugin ID or SV-####r####_rule
    allocated_control: str = ''
    source_checklist: str = ''

    # Weakness details
    weaknesses: str = ''
    weakness: str = ''
    library_description: str = ''

    # Mitigation and comments
    mitigations: str = ''
    comments: str = ''

    # Affected systems (may be multiple, newline-separated)
    affected_hardware: str = ''
    affected_hardware_list: List[str] = field(default_factory=list)

    # CVSS Base metrics
    attack_vector: str = ''
    attack_complexity: str = ''
    privileges_required: str = ''
    user_interaction: str = ''
    scope: str = ''
    confidentiality_impact: str = ''
    integrity_impact: str = ''
    availability_impact: str = ''

    # CVSS Temporal metrics
    exploit_code_maturity: str = ''
    remediation_level: str = ''
    report_confidence: str = ''

    # CVSS Environmental metrics
    confidentiality_requirement: str = ''
    integrity_requirement: str = ''
    availability_requirement: str = ''

    # CVSS Modified metrics
    modified_attack_vector: str = ''
    modified_attack_complexity: str = ''
    modified_privileges_required: str = ''
    modified_user_interaction: str = ''
    modified_scope: str = ''
    modified_confidentiality_impact: str = ''
    modified_integrity_impact: str = ''
    modified_availability_impact: str = ''

    # CVSS Scores
    cvss_base_score: Optional[float] = None
    cvss_temporal_score: Optional[float] = None
    cvss_environmental_score: Optional[float] = None
    cvss_overall_score: Optional[float] = None

    # Change request tracking
    responsible_team: str = ''
    cr: str = ''
    cr_tracability: str = ''
    cr_status: str = ''

    # Environment and consolidation
    environment: str = ''
    consolidated_row_count: int = 1

    # Derived fields
    is_plugin_id: bool = False  # True if rule_id is Nessus plugin
    is_stig_rule: bool = False  # True if rule_id is SV-####
    plugin_id: str = ''  # Extracted plugin ID
    sv_id_base: str = ''  # Extracted SV ID without revision
    rule_revision: str = ''  # Rule revision if STIG

    # Source file tracking
    source_file: str = ''


def parse_date(value: Any) -> Optional[datetime]:
    """Parse various date formats to datetime."""
    if pd.isna(value) or value is None or value == '':
        return None

    if isinstance(value, datetime):
        return value

    if isinstance(value, pd.Timestamp):
        return value.to_pydatetime()

    if isinstance(value, str):
        # Try various date formats
        date_formats = [
            '%Y-%m-%d',
            '%m/%d/%Y',
            '%m-%d-%Y',
            '%d/%m/%Y',
            '%Y/%m/%d',
            '%B %d, %Y',
            '%b %d, %Y',
        ]
        for fmt in date_formats:
            try:
                return datetime.strptime(value.strip(), fmt)
            except ValueError:
                continue

    return None


def parse_float(value: Any) -> Optional[float]:
    """Parse value to float, handling various formats."""
    if pd.isna(value) or value is None or value == '':
        return None

    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def parse_int(value: Any) -> int:
    """Parse value to int with default of 1."""
    if pd.isna(value) or value is None or value == '':
        return 1

    try:
        return int(float(value))
    except (ValueError, TypeError):
        return 1


def parse_affected_hardware(value: Any) -> List[str]:
    """Parse affected hardware field which may contain multiple hosts."""
    if pd.isna(value) or value is None or value == '':
        return []

    value_str = str(value).strip()

    # Split by newline (carriage return), comma, or semicolon
    # Handle Windows (\r\n), Unix (\n), and Mac (\r) line endings
    hosts = re.split(r'[\r\n,;]+', value_str)

    # Clean up each hostname
    cleaned = []
    for host in hosts:
        host = host.strip()
        if host:
            cleaned.append(host)

    return cleaned


def extract_rule_id_info(rule_id: str) -> Dict[str, Any]:
    """
    Extract information from Vulnerability Library (Rule ID).

    Returns dict with:
    - is_plugin_id: True if Nessus plugin ID
    - is_stig_rule: True if STIG SV rule
    - plugin_id: Extracted plugin ID (if applicable)
    - sv_id_base: SV ID without revision (if applicable)
    - rule_revision: Rule revision number (if applicable)
    """
    result = {
        'is_plugin_id': False,
        'is_stig_rule': False,
        'plugin_id': '',
        'sv_id_base': '',
        'rule_revision': ''
    }

    if not rule_id:
        return result

    rule_id = str(rule_id).strip()

    # Check for STIG SV rule format: SV-######r######_rule
    sv_match = re.match(r'(SV-\d+)(r\d+)?(_rule)?', rule_id, re.IGNORECASE)
    if sv_match:
        result['is_stig_rule'] = True
        result['sv_id_base'] = sv_match.group(1).upper()
        if sv_match.group(2):
            result['rule_revision'] = sv_match.group(2)
        return result

    # Check for pure numeric (Nessus Plugin ID)
    if rule_id.isdigit():
        result['is_plugin_id'] = True
        result['plugin_id'] = rule_id
        return result

    # Try to extract numeric plugin ID from mixed format
    numeric_match = re.search(r'^(\d+)', rule_id)
    if numeric_match:
        result['is_plugin_id'] = True
        result['plugin_id'] = numeric_match.group(1)
        return result

    return result


def parse_poam_excel(file_path: str, return_mapping_info: bool = False) -> Tuple[pd.DataFrame, List[POAMEntry], Optional[Dict]]:
    """
    Parse a POAM Excel file.

    Args:
        file_path: Path to the Excel file
        return_mapping_info: If True, returns column mapping details as third element

    Returns:
        Tuple of (DataFrame with all data, List of POAMEntry objects, Optional mapping_info dict)
        mapping_info contains:
            - mapped_columns: dict of {original_col: internal_name}
            - unmapped_columns: list of column names not recognized
            - missing_required: list of required columns not found
    """
    logger.info(f"Parsing POAM file: {file_path}")

    try:
        # Read Excel file
        df = pd.read_excel(file_path, engine='openpyxl')
        logger.info(f"Read {len(df)} rows from POAM file")

    except Exception as e:
        logger.error(f"Error reading POAM file: {e}")
        raise

    # Normalize column names (strip whitespace, handle variations)
    df.columns = df.columns.str.strip()

    # Column mapping for common variations
    column_mapping = {
        'POAM ID': 'poam_id',
        'Authorization Package (Authorization Package Name)': 'authorization_package',
        'Authorization Package': 'authorization_package',
        'POAM Owner': 'poam_owner',
        'Name': 'name',
        'Date Identified': 'date_identified',
        'Source Identifying Weakness': 'source_identifying_weakness',
        'POAM Status': 'poam_status',
        'Severity': 'severity',
        'Mitigated Severity': 'mitigated_severity',
        'Calculated Risk Level': 'calculated_risk_level',
        'Mitigated Risk Level': 'mitigated_risk_level',
        'Estimated Start Date': 'estimated_start_date',
        'Estimated Completion Date': 'estimated_completion_date',
        'Actual Start Date': 'actual_start_date',
        'Actual Completion Date': 'actual_completion_date',
        'Vulnerability Library (Rule ID)': 'vulnerability_library_rule_id',
        'Vulnerability Library': 'vulnerability_library_rule_id',
        'Rule ID': 'vulnerability_library_rule_id',
        'Allocated Control': 'allocated_control',
        'Subjective Mitigated Risk Level': 'subjective_mitigated_risk_level',
        'Weaknesses': 'weaknesses',
        'Source Checklist': 'source_checklist',
        'Mitigations': 'mitigations',
        'Comments': 'comments',
        'Affected Hardware (Hardware Name)': 'affected_hardware',
        'Affected Hardware': 'affected_hardware',
        'Hardware Name': 'affected_hardware',
        'Attack Vector': 'attack_vector',
        'Attack Complexity': 'attack_complexity',
        'Privileges Required': 'privileges_required',
        'User Interaction': 'user_interaction',
        'Scope': 'scope',
        'Confidentiality Impact': 'confidentiality_impact',
        'Integrity Impact': 'integrity_impact',
        'Availability Impact': 'availability_impact',
        'Exploit Code Maturity': 'exploit_code_maturity',
        'Remediation Level': 'remediation_level',
        'Report Confidence': 'report_confidence',
        'Confidentiality Requirement': 'confidentiality_requirement',
        'Integrity Requirement': 'integrity_requirement',
        'Availability Requirement': 'availability_requirement',
        'Modified Attack Vector': 'modified_attack_vector',
        'Modified Attack Complexity': 'modified_attack_complexity',
        'Modified Privileges Required': 'modified_privileges_required',
        'Modified User Interaction': 'modified_user_interaction',
        'Modified Scope': 'modified_scope',
        'Modified Confidentiality Impact': 'modified_confidentiality_impact',
        'Modified Integrity Impact': 'modified_integrity_impact',
        'Modified Availability Impact': 'modified_availability_impact',
        'CVSS Base Score': 'cvss_base_score',
        'CVSS Temporal Score': 'cvss_temporal_score',
        'CVSS Environmental Score': 'cvss_environmental_score',
        'CVSS Overall Score': 'cvss_overall_score',
        'Responsible Team': 'responsible_team',
        'CR': 'cr',
        'CR Tracability': 'cr_tracability',
        'CR Traceability': 'cr_tracability',
        'CR Status': 'cr_status',
        'Environment': 'environment',
        'Weakness': 'weakness',
        'Library Description': 'library_description',
        'GPM UID': 'gpm_uid',
        'GPM.UID': 'gpm_uid',
        'Consolidated_Row_Count': 'consolidated_row_count',
        'Consolidated Row Count': 'consolidated_row_count',
    }

    # Rename columns that match and track mapping info
    rename_cols = {}
    mapped_columns = {}
    unmapped_columns = []

    for orig_col in df.columns:
        if orig_col in column_mapping:
            rename_cols[orig_col] = column_mapping[orig_col]
            mapped_columns[orig_col] = column_mapping[orig_col]
        else:
            unmapped_columns.append(orig_col)

    df = df.rename(columns=rename_cols)

    # Check for required columns
    required_columns = ['gpm_uid']  # GPM UID is the key for matching
    missing_required = [col for col in required_columns if col not in df.columns]

    mapping_info = {
        'mapped_columns': mapped_columns,
        'unmapped_columns': unmapped_columns,
        'missing_required': missing_required,
        'original_columns': list(df.columns)
    }

    if unmapped_columns:
        logger.warning(f"Unmapped columns in POAM file: {unmapped_columns}")

    # Parse into POAMEntry objects
    entries = []

    for idx, row in df.iterrows():
        try:
            # Get rule ID info
            rule_id = str(row.get('vulnerability_library_rule_id', '')).strip()
            rule_info = extract_rule_id_info(rule_id)

            # Parse affected hardware list
            affected_hw = str(row.get('affected_hardware', '')).strip()
            hw_list = parse_affected_hardware(affected_hw)

            # Build GPM UID if not present
            gpm_uid = str(row.get('gpm_uid', '')).strip()
            if not gpm_uid and rule_id and hw_list:
                gpm_uid = f"{rule_id}.{hw_list[0]}"

            entry = POAMEntry(
                poam_id=str(row.get('poam_id', '')).strip(),
                gpm_uid=gpm_uid,
                authorization_package=str(row.get('authorization_package', '')).strip(),
                poam_owner=str(row.get('poam_owner', '')).strip(),
                name=str(row.get('name', '')).strip(),
                date_identified=parse_date(row.get('date_identified')),
                estimated_start_date=parse_date(row.get('estimated_start_date')),
                estimated_completion_date=parse_date(row.get('estimated_completion_date')),
                actual_start_date=parse_date(row.get('actual_start_date')),
                actual_completion_date=parse_date(row.get('actual_completion_date')),
                source_identifying_weakness=str(row.get('source_identifying_weakness', '')).strip(),
                poam_status=str(row.get('poam_status', 'Not Started')).strip(),
                severity=str(row.get('severity', '')).strip(),
                mitigated_severity=str(row.get('mitigated_severity', '')).strip(),
                calculated_risk_level=str(row.get('calculated_risk_level', '')).strip(),
                mitigated_risk_level=str(row.get('mitigated_risk_level', '')).strip(),
                subjective_mitigated_risk_level=str(row.get('subjective_mitigated_risk_level', '')).strip(),
                vulnerability_library_rule_id=rule_id,
                allocated_control=str(row.get('allocated_control', '')).strip(),
                source_checklist=str(row.get('source_checklist', '')).strip(),
                weaknesses=str(row.get('weaknesses', '')).strip(),
                weakness=str(row.get('weakness', '')).strip(),
                library_description=str(row.get('library_description', '')).strip(),
                mitigations=str(row.get('mitigations', '')).strip(),
                comments=str(row.get('comments', '')).strip(),
                affected_hardware=affected_hw,
                affected_hardware_list=hw_list,
                attack_vector=str(row.get('attack_vector', '')).strip(),
                attack_complexity=str(row.get('attack_complexity', '')).strip(),
                privileges_required=str(row.get('privileges_required', '')).strip(),
                user_interaction=str(row.get('user_interaction', '')).strip(),
                scope=str(row.get('scope', '')).strip(),
                confidentiality_impact=str(row.get('confidentiality_impact', '')).strip(),
                integrity_impact=str(row.get('integrity_impact', '')).strip(),
                availability_impact=str(row.get('availability_impact', '')).strip(),
                exploit_code_maturity=str(row.get('exploit_code_maturity', '')).strip(),
                remediation_level=str(row.get('remediation_level', '')).strip(),
                report_confidence=str(row.get('report_confidence', '')).strip(),
                confidentiality_requirement=str(row.get('confidentiality_requirement', '')).strip(),
                integrity_requirement=str(row.get('integrity_requirement', '')).strip(),
                availability_requirement=str(row.get('availability_requirement', '')).strip(),
                modified_attack_vector=str(row.get('modified_attack_vector', '')).strip(),
                modified_attack_complexity=str(row.get('modified_attack_complexity', '')).strip(),
                modified_privileges_required=str(row.get('modified_privileges_required', '')).strip(),
                modified_user_interaction=str(row.get('modified_user_interaction', '')).strip(),
                modified_scope=str(row.get('modified_scope', '')).strip(),
                modified_confidentiality_impact=str(row.get('modified_confidentiality_impact', '')).strip(),
                modified_integrity_impact=str(row.get('modified_integrity_impact', '')).strip(),
                modified_availability_impact=str(row.get('modified_availability_impact', '')).strip(),
                cvss_base_score=parse_float(row.get('cvss_base_score')),
                cvss_temporal_score=parse_float(row.get('cvss_temporal_score')),
                cvss_environmental_score=parse_float(row.get('cvss_environmental_score')),
                cvss_overall_score=parse_float(row.get('cvss_overall_score')),
                responsible_team=str(row.get('responsible_team', '')).strip(),
                cr=str(row.get('cr', '')).strip(),
                cr_tracability=str(row.get('cr_tracability', '')).strip(),
                cr_status=str(row.get('cr_status', '')).strip(),
                environment=str(row.get('environment', '')).strip(),
                consolidated_row_count=parse_int(row.get('consolidated_row_count')),
                is_plugin_id=rule_info['is_plugin_id'],
                is_stig_rule=rule_info['is_stig_rule'],
                plugin_id=rule_info['plugin_id'],
                sv_id_base=rule_info['sv_id_base'],
                rule_revision=rule_info['rule_revision'],
                source_file=str(file_path)
            )

            entries.append(entry)

        except Exception as e:
            logger.warning(f"Error parsing POAM row {idx}: {e}")
            continue

    logger.info(f"Parsed {len(entries)} POAM entries")

    if return_mapping_info:
        return df, entries, mapping_info
    return df, entries, None


def entries_to_dataframe(entries: List[POAMEntry]) -> pd.DataFrame:
    """Convert list of POAMEntry objects to DataFrame."""
    if not entries:
        return pd.DataFrame()

    records = []
    for entry in entries:
        record = {
            'poam_id': entry.poam_id,
            'gpm_uid': entry.gpm_uid,
            'authorization_package': entry.authorization_package,
            'poam_owner': entry.poam_owner,
            'name': entry.name,
            'date_identified': entry.date_identified,
            'estimated_start_date': entry.estimated_start_date,
            'estimated_completion_date': entry.estimated_completion_date,
            'actual_start_date': entry.actual_start_date,
            'actual_completion_date': entry.actual_completion_date,
            'source_identifying_weakness': entry.source_identifying_weakness,
            'poam_status': entry.poam_status,
            'severity': entry.severity,
            'mitigated_severity': entry.mitigated_severity,
            'calculated_risk_level': entry.calculated_risk_level,
            'mitigated_risk_level': entry.mitigated_risk_level,
            'vulnerability_library_rule_id': entry.vulnerability_library_rule_id,
            'allocated_control': entry.allocated_control,
            'source_checklist': entry.source_checklist,
            'weaknesses': entry.weaknesses,
            'weakness': entry.weakness,
            'mitigations': entry.mitigations,
            'comments': entry.comments,
            'affected_hardware': entry.affected_hardware,
            'affected_hardware_count': len(entry.affected_hardware_list),
            'cvss_base_score': entry.cvss_base_score,
            'cvss_overall_score': entry.cvss_overall_score,
            'responsible_team': entry.responsible_team,
            'cr': entry.cr,
            'cr_status': entry.cr_status,
            'environment': entry.environment,
            'consolidated_row_count': entry.consolidated_row_count,
            'is_plugin_id': entry.is_plugin_id,
            'is_stig_rule': entry.is_stig_rule,
            'plugin_id': entry.plugin_id,
            'sv_id_base': entry.sv_id_base,
            'source_file': entry.source_file
        }
        records.append(record)

    return pd.DataFrame(records)


def expand_consolidated_poams(entries: List[POAMEntry]) -> List[POAMEntry]:
    """
    Expand consolidated POAMs into individual host entries.

    For POAMs with multiple hosts in affected_hardware, creates
    a separate entry for each host while keeping other data the same.
    """
    expanded = []

    for entry in entries:
        if len(entry.affected_hardware_list) <= 1:
            # Single host or empty - keep as is
            expanded.append(entry)
        else:
            # Multiple hosts - create entry for each
            for hostname in entry.affected_hardware_list:
                new_entry = POAMEntry(
                    poam_id=entry.poam_id,
                    gpm_uid=f"{entry.vulnerability_library_rule_id}.{hostname}",
                    authorization_package=entry.authorization_package,
                    poam_owner=entry.poam_owner,
                    name=entry.name,
                    date_identified=entry.date_identified,
                    estimated_start_date=entry.estimated_start_date,
                    estimated_completion_date=entry.estimated_completion_date,
                    actual_start_date=entry.actual_start_date,
                    actual_completion_date=entry.actual_completion_date,
                    source_identifying_weakness=entry.source_identifying_weakness,
                    poam_status=entry.poam_status,
                    severity=entry.severity,
                    mitigated_severity=entry.mitigated_severity,
                    calculated_risk_level=entry.calculated_risk_level,
                    mitigated_risk_level=entry.mitigated_risk_level,
                    subjective_mitigated_risk_level=entry.subjective_mitigated_risk_level,
                    vulnerability_library_rule_id=entry.vulnerability_library_rule_id,
                    allocated_control=entry.allocated_control,
                    source_checklist=entry.source_checklist,
                    weaknesses=entry.weaknesses,
                    weakness=entry.weakness,
                    library_description=entry.library_description,
                    mitigations=entry.mitigations,
                    comments=entry.comments,
                    affected_hardware=hostname,
                    affected_hardware_list=[hostname],
                    # Copy all other fields...
                    attack_vector=entry.attack_vector,
                    attack_complexity=entry.attack_complexity,
                    privileges_required=entry.privileges_required,
                    user_interaction=entry.user_interaction,
                    scope=entry.scope,
                    confidentiality_impact=entry.confidentiality_impact,
                    integrity_impact=entry.integrity_impact,
                    availability_impact=entry.availability_impact,
                    exploit_code_maturity=entry.exploit_code_maturity,
                    remediation_level=entry.remediation_level,
                    report_confidence=entry.report_confidence,
                    confidentiality_requirement=entry.confidentiality_requirement,
                    integrity_requirement=entry.integrity_requirement,
                    availability_requirement=entry.availability_requirement,
                    modified_attack_vector=entry.modified_attack_vector,
                    modified_attack_complexity=entry.modified_attack_complexity,
                    modified_privileges_required=entry.modified_privileges_required,
                    modified_user_interaction=entry.modified_user_interaction,
                    modified_scope=entry.modified_scope,
                    modified_confidentiality_impact=entry.modified_confidentiality_impact,
                    modified_integrity_impact=entry.modified_integrity_impact,
                    modified_availability_impact=entry.modified_availability_impact,
                    cvss_base_score=entry.cvss_base_score,
                    cvss_temporal_score=entry.cvss_temporal_score,
                    cvss_environmental_score=entry.cvss_environmental_score,
                    cvss_overall_score=entry.cvss_overall_score,
                    responsible_team=entry.responsible_team,
                    cr=entry.cr,
                    cr_tracability=entry.cr_tracability,
                    cr_status=entry.cr_status,
                    environment=entry.environment,
                    consolidated_row_count=1,  # Now individual
                    is_plugin_id=entry.is_plugin_id,
                    is_stig_rule=entry.is_stig_rule,
                    plugin_id=entry.plugin_id,
                    sv_id_base=entry.sv_id_base,
                    rule_revision=entry.rule_revision,
                    source_file=entry.source_file
                )
                expanded.append(new_entry)

    return expanded


def get_poam_summary(entries: List[POAMEntry]) -> Dict[str, Any]:
    """Get summary statistics for POAM entries."""
    if not entries:
        return {
            'total_poams': 0,
            'status_counts': {},
            'severity_counts': {},
            'source_counts': {},
            'overdue_count': 0,
            'acas_count': 0,
            'stig_count': 0
        }

    today = datetime.now()

    status_counts = {}
    severity_counts = {}
    source_counts = {}
    overdue_count = 0
    acas_count = 0
    stig_count = 0

    for entry in entries:
        # Status
        status = entry.poam_status or 'Unknown'
        status_counts[status] = status_counts.get(status, 0) + 1

        # Severity
        sev = entry.severity or 'Unknown'
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Source
        source = entry.source_identifying_weakness or 'Unknown'
        source_counts[source] = source_counts.get(source, 0) + 1

        # Overdue check
        if entry.estimated_completion_date and entry.poam_status not in ['Complete', 'Closed']:
            if entry.estimated_completion_date < today:
                overdue_count += 1

        # Type counts
        if entry.is_plugin_id:
            acas_count += 1
        if entry.is_stig_rule:
            stig_count += 1

    return {
        'total_poams': len(entries),
        'status_counts': status_counts,
        'severity_counts': severity_counts,
        'source_counts': source_counts,
        'overdue_count': overdue_count,
        'acas_count': acas_count,
        'stig_count': stig_count
    }


def match_poam_to_findings(poam_entries: List[POAMEntry],
                           findings_df: pd.DataFrame,
                           hostname_normalizer=None) -> Dict[str, List[str]]:
    """
    Match POAM entries to findings based on rule ID and hostname.

    Args:
        poam_entries: List of POAM entries
        findings_df: DataFrame with findings (must have hostname, plugin_id columns)
        hostname_normalizer: Optional function to normalize hostnames for matching

    Returns:
        Dict mapping GPM UID to list of matched finding keys (hostname|plugin_id)
    """
    matches = {}

    if findings_df.empty:
        return matches

    # Build finding index for fast lookup
    finding_index = {}
    for _, row in findings_df.iterrows():
        hostname = str(row.get('hostname', '')).lower()
        plugin_id = str(row.get('plugin_id', ''))

        if hostname_normalizer:
            hostname = hostname_normalizer(hostname)

        key = f"{plugin_id}|{hostname}"
        finding_index[key] = True

        # Also index by just plugin_id for broader matching
        if plugin_id not in finding_index:
            finding_index[f"plugin:{plugin_id}"] = []
        if isinstance(finding_index.get(f"plugin:{plugin_id}"), list):
            finding_index[f"plugin:{plugin_id}"].append(hostname)

    # Match each POAM entry
    for entry in poam_entries:
        if not entry.is_plugin_id:
            continue  # Only match plugin-based POAMs for now

        matched_findings = []
        plugin_id = entry.plugin_id

        for hostname in entry.affected_hardware_list:
            host_lower = hostname.lower()
            if hostname_normalizer:
                host_lower = hostname_normalizer(host_lower)

            key = f"{plugin_id}|{host_lower}"
            if key in finding_index:
                matched_findings.append(key)

        if matched_findings:
            matches[entry.gpm_uid] = matched_findings

    return matches
