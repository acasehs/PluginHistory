"""
PDF Generator for POA&M documents.

Fills PDF template forms with IAVM/OPDIR data using PyMuPDF.
"""

import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
import pandas as pd

# Check for PDF libraries
try:
    import fitz  # PyMuPDF
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


def is_pdf_available() -> bool:
    """Check if PDF generation libraries are available."""
    return PDF_AVAILABLE


def get_pdf_form_fields(template_path: str) -> List[Dict[str, str]]:
    """
    Get all form field names from a PDF template.

    Args:
        template_path: Path to PDF template file

    Returns:
        List of dicts with field_name, field_type, current_value
    """
    if not PDF_AVAILABLE:
        return []

    try:
        doc = fitz.open(template_path)
        fields = []

        for page_num in range(doc.page_count):
            page = doc[page_num]
            for widget in page.widgets():
                fields.append({
                    'field_name': widget.field_name,
                    'field_type': widget.field_type_string,
                    'current_value': widget.field_value or '',
                    'page': page_num + 1
                })

        doc.close()
        return fields
    except Exception as e:
        print(f"Error reading PDF fields: {e}")
        return []


def fill_poam_pdf(
    template_path: str,
    output_path: str,
    iavm_id: str,
    opdir_number: str,
    poc_info: Dict[str, str],
    templates: Dict[str, str],
    host_data: Optional[Dict[str, Any]] = None,
    cves: Optional[List[str]] = None,
    plugins: Optional[List[str]] = None,
    due_date: str = '',
    subject: str = ''
) -> Tuple[bool, str]:
    """
    Fill a POA&M PDF template with IAVM data.

    Args:
        template_path: Path to PDF template file
        output_path: Path for output PDF
        iavm_id: IAVM identifier (e.g., "2024-A-0123")
        opdir_number: OPDIR number (e.g., "25-A-0001")
        poc_info: Dictionary of POC information
        templates: Dictionary of narrative templates
        host_data: Optional dict with host-specific data (IPs, hostnames, OS)
        cves: Optional list of CVE identifiers
        plugins: Optional list of plugin IDs
        due_date: Due date string
        subject: IAVM subject/title

    Returns:
        Tuple of (success: bool, message: str)
    """
    if not PDF_AVAILABLE:
        return False, "PyMuPDF library not installed. Run: pip install PyMuPDF"

    if not os.path.exists(template_path):
        return False, f"Template file not found: {template_path}"

    try:
        doc = fitz.open(template_path)
        current_date = datetime.now().strftime("%m/%d/%Y")

        # Build host data strings
        ip_range_str = ""
        workstation_str = ""
        os_str = ""
        total_affected = 0

        if host_data:
            ips = host_data.get('ips', [])
            hostnames = host_data.get('hostnames', [])
            os_list = host_data.get('os_versions', [])

            ip_range_str = "\n".join(ips) if ips else ""
            workstation_str = "\n".join(hostnames) if hostnames else ""
            os_str = "\n".join(sorted(set(os_list))) if os_list else ""
            total_affected = len(ips) if ips else len(hostnames)

        # Build CVE and plugin strings
        cve_str = "\n".join(sorted(cves)) if cves else ""
        plugin_str = "\n".join(sorted(str(p) for p in plugins))[:1000] if plugins else ""

        # Prepare plan of action with CVEs appended
        plan_of_action = templates.get('plan_of_action', '')
        if cve_str:
            plan_of_action += f"\n\nRelated CVEs:\n{cve_str}"

        # Build form data mapping (field names must match PDF template)
        form_data = {
            # IAVM/OPDIR Info
            'IAVM': iavm_id,
            'OpDir': opdir_number,
            'DateSubmitted': current_date,
            'DateDue': due_date,
            'NumberofSubmission': '1st',

            # POC Information
            'RNOSC': poc_info.get('rnosc', ''),
            'CommandUnit': poc_info.get('command_unit', ''),
            'Requestor': poc_info.get('requestor', ''),
            'RequestorPhone': poc_info.get('requestor_phone', ''),
            'RequestorEmail': poc_info.get('requestor_email', ''),
            'LocalIAM': poc_info.get('local_iam', ''),
            'LocalIAMPhone': poc_info.get('local_iam_phone', ''),
            'LocalIAMEmail': poc_info.get('local_iam_email', ''),
            'RegionalIAM': poc_info.get('regional_iam', ''),
            'RegionalIAMPhone': poc_info.get('regional_iam_phone', ''),
            'RegionalIAMEmail': poc_info.get('regional_iam_email', ''),

            # Affected Systems Count
            'NIPRAffected': str(total_affected),
            'NIPRPatched': '0',
            'NIPRNotPatched': str(total_affected),
            'SIPRAffected': '0',
            'SIPRPatched': '0',
            'SIPRNotPatched': '0',

            # Technical Details
            'IPAddressRange': ip_range_str,
            'Workstation': workstation_str,
            'OS': os_str,

            # Narrative Fields
            'ReasonNotCompletion': templates.get('reason_cannot_complete', ''),
            'OperationalImpact': templates.get('operational_impact', ''),
            'PlanOfAction': plan_of_action,
            'Timeline': templates.get('timeline_milestones', ''),
            'VulnerabilityMethod': templates.get('vulnerability_detection_method', ''),
            'TemporaryMitigation': templates.get('temporary_mitigations', ''),

            # CVEs and Plugins
            'CVEs': cve_str,
            'Related Plugins': plugin_str,
        }

        # Fill form fields
        fields_filled = 0
        fields_not_found = []

        for page_num in range(doc.page_count):
            page = doc[page_num]

            for widget in page.widgets():
                field_name = widget.field_name

                if field_name in form_data:
                    widget.field_value = form_data[field_name]
                    widget.update()
                    fields_filled += 1
                else:
                    fields_not_found.append(field_name)

        # Save the filled PDF
        doc.save(output_path)
        doc.close()

        return True, f"Created {output_path} ({fields_filled} fields filled)"

    except Exception as e:
        return False, f"Error filling PDF: {e}"


def generate_poam_pdfs(
    template_path: str,
    output_dir: str,
    iavm_list: List[Dict[str, Any]],
    poc_info: Dict[str, str],
    templates: Dict[str, str],
    historical_df: Optional[pd.DataFrame] = None,
    progress_callback=None
) -> Tuple[int, int, List[str]]:
    """
    Generate multiple POA&M PDFs from a list of IAVMs.

    Args:
        template_path: Path to PDF template
        output_dir: Directory to save output PDFs
        iavm_list: List of IAVM data dicts
        poc_info: POC information dict
        templates: Narrative templates dict
        historical_df: Optional DataFrame with vulnerability data for host lookups
        progress_callback: Optional callback(current, total, message) for progress

    Returns:
        Tuple of (success_count, fail_count, list_of_output_files)
    """
    if not PDF_AVAILABLE:
        return 0, len(iavm_list), []

    os.makedirs(output_dir, exist_ok=True)

    success_count = 0
    fail_count = 0
    output_files = []

    total = len(iavm_list)

    for idx, iavm in enumerate(iavm_list):
        iavm_id = iavm.get('iavm', iavm.get('iavm_id', f'IAVM-{idx+1}'))
        opdir_number = iavm.get('opdir', iavm.get('opdir_number', ''))
        due_date = iavm.get('due_date', '')
        subject = iavm.get('subject', '')

        # Try to get host data from historical_df if available
        host_data = None
        cves = None
        plugins = None

        if historical_df is not None and not historical_df.empty:
            # Look for findings with matching IAVX reference
            iavx_col = 'iavx' if 'iavx' in historical_df.columns else None
            if iavx_col:
                # Match on IAVM ID in iavx column
                mask = historical_df[iavx_col].fillna('').str.contains(iavm_id, case=False, na=False)
                matching_findings = historical_df[mask]

                if not matching_findings.empty:
                    # Extract host data
                    ips = matching_findings['hostname'].unique().tolist() if 'hostname' in matching_findings.columns else []
                    hostnames = []
                    if 'canonical_hostname' in matching_findings.columns:
                        hostnames = matching_findings['canonical_hostname'].dropna().unique().tolist()
                    elif 'hostname' in matching_findings.columns:
                        hostnames = matching_findings['hostname'].dropna().unique().tolist()

                    os_versions = []
                    if 'os' in matching_findings.columns:
                        os_versions = matching_findings['os'].dropna().unique().tolist()

                    host_data = {
                        'ips': ips,
                        'hostnames': hostnames,
                        'os_versions': os_versions
                    }

                    # Extract CVEs
                    if 'cves' in matching_findings.columns:
                        all_cves = []
                        for cve_val in matching_findings['cves'].dropna():
                            if isinstance(cve_val, str):
                                all_cves.extend([c.strip() for c in cve_val.replace('\n', ',').split(',') if c.strip()])
                        cves = list(set(all_cves))

                    # Extract plugin IDs
                    if 'plugin_id' in matching_findings.columns:
                        plugins = [str(p) for p in matching_findings['plugin_id'].unique()]

        # Generate filename
        clean_iavm = iavm_id.replace(':', '-').replace('/', '-')
        clean_opdir = opdir_number.replace(':', '-').replace('/', '-') if opdir_number else 'NO-OPDIR'
        output_filename = f"POAM_{clean_opdir}_{clean_iavm}.pdf"
        output_path = os.path.join(output_dir, output_filename)

        # Progress callback
        if progress_callback:
            progress_callback(idx + 1, total, f"Generating {output_filename}")

        # Fill PDF
        success, message = fill_poam_pdf(
            template_path=template_path,
            output_path=output_path,
            iavm_id=iavm_id,
            opdir_number=opdir_number,
            poc_info=poc_info,
            templates=templates,
            host_data=host_data,
            cves=cves,
            plugins=plugins,
            due_date=due_date,
            subject=subject
        )

        if success:
            success_count += 1
            output_files.append(output_path)
        else:
            fail_count += 1
            print(f"Failed to generate {output_filename}: {message}")

    return success_count, fail_count, output_files
