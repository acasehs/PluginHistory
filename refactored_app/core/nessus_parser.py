"""
Nessus File Parser Module
Core parsing logic for .nessus XML files with DataFrame output.
"""

import os
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import xml.etree.ElementTree as ET
import pandas as pd
import random


def sanitize_hostname_for_excel(hostname: str) -> str:
    """Sanitize hostname for use as Excel sheet name."""
    if not hostname:
        return "Host"
    safe_hostname = re.sub(r'[\\/*[\]:?\-]', '_', hostname)
    if len(safe_hostname) > 31:
        safe_hostname = f"Host_{hash(hostname) % 10000}"
    return safe_hostname


def extract_hostname_from_plugins(host_element: ET.Element) -> Optional[str]:
    """
    Extract hostname from host properties.

    Args:
        host_element: XML ReportHost element

    Returns:
        Extracted hostname or None
    """
    # Try HostProperties first
    props = host_element.find('HostProperties')
    if props is not None:
        for tag in props.findall('tag'):
            name = tag.get('name', '')
            if name in ('hostname', 'host-fqdn', 'netbios-name'):
                if tag.text:
                    return tag.text.split('.')[0]  # Return short hostname
    return None


def resolve_hostname(host_name: str, host_element: ET.Element = None) -> str:
    """
    Resolve hostname from IP or host element.

    Args:
        host_name: IP address or hostname string
        host_element: Optional XML element for additional resolution

    Returns:
        Resolved hostname
    """
    if host_element:
        extracted = extract_hostname_from_plugins(host_element)
        if extracted:
            return extracted

    # If it's not an IP, return short hostname
    if '.' in host_name and not host_name[0].isdigit():
        return host_name.split('.')[0]

    return host_name


def parse_credentialed_scan_info(plugin_output: str) -> Dict[str, str]:
    """
    Parse credentialed scan information from plugin 19506 output.

    Args:
        plugin_output: Raw plugin output text

    Returns:
        Dictionary with credential scan information
    """
    result = {
        'proper_scan': 'No',
        'cred_checks_value': 'N/A',
        'cred_scan_value': 'N/A',
        'auth_method': 'None'
    }

    if not plugin_output:
        return result

    lower_output = plugin_output.lower()

    # Extract exact values
    cred_checks_match = re.search(r"credentialed checks\s*:\s*(\w+)", lower_output)
    if cred_checks_match:
        result['cred_checks_value'] = cred_checks_match.group(1)

    cred_scan_match = re.search(r"credentialed_scan\s*:\s*(\w+)", lower_output)
    if cred_scan_match:
        result['cred_scan_value'] = cred_scan_match.group(1)

    # Check values
    has_cred_checks_no = "credentialed checks : no" in lower_output
    has_cred_scan_false = "credentialed_scan:false" in lower_output
    has_cred_checks_yes = "credentialed checks : yes" in lower_output
    has_cred_scan_true = "credentialed_scan:true" in lower_output

    has_contradiction = (has_cred_checks_no and has_cred_scan_true) or (has_cred_checks_yes and has_cred_scan_false)

    if has_contradiction:
        result['proper_scan'] = "CONTRADICTORY"
    elif has_cred_checks_no or has_cred_scan_false:
        result['proper_scan'] = "No"
    elif has_cred_checks_yes or has_cred_scan_true:
        result['proper_scan'] = "Yes"

        auth_lines = [line for line in plugin_output.split('\n')
                     if "Authentication" in line or "authentication" in line]
        if auth_lines:
            result['auth_method'] = auth_lines[0].split(':', 1)[1].strip() if ':' in auth_lines[0] else auth_lines[0]

    return result


def extract_finding_data(item: ET.Element, host_name: str, hostname: str, plugins_dict: Dict = None) -> Dict[str, Any]:
    """
    Extract finding data from a single ReportItem element.

    Args:
        item: XML ReportItem element
        host_name: IP address of the host
        hostname: Resolved hostname
        plugins_dict: Optional plugins database for enrichment

    Returns:
        Dictionary containing finding information
    """
    plugin_id = item.attrib.get('pluginID', '')
    severity = item.attrib.get('severity', '0')
    plugin_name = item.attrib.get('pluginName', 'Unknown')
    port = item.attrib.get('port', 'N/A')
    protocol = item.attrib.get('protocol', 'N/A')
    svc_name = item.attrib.get('svc_name', '')

    finding = {
        'plugin_id': plugin_id,
        'gmp_uid': f"{plugin_id}.{hostname}",
        'name': plugin_name,
        'family': '',
        'severity': severity,
        'ip_address': host_name,
        'protocol': protocol,
        'port': f"{port}/{protocol}",
        'exploit_available': 'No',
        'output': '',
        'synopsis': '',
        'description': '',
        'solution': '',
        'see_also': '',
        'risk_factor': '',
        'stig_severity': '',
        'cvss3_base_score': None,
        'cvss3_temporal_score': None,
        'cvss_v3_vector': '',
        'cvss2_base_score': None,
        'cpe': '',
        'cves': '',
        'bid': '',
        'cross_references': '',
        'first_discovered': '',
        'last_observed': '',
        'vuln_publication_date': '',
        'patch_publication_date': '',
        'plugin_publication_date': '',
        'plugin_modification_date': '',
        'exploit_ease': '',
        'exploit_frameworks': '',
        'iavx': '',
        'hostname': hostname,
        'svc_name': svc_name
    }

    # Extract plugin output
    plugin_output_elem = item.find("plugin_output")
    if plugin_output_elem is not None and plugin_output_elem.text:
        finding['output'] = plugin_output_elem.text.strip()

    # Extract description
    description_elem = item.find("description")
    if description_elem is not None and description_elem.text:
        finding['description'] = description_elem.text.strip()

    # Extract solution
    solution_elem = item.find("solution")
    if solution_elem is not None and solution_elem.text:
        finding['solution'] = solution_elem.text.strip()

    # Extract CVSS scores
    cvss3_elem = item.find("cvss3_base_score")
    if cvss3_elem is not None and cvss3_elem.text:
        finding['cvss3_base_score'] = cvss3_elem.text.strip()

    cvss2_elem = item.find("cvss_base_score")
    if cvss2_elem is not None and cvss2_elem.text:
        finding['cvss2_base_score'] = cvss2_elem.text.strip()

    # Extract CVEs
    cves = set()
    for cve_elem in item.findall("cve"):
        if cve_elem.text and cve_elem.text.strip():
            cves.add(cve_elem.text.strip())

    # Extract IAVx references
    iavx_refs = set()
    see_also_elem = item.find("see_also")
    if see_also_elem is not None and see_also_elem.text:
        finding['see_also'] = see_also_elem.text.strip()
        for line in see_also_elem.text.split('\n'):
            line = line.strip()
            if line and any(x in line for x in ["IAVA:", "IAVB:", "IATM:"]):
                iavx_refs.add(line)

    for xref_elem in item.findall("xref"):
        if xref_elem.text and xref_elem.text.strip():
            if any(x in xref_elem.text for x in ["IAVA:", "IAVB:", "IATM:"]):
                iavx_refs.add(xref_elem.text.strip())

    # Extract other elements
    element_mappings = {
        'family': 'family',
        'synopsis': 'synopsis',
        'risk_factor': 'risk_factor',
        'stig_severity': 'stig_severity',
        'exploit_available': 'exploit_available',
        'exploit_ease': 'exploit_ease',
    }

    for xml_element, field_name in element_mappings.items():
        elem = item.find(xml_element)
        if elem is not None and elem.text:
            value = elem.text.strip()
            if field_name == 'exploit_available':
                finding[field_name] = "Yes" if value.lower() == "true" else "No"
            else:
                finding[field_name] = value

    finding['cves'] = "\n".join(sorted(cves)) if cves else ""
    finding['iavx'] = "\n".join(sorted(iavx_refs)) if iavx_refs else ""

    # Enrich with plugins database if available
    if plugins_dict and plugin_id in plugins_dict:
        plugin_info = plugins_dict[plugin_id]
        enrichment_mappings = {
            'description': 'description',
            'solution': 'solution',
            'name': 'name',
            'family': 'family',
            'cvss3_base_score': 'cvss3_base_score',
            'cvss2_base_score': 'cvss_base_score',
        }

        for finding_key, plugin_key in enrichment_mappings.items():
            if not finding[finding_key] and plugin_key in plugin_info:
                finding[finding_key] = str(plugin_info[plugin_key])

    return finding


def parse_nessus_file(nessus_file: str, plugins_dict: Dict = None) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Parse a .nessus file and return findings as a pandas DataFrame.

    Args:
        nessus_file: Path to the .nessus file
        plugins_dict: Optional plugins database for enrichment

    Returns:
        Tuple of (findings_df, host_summary_df)
    """
    try:
        print(f"Parsing {os.path.basename(nessus_file)}...")
        start_time = time.time()

        tree = ET.parse(nessus_file)
        root = tree.getroot()

        original_filename = os.path.basename(nessus_file)
        report_name = original_filename
        report_element = root.find(".//Report")
        if report_element is not None and 'name' in report_element.attrib:
            report_name = report_element.attrib['name']

        hosts = root.findall(".//ReportHost")
        print(f"Found {len(hosts)} hosts in {report_name}")

        all_findings = []
        host_summaries = []

        for host_idx, host in enumerate(hosts, 1):
            host_name = host.attrib.get('name', 'Unknown')

            hostname = extract_hostname_from_plugins(host)
            if not hostname:
                hostname = resolve_hostname(host_name, host)

            cred_info = {
                'proper_scan': 'No',
                'cred_checks_value': 'N/A',
                'cred_scan_value': 'N/A',
                'auth_method': 'None'
            }

            items = host.findall(".//ReportItem")
            for item in items:
                plugin_id = item.attrib.get('pluginID', '')

                if plugin_id == '19506':
                    plugin_output = item.find("plugin_output")
                    if plugin_output is not None and plugin_output.text:
                        cred_info = parse_credentialed_scan_info(plugin_output.text)

                finding = extract_finding_data(item, host_name, hostname, plugins_dict)
                all_findings.append(finding)

            host_summary = {
                'report_name': report_name,
                'original_filename': original_filename,
                'host_name': host_name,
                'hostname': hostname,
                'safe_hostname': sanitize_hostname_for_excel(hostname),
                'total_reportitems': len(items),
                **cred_info
            }

            host_summaries.append(host_summary)

        findings_df = pd.DataFrame(all_findings)
        host_summary_df = pd.DataFrame(host_summaries)

        elapsed = time.time() - start_time
        print(f"Completed parsing {nessus_file} in {elapsed:.1f} seconds")
        print(f"Extracted {len(all_findings)} findings from {len(hosts)} hosts")

        return findings_df, host_summary_df

    except Exception as e:
        print(f"Error parsing {nessus_file}: {e}")
        import traceback
        traceback.print_exc()
        return pd.DataFrame(), pd.DataFrame()


def parse_multiple_nessus_files(nessus_files: List[str], plugins_dict: Dict = None) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Parse multiple .nessus files and combine results.

    Args:
        nessus_files: List of .nessus file paths
        plugins_dict: Optional plugins database for enrichment

    Returns:
        Tuple of (combined_findings_df, combined_host_summary_df)
    """
    all_findings = []
    all_host_summaries = []

    for i, nessus_file in enumerate(nessus_files, 1):
        print(f"Processing file {i}/{len(nessus_files)}: {os.path.basename(nessus_file)}")

        findings_df, host_summary_df = parse_nessus_file(nessus_file, plugins_dict)

        if not findings_df.empty:
            all_findings.append(findings_df)
        if not host_summary_df.empty:
            all_host_summaries.append(host_summary_df)

    combined_findings = pd.concat(all_findings, ignore_index=True) if all_findings else pd.DataFrame()
    combined_summaries = pd.concat(all_host_summaries, ignore_index=True) if all_host_summaries else pd.DataFrame()

    print(f"Total findings across all files: {len(combined_findings)}")
    print(f"Total hosts across all files: {len(combined_summaries)}")

    return combined_findings, combined_summaries
