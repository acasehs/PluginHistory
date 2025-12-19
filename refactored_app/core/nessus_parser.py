"""
Nessus File Parser Module
Core parsing logic for .nessus XML files with DataFrame output.
"""

import os
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import pandas as pd
import random

# Try to use lxml for line number tracking, fall back to ElementTree
try:
    from lxml import etree as lxml_etree
    HAS_LXML = True
except ImportError:
    HAS_LXML = False

import xml.etree.ElementTree as ET


def sanitize_hostname_for_excel(hostname: str) -> str:
    """Sanitize hostname for use as Excel sheet name."""
    if not hostname:
        return "Host"
    safe_hostname = re.sub(r'[\\/*[\]:?\-]', '_', hostname)
    if len(safe_hostname) > 31:
        safe_hostname = f"Host_{hash(hostname) % 10000}"
    return safe_hostname


def extract_host_scan_time(host_element: ET.Element) -> Tuple[Optional[datetime], Optional[str], Optional[str]]:
    """
    Extract scan date and time from host properties.

    The HOST_START tag in .nessus files contains the scan start time for each host.
    Format example: "Mon Jan 01 12:00:00 2024"

    Args:
        host_element: XML ReportHost element

    Returns:
        Tuple of (datetime object, date string YYYY-MM-DD, time string HH:MM:SS)
    """
    props = host_element.find('HostProperties')
    if props is None:
        return None, None, None

    host_start = None
    for tag in props.findall('tag'):
        name = tag.get('name', '')
        if name == 'HOST_START' and tag.text:
            host_start = tag.text.strip()
            break

    if not host_start:
        return None, None, None

    # Parse various date formats from Nessus
    date_formats = [
        "%a %b %d %H:%M:%S %Y",      # Mon Jan 01 12:00:00 2024
        "%a %b  %d %H:%M:%S %Y",     # Mon Jan  1 12:00:00 2024 (single digit day with extra space)
        "%Y-%m-%d %H:%M:%S",         # 2024-01-01 12:00:00
        "%Y/%m/%d %H:%M:%S",         # 2024/01/01 12:00:00
        "%d %b %Y %H:%M:%S",         # 01 Jan 2024 12:00:00
    ]

    scan_datetime = None
    for fmt in date_formats:
        try:
            scan_datetime = datetime.strptime(host_start, fmt)
            break
        except ValueError:
            continue

    if scan_datetime is None:
        # Try a more flexible approach - extract date components
        try:
            # Handle "Mon Jan  1 12:00:00 2024" with regex
            match = re.match(r'\w+\s+(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+)\s+(\d+)', host_start)
            if match:
                month_str, day, hour, minute, second, year = match.groups()
                month_map = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                            'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
                month = month_map.get(month_str, 1)
                scan_datetime = datetime(int(year), month, int(day), int(hour), int(minute), int(second))
        except Exception:
            pass

    if scan_datetime:
        scan_date = scan_datetime.strftime('%Y-%m-%d')
        scan_time = scan_datetime.strftime('%H:%M:%S')
        return scan_datetime, scan_date, scan_time

    return None, None, None


def extract_hostname_from_plugins(host_element: ET.Element) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract hostname from Nessus plugins and host properties.

    Priority order:
    1. Plugin 12053 (Host FQDN via DNS) - most reliable
    2. Plugin 55472 (Hostname command output)
    3. Plugin 10150 (NetBIOS/SMB Information)
    4. Plugin 45590 (Common Platform Enumeration)
    5. HostProperties tags (host-fqdn, hostname, netbios-name)

    Args:
        host_element: XML ReportHost element

    Returns:
        Tuple of (resolved_hostname, raw_hostname from HostProperties)
    """
    resolved_hostname = None
    raw_hostname = None

    # First, get raw hostname from HostProperties for reference
    props = host_element.find('HostProperties')
    if props is not None:
        for tag in props.findall('tag'):
            name = tag.get('name', '')
            if name == 'host-fqdn' and tag.text:
                raw_hostname = tag.text.split('.')[0]
                break
            elif name == 'hostname' and tag.text and not raw_hostname:
                raw_hostname = tag.text.split('.')[0]
            elif name == 'netbios-name' and tag.text and not raw_hostname:
                raw_hostname = tag.text

    # Priority 1: Plugin 12053 (Host FQDN via DNS Resolution)
    for item in host_element.findall(".//ReportItem[@pluginID='12053']"):
        plugin_output = item.find("plugin_output")
        if plugin_output is not None and plugin_output.text:
            # Pattern: "192.168.1.1 resolves as server.domain.com."
            match = re.search(r"resolves as ([\w.-]+)", plugin_output.text)
            if match:
                fqdn = match.group(1).rstrip('.')  # Remove trailing dot if present
                resolved_hostname = fqdn.split('.')[0]
                return resolved_hostname, raw_hostname

    # Priority 2: Plugin 55472 (Hostname command)
    for item in host_element.findall(".//ReportItem[@pluginID='55472']"):
        plugin_output = item.find("plugin_output")
        if plugin_output is not None and plugin_output.text:
            lines = plugin_output.text.strip().split("\n")
            for line in lines:
                if "hostname" in line.lower():
                    # Extract hostname - typically first word or after colon
                    parts = line.split(":")
                    if len(parts) > 1:
                        resolved_hostname = parts[1].strip().split('.')[0].split()[0]
                    else:
                        resolved_hostname = line.split()[0].split('.')[0]
                    if resolved_hostname:
                        return resolved_hostname, raw_hostname

    # Priority 3: Plugin 10150 (NetBIOS/SMB Information)
    for item in host_element.findall(".//ReportItem[@pluginID='10150']"):
        plugin_output = item.find("plugin_output")
        if plugin_output is not None and plugin_output.text:
            lines = plugin_output.text.strip().split("\n")
            for line in lines:
                if "computer name" in line.lower():
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        resolved_hostname = parts[1].strip().split()[0]
                        if resolved_hostname:
                            return resolved_hostname, raw_hostname

    # Priority 4: Plugin 45590 (Common Platform Enumeration)
    for item in host_element.findall(".//ReportItem[@pluginID='45590']"):
        plugin_output = item.find("plugin_output")
        if plugin_output is not None and plugin_output.text:
            lines = plugin_output.text.strip().split("\n")
            for line in lines:
                if "hostname" in line.lower() and ":" in line:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        hostname_part = parts[1].strip()
                        if hostname_part:
                            resolved_hostname = hostname_part.split('.')[0]
                            return resolved_hostname, raw_hostname

    # Priority 5: Fall back to HostProperties raw hostname
    if raw_hostname:
        resolved_hostname = raw_hostname

    return resolved_hostname, raw_hostname


def resolve_hostname(host_name: str, host_element: ET.Element = None) -> Tuple[str, Optional[str]]:
    """
    Resolve hostname from IP or host element.

    Args:
        host_name: IP address or hostname string
        host_element: Optional XML element for additional resolution

    Returns:
        Tuple of (resolved_hostname, raw_hostname)
    """
    resolved = None
    raw = None

    if host_element:
        resolved, raw = extract_hostname_from_plugins(host_element)
        if resolved:
            return resolved, raw

    # If it's not an IP, extract short hostname
    if '.' in host_name and not host_name[0].isdigit():
        resolved = host_name.split('.')[0]
        return resolved, raw

    return host_name, raw


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


def extract_finding_data(item, host_name: str, hostname: str,
                         scan_date: str = None, scan_time: str = None,
                         plugins_dict: Dict = None, source_file: str = None,
                         source_line: int = None, hostname_raw: str = None) -> Dict[str, Any]:
    """
    Extract finding data from a single ReportItem element.

    Args:
        item: XML ReportItem element (ElementTree or lxml element)
        host_name: IP address of the host
        hostname: Resolved hostname (from plugin 12053 preferred)
        scan_date: Scan date string (YYYY-MM-DD) from HOST_START
        scan_time: Scan time string (HH:MM:SS) from HOST_START
        plugins_dict: Optional plugins database for enrichment
        source_file: Source .nessus filename for auditability
        source_line: Line number where this ReportItem starts in the source file
        hostname_raw: Raw hostname from HostProperties (before plugin resolution)

    Returns:
        Dictionary containing finding information
    """
    plugin_id = item.attrib.get('pluginID', '')
    severity = item.attrib.get('severity', '0')
    plugin_name = item.attrib.get('pluginName', 'Unknown')
    port_raw = item.attrib.get('port', '0')
    protocol = item.attrib.get('protocol', 'tcp')
    svc_name = item.attrib.get('svc_name', '')

    finding = {
        'plugin_id': plugin_id,
        'gpm_uid': f"{plugin_id}.{hostname}",
        'name': plugin_name,
        'family': '',
        'severity': severity,
        'ip_address': host_name,
        'protocol': protocol,
        'port': port_raw,  # Store just the port number for dedup
        'port_full': f"{port_raw}/{protocol}",  # Combined format for display
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
        'hostname_raw': hostname_raw or hostname,  # Store raw hostname from HostProperties
        'svc_name': svc_name,
        'scan_date': scan_date,
        'scan_time': scan_time,
        'source_file': source_file or '',
        'source_line': source_line
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
            'synopsis': 'synopsis',
            'risk_factor': 'risk_factor',
            'stig_severity': 'stig_severity',
            'exploit_ease': 'exploit_ease',
            'exploit_available': 'exploit_available',
            'exploit_frameworks': 'exploit_frameworks',
            'cpe': 'cpe',
            'vuln_publication_date': 'vuln_publication_date',
            'patch_publication_date': 'patch_publication_date',
            'plugin_publication_date': 'plugin_publication_date',
            'plugin_modification_date': 'plugin_modification_date',
        }

        for finding_key, plugin_key in enrichment_mappings.items():
            if not finding[finding_key] and plugin_key in plugin_info:
                finding[finding_key] = str(plugin_info[plugin_key])

        # Enrich CVEs if not already present from scan
        if not finding['cves'] and 'cves' in plugin_info and plugin_info['cves']:
            finding['cves'] = str(plugin_info['cves'])

        # Enrich IAVX if not already present from scan
        if not finding['iavx'] and 'iavx' in plugin_info and plugin_info['iavx']:
            finding['iavx'] = str(plugin_info['iavx'])
        elif finding['iavx'] and 'iavx' in plugin_info and plugin_info['iavx']:
            # Merge IAVX refs from both sources
            existing_refs = set(finding['iavx'].split('\n'))
            plugin_refs = set(str(plugin_info['iavx']).split('\n'))
            all_refs = existing_refs | plugin_refs
            finding['iavx'] = "\n".join(sorted(all_refs))

    return finding


def parse_nessus_file(nessus_file: str, plugins_dict: Dict = None,
                      import_report: Dict = None) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Parse a .nessus file and return findings as a pandas DataFrame.

    Args:
        nessus_file: Path to the .nessus file
        plugins_dict: Optional plugins database for enrichment
        import_report: Optional dict to collect import statistics and issues

    Returns:
        Tuple of (findings_df, host_summary_df)
    """
    # Initialize import report tracking
    if import_report is None:
        import_report = {}
    if 'files_processed' not in import_report:
        import_report['files_processed'] = []
    if 'files_failed' not in import_report:
        import_report['files_failed'] = []
    if 'hosts_processed' not in import_report:
        import_report['hosts_processed'] = 0
    if 'hosts_skipped' not in import_report:
        import_report['hosts_skipped'] = []
    if 'findings_processed' not in import_report:
        import_report['findings_processed'] = 0
    if 'findings_skipped' not in import_report:
        import_report['findings_skipped'] = []
    if 'parsing_warnings' not in import_report:
        import_report['parsing_warnings'] = []

    try:
        print(f"Parsing {os.path.basename(nessus_file)}...")
        start_time = time.time()

        original_filename = os.path.basename(nessus_file)

        # Use lxml if available for line number tracking, otherwise fall back to ElementTree
        use_lxml = HAS_LXML
        if use_lxml:
            try:
                parser = lxml_etree.XMLParser(remove_blank_text=False)
                tree = lxml_etree.parse(nessus_file, parser)
                root = tree.getroot()
            except Exception as e:
                print(f"lxml parsing failed, falling back to ElementTree: {e}")
                use_lxml = False

        if not use_lxml:
            tree = ET.parse(nessus_file)
            root = tree.getroot()

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

            try:
                # Extract hostname with plugin 12053 priority
                hostname, hostname_raw = extract_hostname_from_plugins(host)
                if not hostname:
                    hostname, hostname_raw = resolve_hostname(host_name, host)

                # Extract scan date and time from HOST_START tag
                scan_datetime, scan_date, scan_time = extract_host_scan_time(host)

                if not scan_date:
                    import_report['parsing_warnings'].append(
                        f"{original_filename}: Host '{hostname}' has no scan date"
                    )

                cred_info = {
                    'proper_scan': 'No',
                    'cred_checks_value': 'N/A',
                    'cred_scan_value': 'N/A',
                    'auth_method': 'None'
                }

                items = host.findall(".//ReportItem")
                host_findings_count = 0

                for item in items:
                    plugin_id = item.attrib.get('pluginID', '')

                    if plugin_id == '19506':
                        plugin_output = item.find("plugin_output")
                        if plugin_output is not None and plugin_output.text:
                            cred_info = parse_credentialed_scan_info(plugin_output.text)

                    try:
                        # Get source line from lxml if available
                        source_line = None
                        if use_lxml and hasattr(item, 'sourceline'):
                            source_line = item.sourceline

                        finding = extract_finding_data(item, host_name, hostname,
                                                       scan_date=scan_date, scan_time=scan_time,
                                                       plugins_dict=plugins_dict,
                                                       source_file=original_filename,
                                                       source_line=source_line,
                                                       hostname_raw=hostname_raw)
                        all_findings.append(finding)
                        host_findings_count += 1
                        import_report['findings_processed'] += 1
                    except Exception as e:
                        import_report['findings_skipped'].append({
                            'file': original_filename,
                            'host': hostname,
                            'plugin_id': plugin_id,
                            'error': str(e)
                        })

                host_summary = {
                    'report_name': report_name,
                    'original_filename': original_filename,
                    'host_name': host_name,
                    'hostname': hostname,
                    'safe_hostname': sanitize_hostname_for_excel(hostname),
                    'total_reportitems': len(items),
                    'findings_extracted': host_findings_count,
                    'scan_date': scan_date,
                    'scan_time': scan_time,
                    **cred_info
                }

                host_summaries.append(host_summary)
                import_report['hosts_processed'] += 1

            except Exception as e:
                import_report['hosts_skipped'].append({
                    'file': original_filename,
                    'host': host_name,
                    'error': str(e)
                })

        findings_df = pd.DataFrame(all_findings)
        host_summary_df = pd.DataFrame(host_summaries)

        elapsed = time.time() - start_time
        print(f"Completed parsing {nessus_file} in {elapsed:.1f} seconds")
        print(f"Extracted {len(all_findings)} findings from {len(hosts)} hosts")

        import_report['files_processed'].append({
            'file': original_filename,
            'hosts': len(hosts),
            'findings': len(all_findings),
            'elapsed': elapsed
        })

        return findings_df, host_summary_df

    except Exception as e:
        print(f"Error parsing {nessus_file}: {e}")
        import traceback
        traceback.print_exc()

        import_report['files_failed'].append({
            'file': os.path.basename(nessus_file),
            'error': str(e)
        })

        return pd.DataFrame(), pd.DataFrame()


def parse_multiple_nessus_files(nessus_files: List[str], plugins_dict: Dict = None,
                                return_import_report: bool = False) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Parse multiple .nessus files and combine results.

    Args:
        nessus_files: List of .nessus file paths
        plugins_dict: Optional plugins database for enrichment
        return_import_report: If True, returns import report as third element

    Returns:
        Tuple of (combined_findings_df, combined_host_summary_df) or
        Tuple of (combined_findings_df, combined_host_summary_df, import_report) if return_import_report=True
    """
    all_findings = []
    all_host_summaries = []

    # Initialize import report
    import_report = {
        'files_processed': [],
        'files_failed': [],
        'hosts_processed': 0,
        'hosts_skipped': [],
        'findings_processed': 0,
        'findings_skipped': [],
        'parsing_warnings': []
    }

    for i, nessus_file in enumerate(nessus_files, 1):
        print(f"Processing file {i}/{len(nessus_files)}: {os.path.basename(nessus_file)}")

        findings_df, host_summary_df = parse_nessus_file(nessus_file, plugins_dict, import_report)

        if not findings_df.empty:
            all_findings.append(findings_df)
        if not host_summary_df.empty:
            all_host_summaries.append(host_summary_df)

    combined_findings = pd.concat(all_findings, ignore_index=True) if all_findings else pd.DataFrame()
    combined_summaries = pd.concat(all_host_summaries, ignore_index=True) if all_host_summaries else pd.DataFrame()

    print(f"Total findings across all files: {len(combined_findings)}")
    print(f"Total hosts across all files: {len(combined_summaries)}")

    # Print import report summary
    print_import_report_summary(import_report)

    if return_import_report:
        return combined_findings, combined_summaries, import_report

    return combined_findings, combined_summaries


def print_import_report_summary(import_report: Dict) -> None:
    """Print a summary of the import report."""
    print("\n" + "=" * 60)
    print("IMPORT REPORT SUMMARY")
    print("=" * 60)

    print(f"\nFiles Processed: {len(import_report.get('files_processed', []))}")
    print(f"Files Failed: {len(import_report.get('files_failed', []))}")
    print(f"Hosts Processed: {import_report.get('hosts_processed', 0)}")
    print(f"Hosts Skipped: {len(import_report.get('hosts_skipped', []))}")
    print(f"Findings Processed: {import_report.get('findings_processed', 0)}")
    print(f"Findings Skipped: {len(import_report.get('findings_skipped', []))}")
    print(f"Parsing Warnings: {len(import_report.get('parsing_warnings', []))}")

    # Show failed files
    if import_report.get('files_failed'):
        print("\n--- FAILED FILES ---")
        for item in import_report['files_failed']:
            print(f"  {item['file']}: {item['error']}")

    # Show skipped hosts
    if import_report.get('hosts_skipped'):
        print("\n--- SKIPPED HOSTS ---")
        for item in import_report['hosts_skipped'][:10]:  # Show first 10
            print(f"  {item['file']} - {item['host']}: {item['error']}")
        if len(import_report['hosts_skipped']) > 10:
            print(f"  ... and {len(import_report['hosts_skipped']) - 10} more")

    # Show skipped findings
    if import_report.get('findings_skipped'):
        print("\n--- SKIPPED FINDINGS ---")
        for item in import_report['findings_skipped'][:10]:  # Show first 10
            print(f"  {item['file']} - {item['host']} - Plugin {item['plugin_id']}: {item['error']}")
        if len(import_report['findings_skipped']) > 10:
            print(f"  ... and {len(import_report['findings_skipped']) - 10} more")

    # Show parsing warnings
    if import_report.get('parsing_warnings'):
        print("\n--- PARSING WARNINGS ---")
        for warning in import_report['parsing_warnings'][:10]:  # Show first 10
            print(f"  {warning}")
        if len(import_report['parsing_warnings']) > 10:
            print(f"  ... and {len(import_report['parsing_warnings']) - 10} more")

    print("\n" + "=" * 60)
