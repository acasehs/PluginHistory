"""
Hostname Resolution Module
Extracts hostnames from various sources including Nessus plugins and network data.
"""

import re
from typing import Optional, Dict, Any
import xml.etree.ElementTree as ET


def extract_hostname_from_plugins(host_element: ET.Element) -> Optional[str]:
    """
    Extract hostname from specific Nessus plugins if available.
    
    Args:
        host_element: XML element representing a host from .nessus file
        
    Returns:
        First hostname found or None if not found
    """
    hostname = None
    
    # Try plugin 55472 (Hostname)
    for item in host_element.findall(".//ReportItem[@pluginID='55472']"):
        plugin_output = item.find("plugin_output")
        if plugin_output is not None and plugin_output.text:
            lines = plugin_output.text.strip().split("\n")
            for line in lines:
                if "hostname command" in line:
                    # Extract hostname (the first part before any spaces)
                    hostname = line.split()[0].split(".")[0]
                    return hostname

    # Try plugin 12053 (DNS Resolution)
    for item in host_element.findall(".//ReportItem[@pluginID='12053']"):
        plugin_output = item.find("plugin_output")
        if plugin_output is not None and plugin_output.text:
            match = re.search(r"resolves as ([\w.-]+)", plugin_output.text)
            if match:
                hostname = match.group(1).split(".")[0]
                return hostname
    
    # Try plugin 10150 (NetBIOS/SMB Information)
    for item in host_element.findall(".//ReportItem[@pluginID='10150']"):
        plugin_output = item.find("plugin_output")
        if plugin_output is not None and plugin_output.text:
            lines = plugin_output.text.strip().split("\n")
            for line in lines:
                if "netbios computer name :" in line.lower():
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        hostname = parts[1].strip()
                        return hostname
    
    # Try Common Platform Enumeration (45590)
    for item in host_element.findall(".//ReportItem[@pluginID='45590']"):
        plugin_output = item.find("plugin_output")
        if plugin_output is not None and plugin_output.text:
            if "hostname :" in plugin_output.text.lower():
                lines = plugin_output.text.strip().split("\n")
                for line in lines:
                    if "hostname :" in line.lower():
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            hostname_part = parts[1].strip()
                            # Extract hostname from FQDN if needed
                            if hostname_part and '.' in hostname_part:
                                hostname = hostname_part.split('.')[0]
                            else:
                                hostname = hostname_part
                            return hostname
    
    return hostname


def resolve_hostname(host_name: str, host_element: ET.Element = None) -> str:
    """
    Resolve hostname using multiple methods.
    
    Args:
        host_name: IP address or hostname from the report
        host_element: Optional XML element for plugin-based resolution
        
    Returns:
        Resolved hostname or sanitized version of input
    """
    hostname = None
    
    # First try plugin-based extraction if available
    if host_element is not None:
        hostname = extract_hostname_from_plugins(host_element)
    
    # If no hostname from plugins, try extracting from host_name
    if not hostname and '.' in host_name and not host_name[0].isdigit():
        # Appears to be FQDN, extract hostname part
        hostname = host_name.split('.')[0]
    # If still no hostname and it's an IP, use the IP
    elif not hostname:
        hostname = host_name
    
    return hostname


def sanitize_hostname_for_excel(hostname: str) -> str:
    """
    Sanitize hostname for Excel sheet name (remove invalid characters).
    
    Args:
        hostname: Raw hostname
        
    Returns:
        Sanitized hostname suitable for Excel sheet names
    """
    if not hostname:
        return "Host"
    
    # Remove invalid characters including hyphens for Excel sheet names
    safe_hostname = re.sub(r'[\\/*[\]:?\-]', '_', hostname)
    
    # Excel has a 31 character limit for sheet names
    if len(safe_hostname) > 31:
        safe_hostname = f"Host_{hash(hostname) % 10000}"
    
    return safe_hostname


def extract_network_info(host_element: ET.Element) -> Dict[str, Optional[str]]:
    """
    Extract network information (DNS, NetBIOS, MAC) from host element.
    
    Args:
        host_element: XML element representing a host
        
    Returns:
        Dictionary containing dns_name, netbios_name, mac_address
    """
    network_info = {
        'dns_name': None,
        'netbios_name': None,
        'mac_address': None
    }
    
    # Extract from various plugins
    for item in host_element.findall(".//ReportItem"):
        plugin_id = item.attrib.get('pluginID', '')
        plugin_output = item.find("plugin_output")
        
        if plugin_output is None or not plugin_output.text:
            continue
            
        output_text = plugin_output.text.lower()
        
        # DNS information
        if plugin_id in ['12053', '45590']:  # DNS Resolution plugins
            if 'dns' in output_text or 'resolves' in output_text:
                # Extract DNS name patterns
                dns_match = re.search(r"dns.*?:\s*([\w.-]+)", output_text, re.IGNORECASE)
                if dns_match:
                    network_info['dns_name'] = dns_match.group(1)
        
        # NetBIOS information  
        if plugin_id in ['10150', '10394']:  # SMB/NetBIOS plugins
            if 'netbios' in output_text:
                netbios_match = re.search(r"netbios.*?name.*?:\s*([\w-]+)", output_text, re.IGNORECASE)
                if netbios_match:
                    network_info['netbios_name'] = netbios_match.group(1)
        
        # MAC address information
        if 'mac' in output_text and 'address' in output_text:
            mac_match = re.search(r"([0-9a-f]{2}[:-]){5}([0-9a-f]{2})", output_text, re.IGNORECASE)
            if mac_match:
                network_info['mac_address'] = mac_match.group(0)
    
    return network_info


def create_gpm_uid(plugin_id: str, hostname: str) -> str:
    """
    Create GPM (Global Plugin Management) UID.
    
    Args:
        plugin_id: Plugin identifier
        hostname: Host identifier
        
    Returns:
        GPM UID in format "plugin_id.hostname"
    """
    return f"{plugin_id}.{hostname}"


def extract_hostname_mapping(host_elements: list) -> Dict[str, Dict[str, str]]:
    """
    Create a mapping of IP addresses to hostnames and network info for multiple hosts.
    
    Args:
        host_elements: List of XML host elements
        
    Returns:
        Dictionary mapping IP addresses to hostname info
    """
    hostname_mapping = {}
    
    for host_element in host_elements:
        host_ip = host_element.attrib.get('name', 'Unknown')
        
        # Get hostname
        hostname = extract_hostname_from_plugins(host_element)
        if not hostname:
            hostname = resolve_hostname(host_ip, host_element)
        
        # Get network info
        network_info = extract_network_info(host_element)
        
        # Create mapping entry
        hostname_mapping[host_ip] = {
            'hostname': hostname,
            'safe_hostname': sanitize_hostname_for_excel(hostname),
            'dns_name': network_info['dns_name'],
            'netbios_name': network_info['netbios_name'], 
            'mac_address': network_info['mac_address']
        }
    
    return hostname_mapping