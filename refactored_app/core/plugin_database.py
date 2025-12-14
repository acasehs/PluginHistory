"""
Plugin Database Management Module
Handles loading, parsing, and managing Nessus plugin databases.
"""

import os
import re
import json
import time
import glob
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, Optional, Tuple, Any, List
import pandas as pd

from .archive_extraction import extract_feed_timestamp


def parse_plugins_xml(xml_file: str) -> Optional[Dict[str, Dict[str, Any]]]:
    """
    Parse a Nessus plugins.xml file and extract relevant information.

    Args:
        xml_file: Path to the plugins XML file

    Returns:
        Dictionary with plugin information indexed by plugin ID, or None if error
    """
    try:
        print(f"Loading plugins XML from {xml_file}...")

        plugins_dict = {}
        start_time = time.time()

        feed_timestamp, feed_timestamp_str = extract_feed_timestamp(xml_file)

        # Determine XML structure
        context = ET.iterparse(xml_file, events=('start',))
        root_tag = None
        for event, elem in context:
            root_tag = elem.tag
            break

        plugin_tag = 'nasl' if root_tag == 'nasl_plugins' else 'ReportItem'
        print(f"Found <{root_tag}> format, looking for <{plugin_tag}> elements")

        plugin_count = 0
        progress_interval = 5000
        last_progress_time = start_time

        context = ET.iterparse(xml_file, events=('end',))

        for event, elem in context:
            if elem.tag == plugin_tag:
                try:
                    script_id_elem = elem.find('script_id')
                    if script_id_elem is not None and script_id_elem.text:
                        plugin_id = script_id_elem.text.strip()

                        plugin_entry = {
                            'plugin_id': plugin_id,
                            'feed_timestamp': feed_timestamp,
                            'feed_timestamp_str': feed_timestamp_str
                        }

                        # Extract direct child elements
                        for child in elem:
                            if child.tag != 'attributes' and child.text:
                                if child.tag == 'script_name':
                                    plugin_entry['name'] = child.text.strip()
                                elif child.tag == 'script_family':
                                    plugin_entry['family'] = child.text.strip()
                                else:
                                    plugin_entry[child.tag] = child.text.strip()

                        # Handle CVEs
                        cves_elem = elem.find('cves')
                        if cves_elem is not None:
                            cves = []
                            for cve_elem in cves_elem.findall('cve'):
                                if cve_elem.text and cve_elem.text.strip():
                                    cves.append(cve_elem.text.strip())
                            if cves:
                                plugin_entry['cves'] = "\n".join(cves)

                        # Handle cross-references
                        xrefs_elem = elem.find('xrefs')
                        if xrefs_elem is not None:
                            iavx_refs = []
                            other_refs = []

                            for xref_elem in xrefs_elem.findall('xref'):
                                if xref_elem.text and xref_elem.text.strip():
                                    if any(x in xref_elem.text for x in ["IAVA:", "IAVB:", "IATM:"]):
                                        iavx_refs.append(xref_elem.text.strip())
                                    else:
                                        other_refs.append(xref_elem.text.strip())

                            if iavx_refs:
                                plugin_entry['iavx'] = "\n".join(iavx_refs)
                            if other_refs:
                                plugin_entry['cross_references'] = "\n".join(other_refs)

                        # Process attributes
                        attributes_elem = elem.find('attributes')
                        if attributes_elem is not None:
                            exploit_frameworks = []

                            for attr_elem in attributes_elem.findall('attribute'):
                                name_elem = attr_elem.find('name')
                                value_elem = attr_elem.find('value')

                                if name_elem is not None and name_elem.text and value_elem is not None and value_elem.text:
                                    attr_name = name_elem.text.strip()
                                    attr_value = value_elem.text.strip()

                                    # Map key attributes
                                    attr_mappings = {
                                        "description": "description",
                                        "solution": "solution",
                                        "risk_factor": "risk_factor",
                                        "cvss_base_score": "cvss_base_score",
                                        "cvss3_base_score": "cvss3_base_score",
                                        "synopsis": "synopsis",
                                        "stig_severity": "stig_severity",
                                        "exploitability_ease": "exploit_ease",
                                        "exploit_available": "exploit_available",
                                        "vpr_score": "vpr_score",
                                    }

                                    if attr_name in attr_mappings:
                                        plugin_entry[attr_mappings[attr_name]] = attr_value
                                    elif attr_name.startswith("exploit_framework_"):
                                        if attr_value.lower() == "true":
                                            framework_name = attr_name.replace("exploit_framework_", "").capitalize()
                                            exploit_frameworks.append(framework_name)

                            if exploit_frameworks:
                                plugin_entry['exploit_frameworks'] = ", ".join(exploit_frameworks)

                        plugins_dict[plugin_id] = plugin_entry
                        plugin_count += 1

                        current_time = time.time()
                        if plugin_count % progress_interval == 0:
                            elapsed = current_time - start_time
                            plugins_per_sec = plugin_count / elapsed if elapsed > 0 else 0
                            print(f"Progress: {plugin_count} plugins processed - {plugins_per_sec:.1f} plugins/sec")

                except Exception as e:
                    continue

                elem.clear()

        elapsed = time.time() - start_time
        print(f"Successfully loaded {plugin_count} plugins from XML in {elapsed:.1f} seconds.")
        return plugins_dict

    except Exception as e:
        print(f"Error loading plugins XML: {e}")
        return None


def load_plugins_database_json(plugins_file: str) -> Optional[Dict[str, Dict[str, Any]]]:
    """
    Load the Nessus plugins database from a JSON file.

    Args:
        plugins_file: Path to the JSON file

    Returns:
        Dictionary with plugin information indexed by plugin ID, or None if error
    """
    try:
        print(f"Loading plugins database from {plugins_file}...")

        plugins_dict = {}
        plugin_count = 0
        start_time = time.time()

        with open(plugins_file, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)

            feed_timestamp = data.get('feed_timestamp')
            feed_timestamp_str = ""
            if feed_timestamp:
                try:
                    feed_timestamp = int(feed_timestamp)
                    feed_timestamp_str = datetime.fromtimestamp(feed_timestamp).strftime('%Y-%m-%d %H:%M:%S')
                except (ValueError, TypeError):
                    pass

            if 'nasl' in data and isinstance(data['nasl'], list):
                for plugin in data['nasl']:
                    if 'script_id' in plugin:
                        plugin_id = str(plugin['script_id'])

                        plugin_entry = {
                            'plugin_id': plugin_id,
                            'feed_timestamp': feed_timestamp,
                            'feed_timestamp_str': feed_timestamp_str
                        }

                        # Copy direct properties
                        for key in plugin:
                            if key not in ('attributes', 'cves', 'xrefs'):
                                plugin_entry[key] = plugin[key]

                        if 'script_name' in plugin:
                            plugin_entry['name'] = plugin['script_name']
                        if 'script_family' in plugin:
                            plugin_entry['family'] = plugin['script_family']

                        # Extract CVEs from cves structure
                        if 'cves' in plugin and plugin['cves']:
                            cves = []
                            cves_data = plugin['cves']
                            if isinstance(cves_data, dict) and 'cve' in cves_data:
                                cve_list = cves_data['cve']
                                if isinstance(cve_list, list):
                                    cves.extend([cve for cve in cve_list if cve])
                                elif cve_list:
                                    cves.append(str(cve_list))
                            if cves:
                                plugin_entry['cves'] = "\n".join(cves)

                        # Extract IAVX from xrefs structure
                        if 'xrefs' in plugin and plugin['xrefs']:
                            iavx_refs = []
                            other_refs = []
                            xrefs_data = plugin['xrefs']
                            if isinstance(xrefs_data, dict) and 'xref' in xrefs_data:
                                xref_list = xrefs_data['xref']
                                if isinstance(xref_list, list):
                                    for xref in xref_list:
                                        if xref:
                                            xref_str = str(xref)
                                            if any(x in xref_str for x in ["IAVA:", "IAVB:", "IAVT:", "IATM:"]):
                                                iavx_refs.append(xref_str)
                                            else:
                                                other_refs.append(xref_str)
                                elif xref_list:
                                    xref_str = str(xref_list)
                                    if any(x in xref_str for x in ["IAVA:", "IAVB:", "IAVT:", "IATM:"]):
                                        iavx_refs.append(xref_str)
                                    else:
                                        other_refs.append(xref_str)
                            if iavx_refs:
                                plugin_entry['iavx'] = "\n".join(iavx_refs)
                            if other_refs:
                                plugin_entry['cross_references'] = "\n".join(other_refs)

                        # Process attributes
                        if 'attributes' in plugin and isinstance(plugin['attributes'], dict):
                            attr_data = plugin['attributes']
                            if 'attribute' in attr_data:
                                attributes = attr_data['attribute']
                                if isinstance(attributes, list):
                                    exploit_frameworks = []
                                    for attr in attributes:
                                        if 'name' in attr and 'value' in attr:
                                            attr_name = attr['name']
                                            attr_value = attr['value']

                                            # Map key attributes
                                            attr_mappings = {
                                                "description": "description",
                                                "solution": "solution",
                                                "risk_factor": "risk_factor",
                                                "cvss_base_score": "cvss_base_score",
                                                "cvss3_base_score": "cvss3_base_score",
                                                "synopsis": "synopsis",
                                                "stig_severity": "stig_severity",
                                                "exploitability_ease": "exploit_ease",
                                                "exploit_available": "exploit_available",
                                                "vpr_score": "vpr_score",
                                                "plugin_publication_date": "plugin_publication_date",
                                                "plugin_modification_date": "plugin_modification_date",
                                                "vuln_publication_date": "vuln_publication_date",
                                                "patch_publication_date": "patch_publication_date",
                                                "cpe": "cpe",
                                                "cvss_vector": "cvss_vector",
                                                "cvss3_vector": "cvss_v3_vector",
                                                "iava": "iava",
                                            }

                                            if attr_name in attr_mappings:
                                                plugin_entry[attr_mappings[attr_name]] = attr_value
                                            elif attr_name.startswith("exploit_framework_"):
                                                if str(attr_value).lower() == "true":
                                                    framework_name = attr_name.replace("exploit_framework_", "").capitalize()
                                                    exploit_frameworks.append(framework_name)

                                            # Handle iava attribute adding to iavx
                                            if attr_name == "iava" and attr_value:
                                                iava_ref = f"IAVA:{attr_value}"
                                                if 'iavx' in plugin_entry:
                                                    if iava_ref not in plugin_entry['iavx']:
                                                        plugin_entry['iavx'] += f"\n{iava_ref}"
                                                else:
                                                    plugin_entry['iavx'] = iava_ref

                                    if exploit_frameworks:
                                        plugin_entry['exploit_frameworks'] = ", ".join(exploit_frameworks)

                        plugins_dict[plugin_id] = plugin_entry
                        plugin_count += 1

        elapsed = time.time() - start_time
        print(f"Successfully loaded {plugin_count} plugins from JSON in {elapsed:.1f} seconds.")
        return plugins_dict

    except Exception as e:
        print(f"Error loading plugins database: {e}")
        import traceback
        traceback.print_exc()
        return None


def load_plugins_database(plugins_file: Optional[str] = None) -> Optional[Dict[str, Dict[str, Any]]]:
    """
    Load the Nessus plugins database for enriching finding information.

    Args:
        plugins_file: Optional explicit path to plugins file

    Returns:
        Dictionary with plugin information indexed by plugin ID or None
    """
    if not plugins_file:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(script_dir)

        # Look for plugins files
        plugins_pattern = os.path.join(parent_dir, "plugins*.xml")
        all_plugins_files = glob.glob(plugins_pattern)

        if not all_plugins_files:
            plugins_pattern = os.path.join(script_dir, "plugins*.xml")
            all_plugins_files = glob.glob(plugins_pattern)

        if all_plugins_files:
            # Sort by modification time, use newest
            all_plugins_files.sort(key=os.path.getmtime, reverse=True)
            plugins_file = all_plugins_files[0]
            print(f"Using plugins file: {plugins_file}")
        else:
            print("No plugins database file found.")
            return None

    try:
        if plugins_file.lower().endswith('.xml'):
            return parse_plugins_xml(plugins_file)
        elif plugins_file.lower().endswith('.json'):
            return load_plugins_database_json(plugins_file)
        else:
            # Try to detect format
            with open(plugins_file, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline().strip()
                if first_line.startswith('{') or first_line.startswith('['):
                    return load_plugins_database_json(plugins_file)
                elif first_line.startswith('<?xml') or first_line.startswith('<'):
                    return parse_plugins_xml(plugins_file)
                else:
                    print(f"Unknown file format for {plugins_file}")
                    return None

    except Exception as e:
        print(f"Error accessing plugins database file: {e}")
        return None


def plugins_dict_to_dataframe(plugins_dict: Dict[str, Dict[str, Any]]) -> pd.DataFrame:
    """
    Convert plugins dictionary to pandas DataFrame.

    Args:
        plugins_dict: Dictionary of plugin data

    Returns:
        pandas DataFrame with plugin information
    """
    if not plugins_dict:
        return pd.DataFrame()

    df = pd.DataFrame.from_dict(plugins_dict, orient='index')
    df.reset_index(drop=True, inplace=True)

    return df
