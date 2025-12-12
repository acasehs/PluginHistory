"""
Plugin Database Management Module
Handles loading, parsing, and managing Nessus plugin databases from various sources.
"""

import os
import re
import json
import time
import glob
import shutil
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, Optional, Tuple, Any, List
import pandas as pd  # pip install pandas


def extract_feed_timestamp(xml_file: str) -> Tuple[Optional[int], str]:
    """
    Extract feed timestamp from plugins.xml file.
    
    Args:
        xml_file: Path to the XML file
        
    Returns:
        Tuple of (timestamp as int, timestamp as formatted string)
    """
    try:
        print(f"Extracting timestamp from {xml_file}...")
        file_size = os.path.getsize(xml_file)
        print(f"File size: {file_size} bytes")
        
        with open(xml_file, 'r', encoding='utf-8', errors='ignore') as f:
            header = f.read(10000)
            print(f"Reading first 10KB for timestamp...")
        
        # Method 1: <feed_timestamp> element
        feed_timestamp_match = re.search(r'<feed_timestamp>(\d+)</feed_timestamp>', header)
        if feed_timestamp_match:
            timestamp = int(feed_timestamp_match.group(1))
            timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            print(f"Found <feed_timestamp> element: {timestamp} ({timestamp_str})")
            return timestamp, timestamp_str
        
        # Method 2: <xml_timestamp> element
        xml_timestamp_match = re.search(r'<xml_timestamp>(\d+)</xml_timestamp>', header)
        if xml_timestamp_match:
            timestamp = int(xml_timestamp_match.group(1))
            timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            print(f"Found <xml_timestamp> element: {timestamp} ({timestamp_str})")
            return timestamp, timestamp_str
        
        # Method 3: feed_timestamp attribute
        feed_timestamp_attr_match = re.search(r'feed_timestamp="(\d+)"', header)
        if feed_timestamp_attr_match:
            timestamp = int(feed_timestamp_attr_match.group(1))
            timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            print(f"Found feed_timestamp attribute: {timestamp} ({timestamp_str})")
            return timestamp, timestamp_str
        
        # Method 4: Partial pattern
        partial_feed_timestamp_match = re.search(r'<feed_timestamp>(\d+)', header)
        if partial_feed_timestamp_match:
            timestamp = int(partial_feed_timestamp_match.group(1))
            timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            print(f"Found partial <feed_timestamp> pattern: {timestamp} ({timestamp_str})")
            return timestamp, timestamp_str
        
        # Method 5: Generic timestamp pattern
        timestamp_pattern_match = re.search(r'timestamp[^>]*>(\d{10})<', header)
        if timestamp_pattern_match:
            timestamp = int(timestamp_pattern_match.group(1))
            timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            print(f"Found generic timestamp pattern: {timestamp} ({timestamp_str})")
            return timestamp, timestamp_str
        
        print("No timestamp found in XML header, checking for alternative sources...")
        
        # Check nasl_plugins format
        if '<nasl_plugins>' in header:
            print("Found <nasl_plugins> format")
            filename = os.path.basename(xml_file)
            if 'plugins' in filename and '.xml' in filename:
                date_match = re.search(r'plugins(\d{6})\.xml', filename)
                if date_match:
                    date_str = date_match.group(1)
                    try:
                        date_obj = datetime.strptime(date_str, '%m%d%y')
                        timestamp = int(date_obj.timestamp())
                        print(f"Using date from filename: {date_str} ({date_obj.strftime('%Y-%m-%d')})")
                        return timestamp, date_obj.strftime('%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        pass
        
        # Fallback: file modification time
        mod_time = os.path.getmtime(xml_file)
        mod_time_str = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')
        print(f"Using file modification time as fallback: {int(mod_time)} ({mod_time_str})")
        return int(mod_time), mod_time_str
    
    except Exception as e:
        print(f"Error extracting feed timestamp: {e}")
        import traceback
        traceback.print_exc()
        
        try:
            mod_time = os.path.getmtime(xml_file)
            mod_time_str = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')
            print(f"Using file modification time after error: {int(mod_time)} ({mod_time_str})")
            return int(mod_time), f"Error recovery - {mod_time_str}"
        except:
            current_time = int(time.time())
            current_time_str = datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')
            return current_time, f"Error fallback - {current_time_str}"


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
        
        print("Examining XML structure...")
        context = ET.iterparse(xml_file, events=('start',))
        for event, elem in context:
            root_tag = elem.tag
            print(f"Root element: <{root_tag}>")
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
                                    
                                    plugin_entry[f"atb_{attr_name}"] = attr_value
                                    
                                    # Map key attributes to standard names
                                    if attr_name == "description":
                                        plugin_entry['description'] = attr_value
                                    elif attr_name == "solution":
                                        plugin_entry['solution'] = attr_value
                                    elif attr_name == "risk_factor":
                                        plugin_entry['severity'] = attr_value
                                        plugin_entry['risk_factor'] = attr_value
                                    elif attr_name == "cvss_base_score":
                                        plugin_entry['cvss_base_score'] = attr_value
                                    elif attr_name == "cvss3_base_score":
                                        plugin_entry['cvss3_base_score'] = attr_value
                                    elif attr_name == "cvss3_temporal_score":
                                        plugin_entry['cvss3_temporal_score'] = attr_value
                                    elif attr_name == "synopsis":
                                        plugin_entry['synopsis'] = attr_value
                                    elif attr_name == "plugin_publication_date":
                                        plugin_entry['plugin_publication_date'] = attr_value
                                    elif attr_name == "plugin_modification_date":
                                        plugin_entry['plugin_modification_date'] = attr_value
                                    elif attr_name == "vuln_publication_date":
                                        plugin_entry['vuln_publication_date'] = attr_value
                                    elif attr_name == "patch_publication_date":
                                        plugin_entry['patch_publication_date'] = attr_value
                                    elif attr_name == "stig_severity":
                                        plugin_entry['stig_severity'] = attr_value
                                    elif attr_name == "exploitability_ease":
                                        plugin_entry['exploit_ease'] = attr_value
                                    elif attr_name == "exploit_available":
                                        plugin_entry['exploit_available'] = attr_value
                                    elif attr_name == "exploit_framework":
                                        plugin_entry['exploit_frameworks'] = attr_value
                                    elif attr_name.startswith("exploit_framework_"):
                                        if attr_value.lower() == "true":
                                            framework_name = attr_name.replace("exploit_framework_", "").capitalize()
                                            exploit_frameworks.append(framework_name)
                                    elif attr_name == "cpe":
                                        plugin_entry['cpe'] = attr_value
                                    elif attr_name == "cvss_vector":
                                        plugin_entry['cvss_vector'] = attr_value
                                    elif attr_name == "cvss3_vector":
                                        plugin_entry['cvss_v3_vector'] = attr_value
                                    elif attr_name == "see_also":
                                        plugin_entry['see_also'] = attr_value
                                    elif attr_name == "bid":
                                        plugin_entry['bid'] = attr_value
                                    elif attr_name == "iava":
                                        plugin_entry['iava'] = attr_value
                                        if 'iavx' not in plugin_entry:
                                            plugin_entry['iavx'] = f"IAVA:{attr_value}"
                                        else:
                                            plugin_entry['iavx'] += f"\nIAVA:{attr_value}"
                                    elif attr_name == "vpr_score":
                                        plugin_entry['vpr_score'] = attr_value
                                        plugin_entry['vuln_priority'] = attr_value
                                    elif attr_name == "repository":
                                        plugin_entry['repository'] = attr_value
                                    elif attr_name == "mac_address":
                                        plugin_entry['mac_address'] = attr_value
                                    elif attr_name == "dns_name":
                                        plugin_entry['dns_name'] = attr_value
                                    elif attr_name == "netbios_name":
                                        plugin_entry['netbios_name'] = attr_value
                            
                            if exploit_frameworks:
                                plugin_entry['exploit_frameworks'] = ", ".join(exploit_frameworks)
                        
                        plugins_dict[plugin_id] = plugin_entry
                        plugin_count += 1
                        
                        current_time = time.time()
                        if plugin_count % progress_interval == 0 or (current_time - last_progress_time) >= 10:
                            elapsed = current_time - start_time
                            plugins_per_sec = plugin_count / elapsed if elapsed > 0 else 0
                            print(f"Progress: {plugin_count} plugins processed - {plugins_per_sec:.1f} plugins/sec")
                            last_progress_time = current_time
                
                except Exception as e:
                    print(f"Error processing plugin: {str(e)}")
                    continue
                
                elem.clear()
        
        elapsed = time.time() - start_time
        print(f"Successfully loaded {plugin_count} plugins from XML in {elapsed:.1f} seconds.")
        return plugins_dict
    
    except Exception as e:
        print(f"Error loading plugins XML: {e}")
        import traceback
        traceback.print_exc()
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
        progress_interval = 5000
        last_progress_time = start_time
        
        try:
            with open(plugins_file, 'r', encoding='utf-8', errors='ignore') as f:
                print("Parsing JSON file - this may take a while for large files...")
                data = json.load(f)
                print("JSON parsing complete, extracting plugin data...")
                
                feed_timestamp = None
                if 'feed_timestamp' in data:
                    try:
                        feed_timestamp = int(data['feed_timestamp'])
                        feed_timestamp_date = datetime.fromtimestamp(feed_timestamp)
                        print(f"Plugin feed timestamp: {feed_timestamp} ({feed_timestamp_date.strftime('%Y-%m-%d %H:%M:%S')})")
                    except (ValueError, TypeError) as e:
                        print(f"Error parsing feed timestamp: {e}")
                
                feed_timestamp_str = ""
                if feed_timestamp:
                    feed_timestamp_str = datetime.fromtimestamp(feed_timestamp).strftime('%Y-%m-%d %H:%M:%S')
                
                if 'nasl' in data and isinstance(data['nasl'], list):
                    total_plugins = len(data['nasl'])
                    print(f"Processing {total_plugins} plugins from structured JSON...")
                    
                    for i, plugin in enumerate(data['nasl']):
                        try:
                            if 'script_id' in plugin:
                                plugin_id = str(plugin['script_id'])
                                
                                plugin_entry = {
                                    'plugin_id': plugin_id,
                                    'feed_timestamp': feed_timestamp,
                                    'feed_timestamp_str': feed_timestamp_str
                                }
                                
                                for key in plugin:
                                    if key != 'attributes':
                                        plugin_entry[key] = plugin[key]
                                
                                if 'script_name' in plugin:
                                    plugin_entry['name'] = plugin['script_name']
                                    
                                if 'script_family' in plugin:
                                    plugin_entry['family'] = plugin['script_family']
                                
                                # Process attributes (similar to XML logic)
                                if 'attributes' in plugin and isinstance(plugin['attributes'], dict) and 'attribute' in plugin['attributes']:
                                    attributes = plugin['attributes']['attribute']
                                    if isinstance(attributes, list):
                                        exploit_frameworks = []
                                        
                                        for attr in attributes:
                                            if 'name' in attr and 'value' in attr:
                                                attr_name = f"atb_{attr['name']}"
                                                plugin_entry[attr_name] = attr['value']
                                                
                                                # Map key attributes (same as XML)
                                                if attr['name'] == "description":
                                                    plugin_entry['description'] = attr['value']
                                                elif attr['name'] == "solution":
                                                    plugin_entry['solution'] = attr['value']
                                                elif attr['name'] == "risk_factor":
                                                    plugin_entry['severity'] = attr['value']
                                                    plugin_entry['risk_factor'] = attr['value']
                                                elif attr['name'] == "cvss_base_score":
                                                    plugin_entry['cvss_base_score'] = attr['value']
                                                elif attr['name'] == "cvss3_base_score":
                                                    plugin_entry['cvss3_base_score'] = attr['value']
                                                elif attr['name'] == "cvss3_temporal_score":
                                                    plugin_entry['cvss3_temporal_score'] = attr['value']
                                                elif attr['name'] == "synopsis":
                                                    plugin_entry['synopsis'] = attr['value']
                                                elif attr['name'] == "plugin_publication_date":
                                                    plugin_entry['plugin_publication_date'] = attr['value']
                                                elif attr['name'] == "plugin_modification_date":
                                                    plugin_entry['plugin_modification_date'] = attr['value']
                                                elif attr['name'] == "vuln_publication_date":
                                                    plugin_entry['vuln_publication_date'] = attr['value']
                                                elif attr['name'] == "patch_publication_date":
                                                    plugin_entry['patch_publication_date'] = attr['value']
                                                elif attr['name'] == "stig_severity":
                                                    plugin_entry['stig_severity'] = attr['value']
                                                elif attr['name'] == "exploitability_ease":
                                                    plugin_entry['exploit_ease'] = attr['value']
                                                elif attr['name'] == "exploit_available":
                                                    plugin_entry['exploit_available'] = attr['value']
                                                elif attr['name'] == "exploit_framework":
                                                    plugin_entry['exploit_frameworks'] = attr['value']
                                                elif attr['name'] == "cpe":
                                                    plugin_entry['cpe'] = attr['value']
                                                elif attr['name'] == "cvss_vector":
                                                    plugin_entry['cvss_vector'] = attr['value']
                                                elif attr['name'] == "cvss3_vector":
                                                    plugin_entry['cvss_v3_vector'] = attr['value']
                                                elif attr['name'] == "see_also":
                                                    plugin_entry['see_also'] = attr['value']
                                                elif attr['name'] == "bid":
                                                    plugin_entry['bid'] = attr['value']
                                                elif attr['name'] == "iava":
                                                    plugin_entry['iava'] = attr['value']
                                                    if 'iavx' not in plugin_entry:
                                                        plugin_entry['iavx'] = f"IAVA:{attr['value']}"
                                                    else:
                                                        plugin_entry['iavx'] += f"\nIAVA:{attr['value']}"
                                                elif attr['name'] == "vpr_score":
                                                    plugin_entry['vpr_score'] = attr['value']
                                                    plugin_entry['vuln_priority'] = attr['value']
                                                elif attr['name'].startswith("exploit_framework_"):
                                                    if attr['value'].lower() == "true":
                                                        framework_name = attr['name'].replace("exploit_framework_", "").capitalize()
                                                        exploit_frameworks.append(framework_name)
                                                elif attr['name'] == "repository":
                                                    plugin_entry['repository'] = attr['value']
                                                elif attr['name'] == "mac_address":
                                                    plugin_entry['mac_address'] = attr['value']
                                                elif attr['name'] == "dns_name":
                                                    plugin_entry['dns_name'] = attr['value']
                                                elif attr['name'] == "netbios_name":
                                                    plugin_entry['netbios_name'] = attr['value']
                                        
                                        if exploit_frameworks:
                                            plugin_entry['exploit_frameworks'] = ", ".join(exploit_frameworks)
                                
                                # Extract CVEs
                                if 'cves' in plugin and plugin['cves']:
                                    cves = []
                                    if isinstance(plugin['cves'], dict) and 'cve' in plugin['cves']:
                                        cve_data = plugin['cves']['cve']
                                        if isinstance(cve_data, list):
                                            cves.extend([cve for cve in cve_data if cve])
                                        elif cve_data:
                                            cves.append(str(cve_data))
                                    
                                    if cves:
                                        plugin_entry['cves'] = "\n".join(cves)
                                
                                # Extract cross references
                                if 'xrefs' in plugin and plugin['xrefs']:
                                    iavx_refs = []
                                    other_refs = []
                                    
                                    if isinstance(plugin['xrefs'], dict) and 'xref' in plugin['xrefs']:
                                        xref_data = plugin['xrefs']['xref']
                                        if isinstance(xref_data, list):
                                            for xref in xref_data:
                                                if xref:
                                                    if any(x in xref for x in ["IAVA:", "IAVB:", "IATM:"]):
                                                        iavx_refs.append(xref)
                                                    else:
                                                        other_refs.append(xref)
                                        elif xref_data:
                                            if any(x in str(xref_data) for x in ["IAVA:", "IAVB:", "IATM:"]):
                                                iavx_refs.append(str(xref_data))
                                            else:
                                                other_refs.append(str(xref_data))
                                    
                                    if other_refs:
                                        plugin_entry['cross_references'] = "\n".join(other_refs)
                                    
                                    if iavx_refs:
                                        if 'iavx' not in plugin_entry:
                                            plugin_entry['iavx'] = "\n".join(iavx_refs)
                                        else:
                                            plugin_entry['iavx'] += "\n" + "\n".join(iavx_refs)
                                
                                plugins_dict[plugin_id] = plugin_entry
                                plugin_count += 1
                                
                                current_time = time.time()
                                if plugin_count % progress_interval == 0 or (current_time - last_progress_time) >= 10:
                                    elapsed = current_time - start_time
                                    percent = (i + 1) / total_plugins * 100
                                    plugins_per_sec = plugin_count / elapsed if elapsed > 0 else 0
                                    
                                    print(f"Progress: {i+1}/{total_plugins} plugins ({percent:.1f}%) - {plugins_per_sec:.1f} plugins/sec")
                                    last_progress_time = current_time
                                
                        except Exception as e:
                            print(f"Error processing plugin {i}: {str(e)}")
                            continue
                
                if plugin_count > 0:
                    elapsed = time.time() - start_time
                    print(f"Successfully loaded {plugin_count} plugins from database in {elapsed:.1f} seconds.")
                    return plugins_dict
            
            print("No plugins found in the standard format. The file may have a different structure.")
            return None
            
        except json.JSONDecodeError:
            print("JSON parsing error. The file may be too large or have an invalid format.")
            return None
        except Exception as e:
            print(f"Error loading plugins database: {e}")
            return None
    
    except Exception as e:
        print(f"Error accessing plugins database file: {e}")
        return None


def load_plugins_database(plugins_file: Optional[str] = None) -> Optional[Dict[str, Dict[str, Any]]]:
    """
    Load the Nessus plugins database for enriching finding information.
    
    First checks for CM-xxxxxx-sc-plugins.tar.gz files,
    then checks for plugins.xml in the script directory,
    then uses provided file or returns None.
    
    Args:
        plugins_file: Optional explicit path to plugins file
        
    Returns:
        Dictionary with plugin information indexed by plugin ID or None
    """
    # Import here to avoid circular dependency
    try:
        from archive_extraction import extract_plugins_from_archive
    except ImportError:
        extract_plugins_from_archive = None
    
    if not plugins_file:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        default_plugins_file = os.path.join(script_dir, "plugins.xml")
        existing_plugins_feed_timestamp = None
        existing_plugins_feed_timestamp_str = "Unknown"
        
        # Find all plugins XML files
        plugins_pattern = os.path.join(script_dir, "plugins*.xml")
        all_plugins_files = glob.glob(plugins_pattern)
        
        plugins_timestamps = {}
        
        for plugin_file in all_plugins_files:
            file_timestamp, file_timestamp_str = extract_feed_timestamp(plugin_file)
            if file_timestamp:
                print(f"Found plugins file: {os.path.basename(plugin_file)}, timestamp: {file_timestamp_str}")
                plugins_timestamps[plugin_file] = (file_timestamp, False)
        
        # Look for CM-xxxxxx-sc-plugins.tar.gz files
        sc_plugins_pattern = os.path.join(script_dir, "CM-*-sc-plugins.tar.gz")
        sc_plugins_files = glob.glob(sc_plugins_pattern)
        
        if sc_plugins_files and extract_plugins_from_archive:
            sc_plugins_files.sort(key=os.path.getmtime, reverse=True)
            archive_file = sc_plugins_files[0]
            archive_date = os.path.getmtime(archive_file)
            print(f"Found plugins archive at {archive_file}")
            print(f"Archive file date: {datetime.fromtimestamp(archive_date).strftime('%Y-%m-%d %H:%M:%S')}")
            
            extracted_xml, archive_feed_timestamp, archive_feed_timestamp_str = extract_plugins_from_archive(archive_file, tempfile.mkdtemp())
            
            if extracted_xml and archive_feed_timestamp:
                print(f"Extracted plugins.xml feed timestamp: {archive_feed_timestamp_str} (Unix: {archive_feed_timestamp})")
                
                plugins_timestamps[extracted_xml] = (archive_feed_timestamp, True)
                
                newest_file = None
                newest_timestamp = 0
                is_fresh = False
                
                if plugins_timestamps:
                    sorted_files = sorted(plugins_timestamps.items(), 
                                          key=lambda x: (x[1][0], x[1][1]), 
                                          reverse=True)
                    newest_file, (newest_timestamp, is_fresh) = sorted_files[0]
                
                if newest_timestamp > archive_feed_timestamp or (newest_timestamp == archive_feed_timestamp and is_fresh):
                    print(f"Found existing plugins file with newer or same timestamp: {os.path.basename(newest_file)}")
                    print(f"Using existing file: {newest_file}")
                    plugins_file = newest_file
                else:
                    print(f"Archive has newest feed timestamp. Copying extracted plugins.xml to {default_plugins_file}")
                    shutil.copy2(extracted_xml, default_plugins_file)
                    plugins_file = default_plugins_file
                    
                    plugins_timestamps[default_plugins_file] = (archive_feed_timestamp, True)
            else:
                print("Could not extract plugins.xml or determine feed timestamp from archive.")
                if plugins_timestamps:
                    sorted_files = sorted(plugins_timestamps.items(), 
                                          key=lambda x: (x[1][0], x[1][1]), 
                                          reverse=True)
                    newest_file, _ = sorted_files[0]
                    print(f"Using existing plugins file: {newest_file}")
                    plugins_file = newest_file
                else:
                    print("No plugins database file found.")
                    return None
        elif plugins_timestamps:
            sorted_files = sorted(plugins_timestamps.items(), 
                                 key=lambda x: x[1][0], 
                                 reverse=True)
            newest_file, _ = sorted_files[0]
            print(f"Using newest existing plugins file: {newest_file}")
            plugins_file = newest_file
        else:
            print("No plugins database file found.")
            return None
        
        # Clean up old plugins files - keep only the newest two
        if len(plugins_timestamps) > 2:
            print("Cleaning up older plugins files...")
            
            sorted_files = sorted(plugins_timestamps.items(), 
                                 key=lambda x: (x[1][0], x[1][1]), 
                                 reverse=True)
            
            files_to_keep = set()
            files_to_keep.add(plugins_file)
            
            if plugins_file == default_plugins_file:
                for file_path, _ in sorted_files:
                    if file_path != default_plugins_file:
                        files_to_keep.add(file_path)
                        break
            else:
                if os.path.exists(default_plugins_file):
                    files_to_keep.add(default_plugins_file)
            
            files_to_keep = list(files_to_keep)[:2]
            
            print(f"Keeping files: {[os.path.basename(f) for f in files_to_keep]}")
            
            for file_path in plugins_timestamps:
                if file_path not in files_to_keep:
                    try:
                        print(f"Removing old plugins file: {os.path.basename(file_path)}")
                        os.remove(file_path)
                    except Exception as e:
                        print(f"Error removing file {file_path}: {e}")
    
    try:
        if plugins_file.lower().endswith('.xml'):
            return parse_plugins_xml(plugins_file)
        elif plugins_file.lower().endswith('.json'):
            return load_plugins_database_json(plugins_file)
        else:
            with open(plugins_file, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline().strip()
                if first_line.startswith('{') or first_line.startswith('['):
                    return load_plugins_database_json(plugins_file)
                elif first_line.startswith('<?xml') or first_line.startswith('<'):
                    return parse_plugins_xml(plugins_file)
                else:
                    print(f"Unknown file format for {plugins_file}. File should be XML or JSON.")
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


def find_latest_plugins_file(directory: str = None) -> Optional[str]:
    """
    Find the latest plugins file in the given directory.
    
    Args:
        directory: Directory to search (defaults to script directory)
        
    Returns:
        Path to the latest plugins file, or None if not found
    """
    if directory is None:
        directory = os.path.dirname(os.path.abspath(__file__))
    
    plugins_pattern = os.path.join(directory, "plugins*.xml")
    all_plugins_files = glob.glob(plugins_pattern)
    
    plugins_timestamps = {}
    
    for plugin_file in all_plugins_files:
        file_timestamp, _ = extract_feed_timestamp(plugin_file)
        if file_timestamp:
            plugins_timestamps[plugin_file] = file_timestamp
    
    if plugins_timestamps:
        latest_file = max(plugins_timestamps, key=plugins_timestamps.get)
        return latest_file
    
    return None


def cleanup_old_plugins_files(directory: str = None, keep_count: int = 2) -> None:
    """
    Clean up old plugins files, keeping only the newest ones.
    
    Args:
        directory: Directory to clean (defaults to script directory)
        keep_count: Number of files to keep
    """
    if directory is None:
        directory = os.path.dirname(os.path.abspath(__file__))
    
    plugins_pattern = os.path.join(directory, "plugins*.xml")
    all_plugins_files = glob.glob(plugins_pattern)
    
    if len(all_plugins_files) <= keep_count:
        return
    
    all_plugins_files.sort(key=os.path.getmtime, reverse=True)
    
    files_to_keep = all_plugins_files[:keep_count]
    files_to_remove = all_plugins_files[keep_count:]
    
    print(f"Keeping files: {[os.path.basename(f) for f in files_to_keep]}")
    
    for file_path in files_to_remove:
        try:
            print(f"Removing old plugins file: {os.path.basename(file_path)}")
            os.remove(file_path)
        except Exception as e:
            print(f"Error removing file {file_path}: {e}")