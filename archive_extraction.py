"""
Archive Extraction Module
Handles extraction of nested archives including zip files and compressed plugin databases.
"""

import os
import zipfile
import tarfile
import tempfile
import shutil
import glob
import gzip
import re
from datetime import datetime
from typing import Tuple, Optional, List


def extract_nested_archives(archive_path: str, extraction_dir: str) -> None:
    """
    Extract a zip file that may contain other zip files.
    
    Args:
        archive_path: Path to the archive file
        extraction_dir: Directory to extract files to
    """
    # Extract the main zip file
    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
        zip_ref.extractall(extraction_dir)
    
    # Look for zip files in the extraction directory and extract them
    for root, _, files in os.walk(extraction_dir):
        for file in files:
            if file.endswith('.zip'):
                zip_path = os.path.join(root, file)
                # Create a directory with the same name as the zip file (without extension)
                nested_dir = os.path.join(root, os.path.splitext(file)[0])
                os.makedirs(nested_dir, exist_ok=True)
                
                # Extract the nested zip
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(nested_dir)


def find_files_by_extension(directory: str, extension: str) -> List[str]:
    """
    Find all files with specified extension in a directory (recursively).
    
    Args:
        directory: Directory to search
        extension: File extension (e.g., '.nessus')
        
    Returns:
        List of file paths
    """
    found_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(extension):
                found_files.append(os.path.join(root, file))
    return found_files


def extract_feed_timestamp(xml_file: str) -> Tuple[Optional[int], str]:
    """
    Extract feed timestamp from plugins.xml file.
    
    Args:
        xml_file: Path to the XML file
        
    Returns:
        Tuple of (timestamp as int, timestamp as formatted string)
        If timestamp is not found, returns (None, "Unknown")
    """
    try:
        print(f"Extracting timestamp from {xml_file}...")
        file_size = os.path.getsize(xml_file)
        print(f"File size: {file_size} bytes")
        
        # Read the beginning of the file to check structure
        with open(xml_file, 'r', encoding='utf-8', errors='ignore') as f:
            header = f.read(10000)  # Read first 10KB
            print(f"Reading first 10KB for timestamp...")
        
        # Method 1: Look for <feed_timestamp> element
        feed_timestamp_match = re.search(r'<feed_timestamp>(\d+)</feed_timestamp>', header)
        if feed_timestamp_match:
            timestamp = int(feed_timestamp_match.group(1))
            timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            print(f"Found <feed_timestamp> element: {timestamp} ({timestamp_str})")
            return timestamp, timestamp_str
        
        # Method 2: Look for <xml_timestamp> element as alternative
        xml_timestamp_match = re.search(r'<xml_timestamp>(\d+)</xml_timestamp>', header)
        if xml_timestamp_match:
            timestamp = int(xml_timestamp_match.group(1))
            timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            print(f"Found <xml_timestamp> element: {timestamp} ({timestamp_str})")
            return timestamp, timestamp_str
        
        # Method 3: Look for feed_timestamp attribute
        feed_timestamp_attr_match = re.search(r'feed_timestamp="(\d+)"', header)
        if feed_timestamp_attr_match:
            timestamp = int(feed_timestamp_attr_match.group(1))
            timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            print(f"Found feed_timestamp attribute: {timestamp} ({timestamp_str})")
            return timestamp, timestamp_str
        
        # Method 4: Look for <feed_timestamp> pattern without the closing tag
        partial_feed_timestamp_match = re.search(r'<feed_timestamp>(\d+)', header)
        if partial_feed_timestamp_match:
            timestamp = int(partial_feed_timestamp_match.group(1))
            timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            print(f"Found partial <feed_timestamp> pattern: {timestamp} ({timestamp_str})")
            return timestamp, timestamp_str
        
        # Method 5: Look for any pattern that resembles a timestamp
        timestamp_pattern_match = re.search(r'timestamp[^>]*>(\d{10})<', header)
        if timestamp_pattern_match:
            timestamp = int(timestamp_pattern_match.group(1))
            timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            print(f"Found generic timestamp pattern: {timestamp} ({timestamp_str})")
            return timestamp, timestamp_str
        
        print("No timestamp found in XML header, checking for alternative sources...")
        
        # Check if this is a nasl_plugins format file
        if '<nasl_plugins>' in header:
            print("Found <nasl_plugins> format")
            
            # Extract archive date from the filename if possible
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
        
        # Use file modification time as fallback
        mod_time = os.path.getmtime(xml_file)
        mod_time_str = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')
        print(f"Using file modification time as fallback: {int(mod_time)} ({mod_time_str})")
        return int(mod_time), mod_time_str
    
    except Exception as e:
        print(f"Error extracting feed timestamp: {e}")
        import traceback
        traceback.print_exc()
        
        # Always return a timestamp even in case of errors (use file mod time)
        try:
            mod_time = os.path.getmtime(xml_file)
            mod_time_str = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')
            print(f"Using file modification time after error: {int(mod_time)} ({mod_time_str})")
            return int(mod_time), f"Error recovery - {mod_time_str}"
        except:
            # Last resort if even the file mod time fails
            import time
            current_time = int(time.time())
            current_time_str = datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')
            return current_time, f"Error fallback - {current_time_str}"


def extract_plugins_from_archive(archive_file: str, output_dir: str) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """
    Extract plugins.xml from a compressed archive file.
    Handles various archive formats (zip, tar.gz) and specifically handles direct plugins.xml.gz files.
    
    Args:
        archive_file: Path to the archive file
        output_dir: Directory to extract to
        
    Returns:
        Tuple of (extracted_xml_path, feed_timestamp, feed_timestamp_str)
    """
    print(f"Attempting to extract plugins.xml from {archive_file}...")
    
    try:
        # Create temporary directory for extraction
        temp_dir = tempfile.mkdtemp(dir=output_dir)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Check if plugins.xml already exists in the script directory
        existing_plugins_path = os.path.join(script_dir, "plugins.xml")
        existing_plugins_timestamp = None
        existing_timestamp_str = None
        
        if os.path.exists(existing_plugins_path):
            # Get the timestamp of the existing file
            existing_plugins_timestamp, existing_timestamp_str = extract_feed_timestamp(existing_plugins_path)
            
            if existing_plugins_timestamp:
                # Create a new filename with the timestamp embedded
                date_str = datetime.fromtimestamp(existing_plugins_timestamp).strftime('%m%d%y')
                new_filename = f"plugins{date_str}.xml"
                new_filepath = os.path.join(script_dir, new_filename)
                
                # Rename the existing file
                print(f"Renaming existing plugins.xml to {new_filename} (Feed date: {existing_timestamp_str})")
                try:
                    shutil.copy2(existing_plugins_path, new_filepath)
                except Exception as e:
                    print(f"Error renaming existing plugins.xml: {e}")
            else:
                # If we can't get a timestamp, use the file modification time
                file_mod_time = os.path.getmtime(existing_plugins_path)
                date_str = datetime.fromtimestamp(file_mod_time).strftime('%m%d%y')
                new_filename = f"plugins{date_str}.xml"
                new_filepath = os.path.join(script_dir, new_filename)
                
                print(f"No feed timestamp found, using file modification time: {datetime.fromtimestamp(file_mod_time).strftime('%Y-%m-%d %H:%M:%S')}")
                try:
                    shutil.copy2(existing_plugins_path, new_filepath)
                except Exception as e:
                    print(f"Error renaming existing plugins.xml: {e}")
        
        # Check file extension
        extracted_xml = None
        feed_timestamp = None
        feed_timestamp_str = None
        
        if archive_file.endswith('.tar.gz') or archive_file.endswith('.tgz'):
            # Extract tar.gz file
            try:
                with tarfile.open(archive_file, 'r:gz') as tar_ref:
                    # List all files in the tar.gz for debugging
                    tar_contents = tar_ref.getnames()
                    print(f"TAR.GZ archive contains {len(tar_contents)} files/directories")
                    if tar_contents:
                        print(f"Contents: {tar_contents}")
                    
                    # Check for plugins.xml.gz directly in the archive (common in SC plugins)
                    plugins_xml_gz_files = [f for f in tar_contents if f.endswith('plugins.xml.gz')]
                    
                    if plugins_xml_gz_files:
                        print(f"Found plugins.xml.gz files: {plugins_xml_gz_files}")
                        # Extract only the plugins.xml.gz file
                        for plugins_xml_gz in plugins_xml_gz_files:
                            print(f"Extracting {plugins_xml_gz}...")
                            tar_ref.extract(plugins_xml_gz, temp_dir)
                    else:
                        # If not found, extract everything
                        print("No plugins.xml.gz found directly, extracting all files...")
                        tar_ref.extractall(temp_dir)
                
                # Process each plugins.xml.gz file
                for plugins_xml_gz in plugins_xml_gz_files:
                    extracted_gz_path = os.path.join(temp_dir, plugins_xml_gz)
                    if os.path.exists(extracted_gz_path):
                        print(f"Processing {plugins_xml_gz}...")
                        # Create output path for the decompressed file
                        plugins_xml_path = os.path.join(temp_dir, "plugins.xml")
                        
                        try:
                            # Decompress the gzip file
                            with gzip.open(extracted_gz_path, 'rb') as f_in:
                                with open(plugins_xml_path, 'wb') as f_out:
                                    print(f"Decompressing to {plugins_xml_path}...")
                                    shutil.copyfileobj(f_in, f_out)
                            
                            # Check if the file exists and has content
                            if os.path.exists(plugins_xml_path) and os.path.getsize(plugins_xml_path) > 0:
                                print(f"Successfully extracted to {plugins_xml_path} ({os.path.getsize(plugins_xml_path)} bytes)")
                                
                                # Verify the file is valid XML by reading the first few bytes
                                with open(plugins_xml_path, 'rb') as f:
                                    start_bytes = f.read(100)
                                    print(f"First 100 bytes: {start_bytes}")
                                
                                # Try to extract the feed timestamp
                                try:
                                    feed_timestamp, feed_timestamp_str = extract_feed_timestamp(plugins_xml_path)
                                    if feed_timestamp:
                                        print(f"Found feed timestamp: {feed_timestamp_str}")
                                        extracted_xml = plugins_xml_path
                                        # Copy to the script directory as plugins.xml
                                        final_path = os.path.join(script_dir, "plugins.xml")
                                        print(f"Copying to {final_path}...")
                                        shutil.copy2(plugins_xml_path, final_path)
                                        extracted_xml = final_path
                                        break
                                    else:
                                        print("No feed timestamp found, file may be invalid")
                                except Exception as e:
                                    print(f"Error extracting timestamp: {e}")
                            else:
                                print(f"Error: Extracted file is empty or doesn't exist")
                        
                        except Exception as e:
                            print(f"Error processing {plugins_xml_gz}: {e}")
                            import traceback
                            traceback.print_exc()
                
                # If still not found, try a recursive search
                if not extracted_xml:
                    print("Trying recursive search...")
                    # Find all plugins.xml files
                    for root, dirs, files in os.walk(temp_dir):
                        for file in files:
                            if file == "plugins.xml":
                                full_path = os.path.join(root, file)
                                print(f"Found plugins.xml at {full_path}")
                                try:
                                    feed_timestamp, feed_timestamp_str = extract_feed_timestamp(full_path)
                                    if feed_timestamp:
                                        print(f"Found valid plugins.xml with timestamp: {feed_timestamp_str}")
                                        # Copy to the script directory as plugins.xml
                                        final_path = os.path.join(script_dir, "plugins.xml")
                                        shutil.copy2(full_path, final_path)
                                        extracted_xml = final_path
                                        break
                                except Exception as e:
                                    print(f"Error processing {full_path}: {e}")
                        
                        if extracted_xml:
                            break
                    
                    # Find all plugins.xml.gz files if still not found
                    if not extracted_xml:
                        for root, dirs, files in os.walk(temp_dir):
                            for file in files:
                                if file.endswith("plugins.xml.gz"):
                                    full_path = os.path.join(root, file)
                                    print(f"Found plugins.xml.gz at {full_path}")
                                    try:
                                        # Decompress to temporary location
                                        decompressed_path = os.path.join(temp_dir, "plugins.xml")
                                        with gzip.open(full_path, 'rb') as f_in:
                                            with open(decompressed_path, 'wb') as f_out:
                                                shutil.copyfileobj(f_in, f_out)
                                        
                                        feed_timestamp, feed_timestamp_str = extract_feed_timestamp(decompressed_path)
                                        if feed_timestamp:
                                            print(f"Found valid plugins.xml.gz with timestamp: {feed_timestamp_str}")
                                            # Copy to the script directory as plugins.xml
                                            final_path = os.path.join(script_dir, "plugins.xml")
                                            shutil.copy2(decompressed_path, final_path)
                                            extracted_xml = final_path
                                            break
                                    except Exception as e:
                                        print(f"Error processing {full_path}: {e}")
                            
                            if extracted_xml:
                                break
            
            except Exception as e:
                print(f"Error during tar.gz extraction: {e}")
                import traceback
                traceback.print_exc()
        
        # Handle ZIP files as well
        elif archive_file.endswith('.zip'):
            try:
                with zipfile.ZipFile(archive_file, 'r') as zip_ref:
                    zip_contents = zip_ref.namelist()
                    print(f"ZIP archive contains {len(zip_contents)} files")
                    
                    # Look for plugins.xml or plugins.xml.gz files
                    plugins_files = [f for f in zip_contents if f.endswith('plugins.xml') or f.endswith('plugins.xml.gz')]
                    
                    if plugins_files:
                        for plugins_file in plugins_files:
                            print(f"Extracting {plugins_file}...")
                            zip_ref.extract(plugins_file, temp_dir)
                            
                            extracted_path = os.path.join(temp_dir, plugins_file)
                            
                            if plugins_file.endswith('.gz'):
                                # Decompress gzipped file
                                decompressed_path = os.path.join(temp_dir, "plugins.xml")
                                with gzip.open(extracted_path, 'rb') as f_in:
                                    with open(decompressed_path, 'wb') as f_out:
                                        shutil.copyfileobj(f_in, f_out)
                                extracted_path = decompressed_path
                            
                            # Check timestamp and copy to final location
                            try:
                                feed_timestamp, feed_timestamp_str = extract_feed_timestamp(extracted_path)
                                if feed_timestamp:
                                    print(f"Found valid plugins file with timestamp: {feed_timestamp_str}")
                                    final_path = os.path.join(script_dir, "plugins.xml")
                                    shutil.copy2(extracted_path, final_path)
                                    extracted_xml = final_path
                                    break
                            except Exception as e:
                                print(f"Error processing {plugins_file}: {e}")
                    else:
                        print("No plugins.xml files found in ZIP archive")
                        
            except Exception as e:
                print(f"Error during ZIP extraction: {e}")
                import traceback
                traceback.print_exc()
        
        # If successful extraction, delete the archive file
        if extracted_xml and feed_timestamp:
            try:
                print(f"Extraction successful. Deleting archive file: {archive_file}")
                os.remove(archive_file)
                print(f"Archive file deleted.")
            except Exception as e:
                print(f"Warning: Could not delete archive file: {e}")
        
        # If we get here and nothing was found
        if not extracted_xml:
            print(f"plugins.xml not found in {archive_file}")
            print("DEBUG: Listing all files in temp directory:")
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    print(f"  {os.path.join(root, file)}")
            return None, None, None
            
        return extracted_xml, feed_timestamp, feed_timestamp_str
    
    except Exception as e:
        print(f"Error extracting plugins.xml from archive: {e}")
        import traceback
        traceback.print_exc()
        return None, None, None


def cleanup_temp_directory(temp_dir: str) -> None:
    """
    Clean up temporary directory.
    
    Args:
        temp_dir: Path to temporary directory to remove
    """
    try:
        shutil.rmtree(temp_dir, ignore_errors=True)
        print("Temporary files cleaned up.")
    except Exception as e:
        print(f"Warning: Could not clean up temporary directory: {e}")


def find_archive_files(directory: str, patterns: List[str] = None) -> List[str]:
    """
    Find archive files matching specific patterns.
    
    Args:
        directory: Directory to search
        patterns: List of glob patterns to match (default: ['CM-*-sc-plugins.tar.gz'])
        
    Returns:
        List of matching archive files, sorted by modification time (newest first)
    """
    if patterns is None:
        patterns = ['CM-*-sc-plugins.tar.gz']
    
    all_files = []
    for pattern in patterns:
        pattern_path = os.path.join(directory, pattern)
        matching_files = glob.glob(pattern_path)
        all_files.extend(matching_files)
    
    # Sort by modification time (newest first)
    all_files.sort(key=os.path.getmtime, reverse=True)
    return all_files