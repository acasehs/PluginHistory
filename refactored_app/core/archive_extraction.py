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
    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
        zip_ref.extractall(extraction_dir)

    # Look for zip files in the extraction directory and extract them
    for root, _, files in os.walk(extraction_dir):
        for file in files:
            if file.endswith('.zip'):
                zip_path = os.path.join(root, file)
                nested_dir = os.path.join(root, os.path.splitext(file)[0])
                os.makedirs(nested_dir, exist_ok=True)

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
    """
    try:
        file_size = os.path.getsize(xml_file)

        with open(xml_file, 'r', encoding='utf-8', errors='ignore') as f:
            header = f.read(10000)

        # Method 1: <feed_timestamp> element
        feed_timestamp_match = re.search(r'<feed_timestamp>(\d+)</feed_timestamp>', header)
        if feed_timestamp_match:
            timestamp = int(feed_timestamp_match.group(1))
            timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            return timestamp, timestamp_str

        # Method 2: <xml_timestamp> element
        xml_timestamp_match = re.search(r'<xml_timestamp>(\d+)</xml_timestamp>', header)
        if xml_timestamp_match:
            timestamp = int(xml_timestamp_match.group(1))
            timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            return timestamp, timestamp_str

        # Method 3: feed_timestamp attribute
        feed_timestamp_attr_match = re.search(r'feed_timestamp="(\d+)"', header)
        if feed_timestamp_attr_match:
            timestamp = int(feed_timestamp_attr_match.group(1))
            timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            return timestamp, timestamp_str

        # Fallback: file modification time
        mod_time = os.path.getmtime(xml_file)
        mod_time_str = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')
        return int(mod_time), mod_time_str

    except Exception as e:
        print(f"Error extracting feed timestamp: {e}")
        import time
        current_time = int(time.time())
        current_time_str = datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')
        return current_time, f"Error fallback - {current_time_str}"


def extract_plugins_from_archive(archive_file: str, output_dir: str) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """
    Extract plugins.xml from a compressed archive file.

    Args:
        archive_file: Path to the archive file
        output_dir: Directory to extract to

    Returns:
        Tuple of (extracted_xml_path, feed_timestamp, feed_timestamp_str)
    """
    try:
        temp_dir = tempfile.mkdtemp(dir=output_dir)
        script_dir = os.path.dirname(os.path.abspath(__file__))

        extracted_xml = None
        feed_timestamp = None
        feed_timestamp_str = None

        if archive_file.endswith('.tar.gz') or archive_file.endswith('.tgz'):
            with tarfile.open(archive_file, 'r:gz') as tar_ref:
                tar_contents = tar_ref.getnames()
                plugins_xml_gz_files = [f for f in tar_contents if f.endswith('plugins.xml.gz')]

                if plugins_xml_gz_files:
                    for plugins_xml_gz in plugins_xml_gz_files:
                        tar_ref.extract(plugins_xml_gz, temp_dir)
                else:
                    tar_ref.extractall(temp_dir)

            # Process plugins.xml.gz files
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith("plugins.xml.gz"):
                        full_path = os.path.join(root, file)
                        decompressed_path = os.path.join(temp_dir, "plugins.xml")

                        with gzip.open(full_path, 'rb') as f_in:
                            with open(decompressed_path, 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)

                        feed_timestamp, feed_timestamp_str = extract_feed_timestamp(decompressed_path)
                        if feed_timestamp:
                            final_path = os.path.join(script_dir, "plugins.xml")
                            shutil.copy2(decompressed_path, final_path)
                            extracted_xml = final_path
                            break

                if extracted_xml:
                    break

        elif archive_file.endswith('.zip'):
            with zipfile.ZipFile(archive_file, 'r') as zip_ref:
                zip_contents = zip_ref.namelist()
                plugins_files = [f for f in zip_contents if f.endswith('plugins.xml') or f.endswith('plugins.xml.gz')]

                for plugins_file in plugins_files:
                    zip_ref.extract(plugins_file, temp_dir)
                    extracted_path = os.path.join(temp_dir, plugins_file)

                    if plugins_file.endswith('.gz'):
                        decompressed_path = os.path.join(temp_dir, "plugins.xml")
                        with gzip.open(extracted_path, 'rb') as f_in:
                            with open(decompressed_path, 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)
                        extracted_path = decompressed_path

                    feed_timestamp, feed_timestamp_str = extract_feed_timestamp(extracted_path)
                    if feed_timestamp:
                        final_path = os.path.join(script_dir, "plugins.xml")
                        shutil.copy2(extracted_path, final_path)
                        extracted_xml = final_path
                        break

        return extracted_xml, feed_timestamp, feed_timestamp_str

    except Exception as e:
        print(f"Error extracting plugins.xml from archive: {e}")
        return None, None, None


def cleanup_temp_directory(temp_dir: str) -> None:
    """
    Clean up temporary directory.

    Args:
        temp_dir: Path to temporary directory to remove
    """
    try:
        shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception as e:
        print(f"Warning: Could not clean up temporary directory: {e}")


def find_archive_files(directory: str, patterns: List[str] = None) -> List[str]:
    """
    Find archive files matching specific patterns.

    Args:
        directory: Directory to search
        patterns: List of glob patterns to match

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

    all_files.sort(key=os.path.getmtime, reverse=True)
    return all_files
