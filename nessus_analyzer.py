"""
Nessus Analyzer - Main Integration Module
High-level interface for processing Nessus files with modular components.
"""

import os
import tempfile
from typing import Dict, List, Tuple, Optional, Any
import pandas as pd  # pip install pandas

try:
    from archive_extraction import (
        extract_nested_archives, find_files_by_extension, 
        extract_plugins_from_archive, cleanup_temp_directory,
        find_archive_files
    )
    from plugin_database import (
        parse_plugins_xml, load_plugins_database_json,
        plugins_dict_to_dataframe, find_latest_plugins_file,
        cleanup_old_plugins_files
    )
    from nessus_parser import parse_nessus_file, parse_multiple_nessus_files
    from data_processing import (
        enrich_findings_with_severity, create_severity_summary,
        create_age_distribution, create_cve_summary, create_iavx_summary,
        identify_unmapped_findings, filter_by_severity, export_to_formats,
        create_executive_summary
    )
except ImportError:
    # Fallback to relative imports
    from .archive_extraction import (
        extract_nested_archives, find_files_by_extension, 
        extract_plugins_from_archive, cleanup_temp_directory,
        find_archive_files
    )
    from .plugin_database import (
        parse_plugins_xml, load_plugins_database_json,
        plugins_dict_to_dataframe, find_latest_plugins_file,
        cleanup_old_plugins_files
    )
    from .nessus_parser import parse_nessus_file, parse_multiple_nessus_files
    from .data_processing import (
        enrich_findings_with_severity, create_severity_summary,
        create_age_distribution, create_cve_summary, create_iavx_summary,
        identify_unmapped_findings, filter_by_severity, export_to_formats,
        create_executive_summary
    )


class NessusAnalyzer:
    """
    Main class for analyzing Nessus scan results with modular processing.
    """
    
    def __init__(self, plugins_db_path: Optional[str] = None):
        """
        Initialize the analyzer.
        
        Args:
            plugins_db_path: Optional path to plugins database file
        """
        self.plugins_dict = None
        self.plugins_df = None
        self.findings_df = pd.DataFrame()
        self.host_summary_df = pd.DataFrame()
        self.processed_files = []
        
        # Load plugins database if provided
        if plugins_db_path:
            self.load_plugins_database(plugins_db_path)
    
    def load_plugins_database(self, plugins_path: str) -> bool:
        """
        Load plugins database from file.
        
        Args:
            plugins_path: Path to plugins XML or JSON file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            print(f"Loading plugins database from {plugins_path}")
            
            if plugins_path.lower().endswith('.xml'):
                self.plugins_dict = parse_plugins_xml(plugins_path)
            elif plugins_path.lower().endswith('.json'):
                self.plugins_dict = load_plugins_database_json(plugins_path)
            else:
                # Try to guess based on content
                with open(plugins_path, 'r', encoding='utf-8', errors='ignore') as f:
                    first_line = f.readline().strip()
                    if first_line.startswith('{') or first_line.startswith('['):
                        self.plugins_dict = load_plugins_database_json(plugins_path)
                    elif first_line.startswith('<?xml') or first_line.startswith('<'):
                        self.plugins_dict = parse_plugins_xml(plugins_path)
                    else:
                        print(f"Unknown file format for {plugins_path}")
                        return False
            
            if self.plugins_dict:
                # Convert to DataFrame for easier analysis
                self.plugins_df = plugins_dict_to_dataframe(self.plugins_dict)
                print(f"Loaded {len(self.plugins_dict)} plugins from database")
                return True
            else:
                print("Failed to load plugins database")
                return False
                
        except Exception as e:
            print(f"Error loading plugins database: {e}")
            return False
    
    def auto_load_plugins_database(self, search_directory: Optional[str] = None) -> bool:
        """
        Automatically find and load the latest plugins database.
        
        Args:
            search_directory: Directory to search (defaults to current directory)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Look for CM archive files first
            if search_directory is None:
                search_directory = os.getcwd()
            
            archive_files = find_archive_files(search_directory)
            
            if archive_files:
                print(f"Found plugins archive: {archive_files[0]}")
                # Extract the archive
                temp_dir = tempfile.mkdtemp()
                try:
                    extracted_xml, _, _ = extract_plugins_from_archive(archive_files[0], temp_dir)
                    if extracted_xml:
                        success = self.load_plugins_database(extracted_xml)
                        cleanup_temp_directory(temp_dir)
                        return success
                finally:
                    cleanup_temp_directory(temp_dir)
            
            # Fallback to existing plugins files
            plugins_file = find_latest_plugins_file(search_directory)
            if plugins_file:
                print(f"Found existing plugins file: {plugins_file}")
                return self.load_plugins_database(plugins_file)
            
            print("No plugins database found")
            return False
            
        except Exception as e:
            print(f"Error auto-loading plugins database: {e}")
            return False
    
    def process_archive(self, archive_path: str, include_info: bool = True) -> Dict[str, pd.DataFrame]:
        """
        Process a Nessus archive file (zip containing .nessus files).
        
        Args:
            archive_path: Path to the archive file
            include_info: Whether to include informational findings
            
        Returns:
            Dictionary of DataFrames with analysis results
        """
        print(f"Processing archive: {archive_path}")
        
        # Create temporary directory
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Extract archive
            extract_nested_archives(archive_path, temp_dir)
            
            # Find .nessus files
            nessus_files = find_files_by_extension(temp_dir, '.nessus')
            print(f"Found {len(nessus_files)} .nessus files")
            
            if not nessus_files:
                print("No .nessus files found in archive")
                return {}
            
            # Process files
            return self.process_nessus_files(nessus_files, include_info)
            
        finally:
            cleanup_temp_directory(temp_dir)
    
    def process_nessus_files(self, file_paths: List[str], include_info: bool = True) -> Dict[str, pd.DataFrame]:
        """
        Process multiple .nessus files.
        
        Args:
            file_paths: List of .nessus file paths
            include_info: Whether to include informational findings
            
        Returns:
            Dictionary of DataFrames with analysis results
        """
        print(f"Processing {len(file_paths)} .nessus files")
        
        # Parse files
        self.findings_df, self.host_summary_df = parse_multiple_nessus_files(file_paths, self.plugins_dict)
        self.processed_files.extend(file_paths)
        
        if self.findings_df.empty:
            print("No findings extracted from files")
            return {}
        
        # Enrich with severity calculations
        self.findings_df = enrich_findings_with_severity(self.findings_df)
        
        # Filter by severity if requested
        filtered_findings = filter_by_severity(self.findings_df, include_info)
        
        # Create analysis DataFrames
        results = {
            'findings': filtered_findings,
            'host_summary': self.host_summary_df,
            'severity_summary': create_severity_summary(filtered_findings),
            'age_distribution': create_age_distribution(filtered_findings),
            'cve_summary': create_cve_summary(filtered_findings),
            'iavx_summary': create_iavx_summary(filtered_findings),
            'unmapped_findings': identify_unmapped_findings(filtered_findings)
        }
        
        # Remove empty DataFrames
        results = {k: v for k, v in results.items() if not v.empty}
        
        print(f"Analysis complete. Generated {len(results)} result sets.")
        
        return results
    
    def get_executive_summary(self) -> Dict[str, Any]:
        """
        Get executive summary of processed data.
        
        Returns:
            Dictionary with executive summary statistics
        """
        return create_executive_summary(self.findings_df, self.host_summary_df)
    
    def export_results(self, base_filename: str, results: Dict[str, pd.DataFrame] = None) -> Dict[str, str]:
        """
        Export results to multiple formats.
        
        Args:
            base_filename: Base filename without extension
            results: Optional results dictionary (uses internal data if not provided)
            
        Returns:
            Dictionary mapping format names to file paths
        """
        if results is None:
            if self.findings_df.empty:
                print("No data to export. Process files first.")
                return {}
            findings_df = self.findings_df
            host_summary_df = self.host_summary_df
        else:
            findings_df = results.get('findings', pd.DataFrame())
            host_summary_df = results.get('host_summary', pd.DataFrame())
        
        return export_to_formats(findings_df, host_summary_df, base_filename)
    
    def get_plugins_dataframe(self) -> pd.DataFrame:
        """
        Get plugins database as DataFrame.
        
        Returns:
            DataFrame with plugin information
        """
        return self.plugins_df if self.plugins_df is not None else pd.DataFrame()
    
    def get_findings_dataframe(self) -> pd.DataFrame:
        """
        Get findings as DataFrame.
        
        Returns:
            DataFrame with finding information
        """
        return self.findings_df
    
    def get_host_summary_dataframe(self) -> pd.DataFrame:
        """
        Get host summary as DataFrame.
        
        Returns:
            DataFrame with host summary information
        """
        return self.host_summary_df
    
    def cleanup_old_plugins(self, keep_count: int = 2) -> None:
        """
        Clean up old plugins files.
        
        Args:
            keep_count: Number of plugins files to keep
        """
        cleanup_old_plugins_files(keep_count=keep_count)


def quick_analyze(archive_path: str, plugins_db_path: Optional[str] = None, 
                 include_info: bool = True, export_base: Optional[str] = None) -> Dict[str, Any]:
    """
    Quick analysis function for simple use cases.
    
    Args:
        archive_path: Path to Nessus archive or .nessus file
        plugins_db_path: Optional path to plugins database
        include_info: Whether to include informational findings
        export_base: Optional base filename for exports
        
    Returns:
        Dictionary with analysis results and summary
    """
    analyzer = NessusAnalyzer(plugins_db_path)
    
    # Auto-load plugins if not provided
    if not analyzer.plugins_dict:
        analyzer.auto_load_plugins_database()
    
    # Process input
    if archive_path.lower().endswith('.zip'):
        results = analyzer.process_archive(archive_path, include_info)
    elif archive_path.lower().endswith('.nessus'):
        results = analyzer.process_nessus_files([archive_path], include_info)
    else:
        raise ValueError("Input must be a .zip archive or .nessus file")
    
    # Get executive summary
    executive_summary = analyzer.get_executive_summary()
    
    # Export if requested
    exported_files = {}
    if export_base:
        exported_files = analyzer.export_results(export_base, results)
    
    return {
        'results': results,
        'executive_summary': executive_summary,
        'exported_files': exported_files,
        'analyzer': analyzer  # Return analyzer instance for further use
    }


# Example usage and integration points
if __name__ == "__main__":
    # Example 1: Simple usage
    try:
        analysis = quick_analyze(
            archive_path="nessus_scans.zip",
            plugins_db_path="plugins.xml",
            include_info=False,
            export_base="vulnerability_report"
        )
        
        print("Analysis Results:")
        print(f"Total findings: {len(analysis['results']['findings'])}")
        print(f"Total hosts: {len(analysis['results']['host_summary'])}")
        print(f"Executive Summary: {analysis['executive_summary']}")
        
    except Exception as e:
        print(f"Analysis failed: {e}")
    
    # Example 2: Advanced usage with custom processing
    try:
        analyzer = NessusAnalyzer()
        
        # Load plugins
        analyzer.auto_load_plugins_database()
        
        # Process files
        results = analyzer.process_nessus_files(
            ["scan1.nessus", "scan2.nessus"],
            include_info=True
        )
        
        # Get specific analysis
        severity_summary = results.get('severity_summary', pd.DataFrame())
        cve_summary = results.get('cve_summary', pd.DataFrame())
        
        # Custom export
        exported = analyzer.export_results("custom_analysis")
        
        print(f"Exported files: {exported}")
        
    except Exception as e:
        print(f"Advanced analysis failed: {e}")
