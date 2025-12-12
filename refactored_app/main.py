#!/usr/bin/env python3
"""
Nessus History Tracker v2.0
Main entry point for the application.

A comprehensive vulnerability tracking and analysis tool for Nessus scan data.
Tracks vulnerabilities across multiple scans, analyzes trends, and provides
visualizations and reports.

Usage:
    From parent directory:
        python -m refactored_app

    Or directly:
        python refactored_app/main.py

Options:
    --gui           Launch the GUI application (default)
    --cli           Run in command-line mode
    --help          Show this help message

Example CLI usage:
    python -m refactored_app --cli --input scan1.nessus scan2.nessus --output report.xlsx
"""

import sys
import os
import argparse
from pathlib import Path

# Add parent directory to path for direct script execution
if __name__ == "__main__" and __package__ is None:
    # Running as script directly
    script_dir = Path(__file__).resolve().parent
    parent_dir = script_dir.parent
    if str(parent_dir) not in sys.path:
        sys.path.insert(0, str(parent_dir))


def _import_modules():
    """Import modules with fallback for direct execution."""
    global NessusHistoryTrackerApp
    global parse_multiple_nessus_files, load_plugins_database, enrich_findings_with_severity
    global analyze_finding_lifecycle, create_host_presence_analysis, analyze_scan_changes
    global export_to_excel, export_to_sqlite, export_to_json

    try:
        # Try relative imports first (when run as module)
        from .gui.app import NessusHistoryTrackerApp
        from .core.nessus_parser import parse_multiple_nessus_files
        from .core.plugin_database import load_plugins_database
        from .core.data_processing import enrich_findings_with_severity
        from .analysis.lifecycle import analyze_finding_lifecycle
        from .analysis.host_presence import create_host_presence_analysis
        from .analysis.scan_changes import analyze_scan_changes
        from .export.excel_export import export_to_excel
        from .export.sqlite_export import export_to_sqlite
        from .export.json_export import export_to_json
    except ImportError:
        # Fall back to absolute imports (when run directly)
        from refactored_app.gui.app import NessusHistoryTrackerApp
        from refactored_app.core.nessus_parser import parse_multiple_nessus_files
        from refactored_app.core.plugin_database import load_plugins_database
        from refactored_app.core.data_processing import enrich_findings_with_severity
        from refactored_app.analysis.lifecycle import analyze_finding_lifecycle
        from refactored_app.analysis.host_presence import create_host_presence_analysis
        from refactored_app.analysis.scan_changes import analyze_scan_changes
        from refactored_app.export.excel_export import export_to_excel
        from refactored_app.export.sqlite_export import export_to_sqlite
        from refactored_app.export.json_export import export_to_json

    return True


def launch_gui():
    """Launch the GUI application."""
    try:
        _import_modules()
        app = NessusHistoryTrackerApp()
        app.run()

    except ImportError as e:
        print(f"Error importing GUI modules: {e}")
        print("\nPossible solutions:")
        print("  1. Run from parent directory: python -m refactored_app")
        print("  2. Make sure all dependencies are installed: pip install pandas numpy matplotlib openpyxl")
        print("  3. tkinter is included with Python, but may need separate install on Linux: sudo apt install python3-tk")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"Error launching GUI: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def run_cli(args):
    """Run in command-line mode."""
    import pandas as pd

    _import_modules()

    print("Nessus History Tracker v2.0 - CLI Mode")
    print("=" * 50)

    # Load plugins database if specified
    plugins_dict = None
    if args.plugins:
        print(f"Loading plugins database: {args.plugins}")
        plugins_dict = load_plugins_database(args.plugins)

    # Process input files
    nessus_files = args.input
    print(f"Processing {len(nessus_files)} file(s)...")

    findings_df, host_summary_df = parse_multiple_nessus_files(nessus_files, plugins_dict)

    if findings_df.empty:
        print("No findings extracted from input files.")
        sys.exit(1)

    print(f"Extracted {len(findings_df)} findings from {findings_df['hostname'].nunique()} hosts")

    # Enrich with severity
    findings_df = enrich_findings_with_severity(findings_df)

    # Run analysis
    print("Running analysis...")
    lifecycle_df = analyze_finding_lifecycle(findings_df)
    host_presence_df = create_host_presence_analysis(findings_df)
    scan_changes_df = analyze_scan_changes(findings_df)

    print(f"  - {len(lifecycle_df)} unique finding lifecycles")
    print(f"  - {len(host_presence_df)} hosts tracked")

    # Export results
    output_path = Path(args.output)
    opdir_df = pd.DataFrame()  # Empty OPDIR for CLI mode

    if output_path.suffix == '.xlsx':
        export_to_excel(findings_df, lifecycle_df, host_presence_df,
                       scan_changes_df, opdir_df, str(output_path))
    elif output_path.suffix == '.db':
        export_to_sqlite(findings_df, lifecycle_df, host_presence_df,
                        scan_changes_df, opdir_df, str(output_path))
    elif output_path.suffix == '.json':
        export_to_json(findings_df, lifecycle_df, host_presence_df,
                      scan_changes_df, str(output_path))
    else:
        print(f"Unknown output format: {output_path.suffix}")
        sys.exit(1)

    print(f"Results exported to: {output_path}")
    print("Done!")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Nessus History Tracker v2.0 - Vulnerability Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Launch GUI:
    python -m refactored_app

  CLI mode with single file:
    python -m refactored_app --cli --input scan.nessus --output report.xlsx

  CLI mode with multiple files:
    python -m refactored_app --cli --input scan1.nessus scan2.nessus --output history.db
        """
    )

    parser.add_argument('--gui', action='store_true', default=True,
                       help='Launch the GUI application (default)')
    parser.add_argument('--cli', action='store_true',
                       help='Run in command-line mode')
    parser.add_argument('--input', '-i', nargs='+', metavar='FILE',
                       help='Input .nessus file(s) (CLI mode)')
    parser.add_argument('--output', '-o', metavar='FILE',
                       help='Output file path (CLI mode)')
    parser.add_argument('--plugins', '-p', metavar='FILE',
                       help='Plugins database file (optional)')

    args = parser.parse_args()

    if args.cli:
        if not args.input:
            parser.error("--cli mode requires --input file(s)")
        if not args.output:
            parser.error("--cli mode requires --output file")
        run_cli(args)
    else:
        launch_gui()


if __name__ == "__main__":
    main()
