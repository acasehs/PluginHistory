#!/usr/bin/env python3
"""
Nessus History Tracker v2.0
Main entry point for the application.

A comprehensive vulnerability tracking and analysis tool for Nessus scan data.
Tracks vulnerabilities across multiple scans, analyzes trends, and provides
visualizations and reports.

Usage:
    python -m refactored_app.main [options]

Options:
    --gui           Launch the GUI application (default)
    --cli           Run in command-line mode
    --help          Show this help message

Example CLI usage:
    python -m refactored_app.main --cli --input scan1.nessus scan2.nessus --output report.xlsx
"""

import sys
import argparse
from pathlib import Path


def launch_gui():
    """Launch the GUI application."""
    try:
        from .gui.app import NessusHistoryTrackerApp

        app = NessusHistoryTrackerApp()
        app.run()

    except ImportError as e:
        print(f"Error importing GUI modules: {e}")
        print("Make sure tkinter is installed.")
        sys.exit(1)
    except Exception as e:
        print(f"Error launching GUI: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def run_cli(args):
    """Run in command-line mode."""
    from .core.nessus_parser import parse_multiple_nessus_files
    from .core.plugin_database import load_plugins_database
    from .core.data_processing import enrich_findings_with_severity
    from .analysis.lifecycle import analyze_finding_lifecycle
    from .analysis.host_presence import create_host_presence_analysis
    from .analysis.scan_changes import analyze_scan_changes
    from .export.excel_export import export_to_excel
    from .export.sqlite_export import export_to_sqlite
    from .export.json_export import export_to_json

    import pandas as pd

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
    python -m refactored_app.main

  CLI mode with single file:
    python -m refactored_app.main --cli --input scan.nessus --output report.xlsx

  CLI mode with multiple files:
    python -m refactored_app.main --cli --input scan1.nessus scan2.nessus --output history.db
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
