#!/usr/bin/env python3
"""
Generate PDF versions of all documentation files.
Includes screenshots and proper formatting.
"""

import os
import markdown
from weasyprint import HTML, CSS
from pathlib import Path

# Configuration
DOCS_DIR = Path(__file__).parent
SCREENSHOTS_DIR = DOCS_DIR / 'screenshots'
OUTPUT_DIR = DOCS_DIR / 'pdf'

# Markdown files to convert
MARKDOWN_FILES = [
    'USER_GUIDE.md',
    'VISUALIZATION_GUIDE.md',
    'DATA_SCIENCE_ANALYSIS.md'
]

# CSS styling for PDFs
PDF_CSS = """
@page {
    size: A4;
    margin: 2cm;
    @top-center {
        content: "Plugin History Analysis - Documentation";
        font-size: 9pt;
        color: #666;
    }
    @bottom-center {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 9pt;
        color: #666;
    }
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    font-size: 11pt;
    line-height: 1.6;
    color: #333;
    max-width: 100%;
}

h1 {
    color: #2c3e50;
    font-size: 24pt;
    border-bottom: 3px solid #3498db;
    padding-bottom: 10px;
    margin-top: 30px;
    page-break-after: avoid;
}

h2 {
    color: #34495e;
    font-size: 18pt;
    border-bottom: 1px solid #bdc3c7;
    padding-bottom: 5px;
    margin-top: 25px;
    page-break-after: avoid;
}

h3 {
    color: #7f8c8d;
    font-size: 14pt;
    margin-top: 20px;
    page-break-after: avoid;
}

h4 {
    color: #95a5a6;
    font-size: 12pt;
    margin-top: 15px;
    page-break-after: avoid;
}

code {
    background-color: #f8f9fa;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 10pt;
    color: #c7254e;
}

pre {
    background-color: #282c34;
    color: #abb2bf;
    padding: 15px;
    border-radius: 5px;
    overflow-x: auto;
    font-size: 9pt;
    line-height: 1.4;
    page-break-inside: avoid;
}

pre code {
    background-color: transparent;
    color: inherit;
    padding: 0;
}

table {
    border-collapse: collapse;
    width: 100%;
    margin: 15px 0;
    font-size: 10pt;
    page-break-inside: avoid;
}

th {
    background-color: #3498db;
    color: white;
    padding: 10px;
    text-align: left;
    font-weight: bold;
}

td {
    border: 1px solid #ddd;
    padding: 8px;
    vertical-align: top;
}

tr:nth-child(even) {
    background-color: #f8f9fa;
}

tr:hover {
    background-color: #e8f4fc;
}

blockquote {
    border-left: 4px solid #3498db;
    margin: 15px 0;
    padding: 10px 20px;
    background-color: #f8f9fa;
    font-style: italic;
}

ul, ol {
    margin: 10px 0;
    padding-left: 30px;
}

li {
    margin: 5px 0;
}

img {
    max-width: 100%;
    height: auto;
    display: block;
    margin: 15px auto;
    border: 1px solid #ddd;
    border-radius: 5px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
}

a {
    color: #3498db;
    text-decoration: none;
}

a:hover {
    text-decoration: underline;
}

hr {
    border: none;
    border-top: 2px solid #ecf0f1;
    margin: 30px 0;
}

.toc {
    background-color: #f8f9fa;
    padding: 20px;
    border-radius: 5px;
    margin-bottom: 30px;
}

.warning {
    background-color: #fff3cd;
    border-left: 4px solid #ffc107;
    padding: 10px 15px;
    margin: 15px 0;
}

.info {
    background-color: #d1ecf1;
    border-left: 4px solid #17a2b8;
    padding: 10px 15px;
    margin: 15px 0;
}

.danger {
    background-color: #f8d7da;
    border-left: 4px solid #dc3545;
    padding: 10px 15px;
    margin: 15px 0;
}

/* Cover page styling */
.cover-page {
    text-align: center;
    padding: 100px 50px;
    page-break-after: always;
}

.cover-page h1 {
    font-size: 36pt;
    border-bottom: none;
    margin-bottom: 30px;
}

.cover-page .subtitle {
    font-size: 18pt;
    color: #7f8c8d;
    margin-bottom: 50px;
}

.cover-page .version {
    font-size: 14pt;
    color: #95a5a6;
}
"""

def convert_markdown_to_html(md_content: str, base_path: Path) -> str:
    """Convert markdown to HTML with extensions."""

    # Configure markdown extensions
    extensions = [
        'markdown.extensions.tables',
        'markdown.extensions.fenced_code',
        'markdown.extensions.codehilite',
        'markdown.extensions.toc',
        'markdown.extensions.nl2br',
        'markdown.extensions.sane_lists'
    ]

    # Convert markdown to HTML
    md = markdown.Markdown(extensions=extensions)
    html_content = md.convert(md_content)

    # Fix image paths to absolute paths
    screenshots_abs = str(SCREENSHOTS_DIR.absolute())
    html_content = html_content.replace('screenshots/', f'file://{screenshots_abs}/')
    html_content = html_content.replace('(screenshots/', f'(file://{screenshots_abs}/')

    return html_content


def create_pdf(md_file: str):
    """Create PDF from a markdown file."""

    md_path = DOCS_DIR / md_file
    if not md_path.exists():
        print(f"Warning: {md_file} not found, skipping")
        return

    print(f"Processing {md_file}...")

    # Read markdown content
    with open(md_path, 'r', encoding='utf-8') as f:
        md_content = f.read()

    # Convert to HTML
    html_body = convert_markdown_to_html(md_content, md_path.parent)

    # Get document title from first heading
    title = md_file.replace('.md', '').replace('_', ' ')
    for line in md_content.split('\n'):
        if line.startswith('# '):
            title = line[2:].strip()
            break

    # Create full HTML document
    html_document = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>{title}</title>
    </head>
    <body>
        <div class="cover-page">
            <h1>{title}</h1>
            <p class="subtitle">Plugin History Analysis Tool</p>
            <p class="version">Version 2.0 - December 2025</p>
        </div>
        {html_body}
    </body>
    </html>
    """

    # Create output directory
    OUTPUT_DIR.mkdir(exist_ok=True)

    # Generate PDF
    output_file = OUTPUT_DIR / md_file.replace('.md', '.pdf')

    try:
        html = HTML(string=html_document, base_url=str(DOCS_DIR))
        css = CSS(string=PDF_CSS)
        html.write_pdf(output_file, stylesheets=[css])
        print(f"  Created: {output_file}")
    except Exception as e:
        print(f"  Error creating PDF: {e}")
        # Try simpler approach without some features
        try:
            html = HTML(string=html_document)
            html.write_pdf(output_file)
            print(f"  Created (basic): {output_file}")
        except Exception as e2:
            print(f"  Failed: {e2}")


def create_combined_pdf():
    """Create a combined PDF with all documentation."""

    print("Creating combined documentation PDF...")

    all_html = []

    for md_file in MARKDOWN_FILES:
        md_path = DOCS_DIR / md_file
        if not md_path.exists():
            continue

        with open(md_path, 'r', encoding='utf-8') as f:
            md_content = f.read()

        # Get title
        title = md_file.replace('.md', '').replace('_', ' ')
        for line in md_content.split('\n'):
            if line.startswith('# '):
                title = line[2:].strip()
                break

        html_body = convert_markdown_to_html(md_content, md_path.parent)

        all_html.append(f"""
        <div style="page-break-before: always;">
            <div class="cover-page" style="padding: 50px;">
                <h1 style="font-size: 28pt;">{title}</h1>
            </div>
            {html_body}
        </div>
        """)

    # Create combined document
    html_document = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Plugin History Analysis - Complete Documentation</title>
    </head>
    <body>
        <div class="cover-page">
            <h1>Plugin History Analysis Tool</h1>
            <p class="subtitle">Complete Documentation</p>
            <p class="version">Version 2.0 - December 2025</p>
            <hr style="margin: 40px 0;">
            <p style="font-size: 12pt; color: #7f8c8d;">
                Includes:<br>
                - User Guide<br>
                - Visualization Guide<br>
                - Data Science Analysis
            </p>
        </div>
        {''.join(all_html)}
    </body>
    </html>
    """

    OUTPUT_DIR.mkdir(exist_ok=True)
    output_file = OUTPUT_DIR / 'Complete_Documentation.pdf'

    try:
        html = HTML(string=html_document, base_url=str(DOCS_DIR))
        css = CSS(string=PDF_CSS)
        html.write_pdf(output_file, stylesheets=[css])
        print(f"Created: {output_file}")
    except Exception as e:
        print(f"Error creating combined PDF: {e}")


def main():
    """Generate all PDF documentation."""

    print("=" * 60)
    print("PDF Documentation Generator")
    print("=" * 60)

    # Check for screenshots
    if not SCREENSHOTS_DIR.exists():
        print(f"Note: Screenshots directory not found at {SCREENSHOTS_DIR}")
        print("PDFs will be generated without embedded images.")

    # Generate individual PDFs
    print("\nGenerating individual PDFs...")
    for md_file in MARKDOWN_FILES:
        create_pdf(md_file)

    # Generate combined PDF
    print("\nGenerating combined documentation...")
    create_combined_pdf()

    print("\n" + "=" * 60)
    print("PDF generation complete!")
    print(f"Output directory: {OUTPUT_DIR}")
    print("=" * 60)

    # List generated files
    if OUTPUT_DIR.exists():
        print("\nGenerated files:")
        for pdf_file in OUTPUT_DIR.glob('*.pdf'):
            size_kb = pdf_file.stat().st_size / 1024
            print(f"  - {pdf_file.name} ({size_kb:.1f} KB)")


if __name__ == '__main__':
    main()
