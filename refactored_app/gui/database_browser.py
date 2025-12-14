"""
Database Browser Dialog for viewing SQLite database structure and data.
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import sqlite3
from typing import Optional, Dict, List, Tuple
import os


class DatabaseBrowserDialog:
    """Dialog for browsing SQLite database structure and data."""

    PAGE_SIZE = 100  # Rows per page

    def __init__(self, parent, db_path: Optional[str] = None):
        """
        Initialize the database browser dialog.

        Args:
            parent: Parent window
            db_path: Optional path to database file to open
        """
        self.parent = parent
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None

        # Pagination state
        self.current_table: Optional[str] = None
        self.current_offset = 0
        self.total_rows = 0
        self.col_names: List[str] = []

        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Database Browser")
        self.dialog.geometry("1000x700")
        self.dialog.transient(parent)

        # Center on parent
        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - 1000) // 2
        y = parent.winfo_y() + (parent.winfo_height() - 700) // 2
        self.dialog.geometry(f"+{x}+{y}")

        self._build_ui()

        if db_path:
            self._open_database(db_path)

    def _build_ui(self):
        """Build the dialog UI."""
        # Main container
        main_frame = ttk.Frame(self.dialog, padding="5")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Top toolbar
        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=(0, 5))

        ttk.Button(toolbar, text="Open Database", command=self._browse_database).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Refresh", command=self._refresh).pack(side=tk.LEFT, padx=2)

        self.db_label = ttk.Label(toolbar, text="No database loaded", font=('TkDefaultFont', 9, 'italic'))
        self.db_label.pack(side=tk.LEFT, padx=10)

        # Paned window for tables list and content
        paned = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Left panel - Tables list
        left_frame = ttk.Frame(paned)
        paned.add(left_frame, weight=1)

        ttk.Label(left_frame, text="Tables", font=('TkDefaultFont', 10, 'bold')).pack(anchor=tk.W)

        # Tables treeview
        tables_frame = ttk.Frame(left_frame)
        tables_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.tables_tree = ttk.Treeview(tables_frame, columns=('rows',), show='tree headings', height=15)
        self.tables_tree.heading('#0', text='Table / Column')
        self.tables_tree.heading('rows', text='Rows/Type')
        self.tables_tree.column('#0', width=180)
        self.tables_tree.column('rows', width=100)

        tables_scroll = ttk.Scrollbar(tables_frame, orient=tk.VERTICAL, command=self.tables_tree.yview)
        self.tables_tree.configure(yscrollcommand=tables_scroll.set)

        self.tables_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tables_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tables_tree.bind('<<TreeviewSelect>>', self._on_table_select)

        # Right panel - Data view
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=3)

        # Table info header
        self.table_info_label = ttk.Label(right_frame, text="Select a table to view data",
                                          font=('TkDefaultFont', 10, 'bold'))
        self.table_info_label.pack(anchor=tk.W)

        # Schema info
        self.schema_frame = ttk.LabelFrame(right_frame, text="Schema", padding="5")
        self.schema_frame.pack(fill=tk.X, pady=5)

        self.schema_text = tk.Text(self.schema_frame, height=4, wrap=tk.WORD,
                                   font=('Consolas', 9), state=tk.DISABLED)
        self.schema_text.pack(fill=tk.X)

        # Data preview header with navigation
        data_header_frame = ttk.Frame(right_frame)
        data_header_frame.pack(fill=tk.X)

        ttk.Label(data_header_frame, text="Data Preview",
                  font=('TkDefaultFont', 9, 'bold')).pack(side=tk.LEFT)

        # Navigation controls
        nav_frame = ttk.Frame(data_header_frame)
        nav_frame.pack(side=tk.RIGHT)

        self.first_btn = ttk.Button(nav_frame, text="<<", width=3, command=self._go_first)
        self.first_btn.pack(side=tk.LEFT, padx=1)

        self.prev_btn = ttk.Button(nav_frame, text="<", width=3, command=self._go_prev)
        self.prev_btn.pack(side=tk.LEFT, padx=1)

        self.page_label = ttk.Label(nav_frame, text="", width=25)
        self.page_label.pack(side=tk.LEFT, padx=5)

        self.next_btn = ttk.Button(nav_frame, text=">", width=3, command=self._go_next)
        self.next_btn.pack(side=tk.LEFT, padx=1)

        self.last_btn = ttk.Button(nav_frame, text=">>", width=3, command=self._go_last)
        self.last_btn.pack(side=tk.LEFT, padx=1)

        self.row_count_label = ttk.Label(data_header_frame, text="")
        self.row_count_label.pack(side=tk.RIGHT, padx=10)

        # Data treeview with scrollbars
        data_frame = ttk.Frame(right_frame)
        data_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.data_tree = ttk.Treeview(data_frame, show='headings')

        data_scroll_y = ttk.Scrollbar(data_frame, orient=tk.VERTICAL, command=self.data_tree.yview)
        data_scroll_x = ttk.Scrollbar(data_frame, orient=tk.HORIZONTAL, command=self.data_tree.xview)
        self.data_tree.configure(yscrollcommand=data_scroll_y.set, xscrollcommand=data_scroll_x.set)

        self.data_tree.grid(row=0, column=0, sticky='nsew')
        data_scroll_y.grid(row=0, column=1, sticky='ns')
        data_scroll_x.grid(row=1, column=0, sticky='ew')

        data_frame.grid_rowconfigure(0, weight=1)
        data_frame.grid_columnconfigure(0, weight=1)

        # Summary panel at bottom
        summary_frame = ttk.LabelFrame(main_frame, text="Database Summary", padding="5")
        summary_frame.pack(fill=tk.X, pady=(5, 0))

        self.summary_text = ttk.Label(summary_frame, text="", wraplength=950)
        self.summary_text.pack(fill=tk.X)

        # Close button
        ttk.Button(main_frame, text="Close", command=self.dialog.destroy).pack(pady=5)

        # Initially disable nav buttons
        self._update_nav_buttons()

    def _browse_database(self):
        """Browse for a database file."""
        filepath = filedialog.askopenfilename(
            title="Select SQLite Database",
            filetypes=[("SQLite Database", "*.db"), ("All files", "*.*")]
        )
        if filepath:
            self._open_database(filepath)

    def _open_database(self, db_path: str):
        """Open a database file."""
        if self.conn:
            self.conn.close()

        try:
            self.conn = sqlite3.connect(db_path)
            self.db_path = db_path
            self.db_label.config(text=os.path.basename(db_path))
            self.current_table = None
            self.current_offset = 0
            self._load_tables()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open database: {e}")

    def _refresh(self):
        """Refresh the database view."""
        if self.db_path:
            self._open_database(self.db_path)

    def _load_tables(self):
        """Load tables list from database."""
        if not self.conn:
            return

        # Clear existing items
        for item in self.tables_tree.get_children():
            self.tables_tree.delete(item)

        cursor = self.conn.cursor()

        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = cursor.fetchall()

        total_rows = 0
        table_info = []

        for (table_name,) in tables:
            # Get row count
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            row_count = cursor.fetchone()[0]
            total_rows += row_count

            # Get column info
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()

            # Insert table node
            table_node = self.tables_tree.insert('', 'end', text=f"  {table_name}",
                                                  values=(f"{row_count:,} rows",),
                                                  tags=('table',))

            # Insert column nodes
            for col in columns:
                col_id, col_name, col_type, not_null, default, pk = col
                type_info = col_type
                if pk:
                    type_info += " PK"
                if not_null:
                    type_info += " NOT NULL"
                self.tables_tree.insert(table_node, 'end', text=f"    {col_name}",
                                        values=(type_info,), tags=('column',))

            table_info.append((table_name, row_count, len(columns)))

        # Update summary
        summary = f"Database: {os.path.basename(self.db_path)} | "
        summary += f"Tables: {len(tables)} | "
        summary += f"Total Rows: {total_rows:,}"

        if table_info:
            summary += "\n"
            summary += " | ".join([f"{name}: {rows:,}" for name, rows, _ in table_info])

        self.summary_text.config(text=summary)

        # Get indexes
        cursor.execute("SELECT name, tbl_name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'")
        indexes = cursor.fetchall()
        if indexes:
            idx_node = self.tables_tree.insert('', 'end', text="  Indexes",
                                               values=(f"{len(indexes)} indexes",),
                                               tags=('indexes',))
            for idx_name, tbl_name in indexes:
                self.tables_tree.insert(idx_node, 'end', text=f"    {idx_name}",
                                        values=(f"on {tbl_name}",), tags=('index',))

    def _on_table_select(self, event):
        """Handle table selection."""
        selection = self.tables_tree.selection()
        if not selection:
            return

        item = selection[0]
        tags = self.tables_tree.item(item, 'tags')

        if 'table' in tags:
            table_name = self.tables_tree.item(item, 'text').strip()
            self.current_table = table_name
            self.current_offset = 0
            self._load_table_schema(table_name)
            self._load_table_data()

    def _load_table_schema(self, table_name: str):
        """Load and display table schema."""
        if not self.conn:
            return

        cursor = self.conn.cursor()

        # Get column info
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = cursor.fetchall()

        # Build schema text
        schema_lines = []
        self.col_names = []
        for col in columns:
            col_id, col_name, col_type, not_null, default, pk = col
            self.col_names.append(col_name)
            line = f"{col_name} {col_type}"
            if pk:
                line += " PRIMARY KEY"
            if not_null:
                line += " NOT NULL"
            if default is not None:
                line += f" DEFAULT {default}"
            schema_lines.append(line)

        self.schema_text.config(state=tk.NORMAL)
        self.schema_text.delete('1.0', tk.END)
        self.schema_text.insert('1.0', ", ".join(schema_lines))
        self.schema_text.config(state=tk.DISABLED)

        # Get total row count
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        self.total_rows = cursor.fetchone()[0]

        self.table_info_label.config(text=f"Table: {table_name}")
        self.row_count_label.config(text=f"Total: {self.total_rows:,} rows")

        # Configure data tree columns
        self.data_tree.delete(*self.data_tree.get_children())
        self.data_tree['columns'] = self.col_names

        for col_name in self.col_names:
            self.data_tree.heading(col_name, text=col_name)
            self.data_tree.column(col_name, width=100, minwidth=50)

    def _load_table_data(self):
        """Load data for current page."""
        if not self.conn or not self.current_table:
            return

        cursor = self.conn.cursor()

        # Clear existing data
        self.data_tree.delete(*self.data_tree.get_children())

        # Get data for current page
        cursor.execute(f"SELECT * FROM {self.current_table} LIMIT {self.PAGE_SIZE} OFFSET {self.current_offset}")
        rows = cursor.fetchall()

        for row in rows:
            # Truncate long values for display
            display_row = []
            for val in row:
                if val is None:
                    display_row.append('')
                elif isinstance(val, str) and len(val) > 50:
                    display_row.append(val[:47] + '...')
                else:
                    display_row.append(str(val))
            self.data_tree.insert('', 'end', values=display_row)

        self._update_nav_buttons()

    def _update_nav_buttons(self):
        """Update navigation button states and page label."""
        if not self.current_table or self.total_rows == 0:
            self.first_btn.config(state=tk.DISABLED)
            self.prev_btn.config(state=tk.DISABLED)
            self.next_btn.config(state=tk.DISABLED)
            self.last_btn.config(state=tk.DISABLED)
            self.page_label.config(text="")
            return

        # Calculate current page info
        current_page = (self.current_offset // self.PAGE_SIZE) + 1
        total_pages = ((self.total_rows - 1) // self.PAGE_SIZE) + 1 if self.total_rows > 0 else 1
        start_row = self.current_offset + 1
        end_row = min(self.current_offset + self.PAGE_SIZE, self.total_rows)

        self.page_label.config(text=f"Rows {start_row:,}-{end_row:,} (Page {current_page}/{total_pages})")

        # Enable/disable buttons based on position
        can_go_back = self.current_offset > 0
        can_go_forward = self.current_offset + self.PAGE_SIZE < self.total_rows

        self.first_btn.config(state=tk.NORMAL if can_go_back else tk.DISABLED)
        self.prev_btn.config(state=tk.NORMAL if can_go_back else tk.DISABLED)
        self.next_btn.config(state=tk.NORMAL if can_go_forward else tk.DISABLED)
        self.last_btn.config(state=tk.NORMAL if can_go_forward else tk.DISABLED)

    def _go_first(self):
        """Go to first page."""
        self.current_offset = 0
        self._load_table_data()

    def _go_prev(self):
        """Go to previous page."""
        self.current_offset = max(0, self.current_offset - self.PAGE_SIZE)
        self._load_table_data()

    def _go_next(self):
        """Go to next page."""
        new_offset = self.current_offset + self.PAGE_SIZE
        if new_offset < self.total_rows:
            self.current_offset = new_offset
            self._load_table_data()

    def _go_last(self):
        """Go to last page."""
        if self.total_rows > 0:
            self.current_offset = ((self.total_rows - 1) // self.PAGE_SIZE) * self.PAGE_SIZE
            self._load_table_data()

    def destroy(self):
        """Clean up and close dialog."""
        if self.conn:
            self.conn.close()
        self.dialog.destroy()


def show_database_browser(parent, db_path: Optional[str] = None):
    """
    Show the database browser dialog.

    Args:
        parent: Parent window
        db_path: Optional path to database file to open
    """
    DatabaseBrowserDialog(parent, db_path)
