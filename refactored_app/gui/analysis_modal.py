"""
Analysis Results Modal
Displays AI analysis results with follow-up question capability.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
from typing import Optional, Callable, List, Dict, Any
from datetime import datetime

try:
    from ..ai.predictions import (
        VulnerabilityPredictor, AnalysisRequest, AnalysisResult,
        AnalysisMode, PredictionType
    )
    from ..ai.openwebui_client import OpenWebUIClient
except ImportError:
    from refactored_app.ai.predictions import (
        VulnerabilityPredictor, AnalysisRequest, AnalysisResult,
        AnalysisMode, PredictionType
    )
    from refactored_app.ai.openwebui_client import OpenWebUIClient


class AnalysisModal:
    """Modal window for displaying AI analysis results with follow-up capability."""

    def __init__(
        self,
        parent: tk.Tk,
        predictor: VulnerabilityPredictor,
        initial_result: Optional[AnalysisResult] = None,
        collection_ids: Optional[List[str]] = None
    ):
        """
        Initialize analysis modal.

        Args:
            parent: Parent window
            predictor: VulnerabilityPredictor instance for follow-up queries
            initial_result: Optional initial analysis result to display
            collection_ids: RAG collection IDs for queries
        """
        self.parent = parent
        self.predictor = predictor
        self.collection_ids = collection_ids
        self.processing = False

        # Create modal window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("AI Analysis Results")
        self.dialog.geometry("900x700")
        self.dialog.transient(parent)

        # Center on parent
        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - 900) // 2
        y = parent.winfo_y() + (parent.winfo_height() - 700) // 2
        self.dialog.geometry(f"+{x}+{y}")

        self._build_ui()

        # Display initial result if provided
        if initial_result:
            self._display_result(initial_result)

    def _build_ui(self):
        """Build the modal UI."""
        main_frame = ttk.Frame(self.dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header with info
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        self.model_label = ttk.Label(header_frame, text="Model: -")
        self.model_label.pack(side=tk.LEFT)

        self.timestamp_label = ttk.Label(header_frame, text="")
        self.timestamp_label.pack(side=tk.RIGHT)

        # Results display area
        results_frame = ttk.LabelFrame(main_frame, text="Analysis Results", padding="5")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Text widget with scrollbar
        text_frame = ttk.Frame(results_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)

        self.results_text = tk.Text(
            text_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            padx=10,
            pady=10
        )
        self.results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.results_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_text.config(yscrollcommand=scrollbar.set)

        # Configure text tags for formatting
        self.results_text.tag_configure('header', font=('Consolas', 11, 'bold'))
        self.results_text.tag_configure('subheader', font=('Consolas', 10, 'bold'))
        self.results_text.tag_configure('emphasis', font=('Consolas', 10, 'italic'))
        self.results_text.tag_configure('user', foreground='#0066cc', font=('Consolas', 10, 'bold'))
        self.results_text.tag_configure('assistant', foreground='#006600')
        self.results_text.tag_configure('error', foreground='#cc0000')
        self.results_text.tag_configure('separator', foreground='#999999')

        # Follow-up section
        followup_frame = ttk.LabelFrame(main_frame, text="Ask Follow-up Question", padding="5")
        followup_frame.pack(fill=tk.X, pady=(0, 10))

        # Follow-up input
        input_frame = ttk.Frame(followup_frame)
        input_frame.pack(fill=tk.X)

        self.followup_entry = ttk.Entry(input_frame, font=('TkDefaultFont', 10))
        self.followup_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.followup_entry.bind('<Return>', lambda e: self._send_followup())

        self.send_button = ttk.Button(
            input_frame,
            text="Send",
            command=self._send_followup
        )
        self.send_button.pack(side=tk.RIGHT)

        # Example questions
        examples_frame = ttk.Frame(followup_frame)
        examples_frame.pack(fill=tk.X, pady=(5, 0))

        ttk.Label(examples_frame, text="Examples:", font=('TkDefaultFont', 8)).pack(side=tk.LEFT)

        example_questions = [
            "Why are Java vulns taking longer?",
            "Which findings should I escalate?",
            "What's the biggest risk right now?"
        ]

        for q in example_questions:
            btn = ttk.Button(
                examples_frame,
                text=q,
                command=lambda question=q: self._use_example(question),
                style='Link.TButton'
            )
            btn.pack(side=tk.LEFT, padx=5)

        # Progress indicator
        self.progress_frame = ttk.Frame(followup_frame)
        self.progress_frame.pack(fill=tk.X, pady=(5, 0))
        self.progress_label = ttk.Label(self.progress_frame, text="")
        self.progress_label.pack(side=tk.LEFT)
        self.progress_bar = ttk.Progressbar(
            self.progress_frame,
            mode='indeterminate',
            length=100
        )

        # Bottom buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)

        ttk.Button(
            button_frame,
            text="Copy to Clipboard",
            command=self._copy_to_clipboard
        ).pack(side=tk.LEFT)

        ttk.Button(
            button_frame,
            text="Export...",
            command=self._export_results
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            button_frame,
            text="Close",
            command=self.dialog.destroy
        ).pack(side=tk.RIGHT)

        ttk.Button(
            button_frame,
            text="New Analysis",
            command=self._clear_for_new
        ).pack(side=tk.RIGHT, padx=5)

    def _display_result(self, result: AnalysisResult):
        """Display an analysis result."""
        if result.success:
            self.model_label.config(text=f"Model: {result.model_used or 'Unknown'}")
            self.timestamp_label.config(text=f"Generated: {result.timestamp[:19]}")

            self._append_text("\n" + "=" * 60 + "\n", 'separator')
            self._append_text(f"Analysis Type: {result.prediction_type.value.replace('_', ' ').title()}\n", 'header')
            self._append_text(f"Mode: {result.mode.value.title()}\n", 'subheader')
            self._append_text("=" * 60 + "\n\n", 'separator')

            self._append_text(result.content + "\n", 'assistant')
        else:
            self._append_text(f"\nError: {result.error}\n", 'error')

        self.results_text.see(tk.END)

    def _append_text(self, text: str, tag: Optional[str] = None):
        """Append text to results with optional tag."""
        self.results_text.config(state=tk.NORMAL)
        if tag:
            self.results_text.insert(tk.END, text, tag)
        else:
            self.results_text.insert(tk.END, text)
        self.results_text.config(state=tk.DISABLED)

    def _use_example(self, question: str):
        """Use an example question."""
        self.followup_entry.delete(0, tk.END)
        self.followup_entry.insert(0, question)
        self.followup_entry.focus()

    def _send_followup(self):
        """Send a follow-up question."""
        if self.processing:
            return

        question = self.followup_entry.get().strip()
        if not question:
            return

        self.processing = True
        self.send_button.config(state=tk.DISABLED)
        self.followup_entry.config(state=tk.DISABLED)

        # Show progress
        self.progress_label.config(text="Processing...")
        self.progress_bar.pack(side=tk.LEFT, padx=5)
        self.progress_bar.start(10)

        # Display the question
        self._append_text("\n" + "-" * 40 + "\n", 'separator')
        self._append_text(f"You: {question}\n\n", 'user')

        def _process():
            try:
                result = self.predictor.follow_up(
                    question=question,
                    collection_ids=self.collection_ids
                )
                self.dialog.after(0, lambda: self._followup_complete(result))
            except Exception as e:
                self.dialog.after(0, lambda: self._followup_error(str(e)))

        threading.Thread(target=_process, daemon=True).start()

    def _followup_complete(self, result: AnalysisResult):
        """Handle follow-up completion."""
        self.processing = False
        self.send_button.config(state=tk.NORMAL)
        self.followup_entry.config(state=tk.NORMAL)
        self.followup_entry.delete(0, tk.END)

        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        self.progress_label.config(text="")

        if result.success:
            self._append_text(f"Assistant:\n{result.content}\n", 'assistant')
        else:
            self._append_text(f"Error: {result.error}\n", 'error')

        self.results_text.see(tk.END)

    def _followup_error(self, error: str):
        """Handle follow-up error."""
        self.processing = False
        self.send_button.config(state=tk.NORMAL)
        self.followup_entry.config(state=tk.NORMAL)

        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        self.progress_label.config(text="")

        self._append_text(f"Error: {error}\n", 'error')

    def _copy_to_clipboard(self):
        """Copy results to clipboard."""
        self.dialog.clipboard_clear()
        content = self.results_text.get(1.0, tk.END)
        self.dialog.clipboard_append(content)
        messagebox.showinfo("Copied", "Results copied to clipboard")

    def _export_results(self):
        """Export results to file."""
        from tkinter import filedialog

        filename = filedialog.asksaveasfilename(
            title="Export Analysis Results",
            defaultextension=".txt",
            filetypes=[
                ("Text File", "*.txt"),
                ("Markdown", "*.md"),
                ("All Files", "*.*")
            ]
        )

        if filename:
            try:
                content = self.results_text.get(1.0, tk.END)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Exported", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")

    def _clear_for_new(self):
        """Clear for new analysis."""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)

        self.model_label.config(text="Model: -")
        self.timestamp_label.config(text="")

        # Clear predictor conversation history
        self.predictor.clear_conversation()


class AnalysisLauncher:
    """
    Launcher for starting AI analysis from the main app.
    Handles the analysis flow and displays results in modal.
    """

    def __init__(
        self,
        parent: tk.Tk,
        client: OpenWebUIClient,
        collection_ids: Optional[List[str]] = None
    ):
        """
        Initialize analysis launcher.

        Args:
            parent: Parent window
            client: OpenWebUI client
            collection_ids: RAG collection IDs
        """
        self.parent = parent
        self.client = client
        self.collection_ids = collection_ids
        self.predictor = VulnerabilityPredictor(client)
        self.modal: Optional[AnalysisModal] = None

    def launch_analysis(
        self,
        findings_df,
        lifecycle_df,
        prediction_type: PredictionType = PredictionType.FULL_ANALYSIS,
        mode: AnalysisMode = AnalysisMode.QUICK,
        on_complete: Optional[Callable[[AnalysisResult], None]] = None
    ):
        """
        Launch an analysis and show results in modal.

        Args:
            findings_df: Findings DataFrame
            lifecycle_df: Lifecycle DataFrame
            prediction_type: Type of prediction to run
            mode: Quick or comprehensive
            on_complete: Optional callback when complete
        """
        # Show progress dialog
        progress = self._show_progress_dialog("Running AI Analysis...")

        def _analyze():
            try:
                request = AnalysisRequest(
                    prediction_type=prediction_type,
                    mode=mode,
                    include_recommendations=True
                )

                result = self.predictor.analyze(
                    findings_df=findings_df,
                    lifecycle_df=lifecycle_df,
                    request=request,
                    collection_ids=self.collection_ids
                )

                self.parent.after(0, lambda: self._analysis_complete(result, progress, on_complete))

            except Exception as e:
                self.parent.after(0, lambda: self._analysis_error(str(e), progress))

        threading.Thread(target=_analyze, daemon=True).start()

    def _show_progress_dialog(self, message: str) -> tk.Toplevel:
        """Show a progress dialog."""
        dialog = tk.Toplevel(self.parent)
        dialog.title("Processing")
        dialog.geometry("300x100")
        dialog.transient(self.parent)
        dialog.grab_set()

        # Center
        dialog.update_idletasks()
        x = self.parent.winfo_x() + (self.parent.winfo_width() - 300) // 2
        y = self.parent.winfo_y() + (self.parent.winfo_height() - 100) // 2
        dialog.geometry(f"+{x}+{y}")

        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text=message).pack(pady=(0, 10))
        progress = ttk.Progressbar(frame, mode='indeterminate')
        progress.pack(fill=tk.X)
        progress.start(10)

        return dialog

    def _analysis_complete(
        self,
        result: AnalysisResult,
        progress_dialog: tk.Toplevel,
        on_complete: Optional[Callable[[AnalysisResult], None]]
    ):
        """Handle analysis completion."""
        progress_dialog.destroy()

        # Show modal with results
        self.modal = AnalysisModal(
            parent=self.parent,
            predictor=self.predictor,
            initial_result=result,
            collection_ids=self.collection_ids
        )

        if on_complete:
            on_complete(result)

    def _analysis_error(self, error: str, progress_dialog: tk.Toplevel):
        """Handle analysis error."""
        progress_dialog.destroy()
        messagebox.showerror("Analysis Error", f"Failed to run analysis:\n{error}")


def show_analysis_modal(
    parent: tk.Tk,
    predictor: VulnerabilityPredictor,
    initial_result: Optional[AnalysisResult] = None,
    collection_ids: Optional[List[str]] = None
) -> AnalysisModal:
    """
    Show the analysis modal.

    Args:
        parent: Parent window
        predictor: VulnerabilityPredictor instance
        initial_result: Optional initial result to display
        collection_ids: RAG collection IDs

    Returns:
        Modal instance
    """
    return AnalysisModal(parent, predictor, initial_result, collection_ids)
