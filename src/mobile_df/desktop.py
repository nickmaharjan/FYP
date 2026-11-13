"""Native Windows desktop shell for the local Android DFIR workspace.

Desktop-conversion milestones so far: a native case workspace that reuses the
existing analysis pipeline, local tool-readiness information, a searchable case
library, in-app case review (findings, timeline, correlations, tool runs) and
investigator-initiated cancellation of a running analysis.
"""
import argparse
import json
import os
import threading
import uuid
import webbrowser
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .case_library import (export_findings_csv, facets, filter_findings, filter_timeline,
                           finding_text, list_cases, load_case)
from .config import doctor, load_config
from .pipeline import analyze


PALETTE = {
    "page": "#171a1c", "rail": "#202527", "surface": "#252b2d",
    "surface_alt": "#2c3335", "line": "#3a4244", "ink": "#eff1e9",
    "muted": "#9da6a3", "accent": "#d8f05b", "success": "#91d7a5",
    "warning": "#efc96a", "danger": "#fa8c7d",
}
FONT = "Segoe UI"
MAX_TABLE_ROWS = 5000


def _short_time(value):
    return (value or "")[:19].replace("T", " ")


class DesktopApp:
    def __init__(self, root, data_dir=None, config_path=None):
        self.root = root
        self.root.title("Mobile DF | Local Investigation Workbench")
        self.root.geometry("1260x790")
        self.root.minsize(1000, 680)
        self.root.configure(bg=PALETTE["page"])
        self.data_dir = Path(data_dir or "data/cases").resolve()
        self.config = load_config(config_path)
        self.availability = doctor(self.config)
        self.active_view = "cases"
        self.busy = False
        self.cancel_event = None
        self.case_rows = {}
        self._style_ttk()
        self._build_shell()
        self.show_cases()

    def _style_ttk(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("DF.Treeview", background=PALETTE["page"], foreground=PALETTE["ink"],
                        fieldbackground=PALETTE["page"], borderwidth=0, relief="flat",
                        rowheight=35, font=(FONT, 10))
        style.configure("DF.Treeview.Heading", background=PALETTE["page"], foreground=PALETTE["muted"],
                        borderwidth=0, relief="flat", font=(FONT, 9, "bold"))
        style.map("DF.Treeview", background=[("selected", PALETTE["surface_alt"])],
                  foreground=[("selected", PALETTE["accent"])])
        style.configure("DF.TCombobox", fieldbackground=PALETTE["surface"],
                        background=PALETTE["surface"], foreground=PALETTE["ink"],
                        borderwidth=0, arrowsize=12)
        style.configure("DF.TNotebook", background=PALETTE["page"], borderwidth=0)
        style.configure("DF.TNotebook.Tab", background=PALETTE["surface"], foreground=PALETTE["muted"],
                        padding=(16, 8), borderwidth=0, font=(FONT, 9, "bold"))
        style.map("DF.TNotebook.Tab", background=[("selected", PALETTE["surface_alt"])],
                  foreground=[("selected", PALETTE["accent"])])

    def _build_shell(self):
        shell = tk.Frame(self.root, bg=PALETTE["page"])
        shell.pack(fill="both", expand=True)
        self.rail = tk.Frame(shell, bg=PALETTE["rail"], width=226, padx=22, pady=26)
        self.rail.pack(side="left", fill="y")
        self.rail.pack_propagate(False)

        brand = tk.Frame(self.rail, bg=PALETTE["rail"])
        brand.pack(fill="x", pady=(0, 36))
        tk.Label(brand, text="MOBILE DF", bg=PALETTE["rail"], fg=PALETTE["ink"],
                 font=(FONT, 17, "bold")).pack(anchor="w")
        tk.Label(brand, text="ANDROID FORENSICS  /  LOCAL", bg=PALETTE["rail"], fg=PALETTE["muted"],
                 font=(FONT, 8, "bold")).pack(anchor="w", pady=(4, 0))

        tk.Label(self.rail, text="WORKSPACE", bg=PALETTE["rail"], fg=PALETTE["muted"],
                 font=(FONT, 8, "bold")).pack(anchor="w", pady=(0, 9))
        self.nav_cases = self._nav_button(self.rail, "Investigations", self.show_cases)
        self.nav_tools = self._nav_button(self.rail, "Tool readiness", self.show_tools)
        tk.Frame(self.rail, bg=PALETTE["line"], height=1).pack(fill="x", pady=24)
        tk.Label(self.rail, text="ANALYSIS RUNS ON THIS COMPUTER", bg=PALETTE["rail"],
                 fg=PALETTE["muted"], font=(FONT, 8, "bold"), wraplength=175,
                 justify="left").pack(anchor="w")
        tk.Label(self.rail, text="Evidence is copied into each case workspace before tools run.",
                 bg=PALETTE["rail"], fg=PALETTE["muted"], font=(FONT, 9),
                 wraplength=178, justify="left").pack(anchor="w", pady=(7, 0))

        self.body = tk.Frame(shell, bg=PALETTE["page"], padx=38, pady=30)
        self.body.pack(side="left", fill="both", expand=True)
        self.footer = tk.Label(self.body, text="LOCAL WORKSPACE   •   NO CLOUD UPLOADS", bg=PALETTE["page"],
                               fg=PALETTE["muted"], font=(FONT, 8, "bold"))
        self.footer.pack(side="bottom", anchor="w", pady=(20, 0))
        self.content = tk.Frame(self.body, bg=PALETTE["page"])
        self.content.pack(side="top", fill="both", expand=True)

    def _nav_button(self, parent, label, command):
        button = tk.Button(parent, text=label, command=command, anchor="w", padx=10, pady=10,
                           bg=PALETTE["rail"], fg=PALETTE["muted"], activebackground=PALETTE["surface_alt"],
                           activeforeground=PALETTE["accent"], relief="flat", bd=0, highlightthickness=0,
                           font=(FONT, 10), cursor="hand2")
        button.pack(fill="x", pady=2)
        return button

    def _button(self, parent, label, command, primary=False):
        bg = PALETTE["accent"] if primary else PALETTE["surface_alt"]
        fg = PALETTE["page"] if primary else PALETTE["ink"]
        return tk.Button(parent, text=label, command=command, bg=bg, fg=fg,
                         activebackground=PALETTE["accent"], activeforeground=PALETTE["page"],
                         relief="flat", bd=0, highlightthickness=0, padx=16, pady=10,
                         font=(FONT, 9, "bold"), cursor="hand2")

    def _entry(self, parent, variable, width=None):
        return tk.Entry(parent, textvariable=variable, width=width, bg=PALETTE["surface_alt"], fg=PALETTE["ink"],
                        insertbackground=PALETTE["ink"], relief="flat", bd=0, font=(FONT, 10))

    def _heading(self, eyebrow, title, subtitle):
        tk.Label(self.content, text=eyebrow.upper(), bg=PALETTE["page"], fg=PALETTE["accent"],
                 font=(FONT, 8, "bold")).pack(anchor="w")
        tk.Label(self.content, text=title, bg=PALETTE["page"], fg=PALETTE["ink"],
                 font=(FONT, 24, "bold")).pack(anchor="w", pady=(5, 3))
        tk.Label(self.content, text=subtitle, bg=PALETTE["page"], fg=PALETTE["muted"],
                 font=(FONT, 10), wraplength=800, justify="left").pack(anchor="w", pady=(0, 24))

    def _clear(self):
        for child in self.content.winfo_children():
            child.destroy()

    def _activate_nav(self, selected):
        for name, button in (("cases", self.nav_cases), ("tools", self.nav_tools)):
            button.configure(bg=PALETTE["surface_alt"] if name == selected else PALETTE["rail"],
                             fg=PALETTE["accent"] if name == selected else PALETTE["muted"])

    # ----- Case library -------------------------------------------------------

    def show_cases(self):
        if self.busy:
            return
        self.active_view = "cases"
        self._activate_nav("cases")
        self._clear()
        self._heading("CASEWORK  /  LOCAL MODE", "Investigation workspace",
                      "Open an acquired Android extraction or image. Analysis stays on this computer.")

        split = tk.Frame(self.content, bg=PALETTE["page"])
        split.pack(fill="both", expand=True)
        main = tk.Frame(split, bg=PALETTE["page"])
        main.pack(side="left", fill="both", expand=True, padx=(0, 30))
        side = tk.Frame(split, bg=PALETTE["rail"], padx=18, pady=18, width=255)
        side.pack(side="right", fill="y")
        side.pack_propagate(False)

        command = tk.Frame(main, bg=PALETTE["surface"], padx=20, pady=18)
        command.pack(fill="x", pady=(0, 27))
        tk.Label(command, text="START A CASE", bg=PALETTE["surface"], fg=PALETTE["muted"],
                 font=(FONT, 8, "bold")).pack(anchor="w")
        tk.Label(command, text="Choose an existing acquisition to analyze.", bg=PALETTE["surface"],
                 fg=PALETTE["ink"], font=(FONT, 11)).pack(anchor="w", pady=(7, 12))
        self._button(command, "Choose evidence", self.show_new_case, primary=True).pack(anchor="w")

        header = tk.Frame(main, bg=PALETTE["page"])
        header.pack(fill="x", pady=(0, 8))
        tk.Label(header, text="RECENT INVESTIGATIONS", bg=PALETTE["page"], fg=PALETTE["muted"],
                 font=(FONT, 8, "bold")).pack(side="left")
        self.case_query = tk.StringVar()
        self._entry(header, self.case_query, width=28).pack(side="right", ipady=5)
        tk.Label(header, text="SEARCH", bg=PALETTE["page"], fg=PALETTE["muted"],
                 font=(FONT, 8, "bold")).pack(side="right", padx=(0, 8))

        actions = tk.Frame(main, bg=PALETTE["page"])
        actions.pack(side="bottom", anchor="w", pady=(10, 0))
        self._button(actions, "Review case", self._review_selected_case, primary=True).pack(side="left")
        self._button(actions, "Open report", self._open_selected_report).pack(side="left", padx=(8, 0))
        self._button(actions, "Open case folder", self._open_selected_folder).pack(side="left", padx=(8, 0))
        self.case_empty = tk.Label(main, text="", bg=PALETTE["page"], fg=PALETTE["muted"], font=(FONT, 9))
        self.case_empty.pack(side="bottom", anchor="w", pady=(6, 0))

        self.case_table = ttk.Treeview(main, columns=("case", "status", "integrity", "findings", "started"),
                                       show="headings", style="DF.Treeview", selectmode="browse")
        for column, label, width, anchor in (("case", "CASE", 220, "w"), ("status", "STATUS", 170, "w"),
                                             ("integrity", "INTEGRITY", 100, "w"), ("findings", "FINDINGS", 80, "e"),
                                             ("started", "STARTED (UTC)", 150, "w")):
            self.case_table.heading(column, text=label)
            self.case_table.column(column, width=width, anchor=anchor)
        self.case_table.pack(fill="both", expand=True)
        self.case_table.bind("<Double-1>", lambda _event: self._review_selected_case())
        self.case_query.trace_add("write", lambda *_: self._refresh_case_table())
        self._refresh_case_table()

        tk.Label(side, text="TOOL READINESS", bg=PALETTE["rail"], fg=PALETTE["accent"],
                 font=(FONT, 8, "bold")).pack(anchor="w", pady=(0, 12))
        for name, info in self.availability.items():
            self._tool_row(side, name, info)
        tk.Frame(side, bg=PALETTE["line"], height=1).pack(fill="x", pady=14)
        available = sum(bool(row.get("available")) for row in self.availability.values())
        tk.Label(side, text=f"{available} OF {len(self.availability)} READY", bg=PALETTE["rail"],
                 fg=PALETTE["muted"], font=(FONT, 8, "bold")).pack(anchor="w")
        self._button(side, "Review tool setup", self.show_tools).pack(anchor="w", pady=(12, 0))

    def _refresh_case_table(self):
        table = self.case_table
        table.delete(*table.get_children())
        self.case_rows = {}
        records = list_cases(self.data_dir, self.case_query.get())
        for record in records:
            item = table.insert("", "end", values=(record["case_id"], record["status"], record["integrity"],
                                                   record["findings"], _short_time(record["started_utc"])))
            self.case_rows[item] = record
        if records:
            self.case_empty.configure(text=f"{len(records)} case(s). Double-click a case to review it here.")
        elif self.case_query.get().strip():
            self.case_empty.configure(text="No cases match this search.")
        else:
            self.case_empty.configure(text="No cases yet. Choose evidence to start the first analysis.")

    def _tool_row(self, parent, name, info):
        row = tk.Frame(parent, bg=PALETTE["rail"])
        row.pack(fill="x", pady=4)
        color = PALETTE["success"] if info.get("available") else PALETTE["muted"]
        status = "READY" if info.get("available") else "NOT INSTALLED"
        tk.Label(row, text=name.upper(), bg=PALETTE["rail"], fg=PALETTE["ink"],
                 font=(FONT, 8, "bold")).pack(side="left", anchor="w")
        tk.Label(row, text=status, bg=PALETTE["rail"], fg=color,
                 font=(FONT, 7, "bold")).pack(side="right", anchor="e")

    def _selected_case(self):
        selection = self.case_table.selection()
        if not selection:
            messagebox.showinfo("Select a case", "Select a case in the list first.")
            return None
        return self.case_rows.get(selection[0])

    def _open_selected_report(self):
        record = self._selected_case()
        if record:
            self._open_report(record["folder"])

    def _open_selected_folder(self):
        record = self._selected_case()
        if record:
            self._open_folder(record["folder"])

    def _review_selected_case(self):
        record = self._selected_case()
        if record:
            self.show_case_review(record["folder"])

    def _open_report(self, folder):
        report = Path(folder) / "report.html"
        if report.is_file():
            webbrowser.open(report.resolve().as_uri())
        else:
            messagebox.showwarning("No report", "This case has no report. The analysis may have been interrupted.")

    def _open_folder(self, folder):
        folder = Path(folder)
        if not folder.is_dir():
            return
        if hasattr(os, "startfile"):
            os.startfile(folder)
        else:
            webbrowser.open(folder.resolve().as_uri())

    # ----- Case review --------------------------------------------------------

    def show_case_review(self, folder):
        if self.busy:
            return
        try:
            result = load_case(folder)
        except ValueError as exc:
            messagebox.showwarning("Case unavailable", str(exc))
            return
        self.active_view = "review"
        self._activate_nav("cases")
        self._clear()
        metrics = result.get("metrics") or {}
        status = str(result.get("status", "unknown")).upper().replace("_", " ")
        self._heading("CASE REVIEW  /  " + status, str(result.get("case_id", "Case")),
                      f"Evidence: {result.get('evidence', '')}   |   Started {_short_time(result.get('started_utc'))} UTC")

        actions = tk.Frame(self.content, bg=PALETTE["page"])
        actions.pack(fill="x", pady=(0, 14))
        self._button(actions, "Back to investigations", self.show_cases).pack(side="left")
        self._button(actions, "Open full report", lambda: self._open_report(folder), primary=True).pack(side="left", padx=(8, 0))
        self._button(actions, "Open case folder", lambda: self._open_folder(folder)).pack(side="left", padx=(8, 0))

        band = tk.Frame(self.content, bg=PALETTE["surface"], padx=20, pady=14)
        band.pack(fill="x", pady=(0, 14))
        integrity = (result.get("integrity") or {}).get("status", "unknown")
        tools = f"{metrics.get('tools_successful', 0)}/{metrics.get('tools_attempted', 0)}"
        for label, value, color in (("FILES", metrics.get("files", 0), PALETTE["ink"]),
                                    ("FINDINGS", metrics.get("findings", 0), PALETTE["ink"]),
                                    ("TIMELINE", metrics.get("timeline_events", 0), PALETTE["ink"]),
                                    ("CORRELATIONS", metrics.get("correlations", 0), PALETTE["ink"]),
                                    ("TOOLS OK", tools, PALETTE["ink"]),
                                    ("INTEGRITY", integrity.upper(),
                                     PALETTE["success"] if integrity == "verified" else PALETTE["danger"])):
            cell = tk.Frame(band, bg=PALETTE["surface"])
            cell.pack(side="left", padx=(0, 34))
            tk.Label(cell, text=label, bg=PALETTE["surface"], fg=PALETTE["muted"], font=(FONT, 8, "bold")).pack(anchor="w")
            tk.Label(cell, text=str(value), bg=PALETTE["surface"], fg=color, font=(FONT, 15, "bold")).pack(anchor="w")
        for warning in result.get("warnings") or []:
            tk.Label(self.content, text="WARNING  " + warning, bg=PALETTE["page"], fg=PALETTE["warning"],
                     font=(FONT, 9), wraplength=900, justify="left").pack(anchor="w", pady=(0, 6))

        tabs = ttk.Notebook(self.content, style="DF.TNotebook")
        tabs.pack(fill="both", expand=True)
        tabs.add(self._findings_tab(tabs, result), text="FINDINGS")
        tabs.add(self._timeline_tab(tabs, result), text="TIMELINE")
        tabs.add(self._correlations_tab(tabs, result), text="CORRELATIONS")
        tabs.add(self._tool_runs_tab(tabs, result), text="TOOL RUNS")

    def _table(self, parent, columns):
        frame = tk.Frame(parent, bg=PALETTE["page"])
        frame.pack(fill="both", expand=True)
        table = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings",
                             style="DF.Treeview", selectmode="browse")
        for key, label, width in columns:
            table.heading(key, text=label)
            table.column(key, width=width, anchor="w", stretch=key == columns[-1][0])
        scroll = ttk.Scrollbar(frame, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=scroll.set)
        table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return table

    def _filter_bar(self, parent):
        bar = tk.Frame(parent, bg=PALETTE["page"], pady=10)
        bar.pack(fill="x")
        return bar

    def _labelled(self, bar, label, widget):
        tk.Label(bar, text=label, bg=PALETTE["page"], fg=PALETTE["muted"],
                 font=(FONT, 8, "bold")).pack(side="left", padx=(0, 6))
        widget.pack(side="left", padx=(0, 16), ipady=4)
        return widget

    def _combo(self, bar, variable, values, width):
        return ttk.Combobox(bar, textvariable=variable, values=[""] + list(values),
                            state="readonly", width=width, style="DF.TCombobox")

    def _findings_tab(self, notebook, result):
        tab = tk.Frame(notebook, bg=PALETTE["page"])
        findings = result.get("findings") or []
        sources, severities = facets(findings)
        source, severity, query = tk.StringVar(), tk.StringVar(), tk.StringVar()
        bar = self._filter_bar(tab)
        self._labelled(bar, "SOURCE", self._combo(bar, source, sources, 12))
        self._labelled(bar, "SEVERITY", self._combo(bar, severity, severities, 10))
        self._labelled(bar, "SEARCH", self._entry(bar, query, width=26))
        count = tk.Label(bar, text="", bg=PALETTE["page"], fg=PALETTE["muted"], font=(FONT, 9))
        count.pack(side="left")
        detail = tk.Text(tab, height=7, bg=PALETTE["surface"], fg=PALETTE["ink"], relief="flat", bd=0,
                         font=("Consolas", 9), wrap="word", padx=12, pady=10, state="disabled")
        detail.pack(side="bottom", fill="x", pady=(8, 0))
        table = self._table(tab, (("severity", "SEVERITY", 90), ("source", "SOURCE", 90), ("kind", "KIND", 130),
                                  ("time", "TIME (UTC)", 150), ("path", "PATH", 260), ("summary", "SUMMARY", 320)))
        shown, current = {}, []

        def refresh(*_):
            table.delete(*table.get_children())
            shown.clear()
            current[:] = filter_findings(findings, source.get(), severity.get(), query.get())
            for item in current[:MAX_TABLE_ROWS]:
                iid = table.insert("", "end", values=(item.get("severity", ""), item.get("source", ""),
                                                      item.get("kind", ""), _short_time(item.get("timestamp")),
                                                      item.get("path", ""), finding_text(item)))
                shown[iid] = item
            suffix = f" (first {MAX_TABLE_ROWS} shown)" if len(current) > MAX_TABLE_ROWS else ""
            count.configure(text=f"{len(current)} finding(s){suffix}")

        def select(_event):
            selection = table.selection()
            item = shown.get(selection[0]) if selection else None
            detail.configure(state="normal")
            detail.delete("1.0", "end")
            if item:
                detail.insert("1.0", json.dumps(item, ensure_ascii=False, indent=2))
            detail.configure(state="disabled")

        def export():
            if not current:
                messagebox.showinfo("Nothing to export", "No findings match the current filters.")
                return
            path = filedialog.asksaveasfilename(title="Export filtered findings", defaultextension=".csv",
                                                initialfile=f"{result.get('case_id', 'case')}-findings.csv",
                                                filetypes=[("CSV", "*.csv")])
            if path:
                export_findings_csv(current, path)
                messagebox.showinfo("Export complete", f"{len(current)} finding(s) written to\n{path}")

        self._button(bar, "Export CSV", export).pack(side="right")
        for variable in (source, severity, query):
            variable.trace_add("write", refresh)
        table.bind("<<TreeviewSelect>>", select)
        refresh()
        return tab

    def _timeline_tab(self, notebook, result):
        tab = tk.Frame(notebook, bg=PALETTE["page"])
        timeline = result.get("timeline") or []
        start, end, query = tk.StringVar(), tk.StringVar(), tk.StringVar()
        bar = self._filter_bar(tab)
        self._labelled(bar, "FROM", self._entry(bar, start, width=12))
        self._labelled(bar, "TO", self._entry(bar, end, width=12))
        self._labelled(bar, "SEARCH", self._entry(bar, query, width=26))
        count = tk.Label(bar, text="", bg=PALETTE["page"], fg=PALETTE["muted"], font=(FONT, 9))
        count.pack(side="left")
        tk.Label(tab, text="Dates are ISO prefixes such as 2026-07 or 2026-07-15. All times are UTC.",
                 bg=PALETTE["page"], fg=PALETTE["muted"], font=(FONT, 8)).pack(anchor="w", pady=(0, 6))
        table = self._table(tab, (("time", "TIME (UTC)", 170), ("source", "SOURCE", 90), ("kind", "KIND", 130),
                                  ("path", "PATH", 260), ("summary", "SUMMARY", 320)))

        def refresh(*_):
            table.delete(*table.get_children())
            rows = filter_timeline(timeline, start.get().strip(), end.get().strip(), query.get())
            for item in rows[:MAX_TABLE_ROWS]:
                table.insert("", "end", values=(_short_time(item.get("timestamp")), item.get("source", ""),
                                                item.get("kind", ""), item.get("path", ""), finding_text(item)))
            suffix = f" (first {MAX_TABLE_ROWS} shown)" if len(rows) > MAX_TABLE_ROWS else ""
            count.configure(text=f"{len(rows)} event(s){suffix}")

        for variable in (start, end, query):
            variable.trace_add("write", refresh)
        refresh()
        return tab

    def _correlations_tab(self, notebook, result):
        tab = tk.Frame(notebook, bg=PALETTE["page"])
        tk.Label(tab, text="Exact shared values across tools. Association does not establish causation or compromise.",
                 bg=PALETTE["page"], fg=PALETTE["muted"], font=(FONT, 9)).pack(anchor="w", pady=10)
        table = self._table(tab, (("type", "TYPE", 90), ("sources", "SOURCES", 200), ("count", "FINDINGS", 80),
                                  ("value", "VALUE", 520)))
        for item in result.get("correlations") or []:
            table.insert("", "end", values=(item.get("type", ""), ", ".join(item.get("sources") or []),
                                            len(item.get("finding_ids") or []), item.get("value", "")))
        return tab

    def _tool_runs_tab(self, notebook, result):
        tab = tk.Frame(notebook, bg=PALETTE["page"])
        tk.Label(tab, text="Each adapter's outcome for this case. Raw output is kept in the case logs folder.",
                 bg=PALETTE["page"], fg=PALETTE["muted"], font=(FONT, 9)).pack(anchor="w", pady=10)
        table = self._table(tab, (("tool", "TOOL", 110), ("status", "STATUS", 130), ("count", "FINDINGS", 80),
                                  ("duration", "SECONDS", 80), ("reason", "REASON", 520)))
        for run in result.get("tool_runs") or []:
            table.insert("", "end", values=(run.get("tool", ""), run.get("status", ""), run.get("findings_count", 0),
                                            run.get("duration_seconds", ""), run.get("reason", "")))
        return tab

    # ----- Tools --------------------------------------------------------------

    def show_tools(self):
        if self.busy:
            return
        self.active_view = "tools"
        self._activate_nav("tools")
        self._clear()
        self._heading("ENVIRONMENT  /  LOCAL DEPENDENCIES", "Tool readiness",
                      "The desktop shell checks the local runtime before analysis. It does not install tools yet.")
        columns = tk.Frame(self.content, bg=PALETTE["surface"], padx=20, pady=14)
        columns.pack(fill="x", pady=(0, 3))
        for label, width in (("TOOL", 26), ("STATUS", 20), ("VERSION / COMMAND", 70)):
            tk.Label(columns, text=label, bg=PALETTE["surface"], fg=PALETTE["muted"],
                     width=width, anchor="w", font=(FONT, 8, "bold")).pack(side="left")
        for name, info in self.availability.items():
            row = tk.Frame(self.content, bg=PALETTE["surface"], padx=20, pady=14)
            row.pack(fill="x", pady=1)
            status = "AVAILABLE" if info.get("available") else "MISSING"
            color = PALETTE["success"] if info.get("available") else PALETTE["warning"]
            detail = info.get("version") or info.get("backend") or " / ".join(info.get("command") or []) or info.get("hint", "")
            for label, width, foreground in ((name, 26, PALETTE["ink"]), (status, 20, color), (detail, 70, PALETTE["muted"])):
                tk.Label(row, text=label, bg=PALETTE["surface"], fg=foreground,
                         width=width, anchor="w", font=(FONT, 9)).pack(side="left")
        tk.Label(self.content, text="Tool installation and updates are planned for a later milestone.",
                 bg=PALETTE["page"], fg=PALETTE["muted"], font=(FONT, 9)).pack(anchor="w", pady=(18, 0))

    # ----- New analysis -------------------------------------------------------

    def show_new_case(self):
        if self.busy:
            return
        self.active_view = "new"
        self._clear()
        self._heading("NEW INVESTIGATION  /  ACQUIRED EVIDENCE", "Start analysis",
                      "Select a forensic extraction, archive, Android backup, or supported disk image.")

        form = tk.Frame(self.content, bg=PALETTE["surface"], padx=22, pady=20)
        form.pack(fill="x", anchor="n")
        self.case_id = tk.StringVar(value="CASE-" + datetime.now().strftime("%Y%m%d-%H%M"))
        self.evidence_path = tk.StringVar()
        self.path_label = tk.StringVar(value="No evidence selected")
        tk.Label(form, text="CASE ID", bg=PALETTE["surface"], fg=PALETTE["muted"],
                 font=(FONT, 8, "bold")).pack(anchor="w")
        self._entry(form, self.case_id).pack(fill="x", ipady=9, pady=(6, 18))
        tk.Label(form, text="EVIDENCE", bg=PALETTE["surface"], fg=PALETTE["muted"],
                 font=(FONT, 8, "bold")).pack(anchor="w")
        choose = tk.Frame(form, bg=PALETTE["surface"])
        choose.pack(fill="x", pady=(7, 6))
        self._button(choose, "Choose folder", self._choose_directory).pack(side="left")
        self._button(choose, "Choose archive or image", self._choose_file).pack(side="left", padx=(8, 0))
        tk.Label(form, textvariable=self.path_label, bg=PALETTE["surface"], fg=PALETTE["ink"],
                 font=(FONT, 9), wraplength=740, justify="left").pack(anchor="w", pady=(6, 18))

        tk.Label(form, text="ANALYSIS TOOLS", bg=PALETTE["surface"], fg=PALETTE["muted"],
                 font=(FONT, 8, "bold")).pack(anchor="w")
        tk.Label(form, text="Installed tools will run. Missing tools will be listed in the case report.",
                 bg=PALETTE["surface"], fg=PALETTE["muted"], font=(FONT, 9)).pack(anchor="w", pady=(5, 13))
        actions = tk.Frame(form, bg=PALETTE["surface"])
        actions.pack(fill="x")
        self.run_button = self._button(actions, "Start local analysis", self._start_analysis, primary=True)
        self.run_button.pack(side="left")
        self.cancel_button = self._button(actions, "Cancel analysis", self._cancel_analysis)
        self.back_button = self._button(actions, "Back to investigations", self.show_cases)
        self.back_button.pack(side="left", padx=(8, 0))
        self.progress_text = tk.StringVar(value="")
        tk.Label(self.content, textvariable=self.progress_text, bg=PALETTE["page"], fg=PALETTE["accent"],
                 font=(FONT, 9)).pack(anchor="w", pady=(12, 0))

    def _choose_directory(self):
        path = filedialog.askdirectory(title="Select acquired Android extraction")
        if path:
            self.evidence_path.set(path)
            self.path_label.set(path)

    def _choose_file(self):
        path = filedialog.askopenfilename(title="Select archive, Android backup, or image",
                                          filetypes=[("Forensic evidence", "*.zip *.tar *.gz *.ab *.img *.dd *.raw *.001 *.E01"),
                                                     ("All files", "*.*")])
        if path:
            self.evidence_path.set(path)
            self.path_label.set(path)

    def _start_analysis(self):
        evidence = self.evidence_path.get().strip()
        case_id = self.case_id.get().strip()
        if not evidence or not case_id:
            messagebox.showwarning("Evidence required", "Enter a case ID and choose acquired evidence first.")
            return
        output = self.data_dir / uuid.uuid4().hex
        selected = [name for name, info in self.availability.items() if info.get("available")]
        self.busy = True
        self.active_view = "running"
        self.run_button.configure(state="disabled")
        self.back_button.pack_forget()
        self.cancel_button.configure(state="normal", text="Cancel analysis")
        self.cancel_button.pack(side="left", padx=(8, 0))
        cancel = self.cancel_event = threading.Event()
        self.progress_text.set("Preparing a verified case copy…")

        def progress(message):
            self.root.after(0, lambda text=message: self.progress_text.set(text))

        def work():
            try:
                result = analyze(evidence, output, case_id, config=self.config, tools=selected,
                                 progress=progress, cancel=cancel)
                self.root.after(0, lambda: self._analysis_complete(result, output))
            except Exception as exc:
                self.root.after(0, lambda error=exc: self._analysis_failed(error))

        threading.Thread(target=work, daemon=True).start()

    def _cancel_analysis(self):
        if not self.cancel_event or self.cancel_event.is_set():
            return
        if messagebox.askyesno("Cancel analysis",
                               "Stop the running tool and skip the remaining tools? "
                               "A partial case and report will still be saved."):
            self.cancel_event.set()
            self.cancel_button.configure(state="disabled", text="Cancelling…")
            self.progress_text.set("Cancelling: stopping the current tool and saving a partial case…")

    def _analysis_complete(self, result, output):
        self.busy = False
        self.cancel_event = None
        self.active_view = "result"
        self.cancel_button.pack_forget()
        message = f"{result['status']}  /  {result['metrics']['findings']} findings  /  {result['metrics']['timeline_events']} timeline events"
        self.progress_text.set(message)
        self._button(self.content, "Review case", lambda: self.show_case_review(output), primary=True).pack(anchor="w", pady=(10, 0))
        self._button(self.content, "Open case report", lambda: self._open_report(output)).pack(anchor="w", pady=(8, 0))
        self._button(self.content, "Return to investigations", self.show_cases).pack(anchor="w", pady=(8, 0))

    def _analysis_failed(self, error):
        self.busy = False
        self.cancel_event = None
        self.active_view = "new"
        self.cancel_button.pack_forget()
        self.back_button.pack(side="left", padx=(8, 0))
        self.progress_text.set("Analysis could not start")
        messagebox.showerror("Analysis failed", str(error))
        self.run_button.configure(state="normal")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Mobile DF native desktop workbench")
    parser.add_argument("--data-dir", type=Path, default=Path("data/cases"))
    parser.add_argument("--config", type=Path)
    args = parser.parse_args(argv)
    root = tk.Tk()
    DesktopApp(root, args.data_dir, args.config)
    root.mainloop()


if __name__ == "__main__":
    main()
