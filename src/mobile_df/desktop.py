"""Native Windows desktop shell for the local Android DFIR workspace.

Desktop-conversion milestones so far: a native case workspace that reuses the
existing analysis pipeline, local tool-readiness information, a searchable case
library, in-app case review (findings, timeline, correlations, tool runs),
investigator-initiated cancellation, per-tool live progress, per-case tool
selection, case archive/restore/delete and persistent analysis settings.
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

from .case_library import (archive_case, delete_case, export_findings_csv, facets, filter_findings, step_logs,
                           filter_timeline, list_archived, list_cases, load_case,
                           rerun_options, restore_case)
from .config import doctor, load_config
from .pipeline import analyze
from .progress import ProgressModel
from .settings import DEFAULTS, load_settings, save_settings, selected_tools
from .summary import CATEGORIES, LABELS, case_overview, categorize, describe


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
    def __init__(self, root, data_dir=None, config_path=None, settings_path=None):
        self.root = root
        self.root.title("Mobile DF | Local Investigation Workbench")
        self.root.geometry("1260x790")
        self.root.minsize(1000, 680)
        self.root.configure(bg=PALETTE["page"])
        self.settings_path = Path(settings_path or "data/settings.json").resolve()
        self.settings = load_settings(self.settings_path)
        self.data_dir_override = data_dir is not None
        self.data_dir = Path(data_dir or self.settings["data_dir"]).resolve()
        self.config_path = Path(config_path or "tools.local.json").resolve()
        self.config = load_config(self.config_path)
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
        style.configure("DF.Horizontal.TProgressbar", troughcolor=PALETTE["surface"], background=PALETTE["accent"],
                        bordercolor=PALETTE["surface"], lightcolor=PALETTE["accent"], darkcolor=PALETTE["accent"],
                        thickness=8)
        style.configure("DF.TCheckbutton", background=PALETTE["surface"], foreground=PALETTE["ink"],
                        font=(FONT, 9), focuscolor=PALETTE["surface"])
        style.map("DF.TCheckbutton", background=[("active", PALETTE["surface"])],
                  foreground=[("disabled", PALETTE["muted"])])
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
        self.nav_archive = self._nav_button(self.rail, "Archive", self.show_archive)
        self.nav_tools = self._nav_button(self.rail, "Tool readiness", self.show_tools)
        self.nav_settings = self._nav_button(self.rail, "Settings", self.show_settings)
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
        for name, button in (("cases", self.nav_cases), ("archive", self.nav_archive),
                             ("tools", self.nav_tools), ("settings", self.nav_settings)):
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

        self._setup_checklist(main)
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
        self._button(actions, "Archive", self._archive_selected_case).pack(side="left", padx=(8, 0))
        self._button(actions, "Delete", self._delete_selected_case).pack(side="left", padx=(8, 0))
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

    def _setup_checklist(self, parent):
        from .readiness import checklist_complete, setup_checklist
        items = setup_checklist(self.availability, self.settings, self.data_dir)
        if checklist_complete(items) and all(item["done"] for item in items if item["key"] == "rules"):
            return
        band = tk.Frame(parent, bg=PALETTE["surface"], padx=20, pady=14)
        band.pack(fill="x", pady=(0, 14))
        done = sum(item["done"] for item in items)
        tk.Label(band, text=f"SETUP CHECKLIST  /  {done} OF {len(items)} DONE", bg=PALETTE["surface"],
                 fg=PALETTE["accent"], font=(FONT, 8, "bold")).pack(anchor="w", pady=(0, 6))
        actions = {"tools": ("Tool readiness", self.show_tools), "settings": ("Settings", self.show_settings)}
        for item in items:
            row = tk.Frame(band, bg=PALETTE["surface"])
            row.pack(fill="x", pady=2)
            mark, color = ("DONE", PALETTE["success"]) if item["done"] else (
                ("TO DO", PALETTE["warning"]) if item["required"] else ("OPTIONAL", PALETTE["muted"]))
            tk.Label(row, text=mark, width=9, anchor="w", bg=PALETTE["surface"], fg=color,
                     font=(FONT, 8, "bold")).pack(side="left")
            tk.Label(row, text=f"{item['title']}  -  {item['detail']}", anchor="w", bg=PALETTE["surface"],
                     fg=PALETTE["ink"] if not item["done"] else PALETTE["muted"], font=(FONT, 9),
                     wraplength=620, justify="left").pack(side="left")
            if not item["done"] and item["action"] in actions:
                label, command = actions[item["action"]]
                self._button(row, label, command).pack(side="right")

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
        if not record:
            return
        if record["status"] == "incomplete":
            self._offer_rerun(record)
        else:
            self.show_case_review(record["folder"])

    def _offer_rerun(self, record):
        try:
            options = rerun_options(record["folder"])
        except ValueError as exc:
            messagebox.showwarning("Interrupted case", f"{record['case_id']} did not finish.\n\n{exc}")
            return
        if messagebox.askyesno(
                "Re-run interrupted case",
                f"{record['case_id']} was interrupted before it finished, so it has no results or report.\n\n"
                f"Evidence: {options['evidence']}\n"
                f"Tools: {', '.join(options['tools']) or 'none'}\n\n"
                "Re-run it with the same evidence, tools and limits? The analysis starts in a new case folder; "
                "the interrupted folder is kept so you can archive or delete it."):
            self.show_new_case(rerun=options)
            self._start_analysis()

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

    def _archive_selected_case(self):
        record = self._selected_case()
        if not record:
            return
        try:
            archive_case(self.data_dir, record["folder"])
        except (ValueError, OSError) as exc:
            messagebox.showerror("Archive failed", str(exc))
            return
        self._refresh_case_table()
        self.case_empty.configure(text=f"{record['case_id']} moved to the archive. Restore it from Archive.")

    def _delete_selected_case(self, after=None):
        record = self._selected_case()
        if not record:
            return
        if not messagebox.askyesno(
                "Delete case permanently",
                f"Permanently delete case {record['case_id']}?\n\n"
                "This removes its working copies, tool output, logs and reports from:\n"
                f"{record['folder']}\n\nThe original evidence is not touched. This cannot be undone.",
                icon="warning", default="no"):
            return
        try:
            delete_case(self.data_dir, record["folder"])
        except (ValueError, OSError) as exc:
            messagebox.showerror("Delete failed", str(exc))
            return
        (after or self._refresh_case_table)()

    # ----- Archive ------------------------------------------------------------

    def show_archive(self):
        if self.busy:
            return
        self.active_view = "archive"
        self._activate_nav("archive")
        self._clear()
        self._heading("CASEWORK  /  ARCHIVE", "Archived investigations",
                      "Archived cases are hidden from the investigation list but kept intact on this computer.")
        actions = tk.Frame(self.content, bg=PALETTE["page"])
        actions.pack(side="bottom", anchor="w", pady=(10, 0))
        self.case_empty = tk.Label(self.content, text="", bg=PALETTE["page"], fg=PALETTE["muted"], font=(FONT, 9))
        self.case_empty.pack(side="bottom", anchor="w", pady=(6, 0))
        self.case_table = self._table(self.content, (("case", "CASE", 240), ("status", "STATUS", 180),
                                                     ("findings", "FINDINGS", 90), ("started", "STARTED (UTC)", 200)))
        self.case_table.bind("<Double-1>", lambda _event: self._review_selected_case())

        def refresh():
            self.case_table.delete(*self.case_table.get_children())
            self.case_rows = {}
            records = list_archived(self.data_dir)
            for record in records:
                item = self.case_table.insert("", "end", values=(record["case_id"], record["status"], record["findings"],
                                                                 _short_time(record["started_utc"])))
                self.case_rows[item] = record
            self.case_empty.configure(text=f"{len(records)} archived case(s)." if records else "The archive is empty.")

        def restore():
            record = self._selected_case()
            if not record:
                return
            try:
                restore_case(self.data_dir, record["folder"])
            except (ValueError, OSError) as exc:
                messagebox.showerror("Restore failed", str(exc))
                return
            refresh()

        self._button(actions, "Restore to investigations", restore, primary=True).pack(side="left")
        self._button(actions, "Review case", self._review_selected_case).pack(side="left", padx=(8, 0))
        self._button(actions, "Delete permanently", lambda: self._delete_selected_case(after=refresh)).pack(side="left", padx=(8, 0))
        refresh()

    # ----- Settings -----------------------------------------------------------

    def show_settings(self):
        if self.busy:
            return
        self.active_view = "settings"
        self._activate_nav("settings")
        self._clear()
        self._heading("ENVIRONMENT  /  PREFERENCES", "Analysis settings",
                      f"Applied to every new analysis. Saved locally in {self.settings_path}.")
        form = tk.Frame(self.content, bg=PALETTE["surface"], padx=22, pady=18)
        form.pack(fill="x", anchor="n")
        # Show 0 as "0": `value or ""` would blank it, and saving would then fail on the empty number.
        values = {key: tk.StringVar(value="" if self.settings.get(key) is None else str(self.settings.get(key)))
                  for key in ("data_dir", "timeout", "max_rows", "image_offset", "yara_rules", "iocs")}

        def row(label, key, hint, browse=None):
            tk.Label(form, text=label, bg=PALETTE["surface"], fg=PALETTE["muted"], font=(FONT, 8, "bold")).pack(anchor="w")
            line = tk.Frame(form, bg=PALETTE["surface"])
            line.pack(fill="x", pady=(5, 2))
            self._entry(line, values[key]).pack(side="left", fill="x", expand=True, ipady=7)
            if browse:
                self._button(line, "Browse", browse).pack(side="left", padx=(8, 0))
                self._button(line, "Clear", lambda: values[key].set("")).pack(side="left", padx=(8, 0))
            tk.Label(form, text=hint, bg=PALETTE["surface"], fg=PALETTE["muted"], font=(FONT, 8)).pack(anchor="w", pady=(0, 12))

        def pick_folder():
            path = filedialog.askdirectory(title="Choose the folder where case workspaces are stored")
            if path:
                values["data_dir"].set(path)

        def pick_file(key, title, types):
            path = filedialog.askopenfilename(title=title, filetypes=types + [("All files", "*.*")])
            if path:
                values[key].set(path)

        row("CASE DATA FOLDER", "data_dir", "Where new case workspaces, reports and the archive are kept.", pick_folder)
        row("YARA RULES FILE", "yara_rules", "Required for YARA to run. Leave empty to skip YARA.",
            lambda: pick_file("yara_rules", "Choose YARA rules", [("YARA rules", "*.yar *.yara")]))
        row("INDICATORS FILE (STIX2 / JSON)", "iocs", "Optional indicators of compromise passed to MVT.",
            lambda: pick_file("iocs", "Choose indicators", [("Indicators", "*.json *.stix2")]))
        numbers = tk.Frame(form, bg=PALETTE["surface"])
        numbers.pack(fill="x")
        for label, key, hint in (("TOOL TIMEOUT (SECONDS)", "timeout", "Per tool process"),
                                 ("SQLITE ROW LIMIT", "max_rows", "Rows exported per table"),
                                 ("IMAGE OFFSET (SECTORS)", "image_offset", "Partition start for disk images")):
            cell = tk.Frame(numbers, bg=PALETTE["surface"])
            cell.pack(side="left", padx=(0, 24))
            tk.Label(cell, text=label, bg=PALETTE["surface"], fg=PALETTE["muted"], font=(FONT, 8, "bold")).pack(anchor="w")
            self._entry(cell, values[key], width=14).pack(anchor="w", ipady=7, pady=(5, 2))
            tk.Label(cell, text=hint, bg=PALETTE["surface"], fg=PALETTE["muted"], font=(FONT, 8)).pack(anchor="w")

        tk.Label(form, text="DEFAULT TOOLS FOR NEW CASES", bg=PALETTE["surface"], fg=PALETTE["muted"],
                 font=(FONT, 8, "bold")).pack(anchor="w", pady=(16, 4))
        tool_line = tk.Frame(form, bg=PALETTE["surface"])
        tool_line.pack(fill="x")
        defaults = self.settings.get("default_tools")
        tool_vars = {}
        for name, info in self.availability.items():
            tool_vars[name] = tk.BooleanVar(value=defaults is None or name in defaults)
            ttk.Checkbutton(tool_line, text=name if info.get("available") else f"{name} (not installed)",
                            variable=tool_vars[name], style="DF.TCheckbutton").pack(side="left", padx=(0, 14))

        status = tk.StringVar()

        def save():
            chosen = [name for name, var in tool_vars.items() if var.get()]
            candidate = {key: var.get() for key, var in values.items()}
            candidate["default_tools"] = None if len(chosen) == len(tool_vars) else chosen
            try:
                self.settings = save_settings(self.settings_path, candidate)
            except ValueError as exc:
                messagebox.showerror("Settings not saved", str(exc))
                return
            if not self.data_dir_override:
                self.data_dir = Path(self.settings["data_dir"]).resolve()
            status.set("Settings saved. They apply to the next analysis.")

        def reset():
            if messagebox.askyesno("Reset settings", "Restore the default analysis settings?"):
                for key, var in values.items():
                    var.set(str(DEFAULTS[key] or ""))
                for var in tool_vars.values():
                    var.set(True)

        actions = tk.Frame(self.content, bg=PALETTE["page"])
        actions.pack(anchor="w", pady=(14, 0))
        self._button(actions, "Save settings", save, primary=True).pack(side="left")
        self._button(actions, "Reset to defaults", reset).pack(side="left", padx=(8, 0))
        tk.Label(actions, textvariable=status, bg=PALETTE["page"], fg=PALETTE["success"], font=(FONT, 9)).pack(side="left", padx=(14, 0))
        if self.data_dir_override:
            tk.Label(self.content, text=f"Case data folder is fixed by --data-dir for this session: {self.data_dir}",
                     bg=PALETTE["page"], fg=PALETTE["warning"], font=(FONT, 9)).pack(anchor="w", pady=(10, 0))

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
        self._button(actions, "Export handoff ZIP", lambda: self._export_handoff(folder, result)).pack(side="left", padx=(8, 0))

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
        tabs = ttk.Notebook(self.content, style="DF.TNotebook")
        tabs.pack(fill="both", expand=True)
        findings_tab, show_category = self._findings_tab(tabs, result)

        def open_category(key):
            show_category(key)
            tabs.select(findings_tab)

        # The summary comes first: warnings, problems and what was found, in plain words.
        tabs.add(self._summary_tab(tabs, result, open_category), text="SUMMARY")
        tabs.add(findings_tab, text="FINDINGS")
        tabs.add(self._timeline_tab(tabs, result), text="TIMELINE")
        tabs.add(self._correlations_tab(tabs, result), text="CORRELATIONS")
        tabs.add(self._tool_runs_tab(tabs, result, folder), text="TOOL RUNS")

    def _export_handoff(self, folder, result):
        from .handoff import default_filename, export_case
        path = filedialog.asksaveasfilename(title="Save case handoff package", defaultextension=".zip",
                                            initialfile=default_filename(result), filetypes=[("ZIP archive", "*.zip")])
        if not path:
            return
        include = messagebox.askyesno(
            "Include native tool output?",
            "Also include each tool's raw output folder?\n\n"
            "It helps a reviewer re-check findings, but it can contain files recovered from the evidence "
            "and make the package much larger.\n\n"
            "Evidence working copies are never included.", default="no")
        try:
            summary = export_case(folder, path, include_tool_output=include)
        except (ValueError, OSError) as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        messagebox.showinfo(
            "Handoff package saved",
            f"{summary['files']} files packaged in\n{summary['zip']}\n\n"
            f"ZIP SHA-256:\n{summary['sha256']}\n\n"
            f"The hash is also saved in {Path(summary['sha256_file']).name}. Send both files; "
            "the recipient can check them with: python -m mobile_df.handoff verify <zip>")

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

    def _summary_tab(self, notebook, result, open_category):
        """Plain-language overview: headline, what was found by category, what needs attention, tools."""
        overview = case_overview(result)
        outer = tk.Frame(notebook, bg=PALETTE["page"])
        canvas = tk.Canvas(outer, bg=PALETTE["page"], highlightthickness=0, bd=0)
        scroll = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        tab = tk.Frame(canvas, bg=PALETTE["page"], padx=4, pady=12)
        tab.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        window = canvas.create_window((0, 0), window=tab, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window, width=e.width))
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        def section(title):
            tk.Label(tab, text=title, bg=PALETTE["page"], fg=PALETTE["muted"],
                     font=(FONT, 8, "bold")).pack(anchor="w", pady=(16, 6))

        tk.Label(tab, text=overview["headline"], bg=PALETTE["page"], fg=PALETTE["ink"], font=(FONT, 11),
                 wraplength=1000, justify="left").pack(anchor="w")

        section("WHAT WAS FOUND  (click a box to see those findings)")
        grid = tk.Frame(tab, bg=PALETTE["page"])
        grid.pack(anchor="w", fill="x")
        for index, category in enumerate(overview["categories"]):
            cell = tk.Frame(grid, bg=PALETTE["surface"], padx=14, pady=10, cursor="hand2", width=235, height=84)
            cell.grid(row=index // 4, column=index % 4, padx=(0, 10), pady=(0, 10), sticky="nsew")
            cell.grid_propagate(False)
            color = PALETTE["warning"] if category["key"] in ("leads", "problems") else PALETTE["ink"]
            labels = (tk.Label(cell, text=f"{category['count']:,}", bg=PALETTE["surface"], fg=color,
                               font=(FONT, 15, "bold")),
                      tk.Label(cell, text=category["label"], bg=PALETTE["surface"], fg=PALETTE["ink"],
                               font=(FONT, 9, "bold")),
                      tk.Label(cell, text=category["explanation"], bg=PALETTE["surface"], fg=PALETTE["muted"],
                               font=(FONT, 8), wraplength=205, justify="left"))
            for widget in (cell,) + labels:
                widget.bind("<Button-1>", lambda _e, key=category["key"]: open_category(key))
            for label in labels:
                label.pack(anchor="w")
        if not overview["categories"]:
            tk.Label(tab, text="No findings were produced.", bg=PALETTE["page"], fg=PALETTE["muted"],
                     font=(FONT, 9)).pack(anchor="w")

        section("NEEDS YOUR ATTENTION")
        for item in overview["attention"] or ["Nothing: every selected tool worked and the evidence is unchanged."]:
            tk.Label(tab, text="\u2022  " + item, bg=PALETTE["page"],
                     fg=PALETTE["warning"] if overview["attention"] else PALETTE["success"],
                     font=(FONT, 9), wraplength=1000, justify="left").pack(anchor="w", pady=(0, 4))

        section("WHEN THE ACTIVITY HAPPENED")
        if overview["activity_range"]:
            first, last = overview["activity_range"]
            busiest = ", ".join(f"{day} ({count:,} records)" for day, count in overview["busiest_days"])
            text = f"User activity records run from {first} to {last} (UTC).\nBusiest days: {busiest}."
        else:
            text = "No dated user activity (messages, calls, web history, apps) was found."
        tk.Label(tab, text=text, bg=PALETTE["page"], fg=PALETTE["ink"], font=(FONT, 9),
                 justify="left").pack(anchor="w")

        section("TOOLS")
        for tool in overview["tools"]:
            row = tk.Frame(tab, bg=PALETTE["page"])
            row.pack(anchor="w", fill="x", pady=(0, 3))
            color = {"success": PALETTE["success"], "partial": PALETTE["warning"], "failed": PALETTE["danger"],
                     "timeout": PALETTE["danger"]}.get(tool["status"], PALETTE["muted"])
            tk.Label(row, text=str(tool["tool"]), bg=PALETTE["page"], fg=PALETTE["ink"], width=12, anchor="w",
                     font=(FONT, 9, "bold")).pack(side="left")
            tk.Label(row, text=tool["plain"], bg=PALETTE["page"], fg=color, font=(FONT, 9), wraplength=880,
                     justify="left", anchor="w").pack(side="left", fill="x")

        section("EVIDENCE")
        integrity = overview["integrity"]
        tk.Label(tab, text=("Verified: the evidence was fingerprinted (SHA-256) before and after the analysis and did "
                            "not change." if integrity == "verified" else
                            f"Integrity is {integrity}: compare the evidence fingerprints in the full report."),
                 bg=PALETTE["page"], fg=PALETTE["success"] if integrity == "verified" else PALETTE["danger"],
                 font=(FONT, 9), wraplength=1000, justify="left").pack(anchor="w")
        return outer

    def _findings_tab(self, notebook, result):
        """Returns (tab, show_category) so the summary can open a category directly."""
        tab = tk.Frame(notebook, bg=PALETTE["page"])
        findings = result.get("findings") or []
        sources, severities = facets(findings)
        categories = {id(item): categorize(item) for item in findings}
        present = set(categories.values())
        by_label = {label: key for key, label, _ in CATEGORIES if key in present}
        category, source, severity, query = tk.StringVar(), tk.StringVar(), tk.StringVar(), tk.StringVar()
        bar = self._filter_bar(tab)
        self._labelled(bar, "CATEGORY", self._combo(bar, category, list(by_label), 16))
        self._labelled(bar, "SOURCE", self._combo(bar, source, sources, 12))
        self._labelled(bar, "SEVERITY", self._combo(bar, severity, severities, 10))
        self._labelled(bar, "SEARCH", self._entry(bar, query, width=26))
        count = tk.Label(bar, text="", bg=PALETTE["page"], fg=PALETTE["muted"], font=(FONT, 9))
        count.pack(side="left")
        detail = tk.Text(tab, height=7, bg=PALETTE["surface"], fg=PALETTE["ink"], relief="flat", bd=0,
                         font=("Consolas", 9), wrap="word", padx=12, pady=10, state="disabled")
        detail.pack(side="bottom", fill="x", pady=(8, 0))
        # Readable "what" first; tool, kind and raw values stay in the details panel below.
        table = self._table(tab, (("category", "CATEGORY", 120), ("time", "TIME (UTC)", 140),
                                  ("source", "TOOL", 75), ("what", "WHAT", 760)))
        shown, current = {}, []

        def refresh(*_):
            table.delete(*table.get_children())
            shown.clear()
            wanted = by_label.get(category.get())
            rows = filter_findings(findings, source.get(), severity.get(), query.get(),
                                   include_inventory=wanted == "evidence")
            current[:] = [item for item in rows if not wanted or categories.get(id(item)) == wanted]
            for item in current[:MAX_TABLE_ROWS]:
                iid = table.insert("", "end", values=(LABELS.get(categories.get(id(item)), ""),
                                                      _short_time(item.get("timestamp")), item.get("source", ""),
                                                      describe(item)))
                shown[iid] = item
            suffix = f" (first {MAX_TABLE_ROWS} shown)" if len(current) > MAX_TABLE_ROWS else ""
            count.configure(text=f"{len(current)} finding(s){suffix}")

        def select(_event):
            selection = table.selection()
            item = shown.get(selection[0]) if selection else None
            detail.configure(state="normal")
            detail.delete("1.0", "end")
            if item:
                detail.insert("1.0", describe(item) + "\n\nTechnical details (as recorded by the tool):\n"
                              + json.dumps(item, ensure_ascii=False, indent=2))
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
        for variable in (category, source, severity, query):
            variable.trace_add("write", refresh)
        table.bind("<<TreeviewSelect>>", select)
        refresh()

        def show_category(key):
            category.set(LABELS.get(key, "") if key in present else "")

        return tab, show_category

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
        table = self._table(tab, (("time", "TIME (UTC)", 150), ("category", "CATEGORY", 120),
                                  ("source", "TOOL", 75), ("what", "WHAT", 740)))

        def refresh(*_):
            table.delete(*table.get_children())
            rows = filter_timeline(timeline, start.get().strip(), end.get().strip(), query.get())
            for item in rows[:MAX_TABLE_ROWS]:
                table.insert("", "end", values=(_short_time(item.get("timestamp")), LABELS[categorize(item)],
                                                item.get("source", ""), describe(item)))
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

    def _tool_runs_tab(self, notebook, result, folder):
        tab = tk.Frame(notebook, bg=PALETTE["page"])
        bar = self._filter_bar(tab)
        tk.Label(bar, text="Each adapter's outcome for this case. Select a tool and choose View logs to see why it "
                           "failed or what it printed.", bg=PALETTE["page"], fg=PALETTE["muted"],
                 font=(FONT, 9)).pack(side="left")
        table = self._table(tab, (("tool", "TOOL", 100), ("version", "VERSION", 90), ("status", "STATUS", 120),
                                  ("count", "FINDINGS", 80), ("duration", "SECONDS", 80), ("reason", "REASON", 480)))
        runs = {}
        for run in result.get("tool_runs") or []:
            iid = table.insert("", "end", values=(run.get("tool", ""), run.get("tool_version") or "", run.get("status", ""),
                                                  run.get("findings_count", 0), run.get("duration_seconds", ""),
                                                  run.get("reason", "")))
            runs[iid] = run

        def view(_event=None):
            selection = table.selection()
            run = runs.get(selection[0]) if selection else None
            if not run:
                messagebox.showinfo("View logs", "Select a tool run first.")
            elif not run.get("steps"):
                messagebox.showinfo("No logs", f"{run.get('tool')} did not run: {run.get('reason') or run.get('status')}.")
            else:
                self._show_logs(folder, run)

        self._button(bar, "Open logs folder", lambda: self._open_folder(Path(folder) / "logs")).pack(side="right")
        self._button(bar, "View logs", view, primary=True).pack(side="right", padx=(0, 8))
        table.bind("<Double-1>", view)
        return tab

    def _show_logs(self, folder, run):
        window = tk.Toplevel(self.root, bg=PALETTE["page"])
        window.title(f"{run.get('tool')} logs - {run.get('status')}")
        window.geometry("980x640")
        tk.Label(window, text=f"{run.get('tool', '').upper()}  /  {run.get('status', '').upper()}",
                 bg=PALETTE["page"], fg=PALETTE["accent"], font=(FONT, 9, "bold")).pack(anchor="w", padx=16, pady=(14, 0))
        tk.Label(window, text=run.get("reason") or "Completed without a recorded problem.", bg=PALETTE["page"],
                 fg=PALETTE["ink"], font=(FONT, 10), wraplength=930, justify="left").pack(anchor="w", padx=16, pady=(4, 10))
        text = tk.Text(window, bg=PALETTE["surface"], fg=PALETTE["ink"], relief="flat", bd=0, font=("Consolas", 9),
                       wrap="none", padx=12, pady=10)
        scroll = ttk.Scrollbar(window, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y", padx=(0, 16), pady=(0, 16))
        text.pack(fill="both", expand=True, padx=(16, 0), pady=(0, 16))
        for step in step_logs(folder, run):
            text.insert("end", f"=== {step['step']}: {step['status']} (exit code {step['exit_code']}, "
                               f"{step['duration_seconds']} s)\n")
            if step["reason"]:
                text.insert("end", f"Reason: {step['reason']}\n")
            text.insert("end", f"Command: {step['command']}\n\n--- stderr ---\n{step['stderr'].rstrip()}\n\n"
                               f"--- stdout ---\n{step['stdout'].rstrip()}\n\n")
        text.configure(state="disabled")

    # ----- Tools --------------------------------------------------------------

    def show_tools(self):
        if self.busy:
            return
        from .installer import pack_status
        from .registry import TOOLS, load_packs
        self.active_view = "tools"
        self._activate_nav("tools")
        self._clear()
        self._heading("ENVIRONMENT  /  LOCAL DEPENDENCIES", "Tool readiness",
                      "Installed forensic tools, the versions recorded in every case, and their licences.")
        try:
            packs = load_packs()
            states = pack_status(packs)
        except (OSError, ValueError):
            packs, states = {}, {}
        missing = [name for name, state in states.items() if state["action"]]
        actions = tk.Frame(self.content, bg=PALETTE["page"])
        actions.pack(fill="x", pady=(0, 14))
        if missing:
            self._button(actions, f"Install / update {len(missing)} tool(s)",
                         lambda: self._install_tools(missing), primary=True).pack(side="left", padx=(0, 8))
        self._button(actions, "Install from offline kit", lambda: self._install_tools(sorted(packs), offline=True)
                     ).pack(side="left", padx=(0, 8))
        self._button(actions, "Verify tool packs", self._verify_packs, primary=not missing).pack(side="left")
        self._button(actions, "Licence notices", self._show_notices).pack(side="left", padx=(8, 0))
        self._button(actions, "Re-check tools", self._recheck_tools).pack(side="left", padx=(8, 0))
        columns = tk.Frame(self.content, bg=PALETTE["surface"], padx=20, pady=14)
        columns.pack(fill="x", pady=(0, 3))
        widths = (("TOOL", 26), ("STATUS", 12), ("VERSION", 12), ("PINNED", 10), ("LICENCE", 44), ("INSTALL", 26))
        for label, width in widths:
            tk.Label(columns, text=label, bg=PALETTE["surface"], fg=PALETTE["muted"],
                     width=width, anchor="w", font=(FONT, 8, "bold")).pack(side="left")
        for name, info in self.availability.items():
            meta = TOOLS.get(name, {})
            row = tk.Frame(self.content, bg=PALETTE["surface"], padx=20, pady=12)
            row.pack(fill="x", pady=1)
            status = "AVAILABLE" if info.get("available") else "MISSING"
            color = PALETTE["success"] if info.get("available") else PALETTE["warning"]
            pinned = packs.get(name, {}).get("version", "")
            values = ((meta.get("title", name), PALETTE["ink"]), (status, color), (info.get("version") or "-", PALETTE["ink"]),
                      (pinned or "-", PALETTE["muted"]), (meta.get("license", ""), PALETTE["muted"]),
                      (meta.get("install", ""), PALETTE["muted"]))
            for (label, foreground), (_, width) in zip(values, widths):
                tk.Label(row, text=label, bg=PALETTE["surface"], fg=foreground,
                         width=width, anchor="w", font=(FONT, 9)).pack(side="left")
            state = states.get(name)
            if state:
                label = state["action"] or "Reinstall"
                self._button(row, label, lambda tool=name: self._install_tools([tool]),
                             primary=bool(state["action"])).pack(side="right")
        tk.Label(self.content, text="Install, update and repair download the pinned release over HTTPS (or copy it from "
                                    "an offline kit), check its SHA-256, and only then replace the installed copy. "
                                    "Python packages (YARA, MVT) are installed by scripts\\setup.ps1. See docs/installation.md.",
                 wraplength=1000, justify="left",
                 bg=PALETTE["page"], fg=PALETTE["muted"], font=(FONT, 9)).pack(anchor="w", pady=(18, 0))

    def _install_tools(self, names, offline=False):
        from .installer import InstallCancelled, install_pack
        if self.busy or not names:
            return
        pack_dir = None
        if offline:
            pack_dir = filedialog.askdirectory(title="Choose the offline kit folder (made with setup.ps1 -SavePacks)")
            if not pack_dir:
                return
        elif not messagebox.askyesno("Install tools", "Download and install: " + ", ".join(names) + "?\n\n"
                                     "Each pack is downloaded from its upstream release over HTTPS and checked "
                                     "against the pinned SHA-256 before anything is replaced."):
            return
        self.busy = True
        cancel = threading.Event()
        window = tk.Toplevel(self.root, bg=PALETTE["page"])
        window.title("Installing tools")
        window.geometry("520x170")
        window.transient(self.root)
        text = tk.StringVar(value="Starting…")
        tk.Label(window, textvariable=text, bg=PALETTE["page"], fg=PALETTE["ink"], font=(FONT, 10),
                 wraplength=480, justify="left").pack(anchor="w", padx=18, pady=(18, 8))
        bar = ttk.Progressbar(window, style="DF.Horizontal.TProgressbar", maximum=100)
        bar.pack(fill="x", padx=18)
        self._button(window, "Cancel", cancel.set).pack(anchor="e", padx=18, pady=14)
        window.protocol("WM_DELETE_WINDOW", cancel.set)

        def show(message, percent=None):
            text.set(message)
            if percent is None:
                bar.configure(mode="indeterminate")
                bar.start(12)
            else:
                bar.stop()
                bar.configure(mode="determinate", value=percent)

        def work():
            done, errors = [], []
            for name in names:
                def progress(stage, current, total, name=name):
                    if stage == "download":
                        message = f"{name}: downloading {current // 1048576} MB" + (f" of {total // 1048576} MB" if total else "")
                        percent = current * 100 / total if total else None
                    elif stage == "unpack":
                        message, percent = f"{name}: unpacking", current * 100 / max(total, 1)
                    else:
                        message, percent = f"{name}: checking SHA-256", None
                    self.root.after(0, lambda m=message, p=percent: show(m, p))
                try:
                    if cancel.is_set():
                        raise InstallCancelled("Cancelled")
                    summary = install_pack(name, config_path=self.config_path, pack_dir=pack_dir,
                                           offline=offline, progress=progress, cancel=cancel)
                    done.append(f"{name} {summary['version']}")
                except Exception as exc:
                    errors.append(f"{name}: {exc}")
            self.root.after(0, lambda: finish(done, errors))

        def finish(done, errors):
            window.destroy()
            self.busy = False
            self.config = load_config(self.config_path)
            self.availability = doctor(self.config)
            self.show_tools()
            message = ("Installed: " + ", ".join(done) if done else "Nothing was installed.") + (
                "\n\nProblems:\n" + "\n".join(errors) if errors else "")
            (messagebox.showwarning if errors else messagebox.showinfo)("Install tools", message)

        threading.Thread(target=work, daemon=True).start()

    def _verify_packs(self):
        from .registry import verify_packs
        try:
            report = verify_packs()
        except (OSError, ValueError) as exc:
            messagebox.showerror("Verify tool packs", str(exc))
            return
        lines = [f"{name}  {item['version']}:  {item['status']}" for name, item in report.items()]
        bad = any(item["status"] == "MISMATCH" for item in report.values())
        advice = ("A pack does not match its pinned SHA-256. Delete it from .tools and run setup again." if bad else
                  "Downloaded packs match the versions this project was tested with.")
        (messagebox.showerror if bad else messagebox.showinfo)("Verify tool packs", "\n".join(lines) + "\n\n" + advice)

    def _show_notices(self):
        from .registry import notices
        window = tk.Toplevel(self.root, bg=PALETTE["page"])
        window.title("Third-party licence notices")
        window.geometry("720x520")
        text = tk.Text(window, bg=PALETTE["surface"], fg=PALETTE["ink"], relief="flat", bd=0, font=("Consolas", 9),
                       wrap="word", padx=12, pady=10)
        text.pack(fill="both", expand=True, padx=16, pady=16)
        text.insert("1.0", notices())
        text.configure(state="disabled")

    def _recheck_tools(self):
        self.availability = doctor(self.config)
        self.show_tools()

    # ----- New analysis -------------------------------------------------------

    def show_new_case(self, rerun=None):
        if self.busy:
            return
        self.active_view = "new"
        self.rerun = rerun
        self._clear()
        if rerun:
            self._heading("RE-RUN  /  INTERRUPTED CASE", "Re-run analysis",
                          "Uses the evidence, tools and limits recorded when this case first started.")
        else:
            self._heading("NEW INVESTIGATION  /  ACQUIRED EVIDENCE", "Start analysis",
                          "Select a forensic extraction, archive, Android backup, or supported disk image.")

        form = tk.Frame(self.content, bg=PALETTE["surface"], padx=22, pady=20)
        form.pack(fill="x", anchor="n")
        self.case_id = tk.StringVar(value=rerun["case_id"] if rerun else "CASE-" + datetime.now().strftime("%Y%m%d-%H%M"))
        self.evidence_path = tk.StringVar(value=rerun["evidence"] if rerun else "")
        self.path_label = tk.StringVar(value=rerun["evidence"] if rerun else "No evidence selected")
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
        tool_line = tk.Frame(form, bg=PALETTE["surface"])
        tool_line.pack(fill="x", pady=(6, 4))
        preselected = (rerun["tools"] if rerun else selected_tools(self.settings, self.availability))
        self.tool_vars = {}
        for name, info in self.availability.items():
            installed = bool(info.get("available"))
            self.tool_vars[name] = tk.BooleanVar(value=name in preselected)
            box = ttk.Checkbutton(tool_line, text=name if installed else f"{name} (not installed)",
                                  variable=self.tool_vars[name], style="DF.TCheckbutton")
            if not installed:
                box.state(["disabled"])
            box.pack(side="left", padx=(0, 14))
        notes = ["Tools that do not apply to the chosen evidence type are skipped and listed in the report."]
        if not self.settings.get("yara_rules"):
            notes.append("YARA needs a rules file: set one in Settings or YARA will be skipped.")
        tk.Label(form, text="  ".join(notes), bg=PALETTE["surface"], fg=PALETTE["muted"], font=(FONT, 9),
                 wraplength=760, justify="left").pack(anchor="w", pady=(2, 13))
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
        self.progress_panel = tk.Frame(self.content, bg=PALETTE["page"])
        self.progress_panel.pack(fill="x", anchor="w")

    def _build_progress_panel(self, tools):
        for child in self.progress_panel.winfo_children():
            child.destroy()
        self.progress_bar = ttk.Progressbar(self.progress_panel, style="DF.Horizontal.TProgressbar",
                                            maximum=1000, mode="determinate")
        self.progress_bar.pack(fill="x", pady=(8, 6))
        self.elapsed_text = tk.StringVar(value="0:00 elapsed")
        tk.Label(self.progress_panel, textvariable=self.elapsed_text, bg=PALETTE["page"], fg=PALETTE["muted"],
                 font=(FONT, 8, "bold")).pack(anchor="w")
        grid = tk.Frame(self.progress_panel, bg=PALETTE["page"])
        grid.pack(anchor="w", pady=(6, 0))
        self.progress_labels = {}
        for index, name in enumerate(self.progress_model.tools):
            tk.Label(grid, text=name.upper(), bg=PALETTE["page"], fg=PALETTE["ink"], width=12, anchor="w",
                     font=(FONT, 8, "bold")).grid(row=index // 4, column=(index % 4) * 2, sticky="w", pady=2)
            label = tk.Label(grid, text="WAITING", bg=PALETTE["page"], fg=PALETTE["muted"], width=18, anchor="w",
                             font=(FONT, 8, "bold"))
            label.grid(row=index // 4, column=(index % 4) * 2 + 1, sticky="w", pady=2)
            self.progress_labels[name] = label

    def _render_progress(self):
        model = self.progress_model
        self.progress_bar["value"] = int(model.fraction * 1000)
        colors = {"running": PALETTE["accent"], "success": PALETTE["success"], "partial": PALETTE["warning"],
                  "skipped": PALETTE["muted"], "waiting": PALETTE["muted"]}
        for name, state, findings in model.rows():
            text = state.upper() + (f"  {findings}" if state in ("success", "partial") else "")
            self.progress_labels[name].configure(text=text, fg=colors.get(state, PALETTE["danger"]))

    def _tick_elapsed(self):
        if not self.busy or not getattr(self, "progress_model", None):
            return
        seconds = self.progress_model.elapsed_seconds
        self.elapsed_text.set(f"{seconds // 60}:{seconds % 60:02d} elapsed")
        self.root.after(1000, self._tick_elapsed)

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
        selected = [name for name, var in self.tool_vars.items()
                    if var.get() and self.availability.get(name, {}).get("available")]
        if not selected:
            messagebox.showwarning("No tools selected", "Select at least one installed analysis tool.")
            return
        rerun = getattr(self, "rerun", None)
        if rerun and evidence == rerun["evidence"]:
            # Re-run: reuse the limits, rules and indicators recorded when the case first started.
            options = {key: rerun[key] for key in ("timeout", "max_rows", "max_findings", "max_extract_gb",
                                                   "image_offset", "kind", "mvt_mode", "yara_rules", "iocs")}
        else:
            settings = self.settings
            missing = [label for key, label in (("yara_rules", "YARA rules"), ("iocs", "indicators file"))
                       if settings.get(key) and not Path(settings[key]).is_file()]
            if missing:
                messagebox.showwarning("Settings need attention",
                                       "The saved " + " and ".join(missing) + " no longer exist. Update them in Settings.")
                return
            options = {"timeout": settings["timeout"], "max_rows": settings["max_rows"],
                       "image_offset": settings["image_offset"], "yara_rules": settings["yara_rules"] or None,
                       "iocs": settings["iocs"] or None}
        output = self.data_dir / uuid.uuid4().hex
        self.progress_model = ProgressModel(selected)
        self._build_progress_panel(selected)
        self.busy = True
        self.active_view = "running"
        self.run_button.configure(state="disabled")
        self.back_button.pack_forget()
        self.cancel_button.configure(state="normal", text="Cancel analysis")
        self.cancel_button.pack(side="left", padx=(8, 0))
        cancel = self.cancel_event = threading.Event()
        self.progress_text.set("Preparing a verified case copy…")

        model = self.progress_model

        def apply(message):
            model.update(message)
            self.progress_text.set(message)
            self._render_progress()

        def progress(message):
            self.root.after(0, lambda text=message: apply(text))

        def work():
            try:
                result = analyze(evidence, output, case_id, config=self.config, tools=selected,
                                 progress=progress, cancel=cancel, **options)
                self.root.after(0, lambda: self._analysis_complete(result, output))
            except Exception as exc:
                self.root.after(0, lambda error=exc: self._analysis_failed(error))

        threading.Thread(target=work, daemon=True).start()
        self._tick_elapsed()

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
        self.progress_bar["value"] = 1000
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
    parser.add_argument("--data-dir", type=Path, help="Override the case data folder from Settings")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--settings", type=Path, default=Path("data/settings.json"))
    args = parser.parse_args(argv)
    root = tk.Tk()
    DesktopApp(root, args.data_dir, args.config, args.settings)
    root.mainloop()


if __name__ == "__main__":
    main()
