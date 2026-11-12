"""Native Windows desktop shell for the local Android DFIR workspace.

This is the first desktop-conversion milestone: a native case workspace that
reuses the existing analysis pipeline, plus local tool-readiness information.
"""
import argparse
import json
import threading
import uuid
import webbrowser
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .config import doctor, load_config
from .pipeline import analyze


PALETTE = {
    "page": "#171a1c", "rail": "#202527", "surface": "#252b2d",
    "surface_alt": "#2c3335", "line": "#3a4244", "ink": "#eff1e9",
    "muted": "#9da6a3", "accent": "#d8f05b", "success": "#91d7a5",
    "warning": "#efc96a", "danger": "#fa8c7d",
}
FONT = "Segoe UI"


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

    def _case_records(self):
        records = []
        if not self.data_dir.exists():
            return records
        for folder in self.data_dir.iterdir():
            result_path = folder / "results.json"
            if not folder.is_dir() or not result_path.is_file():
                continue
            try:
                result = json.loads(result_path.read_text(encoding="utf-8"))
                records.append((result.get("started_utc", ""), result.get("case_id", folder.name),
                                result.get("status", "unknown"), result.get("metrics", {}).get("findings", 0),
                                str(folder / "report.html")))
            except (OSError, ValueError):
                continue
        return sorted(records, reverse=True)

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

        tk.Label(main, text="RECENT INVESTIGATIONS", bg=PALETTE["page"], fg=PALETTE["muted"],
                 font=(FONT, 8, "bold")).pack(anchor="w", pady=(0, 8))
        records = self._case_records()
        if not records:
            tk.Label(main, text="No cases yet. Choose evidence to start the first analysis.",
                     bg=PALETTE["surface"], fg=PALETTE["muted"], font=(FONT, 9),
                     padx=16, pady=18, anchor="w").pack(fill="x")
        else:
            table = ttk.Treeview(main, columns=("case", "status", "findings"), show="headings",
                                 style="DF.Treeview", selectmode="browse")
            table.heading("case", text="CASE")
            table.heading("status", text="STATUS")
            table.heading("findings", text="FINDINGS")
            table.column("case", width=280, anchor="w")
            table.column("status", width=170, anchor="w")
            table.column("findings", width=90, anchor="e")
            for record in records:
                table.insert("", "end", values=record[1:4], tags=(record[4],))
            table.pack(fill="both", expand=True)
            table.bind("<Double-1>", lambda _event: self._open_selected_report(table))
            self._button(main, "Open selected report", lambda: self._open_selected_report(table)).pack(anchor="w", pady=(10, 0))

        tk.Label(side, text="TOOL READINESS", bg=PALETTE["rail"], fg=PALETTE["accent"],
                 font=(FONT, 8, "bold")).pack(anchor="w", pady=(0, 12))
        for name, info in self.availability.items():
            self._tool_row(side, name, info)
        tk.Frame(side, bg=PALETTE["line"], height=1).pack(fill="x", pady=14)
        available = sum(bool(row.get("available")) for row in self.availability.values())
        tk.Label(side, text=f"{available} OF {len(self.availability)} READY", bg=PALETTE["rail"],
                 fg=PALETTE["muted"], font=(FONT, 8, "bold")).pack(anchor="w")
        self._button(side, "Review tool setup", self.show_tools).pack(anchor="w", pady=(12, 0))

    def _tool_row(self, parent, name, info):
        row = tk.Frame(parent, bg=PALETTE["rail"])
        row.pack(fill="x", pady=4)
        color = PALETTE["success"] if info.get("available") else PALETTE["muted"]
        status = "READY" if info.get("available") else "NOT INSTALLED"
        label = name.upper()
        tk.Label(row, text=label, bg=PALETTE["rail"], fg=PALETTE["ink"],
                 font=(FONT, 8, "bold")).pack(side="left", anchor="w")
        tk.Label(row, text=status, bg=PALETTE["rail"], fg=color,
                 font=(FONT, 7, "bold")).pack(side="right", anchor="e")

    def _open_selected_report(self, table):
        selection = table.selection()
        if not selection:
            return
        report = table.item(selection[0], "tags")
        if report and Path(report[0]).is_file():
            webbrowser.open(Path(report[0]).resolve().as_uri())

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
        tk.Entry(form, textvariable=self.case_id, bg=PALETTE["surface_alt"], fg=PALETTE["ink"],
                 insertbackground=PALETTE["ink"], relief="flat", bd=0,
                 font=(FONT, 10)).pack(fill="x", ipady=9, pady=(6, 18))
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
        self._button(actions, "Back to investigations", self.show_cases).pack(side="left", padx=(8, 0))
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
        self.progress_text.set("Preparing a verified case copy…")

        def progress(message):
            self.root.after(0, lambda text=message: self.progress_text.set(text))

        def work():
            try:
                result = analyze(evidence, output, case_id, config=self.config, tools=selected, progress=progress)
                self.root.after(0, lambda: self._analysis_complete(result, output))
            except Exception as exc:
                self.root.after(0, lambda error=exc: self._analysis_failed(error))

        threading.Thread(target=work, daemon=True).start()

    def _analysis_complete(self, result, output):
        self.busy = False
        self.active_view = "result"
        message = f"{result['status']}  /  {result['metrics']['findings']} findings  /  {result['metrics']['timeline_events']} timeline events"
        self.progress_text.set(message)
        self._button(self.content, "Open case report", lambda: webbrowser.open((output / "report.html").resolve().as_uri()), primary=True).pack(anchor="w", pady=(10, 0))
        self._button(self.content, "Return to investigations", self.show_cases).pack(anchor="w", pady=(8, 0))

    def _analysis_failed(self, error):
        self.busy = False
        self.active_view = "new"
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
