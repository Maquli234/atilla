"""
gui/app.py — Full Tkinter GUI for ATILLA v3.0.

Mirrors all CLI functionality with:
  - Real-time scrollable output terminal
  - Config profiles (save/load)
  - Results dashboard with severity breakdown
  - One-click HTML report generation
  - Attack scenario builder

Launch:  python3 main.py --gui
"""

import asyncio
import json
import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

PROFILES_FILE = os.path.join(os.path.dirname(__file__), "..", "config_profiles.json")

# ── Color palette ──────────────────────────────────────────────────────────
THEME = {
    "bg":        "#0d1117",
    "bg2":       "#161b22",
    "bg3":       "#21262d",
    "border":    "#30363d",
    "accent":    "#00ff41",
    "accent2":   "#58a6ff",
    "warn":      "#f1c40f",
    "danger":    "#e74c3c",
    "text":      "#c9d1d9",
    "text_dim":  "#8b949e",
    "critical":  "#e74c3c",
    "high":      "#e67e22",
    "medium":    "#f1c40f",
    "low":       "#3498db",
}


class AtillaGUI:
    def __init__(self, root: tk.Tk):
        self.root       = root
        self.scan_thread = None
        self.vulns: List[dict] = []
        self.last_report_html = None

        self._setup_window()
        self._build_ui()
        self._load_profiles()

    # ── Window setup ───────────────────────────────────────────────────────
    def _setup_window(self):
        self.root.title("ATILLA v3.0 — XSS Testing Framework")
        self.root.geometry("1200x800")
        self.root.minsize(900, 650)
        self.root.configure(bg=THEME["bg"])
        try:
            self.root.iconbitmap("")
        except Exception:
            pass

        # Custom style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame",       background=THEME["bg"])
        style.configure("TLabel",       background=THEME["bg"],  foreground=THEME["text"],
                         font=("Consolas", 10))
        style.configure("TButton",      background=THEME["bg3"], foreground=THEME["accent"],
                         font=("Consolas", 10, "bold"), borderwidth=1,
                         relief="flat", padding=(8, 4))
        style.map("TButton",
                  background=[("active", THEME["bg2"]), ("pressed", THEME["border"])],
                  foreground=[("active", THEME["accent"])])
        style.configure("Accent.TButton", background=THEME["accent"],
                         foreground=THEME["bg"], font=("Consolas", 11, "bold"))
        style.map("Accent.TButton", background=[("active", "#00cc35")])
        style.configure("TEntry",       background=THEME["bg2"], foreground=THEME["text"],
                         fieldbackground=THEME["bg2"], insertcolor=THEME["accent"],
                         borderwidth=1, relief="flat", font=("Consolas", 10))
        style.configure("TCombobox",    background=THEME["bg2"], foreground=THEME["text"],
                         fieldbackground=THEME["bg2"], font=("Consolas", 10))
        style.configure("TCheckbutton", background=THEME["bg"],  foreground=THEME["text"],
                         font=("Consolas", 10))
        style.configure("TNotebook",    background=THEME["bg"],  borderwidth=0)
        style.configure("TNotebook.Tab", background=THEME["bg3"], foreground=THEME["text_dim"],
                         padding=(12, 5), font=("Consolas", 10))
        style.map("TNotebook.Tab",
                  background=[("selected", THEME["bg2"])],
                  foreground=[("selected", THEME["accent"])])
        style.configure("TLabelframe",  background=THEME["bg"],  foreground=THEME["accent"],
                         bordercolor=THEME["border"])
        style.configure("TLabelframe.Label", background=THEME["bg"], foreground=THEME["accent"],
                         font=("Consolas", 10, "bold"))
        style.configure("TProgressbar", troughcolor=THEME["bg3"],
                         background=THEME["accent"], thickness=6)

    # ── UI construction ────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Header ────────────────────────────────────────────────────────
        hdr = tk.Frame(self.root, bg=THEME["bg"], pady=8)
        hdr.pack(fill="x", padx=16)
        tk.Label(hdr, text="⚔  ATILLA v3.0",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Consolas", 18, "bold")).pack(side="left")
        tk.Label(hdr, text="  XSS Testing Framework — Authorized Use Only",
                 bg=THEME["bg"], fg=THEME["text_dim"],
                 font=("Consolas", 10)).pack(side="left", pady=5)

        # Status bar (bottom)
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(self.root, textvariable=self.status_var,
                              bg=THEME["bg3"], fg=THEME["text_dim"],
                              font=("Consolas", 9), anchor="w", padx=8, pady=3)
        status_bar.pack(side="bottom", fill="x")

        # Progress bar
        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(side="bottom", fill="x", padx=0, pady=0)

        # Separator
        tk.Frame(self.root, bg=THEME["border"], height=1).pack(fill="x")

        # Main paned window
        paned = ttk.PanedWindow(self.root, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=0, pady=0)

        # Left panel — config
        left = tk.Frame(paned, bg=THEME["bg2"], width=370)
        paned.add(left, weight=0)

        # Right panel — tabs
        right = tk.Frame(paned, bg=THEME["bg"])
        paned.add(right, weight=1)

        self._build_config_panel(left)
        self._build_right_panel(right)

    # ── Left: Config Panel ─────────────────────────────────────────────────
    def _build_config_panel(self, parent):
        canvas = tk.Canvas(parent, bg=THEME["bg2"], highlightthickness=0)
        scroll = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=THEME["bg2"])
        inner_id = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(inner_id, width=e.width))

        pad = {"padx": 12, "pady": 4}

        # ── Target section ─────────────────────────────────────────────────
        self._section(inner, "TARGET")

        self._label(inner, "URL *")
        self.url_var = tk.StringVar()
        self._entry(inner, self.url_var, "http://localhost/search?q=test", **pad)

        self._label(inner, "Auth Cookie")
        self.cookie_var = tk.StringVar()
        self._entry(inner, self.cookie_var, "session=abc123 (optional)", **pad)

        # ── Scan Options ───────────────────────────────────────────────────
        self._section(inner, "SCAN OPTIONS")

        self._label(inner, "Payload Set")
        self.set_var = tk.StringVar(value="owasp")
        cb = ttk.Combobox(inner, textvariable=self.set_var,
                          values=["basic","owasp","advanced","dom","blind","all"],
                          state="readonly", font=("Consolas", 10))
        cb.pack(fill="x", **pad)

        # Numeric options grid
        nums = tk.Frame(inner, bg=THEME["bg2"])
        nums.pack(fill="x", **pad)

        self.timeout_var     = tk.StringVar(value="15")
        self.concurrency_var = tk.StringVar(value="5")
        self.delay_var       = tk.StringVar(value="0.2")
        self.depth_var       = tk.StringVar(value="3")

        for col, (label, var) in enumerate([
            ("Timeout(s)",   self.timeout_var),
            ("Concurrency",  self.concurrency_var),
            ("Delay(s)",     self.delay_var),
            ("Crawl Depth",  self.depth_var),
        ]):
            f = tk.Frame(nums, bg=THEME["bg2"])
            f.grid(row=0, column=col, padx=4)
            tk.Label(f, text=label, bg=THEME["bg2"], fg=THEME["text_dim"],
                     font=("Consolas", 8)).pack()
            ttk.Entry(f, textvariable=var, width=7,
                      font=("Consolas", 10)).pack()

        # ── Toggles ────────────────────────────────────────────────────────
        self._section(inner, "FEATURES")

        toggles = [
            ("crawl_var",    "Crawl domain for URLs"),
            ("playwright_var","Playwright headless browser"),
            ("mutations_var", "WAF bypass mutations"),
            ("context_var",  "Smart context detection"),
            ("blind_var",    "Blind XSS payloads"),
            ("cvss_var",     "CVSS v3.1 scoring"),
            ("verbose_var",  "Verbose output"),
        ]
        defaults = [False, False, True, True, False, False, False]
        for (attr, label), default in zip(toggles, defaults):
            var = tk.BooleanVar(value=default)
            setattr(self, attr, var)
            ttk.Checkbutton(inner, text=label, variable=var).pack(anchor="w", **pad)

        self._label(inner, "OOB Host (blind XSS)")
        self.oob_var = tk.StringVar()
        self._entry(inner, self.oob_var, "yourburp.oastify.com", **pad)

        # ── Output ─────────────────────────────────────────────────────────
        self._section(inner, "OUTPUT")

        self._label(inner, "JSON Report")
        json_frame = tk.Frame(inner, bg=THEME["bg2"])
        json_frame.pack(fill="x", **pad)
        self.json_var = tk.StringVar()
        ttk.Entry(json_frame, textvariable=self.json_var,
                  font=("Consolas", 9)).pack(side="left", fill="x", expand=True)
        ttk.Button(json_frame, text="…",
                   command=lambda: self._browse_save(self.json_var, ".json")).pack(side="right")

        self._label(inner, "HTML Report")
        html_frame = tk.Frame(inner, bg=THEME["bg2"])
        html_frame.pack(fill="x", **pad)
        self.html_var = tk.StringVar()
        ttk.Entry(html_frame, textvariable=self.html_var,
                  font=("Consolas", 9)).pack(side="left", fill="x", expand=True)
        ttk.Button(html_frame, text="…",
                   command=lambda: self._browse_save(self.html_var, ".html")).pack(side="right")

        # ── Profiles ───────────────────────────────────────────────────────
        self._section(inner, "PROFILES")
        prof_frame = tk.Frame(inner, bg=THEME["bg2"])
        prof_frame.pack(fill="x", **pad)

        self.profile_var = tk.StringVar()
        self.profile_cb  = ttk.Combobox(prof_frame, textvariable=self.profile_var,
                                         font=("Consolas", 9), width=14)
        self.profile_cb.pack(side="left", fill="x", expand=True)

        ttk.Button(prof_frame, text="Load",
                   command=self._load_profile).pack(side="left", padx=2)
        ttk.Button(prof_frame, text="Save",
                   command=self._save_profile).pack(side="left", padx=2)

        # ── Scan button ────────────────────────────────────────────────────
        tk.Frame(inner, bg=THEME["border"], height=1).pack(fill="x", pady=10)
        self.scan_btn = ttk.Button(inner, text="▶  START SCAN",
                                   style="Accent.TButton",
                                   command=self._start_scan)
        self.scan_btn.pack(fill="x", padx=12, pady=6, ipady=6)

        self.stop_btn = ttk.Button(inner, text="■  STOP",
                                   command=self._stop_scan, state="disabled")
        self.stop_btn.pack(fill="x", padx=12, pady=2)

    # ── Right: Output tabs ─────────────────────────────────────────────────
    def _build_right_panel(self, parent):
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill="both", expand=True)

        # Tab 1 — Terminal
        term_frame = ttk.Frame(self.notebook)
        self.notebook.add(term_frame, text=" ⌨  Terminal ")
        self._build_terminal(term_frame)

        # Tab 2 — Results Dashboard
        dash_frame = ttk.Frame(self.notebook)
        self.notebook.add(dash_frame, text=" 📊  Results ")
        self._build_dashboard(dash_frame)

        # Tab 3 — Payload Builder
        payload_frame = ttk.Frame(self.notebook)
        self.notebook.add(payload_frame, text=" ⚙  Payload Builder ")
        self._build_payload_builder(payload_frame)

    # ── Terminal tab ───────────────────────────────────────────────────────
    def _build_terminal(self, parent):
        toolbar = tk.Frame(parent, bg=THEME["bg3"], pady=4)
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Clear", command=self._clear_terminal).pack(side="right", padx=6)
        ttk.Button(toolbar, text="Save Log",
                   command=self._save_log).pack(side="right", padx=2)

        self.terminal = scrolledtext.ScrolledText(
            parent,
            bg=THEME["bg"], fg=THEME["text"],
            font=("Consolas", 10),
            insertbackground=THEME["accent"],
            selectbackground=THEME["bg3"],
            wrap=tk.WORD,
            relief="flat",
            borderwidth=0,
            state="disabled",
        )
        self.terminal.pack(fill="both", expand=True)

        # Color tags
        self.terminal.tag_config("critical", foreground=THEME["critical"])
        self.terminal.tag_config("high",     foreground=THEME["high"])
        self.terminal.tag_config("medium",   foreground=THEME["medium"])
        self.terminal.tag_config("low",      foreground=THEME["low"])
        self.terminal.tag_config("info",     foreground=THEME["accent2"])
        self.terminal.tag_config("success",  foreground=THEME["accent"])
        self.terminal.tag_config("warn",     foreground=THEME["warn"])
        self.terminal.tag_config("dim",      foreground=THEME["text_dim"])

    # ── Dashboard tab ──────────────────────────────────────────────────────
    def _build_dashboard(self, parent):
        # Summary cards
        cards_frame = tk.Frame(parent, bg=THEME["bg"])
        cards_frame.pack(fill="x", padx=16, pady=12)

        self.sev_cards = {}
        for sev, color in [("CRITICAL", THEME["critical"]), ("HIGH", THEME["high"]),
                            ("MEDIUM", THEME["medium"]),   ("LOW", THEME["low"]),
                            ("TOTAL", THEME["accent"])]:
            card = tk.Frame(cards_frame, bg=THEME["bg2"],
                            relief="flat", bd=0, padx=16, pady=12)
            card.pack(side="left", padx=6, expand=True, fill="x")
            tk.Frame(card, bg=color, height=3).pack(fill="x", pady=(0,8))
            num = tk.Label(card, text="0", bg=THEME["bg2"], fg=color,
                           font=("Consolas", 26, "bold"))
            num.pack()
            tk.Label(card, text=sev, bg=THEME["bg2"], fg=THEME["text_dim"],
                     font=("Consolas", 9)).pack()
            self.sev_cards[sev] = num

        # Action buttons
        act = tk.Frame(parent, bg=THEME["bg"])
        act.pack(fill="x", padx=16, pady=4)
        ttk.Button(act, text="Open HTML Report",
                   command=self._open_html_report).pack(side="left", padx=4)
        ttk.Button(act, text="Export JSON",
                   command=self._export_json).pack(side="left", padx=4)
        ttk.Button(act, text="Clear Results",
                   command=self._clear_results).pack(side="right", padx=4)

        # Findings tree
        tree_frame = tk.Frame(parent, bg=THEME["bg"])
        tree_frame.pack(fill="both", expand=True, padx=16, pady=8)

        cols = ("Severity", "Param", "Payload", "Confidence", "Context", "URL")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings",
                                  selectmode="browse")
        widths    = [80, 80, 220, 80, 100, 300]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, minwidth=50)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.tree.pack(fill="both", expand=True)

        # Row colors by severity
        self.tree.tag_configure("CRITICAL", foreground=THEME["critical"])
        self.tree.tag_configure("HIGH",     foreground=THEME["high"])
        self.tree.tag_configure("MEDIUM",   foreground=THEME["medium"])
        self.tree.tag_configure("LOW",      foreground=THEME["low"])

        self.tree.bind("<Double-1>", self._show_finding_detail)

        # Detail pane at bottom
        detail_label = tk.Label(parent, text="Double-click a finding for details",
                                bg=THEME["bg2"], fg=THEME["text_dim"],
                                font=("Consolas", 9), anchor="w", padx=8, pady=4)
        detail_label.pack(fill="x", padx=16)
        self.detail_text = scrolledtext.ScrolledText(
            parent, height=6, bg=THEME["bg2"], fg=THEME["text"],
            font=("Consolas", 9), state="disabled", relief="flat"
        )
        self.detail_text.pack(fill="x", padx=16, pady=(0,8))

    # ── Payload Builder tab ────────────────────────────────────────────────
    def _build_payload_builder(self, parent):
        tk.Label(parent, text="Attack Scenario Builder",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Consolas", 12, "bold")).pack(anchor="w", padx=16, pady=8)

        top = tk.Frame(parent, bg=THEME["bg"])
        top.pack(fill="x", padx=16)

        # Base payload input
        tk.Label(top, text="Base Payload:", bg=THEME["bg"],
                 fg=THEME["text"], font=("Consolas", 10)).pack(anchor="w")
        self.builder_input = tk.Text(top, height=3, bg=THEME["bg2"],
                                      fg=THEME["text"], font=("Consolas", 10),
                                      insertbackground=THEME["accent"],
                                      relief="flat")
        self.builder_input.pack(fill="x", pady=4)
        self.builder_input.insert("1.0", "<script>alert(1)</script>")

        # Mutation checkboxes
        tk.Label(top, text="Apply Mutations:", bg=THEME["bg"],
                 fg=THEME["text"], font=("Consolas", 10)).pack(anchor="w", pady=(8,2))
        mut_frame = tk.Frame(top, bg=THEME["bg"])
        mut_frame.pack(fill="x")

        self.mut_vars = {}
        mutations = ["Case Mixing", "HTML Entities", "Null Bytes",
                     "Comment Injection", "Eval Obfuscation", "Double URL Encode",
                     "Whitespace Variants", "Full-width Unicode"]
        for i, m in enumerate(mutations):
            var = tk.BooleanVar(value=True)
            self.mut_vars[m] = var
            ttk.Checkbutton(mut_frame, text=m, variable=var).grid(
                row=i//4, column=i%4, sticky="w", padx=6, pady=2
            )

        ttk.Button(top, text="Generate Variants",
                   command=self._generate_variants).pack(pady=8)

        # Output
        tk.Label(parent, text="Generated Variants:", bg=THEME["bg"],
                 fg=THEME["text_dim"], font=("Consolas", 10)).pack(anchor="w", padx=16)
        self.builder_output = scrolledtext.ScrolledText(
            parent, bg=THEME["bg2"], fg=THEME["accent"],
            font=("Consolas", 9), relief="flat"
        )
        self.builder_output.pack(fill="both", expand=True, padx=16, pady=(4,16))

    # ── Helpers ────────────────────────────────────────────────────────────
    def _section(self, parent, title):
        f = tk.Frame(parent, bg=THEME["bg2"])
        f.pack(fill="x", pady=(12, 0))
        tk.Label(f, text=f"── {title} ──", bg=THEME["bg2"],
                 fg=THEME["accent"], font=("Consolas", 9, "bold")).pack(anchor="w", padx=12)

    def _label(self, parent, text):
        tk.Label(parent, text=text, bg=THEME["bg2"],
                 fg=THEME["text_dim"], font=("Consolas", 9)).pack(anchor="w", padx=12, pady=(4,0))

    def _entry(self, parent, var, placeholder="", **kwargs):
        entry = ttk.Entry(parent, textvariable=var, font=("Consolas", 10))
        entry.pack(fill="x", **kwargs)
        if placeholder and not var.get():
            entry.insert(0, placeholder)
            entry.configure(foreground=THEME["text_dim"])
            def on_focus_in(e):
                if entry.get() == placeholder:
                    entry.delete(0, "end")
                    entry.configure(foreground=THEME["text"])
            def on_focus_out(e):
                if not entry.get():
                    entry.insert(0, placeholder)
                    entry.configure(foreground=THEME["text_dim"])
            entry.bind("<FocusIn>", on_focus_in)
            entry.bind("<FocusOut>", on_focus_out)
        return entry

    def _browse_save(self, var: tk.StringVar, ext: str):
        fname = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[(ext.upper()[1:] + " files", f"*{ext}"), ("All", "*.*")]
        )
        if fname:
            var.set(fname)

    # ── Terminal output ────────────────────────────────────────────────────
    def log(self, text: str, tag: str = ""):
        def _do():
            self.terminal.config(state="normal")
            self.terminal.insert("end", text + "\n", tag)
            self.terminal.see("end")
            self.terminal.config(state="disabled")
        self.root.after(0, _do)

    def _clear_terminal(self):
        self.terminal.config(state="normal")
        self.terminal.delete("1.0", "end")
        self.terminal.config(state="disabled")

    def _save_log(self):
        fname = filedialog.asksaveasfilename(defaultextension=".txt")
        if fname:
            content = self.terminal.get("1.0", "end")
            with open(fname, "w") as f:
                f.write(content)

    # ── Scan control ───────────────────────────────────────────────────────
    def _start_scan(self):
        url = self.url_var.get().strip()
        placeholders = ("http://localhost/search?q=test", "")
        if not url or url in placeholders:
            messagebox.showerror("ATILLA", "Please enter a target URL")
            return
        if not url.startswith(("http://", "https://")):
            messagebox.showerror("ATILLA", "URL must start with http:// or https://")
            return

        self._clear_results()
        self.notebook.select(0)   # switch to terminal tab
        self.log("=" * 65, "info")
        self.log(f"  ATILLA v3.0 — Scan started", "success")
        self.log(f"  Target: {url}", "info")
        self.log("=" * 65, "info")

        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.progress.start(10)
        self._set_status("Scanning …")
        self._stop_flag = False

        self.scan_thread = threading.Thread(target=self._run_scan_thread, daemon=True)
        self.scan_thread.start()

    def _stop_scan(self):
        self._stop_flag = True
        self.log("\n[!] Scan stopped by user", "warn")
        self._scan_done()

    def _scan_done(self):
        def _do():
            self.scan_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            self.progress.stop()
            self._set_status(f"Done — {len(self.vulns)} finding(s)")
        self.root.after(0, _do)

    def _set_status(self, msg: str):
        self.root.after(0, lambda: self.status_var.set(msg))

    def _run_scan_thread(self):
        """Run the async scan in a background thread with its own event loop."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._async_scan())
        except Exception as e:
            self.log(f"\n[!] Scan error: {e}", "warn")
        finally:
            self._scan_done()

    async def _async_scan(self):
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from core.config  import ScanConfig
        from core.engine  import ScanEngine
        from reporting.report import ReportManager

        def _safe(var, default=""):
            v = var.get().strip()
            return v if v not in ("", default) else ""

        cfg = ScanConfig(
            url            = self.url_var.get().strip(),
            auth_cookie    = _safe(self.cookie_var) or None,
            payload_set    = self.set_var.get(),
            timeout        = int(self.timeout_var.get() or 15),
            concurrency    = int(self.concurrency_var.get() or 5),
            delay          = float(self.delay_var.get() or 0.2),
            crawl          = self.crawl_var.get(),
            crawl_depth    = int(self.depth_var.get() or 3),
            use_playwright = self.playwright_var.get(),
            smart_context  = self.context_var.get(),
            use_mutations  = self.mutations_var.get(),
            blind_xss      = self.blind_var.get(),
            oob_host       = _safe(self.oob_var) or None,
            verbose        = self.verbose_var.get(),
            output_json    = _safe(self.json_var) or None,
            output_html    = _safe(self.html_var) or None,
            include_cvss   = self.cvss_var.get(),
        )

        # Redirect stdout to GUI terminal
        import io
        original_stdout = sys.stdout

        class GUIWriter(io.TextIOBase):
            def __init__(self_, gui):
                self_.gui = gui
            def write(self_, text):
                if text.strip():
                    tag = self_._classify(text)
                    self_.gui.log(text.rstrip(), tag)
                return len(text)
            def _classify(self_, text):
                tl = text.lower()
                if "[!]" in text or "critical" in tl: return "critical"
                if "high" in tl: return "high"
                if "medium" in tl: return "medium"
                if "low" in tl: return "low"
                if "[+]" in text or "complete" in tl: return "success"
                if "[*]" in text or "====" in text: return "info"
                if "error" in tl or "fail" in tl: return "warn"
                return ""

        sys.stdout = GUIWriter(self)
        try:
            engine = ScanEngine(cfg)
            vulns  = await engine.run()
            self.vulns = [v.to_dict() for v in vulns]
            reporter = ReportManager(cfg, vulns)
            reporter.print_summary()
            if cfg.output_json:
                reporter.save_json(cfg.output_json)
            if cfg.output_html:
                reporter.save_html(cfg.output_html)
                self.last_report_html = cfg.output_html
        finally:
            sys.stdout = original_stdout

        self.root.after(0, self._populate_dashboard)

    # ── Dashboard population ───────────────────────────────────────────────
    def _populate_dashboard(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in self.vulns:
            sev = v.get("severity", "LOW")
            counts[sev] = counts.get(sev, 0) + 1
            self.tree.insert("", "end",
                             values=(sev, v.get("param",""), v.get("payload","")[:60],
                                     f"{v.get('confidence',0)}%",
                                     v.get("context",""), v.get("url","")[:80]),
                             tags=(sev,))
        for sev, num in counts.items():
            self.sev_cards[sev].config(text=str(num))
        self.sev_cards["TOTAL"].config(text=str(len(self.vulns)))
        if self.vulns:
            self.notebook.select(1)  # switch to results tab

    def _show_finding_detail(self, event):
        sel = self.tree.selection()
        if not sel: return
        idx = self.tree.index(sel[0])
        if idx >= len(self.vulns): return
        v   = self.vulns[idx]
        txt = (f"Parameter : {v.get('param')}\n"
               f"Severity  : {v.get('severity')}\n"
               f"Confidence: {v.get('confidence')}%\n"
               f"Context   : {v.get('context')}\n"
               f"Category  : {v.get('category')}\n"
               f"URL       : {v.get('url')}\n"
               f"Payload   : {v.get('payload')}\n"
               f"Evidence  : {v.get('evidence','')[:200]}\n"
               f"DOM Sinks : {', '.join(v.get('dom_sinks',[]))}\n"
               f"Timestamp : {v.get('timestamp')}")
        if v.get("cvss"):
            txt += f"\nCVSS      : {v['cvss']['base_score']} {v['cvss']['rating']} ({v['cvss']['vector']})"
        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", txt)
        self.detail_text.config(state="disabled")

    def _clear_results(self):
        self.vulns = []
        for item in self.tree.get_children():
            self.tree.delete(item)
        for card in self.sev_cards.values():
            card.config(text="0")
        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.config(state="disabled")

    def _open_html_report(self):
        if self.last_report_html and os.path.exists(self.last_report_html):
            import webbrowser
            webbrowser.open(f"file://{os.path.abspath(self.last_report_html)}")
        elif self.html_var.get() and os.path.exists(self.html_var.get()):
            import webbrowser
            webbrowser.open(f"file://{os.path.abspath(self.html_var.get())}")
        else:
            messagebox.showinfo("ATILLA", "No HTML report found. Run a scan with --html-report.")

    def _export_json(self):
        if not self.vulns:
            messagebox.showinfo("ATILLA", "No results to export.")
            return
        fname = filedialog.asksaveasfilename(defaultextension=".json")
        if fname:
            with open(fname, "w") as f:
                json.dump(self.vulns, f, indent=2, default=str)
            messagebox.showinfo("ATILLA", f"Exported to {fname}")

    # ── Payload Builder ────────────────────────────────────────────────────
    def _generate_variants(self):
        from payloads.mutator import mutate_payload
        base    = self.builder_input.get("1.0", "end").strip()
        results = mutate_payload(base)
        self.builder_output.delete("1.0", "end")
        self.builder_output.insert("end", f"// Base: {base}\n")
        self.builder_output.insert("end", f"// Generated {len(results)} variants:\n\n")
        for i, v in enumerate(results, 1):
            self.builder_output.insert("end", f"[{i:03d}] {v}\n")

    # ── Profile management ─────────────────────────────────────────────────
    def _load_profiles(self):
        self._profiles = {}
        if os.path.exists(PROFILES_FILE):
            try:
                with open(PROFILES_FILE) as f:
                    self._profiles = json.load(f)
                self.profile_cb["values"] = list(self._profiles.keys())
            except Exception:
                pass

    def _save_profile(self):
        name = self.profile_var.get().strip()
        if not name:
            messagebox.showerror("ATILLA", "Enter a profile name first")
            return
        self._profiles[name] = {
            "payload_set":   self.set_var.get(),
            "timeout":       self.timeout_var.get(),
            "concurrency":   self.concurrency_var.get(),
            "delay":         self.delay_var.get(),
            "crawl_depth":   self.depth_var.get(),
            "crawl":         self.crawl_var.get(),
            "mutations":     self.mutations_var.get(),
            "context":       self.context_var.get(),
            "cvss":          self.cvss_var.get(),
            "verbose":       self.verbose_var.get(),
        }
        try:
            with open(PROFILES_FILE, "w") as f:
                json.dump(self._profiles, f, indent=2)
            self.profile_cb["values"] = list(self._profiles.keys())
            messagebox.showinfo("ATILLA", f"Profile '{name}' saved")
        except Exception as e:
            messagebox.showerror("ATILLA", f"Could not save: {e}")

    def _load_profile(self):
        name = self.profile_var.get()
        if name not in self._profiles:
            return
        p = self._profiles[name]
        self.set_var.set(p.get("payload_set", "owasp"))
        self.timeout_var.set(p.get("timeout", "15"))
        self.concurrency_var.set(p.get("concurrency", "5"))
        self.delay_var.set(p.get("delay", "0.2"))
        self.depth_var.set(p.get("crawl_depth", "3"))
        self.crawl_var.set(p.get("crawl", False))
        self.mutations_var.set(p.get("mutations", True))
        self.context_var.set(p.get("context", True))
        self.cvss_var.set(p.get("cvss", False))
        self.verbose_var.set(p.get("verbose", False))


# ── Entry point ────────────────────────────────────────────────────────────
def launch_gui():
    root = tk.Tk()
    app  = AtillaGUI(root)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
