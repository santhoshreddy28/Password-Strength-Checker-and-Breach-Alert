"""
gui.py - Tkinter GUI for Password Strength Checker & Breach Alert
Run: python gui.py
"""

import threading
import tkinter as tk
from tkinter import ttk, messagebox
from checker import check_strength, check_breach, generate_password, generate_passphrase


# ─────────────────────────────────────────────
# THEME
# ─────────────────────────────────────────────
BG        = "#1a1a2e"
BG2       = "#16213e"
BG3       = "#0f3460"
ACCENT    = "#e94560"
TEXT      = "#eaeaea"
TEXT_DIM  = "#888888"
GREEN     = "#2ecc71"
ORANGE    = "#e67e22"
YELLOW    = "#f1c40f"
RED       = "#e74c3c"
WHITE     = "#ffffff"

FONT_TITLE  = ("Segoe UI", 18, "bold")
FONT_LABEL  = ("Segoe UI", 10)
FONT_BOLD   = ("Segoe UI", 10, "bold")
FONT_MONO   = ("Courier New", 11)
FONT_SMALL  = ("Segoe UI", 9)


# ─────────────────────────────────────────────
# MAIN APP
# ─────────────────────────────────────────────
class PasswordCheckerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔐 Password Strength Checker & Breach Alert")
        self.geometry("700x780")
        self.resizable(False, False)
        self.configure(bg=BG)

        self._build_ui()

    # ── UI CONSTRUCTION ───────────────────────
    def _build_ui(self):
        # ── Header
        hdr = tk.Frame(self, bg=BG3, pady=14)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🔐 Password Strength Checker",
                 font=FONT_TITLE, bg=BG3, fg=WHITE).pack()
        tk.Label(hdr, text="& Breach Alert  •  Powered by HaveIBeenPwned",
                 font=FONT_SMALL, bg=BG3, fg=TEXT_DIM).pack()

        # ── Password Entry
        entry_frame = tk.Frame(self, bg=BG, pady=18, padx=24)
        entry_frame.pack(fill="x")

        tk.Label(entry_frame, text="Enter Password", font=FONT_BOLD,
                 bg=BG, fg=TEXT).pack(anchor="w")

        pw_row = tk.Frame(entry_frame, bg=BG)
        pw_row.pack(fill="x", pady=(6, 0))

        self.pw_var   = tk.StringVar()
        self.show_var = tk.BooleanVar(value=False)

        self.pw_entry = tk.Entry(
            pw_row, textvariable=self.pw_var,
            font=FONT_MONO, bg=BG2, fg=TEXT,
            insertbackground=TEXT, relief="flat",
            show="•", bd=0, highlightthickness=2,
            highlightcolor=ACCENT, highlightbackground=BG3,
        )
        self.pw_entry.pack(side="left", fill="x", expand=True, ipady=8, ipadx=10)
        self.pw_entry.bind("<KeyRelease>", self._on_key)

        toggle_btn = tk.Button(
            pw_row, text="👁", font=FONT_SMALL,
            bg=BG3, fg=TEXT, relief="flat",
            activebackground=BG3, activeforeground=ACCENT,
            cursor="hand2", command=self._toggle_show,
            padx=10
        )
        toggle_btn.pack(side="left", padx=(6, 0), ipady=6)

        # ── Strength Bar
        bar_frame = tk.Frame(self, bg=BG, padx=24)
        bar_frame.pack(fill="x")

        bar_row = tk.Frame(bar_frame, bg=BG)
        bar_row.pack(fill="x")
        self.strength_label = tk.Label(bar_row, text="—", font=FONT_BOLD,
                                       bg=BG, fg=TEXT_DIM, width=12, anchor="w")
        self.strength_label.pack(side="left")
        self.score_label = tk.Label(bar_row, text="", font=FONT_SMALL,
                                    bg=BG, fg=TEXT_DIM)
        self.score_label.pack(side="right")

        self.bar_canvas = tk.Canvas(bar_frame, height=12, bg=BG2,
                                    highlightthickness=0)
        self.bar_canvas.pack(fill="x", pady=(4, 0))

        # ── Entropy
        self.entropy_label = tk.Label(bar_frame, text="",
                                      font=FONT_SMALL, bg=BG, fg=TEXT_DIM, anchor="w")
        self.entropy_label.pack(anchor="w", pady=(4, 0))

        # ── Tabs
        nb_frame = tk.Frame(self, bg=BG, padx=24, pady=10)
        nb_frame.pack(fill="both", expand=True)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook",         background=BG,  borderwidth=0)
        style.configure("TNotebook.Tab",     background=BG2, foreground=TEXT_DIM,
                        padding=[14, 6],     font=FONT_SMALL)
        style.map("TNotebook.Tab",
                  background=[("selected", BG3)],
                  foreground=[("selected", WHITE)])
        style.configure("TFrame", background=BG2)

        self.nb = ttk.Notebook(nb_frame)
        self.nb.pack(fill="both", expand=True)

        self._build_checklist_tab()
        self._build_breach_tab()
        self._build_generator_tab()

        # ── Bottom Buttons
        btn_frame = tk.Frame(self, bg=BG, padx=24, pady=12)
        btn_frame.pack(fill="x")

        self._btn(btn_frame, "🔍  Analyse", self._analyse, ACCENT).pack(side="left", padx=(0, 8))
        self._btn(btn_frame, "🌐  Check Breach", self._run_breach_check, BG3).pack(side="left")
        self._btn(btn_frame, "✖  Clear", self._clear, BG2).pack(side="right")

    # ── TAB: CHECKLIST ────────────────────────
    def _build_checklist_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text="  Checklist  ")

        self.check_vars = {}
        checks = [
            ("length_8",       "At least 8 characters"),
            ("length_12",      "At least 12 characters"),
            ("length_16",      "At least 16 characters"),
            ("has_upper",      "Uppercase letters (A–Z)"),
            ("has_lower",      "Lowercase letters (a–z)"),
            ("has_digit",      "Numbers (0–9)"),
            ("has_special",    "Special characters (!@#$%)"),
            ("no_repeats",     "No repeated characters (aaa)"),
            ("no_sequential",  "No sequential patterns (abc, 123)"),
            ("not_common",     "Not a common password"),
        ]

        for i, (key, label) in enumerate(checks):
            row = tk.Frame(frame, bg=BG2)
            row.pack(fill="x", padx=16, pady=3)

            icon_lbl = tk.Label(row, text="○", font=FONT_BOLD,
                                bg=BG2, fg=TEXT_DIM, width=3)
            icon_lbl.pack(side="left")
            txt_lbl = tk.Label(row, text=label, font=FONT_LABEL,
                               bg=BG2, fg=TEXT_DIM, anchor="w")
            txt_lbl.pack(side="left", fill="x", expand=True)
            self.check_vars[key] = (icon_lbl, txt_lbl)

        # Feedback box
        tk.Label(frame, text="Suggestions", font=FONT_BOLD,
                 bg=BG2, fg=TEXT).pack(anchor="w", padx=16, pady=(12, 4))
        self.feedback_text = tk.Text(
            frame, height=4, bg=BG, fg=TEXT,
            font=FONT_SMALL, relief="flat", state="disabled",
            wrap="word", insertbackground=TEXT
        )
        self.feedback_text.pack(fill="x", padx=16, pady=(0, 12))

    # ── TAB: BREACH ───────────────────────────
    def _build_breach_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text="  Breach Check  ")

        info = tk.Frame(frame, bg=BG2, pady=12, padx=16)
        info.pack(fill="x", padx=16, pady=(16, 8))

        tk.Label(info, text="🛡️  k-Anonymity Model", font=FONT_BOLD,
                 bg=BG2, fg=TEXT).pack(anchor="w")
        tk.Label(info,
                 text="Only the first 5 characters of your SHA-1 hash are sent.\n"
                      "Your actual password NEVER leaves your machine.",
                 font=FONT_SMALL, bg=BG2, fg=TEXT_DIM, justify="left").pack(anchor="w", pady=(4, 0))

        self.breach_status = tk.Label(
            frame, text="─  Not checked yet  ─",
            font=("Segoe UI", 14, "bold"), bg=BG2, fg=TEXT_DIM,
            pady=20
        )
        self.breach_status.pack(fill="x", padx=16)

        self.breach_detail = tk.Label(
            frame, text="", font=FONT_LABEL,
            bg=BG2, fg=TEXT_DIM, wraplength=560, justify="center"
        )
        self.breach_detail.pack(padx=16, pady=(0, 12))

        self.breach_btn = self._btn(
            frame, "🌐  Check HaveIBeenPwned", self._run_breach_check, BG3
        )
        self.breach_btn.pack(pady=8)

        self.breach_spinner = tk.Label(frame, text="", font=FONT_LABEL,
                                       bg=BG2, fg=TEXT_DIM)
        self.breach_spinner.pack()

    # ── TAB: GENERATOR ────────────────────────
    def _build_generator_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text="  Generator  ")

        # Options
        opts = tk.Frame(frame, bg=BG2, padx=16, pady=12)
        opts.pack(fill="x", padx=16, pady=(16, 0))

        # Length slider
        tk.Label(opts, text="Length", font=FONT_BOLD, bg=BG2, fg=TEXT).grid(
            row=0, column=0, sticky="w", pady=4)
        self.gen_length = tk.IntVar(value=16)
        self.len_label  = tk.Label(opts, text="16", font=FONT_BOLD,
                                   bg=BG2, fg=ACCENT, width=4)
        self.len_label.grid(row=0, column=2, padx=(8, 0))
        slider = tk.Scale(opts, from_=8, to=64, orient="horizontal",
                          variable=self.gen_length, bg=BG2, fg=TEXT,
                          troughcolor=BG3, highlightthickness=0,
                          command=lambda v: self.len_label.config(text=v))
        slider.grid(row=0, column=1, sticky="ew", padx=(12, 0))
        opts.columnconfigure(1, weight=1)

        # Checkboxes
        self.opt_upper   = tk.BooleanVar(value=True)
        self.opt_lower   = tk.BooleanVar(value=True)
        self.opt_digits  = tk.BooleanVar(value=True)
        self.opt_special = tk.BooleanVar(value=True)

        for i, (var, label) in enumerate([
            (self.opt_upper,   "Uppercase (A–Z)"),
            (self.opt_lower,   "Lowercase (a–z)"),
            (self.opt_digits,  "Numbers (0–9)"),
            (self.opt_special, "Special (!@#$%)"),
        ]):
            cb = tk.Checkbutton(opts, text=label, variable=var,
                                bg=BG2, fg=TEXT, selectcolor=BG3,
                                activebackground=BG2, activeforeground=TEXT,
                                font=FONT_LABEL)
            cb.grid(row=i + 1, column=0, columnspan=3, sticky="w", pady=2)

        # Buttons
        btn_row = tk.Frame(frame, bg=BG2)
        btn_row.pack(pady=12)
        self._btn(btn_row, "⚡  Generate Password",   self._gen_password,   ACCENT).pack(side="left", padx=6)
        self._btn(btn_row, "📝  Generate Passphrase", self._gen_passphrase, BG3).pack(side="left", padx=6)

        # Result
        res_frame = tk.Frame(frame, bg=BG2, padx=16)
        res_frame.pack(fill="x", padx=16, pady=(0, 8))

        tk.Label(res_frame, text="Generated Password", font=FONT_BOLD,
                 bg=BG2, fg=TEXT).pack(anchor="w", pady=(0, 4))

        gen_row = tk.Frame(res_frame, bg=BG2)
        gen_row.pack(fill="x")

        self.gen_result = tk.Entry(
            gen_row, font=FONT_MONO, bg=BG, fg=GREEN,
            relief="flat", state="readonly",
            readonlybackground=BG, insertbackground=TEXT,
            bd=0, highlightthickness=2,
            highlightcolor=GREEN, highlightbackground=BG3
        )
        self.gen_result.pack(side="left", fill="x", expand=True, ipady=8, ipadx=10)

        copy_btn = self._btn(gen_row, "📋 Copy", self._copy_generated, BG3)
        copy_btn.pack(side="left", padx=(6, 0), ipady=2)

        self.copy_label = tk.Label(res_frame, text="", font=FONT_SMALL,
                                   bg=BG2, fg=GREEN)
        self.copy_label.pack(anchor="w", pady=(4, 0))

        # Mini strength preview
        self.gen_strength_lbl = tk.Label(res_frame, text="", font=FONT_SMALL,
                                         bg=BG2, fg=TEXT_DIM)
        self.gen_strength_lbl.pack(anchor="w")

    # ── HELPERS ───────────────────────────────
    def _btn(self, parent, text, command, bg):
        return tk.Button(
            parent, text=text, command=command,
            bg=bg, fg=WHITE, font=FONT_BOLD,
            relief="flat", cursor="hand2",
            activebackground=ACCENT, activeforeground=WHITE,
            padx=14, pady=6
        )

    def _toggle_show(self):
        self.show_var.set(not self.show_var.get())
        self.pw_entry.config(show="" if self.show_var.get() else "•")

    def _clear(self):
        self.pw_var.set("")
        self._reset_ui()

    def _reset_ui(self):
        self.strength_label.config(text="—", fg=TEXT_DIM)
        self.score_label.config(text="")
        self.entropy_label.config(text="")
        self.bar_canvas.delete("all")
        for key, (icon, txt) in self.check_vars.items():
            icon.config(text="○", fg=TEXT_DIM)
            txt.config(fg=TEXT_DIM)
        self._set_feedback([])
        self.breach_status.config(text="─  Not checked yet  ─", fg=TEXT_DIM)
        self.breach_detail.config(text="")

    # ── LIVE UPDATE ───────────────────────────
    def _on_key(self, event=None):
        pw = self.pw_var.get()
        if not pw:
            self._reset_ui()
            return
        result = check_strength(pw)
        self._update_strength_ui(result)

    def _analyse(self):
        pw = self.pw_var.get()
        if not pw:
            messagebox.showwarning("No Password", "Please enter a password first.")
            return
        result = check_strength(pw)
        self._update_strength_ui(result)
        self.nb.select(0)

    def _update_strength_ui(self, result: dict):
        colour = result["color"]
        self.strength_label.config(text=result["label"], fg=colour)
        self.score_label.config(text=f"{result['score']}/100", fg=colour)
        self.entropy_label.config(
            text=f"Entropy: {result['entropy']} bits  •  Length: {result['length']} chars",
            fg=TEXT_DIM
        )

        # Bar
        self.bar_canvas.update_idletasks()
        w = self.bar_canvas.winfo_width()
        h = 12
        filled = int(result["score"] / 100 * w)
        self.bar_canvas.delete("all")
        self.bar_canvas.create_rectangle(0, 0, w, h, fill=BG2, outline="")
        self.bar_canvas.create_rectangle(0, 0, filled, h, fill=colour, outline="")

        # Checklist
        for key, (icon, txt) in self.check_vars.items():
            passed = result["checks"].get(key, False)
            if passed:
                icon.config(text="✓", fg=GREEN)
                txt.config(fg=TEXT)
            else:
                icon.config(text="✗", fg=RED)
                txt.config(fg=TEXT_DIM)

        self._set_feedback(result["feedback"])

    def _set_feedback(self, lines: list):
        self.feedback_text.config(state="normal")
        self.feedback_text.delete("1.0", "end")
        self.feedback_text.insert("end", "\n".join(lines))
        self.feedback_text.config(state="disabled")

    # ── BREACH CHECK ──────────────────────────
    def _run_breach_check(self):
        pw = self.pw_var.get()
        if not pw:
            messagebox.showwarning("No Password", "Please enter a password first.")
            return

        self.breach_status.config(text="⏳  Checking...", fg=YELLOW)
        self.breach_detail.config(text="")
        self.breach_spinner.config(text="Contacting api.pwnedpasswords.com...")
        self.nb.select(1)

        def run():
            result = check_breach(pw)
            self.after(0, lambda: self._update_breach_ui(result))

        threading.Thread(target=run, daemon=True).start()

    def _update_breach_ui(self, result: dict):
        self.breach_spinner.config(text="")
        if result["error"]:
            self.breach_status.config(text="⚠️  API Error", fg=YELLOW)
            self.breach_detail.config(text=result["error"], fg=YELLOW)
        elif result["pwned"]:
            count = f"{result['count']:,}"
            self.breach_status.config(text=f"🚨  BREACHED  —  {count} times", fg=RED)
            self.breach_detail.config(
                text="This password has appeared in known data breaches.\n"
                     "Do NOT use it. Change it immediately!",
                fg=RED
            )
        else:
            self.breach_status.config(text="✅  Not Found in Breaches", fg=GREEN)
            self.breach_detail.config(
                text="Good news — this password was not found in known breach databases.\n"
                     "(This does not guarantee it is 100% safe.)",
                fg=GREEN
            )

    # ── GENERATOR ─────────────────────────────
    def _gen_password(self):
        pwd = generate_password(
            length=self.gen_length.get(),
            use_upper=self.opt_upper.get(),
            use_lower=self.opt_lower.get(),
            use_digits=self.opt_digits.get(),
            use_special=self.opt_special.get(),
        )
        self._set_gen_result(pwd)

    def _gen_passphrase(self):
        phrase = generate_passphrase()
        self._set_gen_result(phrase)

    def _set_gen_result(self, value: str):
        self.gen_result.config(state="normal")
        self.gen_result.delete(0, "end")
        self.gen_result.insert(0, value)
        self.gen_result.config(state="readonly")
        self.copy_label.config(text="")

        result = check_strength(value)
        self.gen_strength_lbl.config(
            text=f"Strength: {result['label']}  •  Score: {result['score']}/100  •  Entropy: {result['entropy']} bits",
            fg=result["color"]
        )

    def _copy_generated(self):
        value = self.gen_result.get()
        if value:
            self.clipboard_clear()
            self.clipboard_append(value)
            self.copy_label.config(text="✅ Copied to clipboard!", fg=GREEN)
            self.after(2000, lambda: self.copy_label.config(text=""))


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    app = PasswordCheckerApp()
    app.mainloop()
