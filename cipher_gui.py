#!/usr/bin/env python3
"""
cipher_gui.py
=============

A Tkinter desktop GUI for the Caesar & Vigenere cipher tool.

Run it with:
    python3 cipher_gui.py

Requires: Python 3 with tkinter (included with most Python installs; on
some Linux distros install it separately with `sudo apt install python3-tk`).

This GUI is a thin presentation layer over cipher_tool.py -- all the actual
cipher and cryptanalysis logic (Caesar shift, Vigenere, chi-squared
frequency scoring, Kasiski examination, Index of Coincidence) lives there
and is imported unchanged. cipher_tool.py must be in the same folder as
this file.
"""

import tkinter as tk
from tkinter import ttk

import cipher_tool as ct

# ---------------------------------------------------------------------------
# Palette -- matches the "Cipher Desk" web version (aged paper / ink / stamp)
# ---------------------------------------------------------------------------
PAPER = "#ECE6D6"
PAPER_DEEP = "#E2DBC7"
CARD = "#F6F2E7"
LINE = "#C9BFA0"
INK = "#22283A"
INK_SOFT = "#5B6178"
STAMP = "#B23A2E"
STAMP_SOFT = "#E8C9C2"
FIELD = "#4C6B57"
FIELD_SOFT = "#DCE5DD"

FONT_DISPLAY = ("Georgia", 11)
FONT_DISPLAY_BOLD = ("Georgia", 11, "bold")
FONT_HEAD = ("Georgia", 22, "bold")
FONT_SUBHEAD = ("Georgia", 13, "bold")
FONT_MONO = ("Consolas", 10)
FONT_MONO_SM = ("Consolas", 9)


def clean(text: str) -> str:
    return ct.clean_text(text)


def guess_key_length_details(ciphertext: str, max_len: int = 20):
    """Same computation as cipher_tool.guess_key_length, but also returns
    the per-length (ioc, metric) details so the GUI can chart them."""
    kasiski_scores = ct.kasiski_key_length_candidates(ciphertext, max_len)
    details = []
    best_len, best_metric = 1, -1.0
    for length in range(1, max_len + 1):
        ioc = ct.average_ioc_for_key_length(ciphertext, length)
        closeness = 1.0 - abs(ioc - ct.ENGLISH_IOC) / ct.ENGLISH_IOC
        bonus = kasiski_scores.get(length, 0) * 0.01
        metric = closeness + bonus
        details.append((length, ioc, metric))
        if metric > best_metric:
            best_len, best_metric = length, metric
    return best_len, details


# ---------------------------------------------------------------------------
# Small reusable widgets
# ---------------------------------------------------------------------------

class Card(tk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=CARD, highlightbackground=LINE,
                          highlightthickness=1, bd=0, **kwargs)


class SectionLabel(tk.Label):
    def __init__(self, parent, text, **kwargs):
        super().__init__(parent, text=text, bg=kwargs.pop("bg", CARD), fg=INK_SOFT,
                          font=FONT_MONO_SM, anchor="w", **kwargs)


class OutputBox(tk.Frame):
    """Read-only text area with a copy button, styled like the web app's
    output block."""

    def __init__(self, parent, height=4):
        super().__init__(parent, bg=CARD)
        self.text = tk.Text(self, height=height, wrap="word", bg=PAPER_DEEP,
                             fg=INK, font=FONT_MONO, relief="flat",
                             highlightbackground=LINE, highlightthickness=1,
                             padx=10, pady=8)
        self.text.pack(fill="both", expand=True, side="left")
        self.text.insert("1.0", "")
        self.text.config(state="disabled")

        btn = tk.Button(self, text="Copy", command=self._copy, bg=CARD,
                         fg=INK_SOFT, font=FONT_MONO_SM, relief="flat",
                         highlightbackground=LINE, highlightthickness=1,
                         padx=8, cursor="hand2")
        btn.place(relx=1.0, rely=0.0, anchor="ne", x=-4, y=4)

    def set_text(self, value: str):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", value)
        self.text.config(state="disabled")

    def get_text(self) -> str:
        return self.text.get("1.0", "end-1c")

    def _copy(self):
        value = self.get_text()
        self.clipboard_clear()
        self.clipboard_append(value)


class FreqChart(tk.Canvas):
    """Bar chart comparing a text's letter frequencies against standard
    English -- the same chart used to justify Caesar cracking."""

    def __init__(self, parent, width=700, height=160):
        super().__init__(parent, width=width, height=height, bg=CARD,
                          highlightthickness=0)
        self.w, self.h = width, height
        self.render("")

    def render(self, text: str):
        self.delete("all")
        cleaned = clean(text)
        n = len(cleaned)
        counts = {}
        for c in cleaned:
            counts[c] = counts.get(c, 0) + 1

        pad_l, pad_b, pad_t, pad_r = 8, 20, 8, 8
        chart_w = self.w - pad_l - pad_r
        chart_h = self.h - pad_b - pad_t
        group_w = chart_w / 26
        max_val = max([12.7] + [
            (counts.get(l, 0) / n * 100 if n else 0) for l in ct.ALPHABET
        ])

        for i, letter in enumerate(ct.ALPHABET):
            observed = (counts.get(letter, 0) / n * 100) if n else 0
            expected = ct.ENGLISH_FREQ[letter]
            gx = pad_l + i * group_w
            bar_w = group_w * 0.36
            exp_h = (expected / max_val) * chart_h
            obs_h = (observed / max_val) * chart_h
            self.create_rectangle(gx + group_w * 0.08, pad_t + chart_h - exp_h,
                                   gx + group_w * 0.08 + bar_w, pad_t + chart_h,
                                   fill=LINE, outline="")
            self.create_rectangle(gx + group_w * 0.08 + bar_w + 1, pad_t + chart_h - obs_h,
                                   gx + group_w * 0.08 + 2 * bar_w + 1, pad_t + chart_h,
                                   fill=STAMP, outline="")
            self.create_text(gx + group_w / 2, self.h - 8, text=letter,
                              font=("Consolas", 7), fill=INK_SOFT)
        self.create_line(pad_l, pad_t + chart_h, self.w - pad_r, pad_t + chart_h,
                          fill=LINE)


class IocChart(tk.Canvas):
    """Bar chart of index-of-coincidence per candidate Vigenere key length,
    with the chosen length highlighted and the English IoC threshold shown
    as a dashed line."""

    def __init__(self, parent, width=620, height=160):
        super().__init__(parent, width=width, height=height, bg=CARD,
                          highlightthickness=0)
        self.w, self.h = width, height
        self.render([], None)

    def render(self, details, best_len):
        self.delete("all")
        if not details:
            return
        pad_l, pad_b, pad_t, pad_r = 12, 20, 14, 8
        chart_w = self.w - pad_l - pad_r
        chart_h = self.h - pad_b - pad_t
        bar_w = chart_w / len(details)
        max_val = max([ct.ENGLISH_IOC] + [d[1] for d in details]) * 1.1

        threshold_y = pad_t + chart_h - (ct.ENGLISH_IOC / max_val) * chart_h
        self.create_line(pad_l, threshold_y, self.w - pad_r, threshold_y,
                          fill=FIELD, dash=(4, 3))
        self.create_text(self.w - pad_r, threshold_y - 8, anchor="e",
                          text="English IoC \u2248 0.067", font=("Consolas", 7), fill=FIELD)

        for i, (length, ioc, _metric) in enumerate(details):
            bar_h = (ioc / max_val) * chart_h
            x = pad_l + i * bar_w
            color = STAMP if length == best_len else LINE
            self.create_rectangle(x + bar_w * 0.15, pad_t + chart_h - bar_h,
                                   x + bar_w * 0.85, pad_t + chart_h,
                                   fill=color, outline="")
            if length % 2 == 1 or len(details) <= 12:
                self.create_text(x + bar_w / 2, self.h - 8, text=str(length),
                                  font=("Consolas", 7), fill=INK_SOFT)
        self.create_line(pad_l, pad_t + chart_h, self.w - pad_r, pad_t + chart_h, fill=LINE)


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------

class CipherDesk(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("The Cipher Desk")
        self.geometry("900x900")
        self.minsize(760, 700)
        self.configure(bg=PAPER)

        self._setup_style()
        self._build_header()

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        caesar_tab = tk.Frame(notebook, bg=PAPER)
        vig_tab = tk.Frame(notebook, bg=PAPER)
        notebook.add(caesar_tab, text="  Caesar cipher  ")
        notebook.add(vig_tab, text="  Vigenère cipher  ")

        self._build_caesar_tab(caesar_tab)
        self._build_vigenere_tab(vig_tab)

    # -- styling ------------------------------------------------------

    def _setup_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TNotebook", background=PAPER, borderwidth=0)
        style.configure("TNotebook.Tab", background=PAPER_DEEP, foreground=INK_SOFT,
                         font=FONT_DISPLAY_BOLD, padding=(14, 8), borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", CARD)],
                  foreground=[("selected", INK)])

    def _build_header(self):
        header = tk.Frame(self, bg=PAPER)
        header.pack(fill="x", padx=24, pady=(20, 10))
        tk.Label(header, text="The Cipher Desk", bg=PAPER, fg=INK,
                  font=FONT_HEAD).pack(anchor="w")
        tk.Label(header, bg=PAPER, fg=INK_SOFT, font=FONT_DISPLAY, justify="left",
                  wraplength=820,
                  text=("Encrypt, decrypt, or break a Caesar or Vigen\u00e8re "
                        "cipher using letter-frequency statistics \u2014 no key "
                        "required.")).pack(anchor="w", pady=(4, 0))

    # -- Caesar tab -----------------------------------------------------

    def _build_caesar_tab(self, parent):
        card = Card(parent)
        card.pack(fill="both", expand=True, padx=4, pady=4)
        pad = {"padx": 20}

        tk.Label(card, text="Encrypt or decrypt", bg=CARD, fg=INK,
                  font=FONT_SUBHEAD).pack(anchor="w", **pad, pady=(18, 2))
        SectionLabel(card, "Every letter shifts by the same fixed amount.").pack(
            anchor="w", **pad, pady=(0, 10))

        SectionLabel(card, "Your text").pack(anchor="w", **pad)
        self.caesar_input = tk.Text(card, height=4, wrap="word", bg=PAPER_DEEP, fg=INK,
                                     font=FONT_MONO, relief="flat",
                                     highlightbackground=LINE, highlightthickness=1,
                                     padx=10, pady=8)
        self.caesar_input.insert("1.0", "attack at dawn")
        self.caesar_input.pack(fill="x", **pad, pady=(4, 12))

        controls = tk.Frame(card, bg=CARD)
        controls.pack(fill="x", **pad)

        mode_frame = tk.Frame(controls, bg=CARD)
        mode_frame.pack(side="left", padx=(0, 30))
        SectionLabel(mode_frame, "Mode").pack(anchor="w")
        self.caesar_mode = tk.StringVar(value="encrypt")
        rb1 = tk.Radiobutton(mode_frame, text="Encrypt", variable=self.caesar_mode,
                              value="encrypt", bg=CARD, fg=INK, selectcolor=FIELD_SOFT,
                              font=FONT_MONO_SM, activebackground=CARD)
        rb2 = tk.Radiobutton(mode_frame, text="Decrypt", variable=self.caesar_mode,
                              value="decrypt", bg=CARD, fg=INK, selectcolor=FIELD_SOFT,
                              font=FONT_MONO_SM, activebackground=CARD)
        rb1.pack(anchor="w")
        rb2.pack(anchor="w")

        shift_frame = tk.Frame(controls, bg=CARD)
        shift_frame.pack(side="left", fill="x", expand=True)
        SectionLabel(shift_frame, "Shift (0\u201325)").pack(anchor="w")
        shift_row = tk.Frame(shift_frame, bg=CARD)
        shift_row.pack(fill="x")
        self.caesar_shift = tk.IntVar(value=3)
        scale = tk.Scale(shift_row, from_=0, to=25, orient="horizontal",
                          variable=self.caesar_shift, bg=CARD, fg=INK,
                          troughcolor=PAPER_DEEP, highlightthickness=0,
                          font=FONT_MONO_SM, showvalue=False)
        scale.pack(side="left", fill="x", expand=True)
        spin = tk.Spinbox(shift_row, from_=0, to=25, textvariable=self.caesar_shift,
                           width=4, font=FONT_MONO, bg=PAPER_DEEP, fg=INK, relief="flat",
                           highlightbackground=LINE, highlightthickness=1)
        spin.pack(side="left", padx=(10, 0))

        btn_row = tk.Frame(card, bg=CARD)
        btn_row.pack(fill="x", **pad, pady=(16, 6))
        tk.Button(btn_row, text="Transform", command=self.run_caesar, bg=FIELD, fg="white",
                   font=FONT_DISPLAY_BOLD, relief="flat", padx=16, pady=6,
                   cursor="hand2").pack(side="left", padx=(0, 10))
        tk.Button(btn_row, text="Crack it (no key)", command=self.crack_caesar, bg=CARD,
                   fg=INK, font=FONT_DISPLAY, relief="flat", padx=16, pady=6,
                   highlightbackground=LINE, highlightthickness=1,
                   cursor="hand2").pack(side="left")

        SectionLabel(card, "Result").pack(anchor="w", **pad, pady=(14, 4))
        self.caesar_output = OutputBox(card, height=3)
        self.caesar_output.pack(fill="x", **pad)

        self.caesar_crack_label = tk.Label(card, bg=STAMP_SOFT, fg=STAMP, font=FONT_MONO_SM,
                                            justify="left", anchor="w", wraplength=820)
        # packed on demand in crack_caesar()

        SectionLabel(card, "Letter frequency: your text (red) vs. standard English (tan)").pack(
            anchor="w", **pad, pady=(16, 4))
        chart_wrap = tk.Frame(card, bg=CARD)
        chart_wrap.pack(fill="x", **pad, pady=(0, 20))
        self.caesar_chart = FreqChart(chart_wrap, width=800, height=150)
        self.caesar_chart.pack(fill="x")

        self.run_caesar()

    def run_caesar(self):
        self.caesar_crack_label.pack_forget()
        text = self.caesar_input.get("1.0", "end-1c")
        shift = self.caesar_shift.get()
        if self.caesar_mode.get() == "encrypt":
            result = ct.caesar_encrypt(text, shift)
        else:
            result = ct.caesar_decrypt(text, shift)
        self.caesar_output.set_text(result)
        self.caesar_chart.render(result)

    def crack_caesar(self):
        text = self.caesar_input.get("1.0", "end-1c")
        shift, plaintext, score = ct.caesar_crack(text)
        self.caesar_output.set_text(plaintext)
        self.caesar_chart.render(plaintext)

        self.caesar_crack_label.config(
            text=(f"Recovered shift: {shift}  \u2014  chosen because its letter "
                  f"frequencies fit standard English best "
                  f"(chi-squared score {score:.2f}, lower is better).")
        )
        self.caesar_crack_label.pack(fill="x", padx=20, pady=(0, 4))

    # -- Vigenere tab -----------------------------------------------------

    def _build_vigenere_tab(self, parent):
        card = Card(parent)
        card.pack(fill="both", expand=True, padx=4, pady=4)
        pad = {"padx": 20}

        tk.Label(card, text="Encrypt or decrypt", bg=CARD, fg=INK,
                  font=FONT_SUBHEAD).pack(anchor="w", **pad, pady=(18, 2))
        SectionLabel(card, "The keyword repeats, letter by letter, choosing a different shift each time.").pack(
            anchor="w", **pad, pady=(0, 10))

        SectionLabel(card, "Your text").pack(anchor="w", **pad)
        self.vig_input = tk.Text(card, height=4, wrap="word", bg=PAPER_DEEP, fg=INK,
                                  font=FONT_MONO, relief="flat",
                                  highlightbackground=LINE, highlightthickness=1,
                                  padx=10, pady=8)
        self.vig_input.insert("1.0", "attack at dawn")
        self.vig_input.pack(fill="x", **pad, pady=(4, 12))
        self.vig_input.bind("<KeyRelease>", lambda e: self.render_tape())

        controls = tk.Frame(card, bg=CARD)
        controls.pack(fill="x", **pad)

        mode_frame = tk.Frame(controls, bg=CARD)
        mode_frame.pack(side="left", padx=(0, 30))
        SectionLabel(mode_frame, "Mode").pack(anchor="w")
        self.vig_mode = tk.StringVar(value="encrypt")
        tk.Radiobutton(mode_frame, text="Encrypt", variable=self.vig_mode, value="encrypt",
                        bg=CARD, fg=INK, selectcolor=FIELD_SOFT, font=FONT_MONO_SM,
                        activebackground=CARD).pack(anchor="w")
        tk.Radiobutton(mode_frame, text="Decrypt", variable=self.vig_mode, value="decrypt",
                        bg=CARD, fg=INK, selectcolor=FIELD_SOFT, font=FONT_MONO_SM,
                        activebackground=CARD).pack(anchor="w")

        key_frame = tk.Frame(controls, bg=CARD)
        key_frame.pack(side="left", fill="x", expand=True)
        SectionLabel(key_frame, "Keyword").pack(anchor="w")
        self.vig_key = tk.StringVar(value="lemon")
        key_entry = tk.Entry(key_frame, textvariable=self.vig_key, font=FONT_MONO,
                              bg=PAPER_DEEP, fg=INK, relief="flat",
                              highlightbackground=LINE, highlightthickness=1)
        key_entry.pack(fill="x", ipady=4)
        key_entry.bind("<KeyRelease>", lambda e: self.render_tape())

        btn_row = tk.Frame(card, bg=CARD)
        btn_row.pack(fill="x", **pad, pady=(16, 6))
        tk.Button(btn_row, text="Transform", command=self.run_vigenere, bg=FIELD, fg="white",
                   font=FONT_DISPLAY_BOLD, relief="flat", padx=16, pady=6,
                   cursor="hand2").pack(side="left", padx=(0, 10))
        tk.Button(btn_row, text="Crack it (no key)", command=self.crack_vigenere, bg=CARD,
                   fg=INK, font=FONT_DISPLAY, relief="flat", padx=16, pady=6,
                   highlightbackground=LINE, highlightthickness=1,
                   cursor="hand2").pack(side="left")

        SectionLabel(card, "How the keyword lines up").pack(anchor="w", **pad, pady=(14, 4))
        self.vig_tape = tk.Text(card, height=2, wrap="none", bg=PAPER_DEEP, fg=INK,
                                 font=FONT_MONO_SM, relief="flat",
                                 highlightbackground=LINE, highlightthickness=1,
                                 padx=10, pady=6)
        self.vig_tape.pack(fill="x", **pad)
        self.vig_tape.tag_configure("keyrow", foreground=INK_SOFT)
        self.vig_tape.config(state="disabled")

        SectionLabel(card, "Result").pack(anchor="w", **pad, pady=(14, 4))
        self.vig_output = OutputBox(card, height=3)
        self.vig_output.pack(fill="x", **pad)

        self.vig_crack_label = tk.Label(card, bg=STAMP_SOFT, fg=STAMP, font=FONT_MONO_SM,
                                         justify="left", anchor="w", wraplength=820)

        self.vig_chart_title = SectionLabel(card, "Index of coincidence by candidate key length")
        chart_wrap = tk.Frame(card, bg=CARD)
        self.vig_chart_wrap = chart_wrap
        self.vig_chart = IocChart(chart_wrap, width=780, height=150)
        self.vig_chart.pack(fill="x")

        self.render_tape()
        self.run_vigenere()

    def render_tape(self):
        key = clean(self.vig_key.get()) or "?"
        text = clean(self.vig_input.get("1.0", "end-1c"))[:60]
        self.vig_tape.config(state="normal")
        self.vig_tape.delete("1.0", "end")
        if text:
            key_line = "".join(key[i % len(key)].upper() + " " for i in range(len(text)))
            text_line = "".join(ch.upper() + " " for ch in text)
            self.vig_tape.insert("1.0", key_line + "\n" + text_line, "keyrow")
        self.vig_tape.config(state="disabled")

    def run_vigenere(self):
        self.vig_crack_label.pack_forget()
        self.vig_chart_title.pack_forget()
        self.vig_chart_wrap.pack_forget()

        text = self.vig_input.get("1.0", "end-1c")
        key = self.vig_key.get()
        if not clean(key):
            self.vig_output.set_text("Enter a keyword with at least one letter.")
            return
        if self.vig_mode.get() == "encrypt":
            result = ct.vigenere_encrypt(text, key)
        else:
            result = ct.vigenere_decrypt(text, key)
        self.vig_output.set_text(result)

    def crack_vigenere(self):
        text = self.vig_input.get("1.0", "end-1c")
        if len(clean(text)) < 20:
            self.vig_output.set_text("")
            self.vig_crack_label.config(
                text=("Not enough ciphertext \u2014 Kasiski examination and index-of-"
                      "coincidence analysis need a longer message (at least a few "
                      "dozen letters) to find reliable patterns.")
            )
            self.vig_crack_label.pack(fill="x", padx=20, pady=(0, 4))
            self.vig_chart_title.pack_forget()
            self.vig_chart_wrap.pack_forget()
            return

        best_len, details = guess_key_length_details(text, max_len=20)
        recovered_key = "".join(
            ct.ALPHABET[ct.caesar_crack(
                "".join(clean(text)[i::best_len])
            )[0]]
            for i in range(best_len)
        )
        plaintext = ct.vigenere_decrypt(text, recovered_key)

        self.vig_output.set_text(plaintext)
        self.vig_key.set(recovered_key)
        self.vig_mode.set("decrypt")
        self.render_tape()

        self.vig_crack_label.config(
            text=(f"Recovered key: {recovered_key}  (length {best_len})  \u2014 chosen by "
                  f"index-of-coincidence and repeated-sequence (Kasiski) analysis; each "
                  f"of the {best_len} columns was then cracked independently.")
        )
        self.vig_crack_label.pack(fill="x", padx=20, pady=(0, 4))

        self.vig_chart_title.pack(anchor="w", padx=20, pady=(16, 4))
        self.vig_chart_wrap.pack(fill="x", padx=20, pady=(0, 20))
        self.vig_chart.render(details, best_len)


def main():
    app = CipherDesk()
    app.mainloop()


if __name__ == "__main__":
    main()
