#!/usr/bin/env python3
"""
cipher_tool.py
==============

A from-scratch Caesar & Vigenere cipher tool with automatic cryptanalysis.

Features
--------
1. Caesar cipher   - encrypt, decrypt, and brute-force / auto-crack
2. Vigenere cipher - encrypt, decrypt, and auto-crack (key-length detection
                      via Index of Coincidence + Kasiski-style repetition
                      analysis, then per-column frequency analysis)
3. Frequency analysis utilities (letter counts, chi-squared scoring against
   standard English letter frequencies)
4. A simple interactive CLI, plus an importable library API

Why this is a good interview conversation piece
-------------------------------------------------
- Caesar / Vigenere are *monoalphabetic* and *polyalphabetic* substitution
  ciphers respectively. Both preserve the underlying letter-frequency
  distribution of the plaintext language (just shifted/rotated), which is
  exactly the weakness this tool exploits to break them without knowing
  the key.
- Modern ciphers (AES, ChaCha20, etc.) are designed specifically to destroy
  this kind of statistical structure -- via confusion (substitution) AND
  diffusion (spreading bits around, e.g. through many rounds), combined
  with large, effectively random-looking keys and keys that are used only
  once per context (nonces/IVs). That's precisely why frequency analysis,
  which cracks Caesar/Vigenere trivially, does nothing against them.

Run this file directly for an interactive demo:
    python3 cipher_tool.py
"""

from __future__ import annotations

import argparse
import string
from collections import Counter
from typing import List, Tuple

ALPHABET = string.ascii_lowercase
ALPHA_SIZE = 26

# Standard relative frequencies of letters in English text (percentages).
# Source: classic cryptanalysis references (approx. values used widely
# in textbooks on classical cryptography).
ENGLISH_FREQ = {
    'a': 8.17, 'b': 1.49, 'c': 2.78, 'd': 4.25, 'e': 12.70, 'f': 2.23,
    'g': 2.02, 'h': 6.09, 'i': 6.97, 'j': 0.15, 'k': 0.77, 'l': 4.03,
    'm': 2.41, 'n': 6.75, 'o': 7.51, 'p': 1.93, 'q': 0.10, 'r': 5.99,
    's': 6.33, 't': 9.06, 'u': 2.76, 'v': 0.98, 'w': 2.36, 'x': 0.15,
    'y': 1.97, 'z': 0.07,
}

# Typical index of coincidence for English prose (~0.0667), vs. ~0.0385
# for random/uniform text. Used to help pick the most likely key length.
ENGLISH_IOC = 0.0667


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shift_char(ch: str, shift: int) -> str:
    """Shift a single alphabetic character by `shift` positions, preserving
    case, and pass through non-alphabetic characters unchanged."""
    if ch.isupper():
        base = ord('A')
    elif ch.islower():
        base = ord('a')
    else:
        return ch
    return chr((ord(ch) - base + shift) % ALPHA_SIZE + base)


def clean_text(text: str) -> str:
    """Lowercase and strip everything except letters -- useful for
    frequency analysis where punctuation/spacing would skew results."""
    return ''.join(c for c in text.lower() if c in ALPHABET)


# ---------------------------------------------------------------------------
# Caesar cipher
# ---------------------------------------------------------------------------

def caesar_encrypt(plaintext: str, shift: int) -> str:
    return ''.join(_shift_char(c, shift) for c in plaintext)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    return caesar_encrypt(ciphertext, -shift)


def caesar_brute_force(ciphertext: str) -> List[Tuple[int, str]]:
    """Return all 26 possible decryptions, useful for manual inspection."""
    return [(s, caesar_decrypt(ciphertext, s)) for s in range(ALPHA_SIZE)]


def chi_squared_score(text: str) -> float:
    """Lower score => letter-frequency distribution of `text` looks more
    like standard English. This is the workhorse statistic used to pick
    the correct shift/key automatically instead of a human eyeballing 26
    (or more) candidate decryptions."""
    cleaned = clean_text(text)
    n = len(cleaned)
    if n == 0:
        return float('inf')

    counts = Counter(cleaned)
    score = 0.0
    for letter in ALPHABET:
        observed = counts.get(letter, 0)
        expected = ENGLISH_FREQ[letter] / 100.0 * n
        if expected > 0:
            score += (observed - expected) ** 2 / expected
    return score


def caesar_crack(ciphertext: str) -> Tuple[int, str, float]:
    """Automatically find the most likely Caesar shift via chi-squared
    frequency analysis. Returns (shift, plaintext, score)."""
    best_shift, best_text, best_score = 0, '', float('inf')
    for shift, candidate in caesar_brute_force(ciphertext):
        score = chi_squared_score(candidate)
        if score < best_score:
            best_shift, best_text, best_score = shift, candidate, score
    return best_shift, best_text, best_score


# ---------------------------------------------------------------------------
# Vigenere cipher
# ---------------------------------------------------------------------------

def vigenere_encrypt(plaintext: str, key: str) -> str:
    key = clean_text(key)
    if not key:
        raise ValueError("Vigenere key must contain at least one letter.")
    result = []
    ki = 0
    for ch in plaintext:
        if ch.isalpha():
            shift = ord(key[ki % len(key)].lower()) - ord('a')
            result.append(_shift_char(ch, shift))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    key = clean_text(key)
    if not key:
        raise ValueError("Vigenere key must contain at least one letter.")
    neg_key = ''.join(_shift_char(k, 0) for k in key)  # no-op, keep readable
    result = []
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            shift = -(ord(key[ki % len(key)].lower()) - ord('a'))
            result.append(_shift_char(ch, shift))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)


# --- Cryptanalysis: Index of Coincidence ------------------------------------

def index_of_coincidence(text: str) -> float:
    """IoC measures how likely two randomly chosen letters from `text` are
    identical. English prose has a distinctly higher IoC (~0.067) than
    random text (~0.038) because English letter frequencies are uneven.
    For Vigenere ciphertext split into columns by the correct key length,
    each column is really just Caesar-shifted English -- so it should have
    an IoC close to the English value. Wrong key lengths look closer to
    random."""
    cleaned = clean_text(text)
    n = len(cleaned)
    if n < 2:
        return 0.0
    counts = Counter(cleaned)
    numerator = sum(c * (c - 1) for c in counts.values())
    denominator = n * (n - 1)
    return numerator / denominator if denominator else 0.0


def average_ioc_for_key_length(ciphertext: str, key_len: int) -> float:
    cleaned = clean_text(ciphertext)
    columns = [cleaned[i::key_len] for i in range(key_len)]
    iocs = [index_of_coincidence(col) for col in columns if len(col) > 1]
    return sum(iocs) / len(iocs) if iocs else 0.0


def find_repeated_sequences(ciphertext: str, seq_len: int = 3):
    """Kasiski examination: find repeated substrings of length `seq_len`
    and record the distances between their occurrences. The key length is
    likely a common divisor of these distances, since identical plaintext
    fragments encrypted at the same phase of a repeating key produce
    identical ciphertext fragments."""
    cleaned = clean_text(ciphertext)
    positions = {}
    for i in range(len(cleaned) - seq_len + 1):
        seq = cleaned[i:i + seq_len]
        positions.setdefault(seq, []).append(i)

    distances = []
    for seq, pos_list in positions.items():
        if len(pos_list) > 1:
            for a, b in zip(pos_list, pos_list[1:]):
                distances.append(b - a)
    return distances


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def kasiski_key_length_candidates(ciphertext: str, max_len: int = 20) -> Counter:
    """Score candidate key lengths by how many Kasiski distances they
    evenly divide. Higher score = more supporting evidence."""
    distances = find_repeated_sequences(ciphertext, seq_len=3)
    scores = Counter()
    for length in range(2, max_len + 1):
        for d in distances:
            if d % length == 0:
                scores[length] += 1
    return scores


def guess_key_length(ciphertext: str, max_len: int = 20) -> int:
    """Combine Kasiski evidence (repeated-sequence distances) with average
    Index of Coincidence to pick the most plausible key length."""
    kasiski_scores = kasiski_key_length_candidates(ciphertext, max_len)

    best_len, best_metric = 1, -1.0
    for length in range(1, max_len + 1):
        ioc = average_ioc_for_key_length(ciphertext, length)
        # Reward IoC close to English (~0.0667) and add a small bonus for
        # Kasiski support so ties favor lengths with repeated-sequence
        # evidence.
        ioc_closeness = 1.0 - abs(ioc - ENGLISH_IOC) / ENGLISH_IOC
        kasiski_bonus = kasiski_scores.get(length, 0) * 0.01
        metric = ioc_closeness + kasiski_bonus
        if metric > best_metric:
            best_len, best_metric = length, metric
    return best_len


def vigenere_crack(ciphertext: str, max_key_len: int = 20) -> Tuple[str, str]:
    """Fully automatic Vigenere crack:
      1. Guess the key length (Kasiski + Index of Coincidence).
      2. Split ciphertext into `key_len` interleaved columns -- each
         column was encrypted with a single, fixed Caesar shift.
      3. Run Caesar frequency-analysis cracking independently on each
         column to recover each letter of the key.
      4. Reassemble the key and decrypt the full ciphertext.
    Returns (recovered_key, plaintext).
    """
    key_len = guess_key_length(ciphertext, max_key_len)
    cleaned = clean_text(ciphertext)
    columns = [cleaned[i::key_len] for i in range(key_len)]

    key_chars = []
    for col in columns:
        shift, _, _ = caesar_crack(col)
        key_chars.append(ALPHABET[shift])
    recovered_key = ''.join(key_chars)

    plaintext = vigenere_decrypt(ciphertext, recovered_key)
    return recovered_key, plaintext


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_frequency_table(text: str) -> None:
    cleaned = clean_text(text)
    n = len(cleaned)
    counts = Counter(cleaned)
    print(f"{'Letter':<8}{'Count':<8}{'Observed %':<12}{'English %':<10}")
    for letter in ALPHABET:
        c = counts.get(letter, 0)
        pct = (c / n * 100) if n else 0.0
        print(f"{letter:<8}{c:<8}{pct:<12.2f}{ENGLISH_FREQ[letter]:<10.2f}")


def interactive_demo() -> None:
    short_sample = (
        "the quick brown fox jumps over the lazy dog while cryptography "
        "protects our secrets from prying eyes"
    )

    # Cryptanalysis (Kasiski / Index of Coincidence) needs a reasonable
    # amount of ciphertext to find reliable statistical patterns, so the
    # Vigenere auto-crack demo uses a longer passage than the short Caesar
    # example above. This mirrors real cryptanalysis: short messages are
    # much harder to break automatically than long ones.
    long_sample = (
        "in cryptography a caesar cipher is one of the simplest and most "
        "widely known encryption techniques it is a type of substitution "
        "cipher in which each letter in the plaintext is replaced by a "
        "letter some fixed number of positions down the alphabet the "
        "method is named after julius caesar who used it in his private "
        "correspondence the vigenere cipher improves on this by using a "
        "keyword to select a different shift for each letter making "
        "frequency analysis of the raw ciphertext much harder however if "
        "the key is short relative to the message it can still be broken "
        "using the index of coincidence and kasiski examination to "
        "recover the key length and then simple frequency analysis on "
        "each column of the ciphertext to recover each letter of the key"
    )

    print("=" * 70)
    print("CAESAR CIPHER DEMO")
    print("=" * 70)
    shift = 7
    enc = caesar_encrypt(short_sample, shift)
    print(f"Plaintext : {short_sample}")
    print(f"Shift     : {shift}")
    print(f"Encrypted : {enc}")
    dec = caesar_decrypt(enc, shift)
    print(f"Decrypted : {dec}")

    print("\n-- Auto-cracking the Caesar ciphertext (no key given) --")
    found_shift, cracked, score = caesar_crack(enc)
    print(f"Recovered shift : {found_shift}  (chi-squared score={score:.2f})")
    print(f"Recovered text  : {cracked}")

    print("\n" + "=" * 70)
    print("VIGENERE CIPHER DEMO")
    print("=" * 70)
    key = "crypto"
    venc = vigenere_encrypt(long_sample, key)
    print(f"Plaintext (truncated) : {long_sample[:80]}...")
    print(f"Key                   : {key}")
    print(f"Encrypted (truncated) : {venc[:80]}...")
    vdec = vigenere_decrypt(venc, key)
    print(f"Decrypted matches original: {vdec == long_sample}")

    print("\n-- Auto-cracking the Vigenere ciphertext (no key given) --")
    print("   (Longer ciphertext gives Kasiski/Index-of-Coincidence analysis")
    print("    enough statistical signal to reliably recover the key.)")
    rec_key, rec_plain = vigenere_crack(venc)
    print(f"Recovered key             : {rec_key}")
    print(f"Recovered text matches    : {rec_plain == long_sample}")
    print(f"Recovered text (truncated): {rec_plain[:80]}...")

    print("\n" + "=" * 70)
    print("FREQUENCY TABLE for the Caesar ciphertext above")
    print("=" * 70)
    _print_frequency_table(enc)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Caesar & Vigenere cipher tool with frequency-analysis cracking."
    )
    sub = parser.add_subparsers(dest="command")

    c_enc = sub.add_parser("caesar-encrypt", help="Encrypt with a Caesar shift")
    c_enc.add_argument("text")
    c_enc.add_argument("shift", type=int)

    c_dec = sub.add_parser("caesar-decrypt", help="Decrypt with a Caesar shift")
    c_dec.add_argument("text")
    c_dec.add_argument("shift", type=int)

    c_crack = sub.add_parser("caesar-crack", help="Auto-crack a Caesar ciphertext")
    c_crack.add_argument("text")

    v_enc = sub.add_parser("vigenere-encrypt", help="Encrypt with a Vigenere key")
    v_enc.add_argument("text")
    v_enc.add_argument("key")

    v_dec = sub.add_parser("vigenere-decrypt", help="Decrypt with a Vigenere key")
    v_dec.add_argument("text")
    v_dec.add_argument("key")

    v_crack = sub.add_parser("vigenere-crack", help="Auto-crack a Vigenere ciphertext")
    v_crack.add_argument("text")
    v_crack.add_argument("--max-key-len", type=int, default=20)

    freq = sub.add_parser("freq", help="Show a letter-frequency table for text")
    freq.add_argument("text")

    sub.add_parser("demo", help="Run the built-in interactive demo")

    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.command == "caesar-encrypt":
        print(caesar_encrypt(args.text, args.shift))
    elif args.command == "caesar-decrypt":
        print(caesar_decrypt(args.text, args.shift))
    elif args.command == "caesar-crack":
        shift, text, score = caesar_crack(args.text)
        print(f"Best shift: {shift} (chi-squared score: {score:.2f})")
        print(f"Plaintext : {text}")
    elif args.command == "vigenere-encrypt":
        print(vigenere_encrypt(args.text, args.key))
    elif args.command == "vigenere-decrypt":
        print(vigenere_decrypt(args.text, args.key))
    elif args.command == "vigenere-crack":
        key, text = vigenere_crack(args.text, args.max_key_len)
        print(f"Recovered key: {key}")
        print(f"Plaintext    : {text}")
    elif args.command == "freq":
        _print_frequency_table(args.text)
    elif args.command == "demo" or args.command is None:
        interactive_demo()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
