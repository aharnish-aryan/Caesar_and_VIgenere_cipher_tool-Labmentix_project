 Caesar_and_VIgenere_cipher_tool-Labmentix_project
A Python-based cryptography tool implementing Caesar and Vigenère ciphers with encryption, decryption, and basic cryptanalysis techniques.

The Cipher Desk — Caesar & Vigenère Cipher Tool
A from-scratch Python implementation of the Caesar and Vigenère ciphers, complete with automatic cryptanalysis (no key required) and a styled Tkinter desktop GUI.
Built as part of the Labmentix cybersecurity project.

Table of Contents
Features
Why This Is Interesting
Screenshots
Requirements
Getting Started
CLI Usage
Library Usage
Project Structure
How the Cracking Works
License
Author
Features
Caesar Cipher
Encrypt / decrypt with any shift (0–25)
Brute-force all 26 possible shifts
Auto-crack ciphertext using chi-squared letter-frequency analysis — no key needed
Vigenère Cipher
Encrypt / decrypt with any keyword
Auto-crack ciphertext using:
Index of Coincidence (IoC) to score candidate key lengths
Kasiski examination (repeated-sequence distance analysis) to support key-length detection
Per-column frequency analysis to recover each letter of the key
Frequency Analysis Utilities
Letter frequency tables
Chi-squared scoring against standard English letter frequencies
Two ways to use it
cipher_tool.py — importable library and interactive CLI
cipher_gui.py — a styled Tkinter desktop app ("The Cipher Desk") with live charts for frequency analysis and IoC-per-key-length
Why This Is Interesting
Caesar and Vigenère are classic substitution ciphers — Caesar is monoalphabetic, Vigenère is polyalphabetic. Both preserve the statistical "fingerprint" of the underlying language (just shifted or rotated), which is exactly what this tool exploits to break them automatically.
Modern ciphers like AES and ChaCha20 are designed specifically to destroy this structure through confusion (substitution) and diffusion (spreading information across many rounds), combined with large, effectively random keys used only once per context. That is why frequency analysis, trivial against Caesar and Vigenère, does nothing against modern cryptography.
Screenshots
Caesar cipher tab — shift slider, encrypt/decrypt, and a one-click "Crack it" that overlays your text's letter frequencies against standard English.

Vigenère cipher tab — keyword input with a live "tape" showing how the keyword lines up against your text, plus one-click cracking that recovers the key automatically.

Requirements
Python 3.7+
tkinter (only needed for the GUI — included with most Python installs)
On some Linux distros: sudo apt install python3-tk
No external dependencies — everything is built from Python's standard library.
Getting Started
Clone the repo:
git clone https://github.com/aharnish-aryan/Caesar_and_VIgenere_cipher_tool-Labmentix_project.git
cd Caesar_and_VIgenere_cipher_tool-Labmentix_project
Run the interactive demo:
python3 cipher_tool.py
Launch the GUI:
python3 cipher_gui.py
cipher_gui.py imports cipher_tool.py directly — keep both files in the same folder.
CLI Usage
# Caesar cipher
python3 cipher_tool.py caesar-encrypt "attack at dawn" 3
python3 cipher_tool.py caesar-decrypt "dwwdfn dw gdzq" 3
python3 cipher_tool.py caesar-crack "dwwdfn dw gdzq"

# Vigenère cipher
python3 cipher_tool.py vigenere-encrypt "attack at dawn" lemon
python3 cipher_tool.py vigenere-decrypt "lxfopv ef rnhr" lemon
python3 cipher_tool.py vigenere-crack "lxfopv ef rnhr..." --max-key-len 20

# Frequency analysis
python3 cipher_tool.py freq "some sample text to analyze"

# Run the built-in demo
python3 cipher_tool.py demo
Library Usage
import cipher_tool as ct

# Caesar
encrypted = ct.caesar_encrypt("hello world", 5)
decrypted = ct.caesar_decrypt(encrypted, 5)
shift, plaintext, score = ct.caesar_crack(encrypted)

# Vigenère
encrypted = ct.vigenere_encrypt("hello world", "key")
decrypted = ct.vigenere_decrypt(encrypted, "key")
recovered_key, plaintext = ct.vigenere_crack(encrypted)
Project Structure
.
├── cipher_tool.py         # Core cipher logic, cryptanalysis, and CLI
├── cipher_gui.py          # Tkinter GUI built on top of cipher_tool.py
├── screenshots/           # README preview images
│   ├── app-preview.jpg
│   ├── caesar-tab.png
│   └── vigenere-tab.png
└── README.md
How the Cracking Works
Cipher
Weakness Exploited
Technique
Caesar
Fixed shift preserves letter frequencies
Chi-squared scoring against English letter frequencies across all 26 shifts
Vigenère
Repeating key creates periodic structure
Index of Coincidence + Kasiski examination to find key length, then per-column Caesar cracking

License
This project is open source — feel free to use, modify, and learn from it. Consider adding a LICENSE file (MIT is a common choice) if you plan to share it publicly.
Author
Built by aharnish-aryan as part of the Labmentix project.
