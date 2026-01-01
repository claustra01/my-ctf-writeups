---
title: SECCON 2014 Quals
event: SECCON
year: 2014
date: 2014-12-07
category: misc
tags: [crypto, reversing]
summary: Quick notes from SECCON 2014 quals with a sample challenge walkthrough.
---

## Overview

SECCON quals always mix playful puzzles with sneaky binary trivia. I kept this entry tight: the environment, a single representative challenge, and the exploit steps that matter.

### Environment

- Tooling: `python3`, `pwntools`, `binwalk`, `radare2`
- Host setup: WSL / Ubuntu 22.04, nothing exotic
- Safety: worked in a throwaway container to avoid leaking tokens

## Challenge: Example Crypto (misc 200)

> A warm-up crypto that hid a flag in a repeating-key XOR stream.

### Recon

- The provided ciphertext repeated every 32 bytes.
- A known-plaintext header (`SECCON{`) leaked the first 7 keystream bytes.
- Frequency analysis on the remainder suggested high entropy -> likely XOR, not substitution.

### Exploit

1. **Recover the key:** used the known header to derive the first bytes, then slid the guess across the text until collisions vanished.
2. **Validate:** decrypted with the candidate key and checked for printable ASCII to confirm.
3. **Extract:** the recovered plaintext cleanly produced the flag.

```python
from itertools import cycle

ct = bytes.fromhex(open("cipher.txt", "r").read().strip())
key = b"SECCON{".ljust(32, b'K')  # placeholder fill for demo
pt = bytes(c ^ k for c, k in zip(ct, cycle(key)))
print(pt.decode(errors="ignore"))
```

### Takeaways

- Keep a checklist: known headers, repeating patterns, and low-key byte histograms cut guesswork.
- For future runs, script keystream guesses instead of hand-tuning in a REPL.

## Notes

- Swap in real challenge artifacts as you add more posts.
- Keep `summary`, `event`, and `year` fields filled so the index stays tidy.
