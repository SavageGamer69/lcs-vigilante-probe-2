# LCSVigilanteProbe2

A **diagnostic-only** 32-bit ASI for the user's Re:LCS Beta 6.0 Build 15 executable.

It verifies the main executable's PE fingerprint and checks a statically identified `CopPursuit` candidate function signature and its associated diagnostic string. It does not call the candidate function, install hooks, patch bytes, or change gameplay.

## Build

1. Create a GitHub repository and upload the contents of this folder.
2. Open **Actions** and run **Build LCSVigilanteProbe2** (or push to `main`/`master`).
3. Download the `LCSVigilanteProbe2-x86` artifact.
4. Put `LCSVigilanteProbe2.asi` in the Re:LCS plugin folder where the working probe is loaded.
5. Launch the game, then look for `LCSVigilanteProbe2.log` in the game's working directory.

## Expected successful log

The log should include:

- `PASS: executable fingerprint matches the analyzed Re:LCS executable.`
- `PASS: CopPursuit candidate signature and diagnostic string match.`
- `DIAGNOSTIC ONLY: no hooks installed, no game functions called, and no memory patched.`

If a `FAIL` line appears, do not use this ASI as a gameplay mod; send the complete log instead. Keep the original working probe available so you can remove this diagnostic independently.

## Analyzed executable fingerprint

- PE machine: x86 (`0x014C`)
- PE timestamp: `0x504D6947`
- image size: `0x00614000`
- entry point RVA: `0x00267BF0`
- PE checksum: `0x002FEA85`
- CopPursuit candidate RVA: `0x000D2260`

The candidate is not yet treated as a callable public API. It must be mapped further before mission code can safely use it.
