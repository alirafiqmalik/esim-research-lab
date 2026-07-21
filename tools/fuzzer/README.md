# eUICC APDU Fuzzer

Gated APDU fuzzing suite for the eUICC ISD-R. Default posture is dry-run. It
sends nothing to the card unless you pass `--live`, and even then only
read-only tags leave the host.

## Safety first

The target is a live eUICC holding two real profiles. Profile #1 (BetterRoaming)
must never be harmed. The card must never be wiped or bricked.

- `safety.py` gates every candidate APDU.
- Read-only ES10x store-data tags are allowlisted. Only these can go live.
- Destructive tags and write instructions are blocklisted. They are never sent.
- Memory reset (`BF34`), delete profile (`BF33`), and GP DELETE (INS `E4`) are
  hard-blocked. No flag overrides them.
- `--i-understand-destructive` exists but is forbidden without maintainer
  sign-off. The code does not honor it for live sends.

## Install

pyAPDUFuzzer is not on PyPI under `pyAPDUFuzzer` or `apdu-fuzzer`. Install it
editable from the vendored upstream clone.

```bash
cd tools/fuzzer
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
git clone https://github.com/petrs/APDUFuzzer.git vendor/APDUFuzzer
.venv/bin/pip install -e vendor/APDUFuzzer
.venv/bin/pip install atheris pytest
```

This is the exact sequence that worked here on Python 3.14. The editable install
pulls `six`, `llsmartcard-ph4`, `psutil`, `pyhashxx`, and `pyscard`, all of which
build from source in this environment. Pinned versions are in
`requirements.txt`.

`.venv/` and `vendor/` are gitignored. Recreate them with the steps above.

## Run the tests

```bash
tools/fuzzer/.venv/bin/python -m pytest tools/fuzzer/tests -q
```

Tests mock `subprocess.run` and never touch a device.

## Transport

`euicc_transport.py` reaches the eUICC through the post-migration CLI:

```bash
python3 -m esim.cli euicc apdu <HEX>   # run with cwd = repo root
```

The CLI prints JSON like `{"resp": "...9000", "sw": "9000", "ok": true}`. The
adapter parses it into an `ApduResult`. The `euicc apdu` subcommand lands in
migration Phase 3 and is absent from this worktree. The adapter only references
the command string.

## Modes

One entrypoint routes all three modes through the safety layer:

```bash
tools/fuzzer/.venv/bin/python tools/fuzzer/run_fuzz.py --mode {prefix,afl,grammar} [--dry-run|--live] [--seeds tools/fuzzer/seeds/]
```

`--dry-run` is the default.

### prefix

Enumerate the CLA/INS/P1/P2 prefix space against the ISD-R. Reuses
pyAPDUFuzzer's `FuzzerInstruction` iteration model. Each candidate header passes
through `safety.py`. Almost all classify as UNKNOWN or BLOCKED and are never
sent.

```bash
tools/fuzzer/.venv/bin/python tools/fuzzer/run_fuzz.py --mode prefix
```

### afl

AFL-style, coverage-guided mutation with atheris over the seed corpus.

The eUICC is a black box behind an opaque APDU pipe. There is no in-process
coverage of the secure element. atheris guides on the coverage of this project's
Python (the safety classifier and the APDU builders), which is real but is not
the target's coverage. The signal that matters for the target is a proxy: the
diversity of status words (live) and safety classifications (dry-run) recorded by
the engine.

```bash
tools/fuzzer/.venv/bin/python tools/fuzzer/run_fuzz.py --mode afl
```

### grammar

Grammar synthesis from seed APDUs. Learns the header prefix, the BER-TLV tag
set, and value templates from the seeds. Synthesizes new well-formed store-data
candidates by recombining tags with values and mutating length and value bytes.
Each candidate keeps a valid `Lc` and inner TLV length.

```bash
tools/fuzzer/.venv/bin/python tools/fuzzer/run_fuzz.py --mode grammar
```

## Files

- `safety.py` — allowlist, blocklist, hard blocks, BER-TLV tag parser.
- `euicc_transport.py` — CLI subprocess adapter, returns `ApduResult`.
- `engine.py` — shared driver. Gates every candidate, records SW/class diversity.
- `corpus.py` — seed loader.
- `fuzz_prefix.py` — prefix scanner.
- `fuzz_afl.py` — atheris harness.
- `fuzz_grammar.py` — grammar synthesis.
- `run_fuzz.py` — single entrypoint.
- `seeds/` — known-good read-only APDUs, one per file.
- `tests/` — `test_transport.py`, `test_safety.py`. Never touch a device.

## Seeds

Eight known-good read-only store-data commands, one per allowlisted tag:

```
81E2910006BF3E035C015A   GetEID
81E2910003BF2000         GetEUICCInfo1
81E2910003BF2200         GetEUICCInfo2
81E2910003BF2E00         GetEUICCChallenge
81E2910003BF2D00         GetProfilesInfo
81E2910003BF2B00         RetrieveNotificationsList
81E2910003BF3C00         GetConfiguredAddresses
81E2910003BF4300         GetRAT
```
