# eUICC APDU Fuzzer

Gated APDU fuzzing suite for the eUICC ISD-R. Default posture is dry-run. It
sends nothing to the card unless you pass `--live`, and even then only
read-only tags leave the host.

## Safety first

The target is a live eUICC holding two real profiles. Profile #1 (BetterRoaming)
must never be harmed. The card must never be wiped or bricked.

- `safety.py` gates every candidate APDU.
- Read-only ES10x store-data tags and read-only ISO-7816 instructions are
  allowlisted. Only these can go live.
- The blocklist is authoritative and takes precedence over the allowlist.
  Destructive tags and write instructions are never sent.
- Memory reset (`BF34`), delete profile (`BF33`), and GP DELETE (INS `E4`) are
  hard-blocked. No flag overrides them.
- Unknown tags/instructions are default-deny for live sends.
- `--i-understand-destructive` exists but is forbidden without maintainer
  sign-off. The code does not honor it for live sends and can never release a
  blocked or unknown APDU.

### Read-only allowlist

Store-data BER-TLV tags (`INS E2`): `BF3E BF20 BF22 BF2E BF2D BF2B BF3C BF43`
(the original vetted eight) plus `BF28` ListNotification (read; the write
`BF30` RemoveNotification stays blocked).

ISO-7816 read instructions, classified by INS: `A4` SELECT (FCI navigation),
`B0` READ BINARY, `B2` READ RECORD, `C0` GET RESPONSE, `CA`/`CB` GET DATA. Each
write counterpart (`D0 D6 D2 DC DA`) stays blocked. Justifications are inline in
`safety.py`. Session/crypto commands (`BF21` PrepareDownload, `BF38`
AuthenticateServer, `BF41` CancelSession) are left UNKNOWN — not verifiably
read-only, so default-deny.

## Trail of Bits testing-handbook skills

The deep campaign follows these skills:

- `harness-writing` — the evolutionary loop, corpus of interesting inputs, and
  structured input extraction (`deep_campaign.py`, `novelty.py`).
- `fuzzing-dictionary` — the eUICC/SGP.22 + ISO-7816 domain dictionary
  (`dictionary.py`).
- `coverage-analysis` — response-diversity interestingness proxy; a black-box SE
  gives no real coverage (`novelty.py`).
- `fuzzing-obstacles` — Lc/BER length framing barriers and malformed framing
  (`dictionary.py`: `encode_lc`, `ber_length_edge_cases`, `malformed_framing`).
- `atheris` — the Python mutation engine used by `--mode afl`.

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

### deep

Deep read-only evolutionary campaign across every allowlisted command. Builds
candidates from the domain dictionary, dedups by behaviour signature, and writes
ONLY unique or unexpected behaviours to JSONL plus a `summary.json`. Dry-run
default; live requires `--live`. Bounded by `--wall` (seconds) and `--send-cap`.

```bash
# Dry-run: enumerate, classify, dedup. Sends nothing.
tools/fuzzer/.venv/bin/python tools/fuzzer/run_fuzz.py --mode deep --dry-run \
  --out tools/fuzzer/out/deep_unique.jsonl --summary tools/fuzzer/out/summary.json

# Live: only allowlisted read-only APDUs are sent, capped and wall-bounded.
tools/fuzzer/.venv/bin/python tools/fuzzer/run_fuzz.py --mode deep --live \
  --wall 300 --send-cap 2000
```

A **behaviour signature** is `(command tag / INS-class, SW, response-structure
fingerprint)`. The fingerprint buckets the response by TLV shape and length, not
raw bytes, so a different EID or ICCID value does not read as new behaviour. A
candidate is *interesting* when its signature is new; interesting inputs are
mutated further.

**Unexpected rules** (each flagged and always logged): `new_signature`,
`novel_sw` (a SW not seen for that command), `success_on_malformed` (`9000` on a
malformed/oversized body), `rare_sw` (`6Fxx 6581 93xx 6A88 6884 6D00`),
`structural_anomaly` (response shape/leading-tag differs from what the command
should yield), `nondeterministic` (a re-sent input gives differing SW/response),
`transport_error`, and `safety_violation` (a blocklisted tag reaching the
transport — impossible by design; if ever detected it is logged `severity:
critical` and the run aborts).

## Files

- `safety.py` — allowlist (tags + INS), blocklist, hard blocks, BER-TLV parser.
- `euicc_transport.py` — CLI subprocess adapter, returns `ApduResult`.
- `engine.py` — shared driver. Gates every candidate, records SW/class diversity.
- `corpus.py` — seed loader.
- `dictionary.py` — eUICC/SGP.22 + ISO-7816 domain fuzzing dictionary.
- `novelty.py` — behaviour signature, dedup, unexpected-behaviour rules.
- `reporting.py` — unique/unexpected JSONL writer and `summary.json`.
- `deep_campaign.py` — evolutionary read-only loop wiring the above together.
- `fuzz_prefix.py` — prefix scanner.
- `fuzz_afl.py` — atheris harness.
- `fuzz_grammar.py` — grammar synthesis.
- `run_fuzz.py` — single entrypoint (`--mode deep` for the campaign).
- `seeds/` — known-good read-only APDUs, one per file.
- `tests/` — `test_transport.py`, `test_safety.py`, `test_novelty.py`,
  `test_reporting.py`. Never touch a device.

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
