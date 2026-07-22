"""Bounded entrypoint for the GET STATUS enumeration campaign.

    run_getstatus.py [--dry-run | --live] --out <jsonl> --summary <json>
                     [--wall <sec>] [--send-cap <n>] [--apps-md <path>]

Defaults to ``--dry-run``: candidates are built and classified, nothing is sent.
``--live`` sends only the allowlisted read-only GET STATUS candidates, and every
one still routes through ``engine.FuzzEngine.consider`` -> ``safety.guard_send``.

The summary carries a ``discovered_apps`` map keyed by AID (life-cycle +
privileges) decoded from the E3 templates in the responses. ``--apps-md`` writes
the same list as a readable ``getstatus_apps.md``. ``--send-cap`` bounds live
traffic; once hit the engine keeps classifying without sending. ``--wall`` bounds
wall-clock time.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import explore_getstatus
from engine import FuzzEngine
from euicc_transport import ApduResult, EuiccTransport, TransportError
from explore_getstatus import AppEntry

_REPO_ROOT = Path(__file__).resolve().parents[2]


class _CliTransport(EuiccTransport):
    """Transport that parses the real ``esim euicc apdu`` output shape.

    The CLI returns ``resp`` (full ISD-R response, SW = trailing 2 bytes) and
    ``ok``, with no separate ``sw`` key. Only ALLOWED read-only candidates ever
    reach here; the safety gate is unchanged.
    """

    @staticmethod
    def _parse(stdout: str, apdu_hex: str) -> ApduResult:
        text = stdout.strip()
        if not text:
            raise TransportError(f"empty CLI output for APDU {apdu_hex}")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise TransportError(f"CLI output is not JSON: {text!r}") from exc
        if not isinstance(data, dict) or "resp" not in data:
            raise TransportError(f"CLI JSON missing 'resp': {text!r}")
        resp = str(data["resp"]).upper()
        sw = resp[-4:] if len(resp) >= 4 else ""
        return ApduResult(resp_hex=resp, sw=sw, ok=bool(data.get("ok", sw == "9000")), raw=data)


def _build_engine(live: bool) -> FuzzEngine:
    transport = _CliTransport(repo_root=_REPO_ROOT, python_executable="python3") if live else None
    return FuzzEngine(live=live, allow_destructive=False, transport=transport)


def _render_apps_md(apps: dict[str, AppEntry], phase: str) -> str:
    lines = [
        "# GET STATUS enumerated applications and security domains",
        "",
        f"Phase: `{phase}`. Source: GlobalPlatform GET STATUS (INS F2) response `E3` templates.",
        "",
    ]
    if not apps:
        lines.append("No `E3` application templates decoded. In dry-run nothing is sent, so")
        lines.append("this is expected until a live run returns registry data.")
        lines.append("")
        return "\n".join(lines)
    lines.append("| AID | Life cycle | Privileges | Raw priv |")
    lines.append("| --- | --- | --- | --- |")
    for aid in sorted(apps):
        entry = apps[aid]
        privs = ", ".join(entry.privileges) if entry.privileges else "-"
        raw = entry.privileges_raw or "-"
        lines.append(f"| `{aid}` | {entry.lifecycle} | {privs} | `{raw}` |")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Read-only eUICC GET STATUS enumeration.")
    posture = parser.add_mutually_exclusive_group()
    posture.add_argument("--dry-run", dest="live", action="store_false", default=False)
    posture.add_argument("--live", dest="live", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--wall", type=int, default=300)
    parser.add_argument("--send-cap", dest="send_cap", type=int, default=None)
    parser.add_argument("--apps-md", dest="apps_md", type=Path, default=None)
    args = parser.parse_args(argv)

    engine = _build_engine(args.live)
    phase = "live" if args.live else "dry"

    summary = explore_getstatus.run(
        engine=engine,
        out_path=args.out,
        summary_path=args.summary,
        phase=phase,
        wall=args.wall,
        send_cap=args.send_cap,
    )

    apps = explore_getstatus.enumerate_apps(engine)
    summary["discovered_apps"] = {aid: asdict(entry) for aid, entry in sorted(apps.items())}
    args.summary.write_text(json.dumps(summary, indent=2) + "\n")

    if args.apps_md is not None:
        args.apps_md.parent.mkdir(parents=True, exist_ok=True)
        args.apps_md.write_text(_render_apps_md(apps, phase))

    sys.stderr.write(f"[getstatus/{phase}] {json.dumps(summary)[:400]}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
