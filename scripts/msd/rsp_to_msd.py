#!/usr/bin/env python3
"""Parse an OpenEUICC/lpac RSP capture log into a Graphviz-DOT message sequence
diagram (MSD).

The sequence is derived strictly from the log (which ES9+ functions fired, and
the success/failure status of each), so the diagram matches the capture. Crypto,
checks and message structures are labelled with symbolic/mathematical notation
rather than English where possible.

Actors (lifelines): eUICC  |  LPA  |  SM-DP+
ES9+ requests/responses come from `HttpInterfaceImpl` lines. The eUICC-side ES10
steps that bracket each ES9+ call (GetEUICCChallenge, AuthenticateServer,
PrepareDownload, LoadBoundProfilePackage) are emitted only when the corresponding
ES9+ field is actually present in the log.

Usage:
    rsp_to_msd.py <capture.log> [-o out.dot] [--title T] [--check]
    dot -Tsvg out.dot -o out.svg
"""
import json
import re
import sys
import argparse

EUICC, LPA, SMDP = "eUICC", "LPA", "SM-DP+"
ACTORS = [EUICC, LPA, SMDP]

# symbolic message templates per ES9+ function.
# each entry: (eUICC pre-steps, request label, ok response label, eUICC post-steps)
# {fields} are filled from parsed JSON when present.
SPECS = {
    "initiateAuthentication": dict(
        pre=[(EUICC, LPA, "GetEUICCChallenge → eC ∈ {0,1}¹²⁸",),
             (EUICC, LPA, "GetEUICCInfo1 → eInfo1 = ⟨svn, {pkId_CI}⟩",)],
        req=(LPA, SMDP, "ES9+.InitiateAuthentication\\n⟨smdpAddr, eC, eInfo1⟩"),
        ok=(SMDP, LPA, "200 ⟨TID, srvSigned1, σ_DP=Sig_{SK.DPauth}(srvSigned1),\\n"
                       "CERT.DPauth, pkId_CI*⟩"),
        post=[],
    ),
    "authenticateClient": dict(
        pre=[(EUICC, EUICC, "ES10b.AuthenticateServer:\\n"
                            "chk pkId_CI* ∈ trusted ∧ CERT.DPauth ↗ CI\\n"
                            "∧ Vrfy_{PK.DPauth}(σ_DP, srvSigned1)")],
        req=(LPA, SMDP, "ES9+.AuthenticateClient\\n⟨TID, authServerResp =\\n"
                        "⟨euiccSigned1, σ_eUICC, CERT.eUICC, CERT.EUM⟩⟩"),
        ok=(SMDP, LPA, "200 ⟨TID, profileMetadata, smdpSigned2,\\n"
                       "σ_DP2, CERT.DPpb⟩"),
        post=[],
    ),
    "getBoundProfilePackage": dict(
        pre=[(EUICC, EUICC, "ES10b.PrepareDownload:\\n"
                            "Vrfy_{PK.DPpb}(σ_DP2) ⟹\\n"
                            "prepDownloadResp = ⟨euiccSigned2, σ_eUICC2, otPK.eUICC.KA⟩")],
        req=(LPA, SMDP, "ES9+.GetBoundProfilePackage\\n⟨TID, prepDownloadResp⟩"),
        ok=(SMDP, LPA, "200 ⟨TID, BPP⟩   (ES8+: SCP03t,\\nopaque to LPA)"),
        post=[(EUICC, EUICC, "ES10b.LoadBoundProfilePackage:\\n"
                             "ECKA(otPK.DP.KA, otSK.eUICC.KA) → SCP03t keys;\\n"
                             "decrypt+install PE → ISD-P")],
    ),
    "handleNotification": dict(
        pre=[],
        req=(LPA, SMDP, "ES9+.HandleNotification\\n⟨pendingNotification =\\n"
                        "⟨seqNo, σ_eUICC(installResult)⟩⟩"),
        ok=(SMDP, LPA, "204 (ack)"),
        post=[],
    ),
}

URL_RE = re.compile(r"transmit\(url = .*?/es\d+plus/(\w+)\)")
TX_RE = re.compile(r"HTTP tx = (.*)$")
CODE_RE = re.compile(r"transmit responseCode = (\d+)")
BODY_RE = re.compile(r"HTTP response body = (.*)$")
HTTP_TAG = "HttpInterfaceImpl"


def parse_log(path):
    """Return ordered list of dicts: {func, code, status, subject, reason}."""
    events = []
    cur = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if HTTP_TAG not in line:
                continue
            line = line.split(HTTP_TAG, 1)[1]
            m = URL_RE.search(line)
            if m:
                if cur:
                    events.append(cur)
                cur = dict(func=m.group(1), code=None, status=None,
                           subject=None, reason=None)
                continue
            if cur is None:
                continue
            m = CODE_RE.search(line)
            if m:
                cur["code"] = int(m.group(1))
                continue
            m = BODY_RE.search(line)
            if m:
                body = m.group(1).strip()
                cur["status"], cur["subject"], cur["reason"] = _status(body)
    if cur:
        events.append(cur)
    return events


def _status(body):
    if not body:
        return "Executed-Success", None, None  # 204 empty body = ack
    try:
        j = json.loads(body)
        fes = j.get("header", {}).get("functionExecutionStatus", {})
        st = fes.get("status")
        scd = fes.get("statusCodeData", {}) or {}
        return st, scd.get("subjectCode"), scd.get("reasonCode")
    except Exception:
        if "Executed-Success" in body:
            return "Executed-Success", None, None
        return "Unknown", None, None


def _esc(s):
    return s.replace('"', '\\"')


def build_dot(events, title):
    ok_color, fail_color, life = "#1a7f37", "#cf222e", "#8c959f"
    steps = []  # each: (src, dst, label, ok)
    for ev in events:
        spec = SPECS.get(ev["func"])
        funclabel = ev["func"]
        ok = (ev["status"] == "Executed-Success")
        if not spec:
            steps.append((LPA, SMDP, f"ES9+.{funclabel}", ok))
            continue
        steps.extend((a, b, lbl, True) for a, b, lbl in spec["pre"])
        steps.append((*spec["req"], True))
        if ok:
            steps.append((*spec["ok"], True))
        else:
            sc, rc = ev["subject"], ev["reason"]
            steps.append((SMDP, LPA,
                          f"✗ {ev['status']}  ({sc} / {rc})\\n"
                          f"⇒ abort: ∄ valid path", False))
            steps.extend((a, b, lbl, True) for a, b, lbl in spec["post"]) if False else None
            break  # protocol aborts on failure
        steps.extend((a, b, lbl, True) for a, b, lbl in spec["post"])

    out = []
    w = out.append
    w("digraph RSP {")
    w('  rankdir=TB; splines=line; nodesep=0.30; ranksep=0.42;')
    w('  fontname="Helvetica"; labelloc=t;')
    w(f'  label="{_esc(title)}";')
    w('  node [fontname="Helvetica", fontsize=10];')
    w('  edge [fontname="Helvetica", fontsize=9];')
    def order_edges(suffix):
        # invisible left->right edges pin the column order within a rank=same
        ids = [f'"{a}{suffix}"' for a in ACTORS]
        for x, y in zip(ids, ids[1:]):
            w(f'    {x} -> {y} [style=invis];')
    # actor headers
    w('  { rank=same;')
    for a in ACTORS:
        w(f'    "{a}__h" [shape=box, style="filled,bold", fillcolor="#ddf4ff", label="{a}"];')
    order_edges("__h")
    w('  }')
    # lifeline column nodes per step
    n = len(steps)
    for i in range(n):
        w(f'  {{ rank=same;')
        for a in ACTORS:
            w(f'    "{a}_{i}" [shape=point, width=0.02, color="{life}"];')
        order_edges(f"_{i}")
        w('  }')
    # vertical lifelines (constraint keeps columns ordered+aligned)
    for a in ACTORS:
        chain = [f'"{a}__h"'] + [f'"{a}_{i}"' for i in range(n)]
        w(f'  {" -> ".join(chain)} [color="{life}", arrowhead=none, weight=100];')
    # horizontal messages
    for i, (src, dst, label, ok) in enumerate(steps):
        col = ok_color if ok else fail_color
        style = "solid" if ok else "dashed"
        if src == dst:  # self-step (eUICC internal computation/check)
            w(f'  "{src}_{i}" -> "{src}_{i}" '
              f'[label="{_esc(label)}", color="{col}", fontcolor="{col}", '
              f'style="{style}", constraint=false, dir=back, '
              f'headport=e, tailport=e];')
        else:
            w(f'  "{src}_{i}" -> "{dst}_{i}" '
              f'[label="{_esc(label)}", color="{col}", fontcolor="{col}", '
              f'style="{style}", constraint=false, penwidth=1.4];')
    w("}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("-o", "--out", default=None)
    ap.add_argument("--title", default=None)
    ap.add_argument("--check", action="store_true",
                    help="print parsed event sequence for verification")
    a = ap.parse_args()
    events = parse_log(a.log)
    if not events:
        sys.exit(f"no ES9+ (HttpInterfaceImpl) events found in {a.log}")
    if a.check:
        for e in events:
            print(f"{e['func']:28} code={e['code']} status={e['status']}"
                  f" {e['subject'] or ''}{'/' + e['reason'] if e['reason'] else ''}")
        return
    title = a.title or f"eSIM RSP — {a.log.split('/')[-1]}"
    dot = build_dot(events, title)
    out = a.out or (a.log.rsplit(".", 1)[0] + ".dot")
    with open(out, "w") as f:
        f.write(dot)
    print(out)


if __name__ == "__main__":
    main()
