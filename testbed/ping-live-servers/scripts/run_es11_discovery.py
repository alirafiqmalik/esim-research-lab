#!/usr/bin/env python3
"""Drive an ES11 (SM-DS) discovery lookup through the src/ request-builder
library, over a real local HTTP socket, against the local ecosim-backed SM-DS
shim (scripts/local_sim_server.py).

Default target is always the local sim. Same live-fire gating as
run_es9plus_flow.py -- see src/client.py.

Run:
    ./venv/bin/python testbed/ping-live-servers/scripts/run_es11_discovery.py
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]
PING_LIVE_SERVERS = HERE.parent
for p in (str(REPO_ROOT), str(PING_LIVE_SERVERS), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

from local_sim_server import start_smds_server  # noqa: E402
from src.client import RspHttpClient  # noqa: E402
from src.envelope import parse_response_header, path_for  # noqa: E402
from src.errors import RspClientError  # noqa: E402
from src.models import Es11DiscoveryRequest, Es11DiscoveryResponse  # noqa: E402
from src.targets import Target  # noqa: E402
from testbed.ecosim.smds import SmDs  # noqa: E402

DEMO_EID = "01234567890123456789012345678901"
DEMO_EVENT_ID = "demo-event-0001"
DEMO_SMDP_ADDRESS = "smdp.ecosim.test"


def run_against_local_sim(eid: str = DEMO_EID) -> dict[str, object]:
    smds = SmDs()
    smds.register_event(eid, DEMO_EVENT_ID, DEMO_SMDP_ADDRESS)

    httpd = start_smds_server(smds)
    try:
        target = Target(name="local-sim-smds", base_url=f"http://127.0.0.1:{httpd.server_port}", is_local=True)
        client = RspHttpClient(target=target)

        req = Es11DiscoveryRequest(eid=eid)
        raw = client.call("ES11", "Discover", path_for("ES11", "Discover"), req.to_wire())
        if not parse_response_header(raw).ok:
            raise RspClientError(f"ES11 discovery failed: {raw}")
        resp = Es11DiscoveryResponse.from_wire(raw)

        return {
            "eid_queried": eid,
            "event_count": len(resp.event_entries),
            "events": [(e.event_id, e.rsp_server_address) for e in resp.event_entries],
            "target": target.base_url,
        }
    finally:
        httpd.shutdown()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", choices=["local", "provider"], default="local")
    parser.add_argument("--provider-host", default=None)
    parser.add_argument("--allow-live-fire", action="store_true")
    parser.add_argument("--eid", default=DEMO_EID)
    args = parser.parse_args()

    if args.target == "provider":
        print(
            "Live-provider execution is gated by the orchestrating session and is not "
            "implemented as a runnable path here: RspHttpClient will refuse it "
            f"(needs allow_live_fire=True AND ESIM_MITM_ALLOW_LIVE_FIRE=1). "
            f"provider-host={args.provider_host!r} allow_live_fire={args.allow_live_fire} "
            f"env={os.environ.get('ESIM_MITM_ALLOW_LIVE_FIRE')!r}",
            file=sys.stderr,
        )
        return 2

    try:
        summary = run_against_local_sim(args.eid)
    except RspClientError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1

    print("OK -- ES11 discovery round-tripped over real HTTP against the local sim:")
    for key, value in summary.items():
        print(f"  {key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
