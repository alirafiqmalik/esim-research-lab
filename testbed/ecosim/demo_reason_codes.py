"""Demo: the four live-observed SM-DP+ failure states, each rendered as the exact
SGP.22 Failed envelope a production server returns.

Drives the real ecosim ecosystem (build_ecosystem) through four scenarios and
prints the resulting `RspError.to_failed_response()` for each:

  (i)   re-download a code whose profile is still installed -> MATCHING_ID_REFUSED (8.2.6/3.8)
  (ii)  delete (release_matching_id) then re-download -> succeeds again
  (iii) finite campaign pool depleted -> POOL_EMPTY (9.4/10.1)
  (iv)  EID-bound order consumed by the wrong device -> EID_REFUSED (8.1.1/3.8)

Runnable: ./venv/bin/python -m testbed.ecosim.demo_reason_codes
"""

from __future__ import annotations

import json

from . import codec, status
from .campaign.test_smdp_eid_binding import run_handshake
from .euicc import SoftwareEuicc
from .orchestrator import Ecosystem, build_ecosystem


def _print_envelope(label: str, err: status.RspError) -> None:
    print(f"  {label}")
    print(f"    {err}")
    print("    " + json.dumps(err.to_failed_response()))


def _consume(eco: Ecosystem, euicc: SoftwareEuicc, matching_id: str, eid: str) -> bool:
    result = run_handshake(eco, euicc, codec.ctx_params1(matching_id), eid)
    return result.installed


def main() -> None:
    eco = build_ecosystem(seed=0xC0DE)
    euicc = eco.euicc
    eid = euicc.get_eid()

    print("== SM-DP+ live-observed failure states ==")

    # (i) matchingId already consumed (profile still installed) -> MATCHING_ID_REFUSED
    eco.smdp.register_order("DEMO-MID", "89010000000000000021", "Demo-Plan", "DemoMNO", 0)
    installed = _consume(eco, euicc, "DEMO-MID", eid)
    print(f"[i] first download installed={installed}; re-downloading the same code:")
    try:
        _consume(eco, euicc, "DEMO-MID", eid)
        raise SystemExit("BUG: re-consume without release should have been refused")
    except status.RspError as err:
        _print_envelope("MATCHING_ID_REFUSED (live 8.2.6/3.8):", err)

    # (ii) eUICC deletes the profile (release_matching_id) -> re-download succeeds
    eco.smdp.release_matching_id("DEMO-MID")
    reinstalled = _consume(eco, euicc, "DEMO-MID", eid)
    print(f"[ii] after release_matching_id, re-download installed={reinstalled}")

    # (iii) finite pool depleted -> POOL_EMPTY
    eco.smdp.register_order("POOL-MID", "89010000000000000022", "Pool-Plan", "DemoMNO", 0, pool=1)
    first = _consume(eco, euicc, "POOL-MID", eid)
    eco.smdp.release_matching_id("POOL-MID")  # clear installed-collision; only inventory remains
    print(f"[iii] pool=1 first download installed={first}; second draw on an empty pool:")
    try:
        _consume(eco, euicc, "POOL-MID", eid)
        raise SystemExit("BUG: depleted pool should have raised POOL_EMPTY")
    except status.RspError as err:
        _print_envelope("POOL_EMPTY (live 9.4/10.1):", err)

    # (iv) EID-bound order consumed by the wrong device -> EID_REFUSED
    wrong_device = SoftwareEuicc(eco.pki, eco.rng)
    wrong_device._eid = "99999999999999999999999999999999"
    assert wrong_device.get_eid() != eid
    eco.smdp.register_order(
        "BOUND-MID", "89010000000000000023", "Bound-Plan", "DemoMNO", 0, eid=eid
    )
    print("[iv] order bound to the intended EID, consumed by a different device:")
    try:
        _consume(eco, wrong_device, "BOUND-MID", wrong_device.get_eid())
        raise SystemExit("BUG: EID-bound order should have refused the wrong device")
    except status.RspError as err:
        _print_envelope("EID_REFUSED (live 8.1.1/3.8):", err)


if __name__ == "__main__":
    main()
