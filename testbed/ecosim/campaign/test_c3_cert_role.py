"""D8 -- certificate role-slot confusion (channel C3).

SGP.22 v3.1 SS4.5.2.2 / SS5.7.13: a conformant eUICC SHALL reject a server
certificate that chains correctly to the trusted CI but was issued for the
wrong role (e.g. an EUM certificate presented where a CERT.DPauth.SIG is
expected), with error code invalidOid. Before pki.require_role() existed,
this testbed's authenticate_server only called verify_chain() -- since our
EUM cert is also issued directly by the CI, it would have chained fine and
been silently accepted where a real eUICC must reject it. This module proves
the fix closes that gap.

Runnable: ./venv/bin/python -m testbed.ecosim.campaign.test_c3_cert_role
"""

from __future__ import annotations

from .. import crypto, protocol
from ..euicc import SoftwareEuicc
from ..orchestrator import build_ecosystem
from . import record


def run() -> list[record.Finding]:
    findings: list[record.Finding] = []
    eco = build_ecosystem(seed=0xD8A)
    euicc: SoftwareEuicc = eco.euicc
    pki = eco.pki

    # Drive up to the point authenticate_server needs a serverCertificate.
    challenge_wire = euicc.get_euicc_challenge()
    from .. import tlv, codec
    challenge = tlv.find(tlv.walk(challenge_wire), codec.TAG_GET_EUICC_CHALLENGE).children[0].value
    transaction_id = bytes(16)
    server_otsk = crypto.ephemeral_keypair()
    server_signed1 = protocol.server_signed1(
        transaction_id, challenge, eco.smdp.address.encode(), protocol.point_bytes(server_otsk)
    )

    # S1: correct role (dp_auth cert) + correct signature -> must succeed.
    sig_correct = crypto.sign(pki.dp_auth.private_key, server_signed1)
    try:
        euicc.authenticate_server(transaction_id, server_signed1, sig_correct, pki.dp_auth.cert_der(), pki.ci.certificate)
        s1_ok, s1_err = True, ""
    except ValueError as exc:
        s1_ok, s1_err = False, repr(exc)
    findings.append(record.Finding(
        round=2, direction="D8-cert-role-confusion", channel="C3",
        spec_section="SGP.22 §5.7.13", hypothesis="A correctly-signed DPauth-role certificate is accepted.",
        mutation="none (baseline)", observed=f"accepted={s1_ok} err={s1_err}",
        classification=record.CONFORMANT if s1_ok else record.ARTIFACT,
        rationale="Sanity check that the new role check doesn't break the honest path.",
        severity="info", artifact_path="testbed/ecosim/pki.py,testbed/ecosim/euicc.py",
    ))

    # S2: wrong role -- present the EUM certificate (CI-signed, chains fine) signed
    # with the EUM's own key over the same server_signed1 bytes.
    eco2 = build_ecosystem(seed=0xD8B)
    euicc2: SoftwareEuicc = eco2.euicc
    challenge_wire2 = euicc2.get_euicc_challenge()
    challenge2 = tlv.find(tlv.walk(challenge_wire2), codec.TAG_GET_EUICC_CHALLENGE).children[0].value
    server_signed1_2 = protocol.server_signed1(
        transaction_id, challenge2, eco2.smdp.address.encode(), protocol.point_bytes(server_otsk)
    )
    sig_wrong_role = crypto.sign(pki.eum.private_key, server_signed1_2)
    try:
        euicc2.authenticate_server(transaction_id, server_signed1_2, sig_wrong_role, pki.eum.cert_der(), pki.ci.certificate)
        s2_ok, s2_err = True, ""
    except ValueError as exc:
        s2_ok, s2_err = False, repr(exc)
    findings.append(record.Finding(
        round=2, direction="D8-cert-role-confusion", channel="C3",
        spec_section="SGP.22 §4.5.2.2 / §5.7.13",
        hypothesis="A validly-CI-signed EUM certificate presented in the DPauth slot must be rejected (invalidOid), even though it chains to the trusted CI.",
        mutation="serverCertificate = EUM cert (correct signature by the EUM key over the served bytes, valid chain to CI)",
        observed=f"rejected={not s2_ok} err={s2_err}",
        classification=record.CONFORMANT if not s2_ok else record.ARTIFACT,
        rationale="SGP.22 §5.7.13 explicit SHALL: reject any serverCertificate that is not CERT.DPauth.SIG/DSauth.SIG with invalidOid, regardless of chain validity. Before pki.require_role() this testbed only checked verify_chain() and would have accepted this (a genuine testbed gap now closed).",
        severity="high" if s2_ok else "info",
        artifact_path="testbed/ecosim/pki.py,testbed/ecosim/euicc.py",
    ))

    record.append_many(findings)
    return findings


if __name__ == "__main__":
    results = run()
    by_class: dict[str, int] = {}
    for f in results:
        by_class[f.classification] = by_class.get(f.classification, 0) + 1
    print(f"D8 cert-role-confusion: {len(results)} findings {by_class}")
    for f in results:
        print(f"  [{f.classification}/{f.severity}] {f.hypothesis}")
        print(f"      observed: {f.observed}")
