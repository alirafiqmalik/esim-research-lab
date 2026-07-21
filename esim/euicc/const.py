from __future__ import annotations
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PKG = "im.angry.openeuicc"
MAIN = f"{PKG}/.ui.PrivilegedMainActivity"
ACT = f"{PKG}/.ui.EsimCtlActivity"
SESS_BASE = REPO / ".sessions" / "esimctl"
VERBOSE_TAGS = ("HttpInterfaceImpl", "OmapiApduInterface", "TelephonyManagerApduInterface",
                "EuiccChannelManager", "app_process64", "EuiccGoogle")
