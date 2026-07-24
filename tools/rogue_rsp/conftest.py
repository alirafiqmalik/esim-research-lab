"""Put rogue_rsp (and the fuzzer's ber codec) on sys.path for direct imports."""

import sys
from pathlib import Path

_here = Path(__file__).resolve().parent
sys.path.insert(0, str(_here))
# Reuse the AuthenticateServer fuzzer's BER-TLV codec (tools/fuzzer/ber.py).
sys.path.insert(0, str(_here.parent / "fuzzer"))
