# Profile Delivery

How a profile reaches the eUICC: the three SM-DP+ interfaces, and the three
trigger methods that start a download. All triggers converge on one ES9+ flow.

## Notes

- `notes/01-interfaces.md` — ES9+ (device-reachable), ES2+ (operator backend),
  ES8+ (sealed profile inside the BPP).
- `notes/02-delivery-methods.md` — QR scan, manual entry, carrier apps /
  universal links; push vs pull.

## Scripts

Local, no device:

```
./venv/bin/python testbed/profile-delivery/scripts/make_qr.py --all
```

Writes a QR (PNG/SVG) per catalog code to `qr/`. Falls back to a `.txt` payload
if no QR library is installed.

Gated, prints the plan and fires nothing by default:

```
./venv/bin/python testbed/profile-delivery/scripts/trigger_download.py \
    --lpa 'LPA:1$rsp.truphone.com$QRF-SPEEDTEST'
```

Shows all three triggers for one activation string. Live execution of the
harness or intent method needs the gates below and an explicit `--method`.

## Interface reach from the phone

| Interface | Device-reachable? | Note |
|---|---|---|
| ES9+ | Yes | the download; already captured live |
| ES2+ | No | operator-to-SM-DP+; mints our activation codes |
| ES8+ | Only inside ES9+ | sealed profile in the BPP |

## Safety

`trigger_download.py` methods `harness` and `intent` install a real profile via
live RSP. They run only with:

```
ESIM_MITM_ALLOW_LIVE_FIRE=1  --allow-live-fire  --i-understand-real-profile
```

The `manual` method prints instructions only. `make_qr.py` never touches the
device or the network.
