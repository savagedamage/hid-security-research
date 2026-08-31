# Lab Fixtures — Synthetic HID Test Corpus

Synthetic, machine-generated HID scenarios used to test `hidwatch` detection and
to demonstrate benign-vs-suspicious behavior **without any real hardware or real
keystroke captures**.

Last reviewed: 2026-08-31

## Why synthetic only

Per `../../SECURITY.md` §5, we never commit real HID captures — a recording of
real typing is effectively a keylog and may contain secrets. Every file here is
**generated** (see `../../software/hidwatch/src/hidwatch/fixtures.py`), never
recorded from a human. There is also no weaponized injection payload here: these
fixtures describe *behavioral shapes* (rates, timings, interface sets), not
runnable attacks.

## Scenario JSON schema

```jsonc
{
  "name": "human-readable name",
  "description": "what this scenario represents",
  "expected_risk": "LOW | MEDIUM | HIGH | CRITICAL",   // asserted by tests
  "device": {
    "transport": "usb",
    "vendor_id": "0x1234",           // hex string or int
    "product_id": "0x5678",
    "manufacturer": "…",
    "product": "…",
    "serial": null,                   // null = no serial
    "declared_purpose": "storage",    // used to flag unexpected keyboard iface
    "interfaces": [
      { "class": 3, "subclass": 1, "protocol": 1, "description": "HID Keyboard" }
    ],
    "report_descriptor": "05010906a101…"   // hex, optional
  },
  "attach_time": 0.0,                  // enumeration timestamp (s), or null
  "events": [
    { "timestamp": 0.01, "keys": [4], "modifiers": 0, "raw_len": 8 }
  ]
}
```

## Corpus

Benign / false-positive controls:
- `benign-keyboard.json` — normal boot keyboard, human-paced typing with jitter;
  scores LOW.
- `benign-barcode-scanner.json` — legitimately fast "typing" HID scanner. It
  intentionally scores HIGH before policy context, then a corpus test verifies
  its known VID:PID drops below HIGH when fast-input allow-listed. This documents
  rather than hides the detector's false-positive boundary.

Suspicious / malicious behavioral shapes (should score HIGH/CRITICAL):
- `impossible-typing-rate.json` — sustained keystroke rate no human can produce.
- `badusb-composite.json` — a "flash drive" that also exposes a keyboard iface.
- `descriptor-anomaly.json` — a report descriptor with structural anomalies.
- `input-right-after-attach.json` — input microseconds after enumeration.

The test suite (`software/hidwatch/tests/test_corpus.py`) loads every scenario
and asserts the analyzer produces `>=` the expected risk band, keeping fixtures
and detector honest together.

## Regenerating / adding fixtures

Add a JSON file following the schema, then reference its expected risk. Prefer
generating event streams via `hidwatch.fixtures.synth_typing(...)` for
determinism. Run `pytest` in `software/hidwatch/` to validate.
