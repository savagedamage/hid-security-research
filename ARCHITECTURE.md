# Project Architecture

Last reviewed: 2026-08-31

```
primary sources → research/data → validated schemas + generated index
                                   │
synthetic/authorized observations → hidwatch parser → analyzer → explainable risk
                                                        │
                                              future policy/enforcement
                                                        │
                                      inline HID gateway / trusted keyboard
```

## Layers

1. **Knowledge layer** (`docs/`, `research/`, `THREAT_MODEL.md`) explains
   protocols, evidence, threats, detection, and limitations.
2. **Data layer** (`data/cves/`, `data/attack-taxonomy/`, `data/schemas/`) stores
   per-entry, cited, machine-readable records. YAML is canonical; Markdown and
   CSV indexes are generated.
3. **Software layer** (`software/hidwatch/`) is a stdlib-only core with models,
   hostile-input descriptor parser, transparent analyzer/policy, synthetic
   fixtures, read-only inventory/lifecycle backends, and CLI. The Linux backend
   models attach, detach, and metadata/interface changes by diffing sysfs
   snapshots without claiming devices. It performs no core network calls.
4. **Lab layer** (`lab/`) contains synthetic fixtures and authorized experiment
   plans. Real keystrokes/captures are excluded.
5. **Hardware/product layer** (`hardware/`, `products/`) separates speculative
   designs from implemented artifacts.

## Trust and data flow

Device attributes, descriptors, reports, files, and captures are untrusted.
Parsers bound every read and allocation. Findings are derived from explicit
signals. No raw keystroke content should leave the machine or enter project
logs; metrics should prefer key-state counts/timing over decoded text.

## Dependency policy

The hidwatch core uses the Python standard library only. Development tools are
pinned by compatible ranges in `pyproject.toml`. Optional Linux integrations
remain isolated behind backends. This reduces supply-chain and installation
risk while preserving testability.

## Intended evolution

The same typed models, parser, policy, and corpus should be reusable in a Linux
agent and in an inline gateway. Hardware enforcement is not treated as a simple
port of Python: the critical data plane must be small, memory-safe, bounded,
independently fuzzed, and fail according to explicit availability/security
policy. See `products/hid-firewall/architecture.md`.
