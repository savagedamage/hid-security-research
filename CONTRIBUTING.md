# Contributing to hid-security-research

Thank you for your interest. This project aims to be a **serious, citable,
professionally organized HID security research resource**. Contributions are
welcome across three broad tracks:

1. **Research** — threat model refinements, new (public) dataset entries,
   documentation of how HID actually works, academic paper summaries.
2. **Software** — the `hidwatch` monitoring tool, parsers, analyzers, fixtures.
3. **Hardware / product research** — design documents for the HID firewall and
   secure-keyboard concepts.

Please read `SECURITY.md` and `CODE_OF_CONDUCT.md` first. The ethical boundaries
in `SECURITY.md` are **not optional**.

Last reviewed: 2026-08-31

---

## Contact / maintainers

Until a dedicated security contact is published, reach maintainers via GitHub
issues (for non-sensitive matters) or GitHub **private vulnerability reporting**
(for anything sensitive). Do not put 0-days or secrets in public issues.

---

## Research quality rules (READ THIS)

These rules are the heart of the project. Contributions that violate them will
be rejected.

1. **Do not fabricate.** No invented CVEs, incidents, dates, or device
   behaviors. If you cannot cite it, do not assert it.
2. **Cite primary sources.** Prefer NVD/CVE, MITRE, CISA, vendor advisories,
   kernel commits, and peer-reviewed papers over blog posts and search-result
   summaries. Preserve the source **URL** and an **access date**.
3. **Use the evidence vocabulary.** Every claim about device behavior should be
   labeled with one of:
   `observed` · `documented` · `demonstrated` · `reported` · `inferred` ·
   `theoretical`. See `GLOSSARY.md` for definitions.
4. **Classify honestly.** Label each dataset entry as one of:
   `CVE` · `academic-research` · `proof-of-concept` · `documented-incident` ·
   `security-product` · `theoretical-threat`. Do not conflate a marketing claim
   with a demonstrated attack.
5. **Record dates.** Every dataset entry and research page carries a
   `last_reviewed` date.
6. **Document disagreement.** When sources conflict, say so and cite both.
7. **Confidence.** Dataset entries carry a `confidence` field
   (`high`/`medium`/`low`) reflecting how well-corroborated the entry is.

---

## Dataset contributions

The canonical dataset lives in `data/cves/` as per-entry YAML files validated
against `data/schemas/cve-entry.schema.json`. To add an entry:

1. Copy `data/cves/_TEMPLATE.yaml` to `data/cves/<id>.yaml`.
2. Fill every required field. Use `null` for genuinely unknown values, not
   guesses.
3. Validate locally:
   ```bash
   python -m pip install -e "software/hidwatch[dev]"
   python scripts/research-tools/validate_dataset.py
   ```
4. CI will re-run validation on your pull request.

Only **public** vulnerabilities may be added (see `SECURITY.md` §3).

---

## Software contributions

The `hidwatch` package lives in `software/hidwatch/`. Development setup:

```bash
cd software/hidwatch
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

Before opening a pull request, run the full local gate:

```bash
ruff check .          # lint
ruff format --check . # formatting
mypy src              # type checking
pytest                # tests
```

All of these run in CI (`.github/workflows/ci.yml`). Keep them green.

Coding conventions:

- Python 3.10+; fully type-annotated public APIs.
- Parsers must treat all input as hostile. Never `assert` on parsed data; raise
  typed exceptions and fuzz-test the parser.
- No network calls in the core library. `hidwatch` observes locally; it does not
  phone home. (This is a deliberate design constraint — the tool that monitors
  for exfiltration must not itself exfiltrate.)

---

## Commit conventions

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `docs:` documentation and research prose
- `research:` dataset / taxonomy / literature additions
- `feat:` new software capability
- `fix:` bug fix
- `test:` tests and fixtures
- `ci:` CI/tooling
- `chore:` housekeeping

Make focused, logical commits. Do not squash unrelated work into one commit.

---

## Pull request checklist

- [ ] Follows the research quality rules above
- [ ] Primary sources cited with URLs and access dates
- [ ] `last_reviewed` dates set
- [ ] Evidence labels applied where relevant
- [ ] Local gate passes (lint, format, types, tests)
- [ ] No secrets, no real keystroke captures, no weaponized payloads
