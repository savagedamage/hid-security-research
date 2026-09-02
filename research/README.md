# Research Directory

The canonical machine-readable catalog is `../data/cves/`. This directory is for
long-form analysis that cannot be represented faithfully in one dataset entry:
advisory comparisons, attack mechanics, paper critiques, case studies, and
technology evaluations. Every page must cite sources and include a
`Last reviewed` date and evidence labels per `../GLOSSARY.md`.

Do not put non-public vulnerabilities, weaponized payloads, firmware blobs, or
real keystroke captures here. See `../SECURITY.md`.

Start with [`scope-and-inclusion.md`](scope-and-inclusion.md) before triaging a
new lead. The generated [`coverage.md`](coverage.md) identifies catalog gaps;
discovery-stage leads belong in `../data/research-queue/`, not directly in the
canonical catalog.
