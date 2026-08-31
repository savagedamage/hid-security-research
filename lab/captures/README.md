# Captures (intentionally empty)

Real HID captures are **never** committed here — a recording of real typing is
effectively a keylog and may contain secrets (see ../../SECURITY.md §5).
`.gitignore` blocks binary capture formats in this directory.

Only synthetic scenarios belong in the project, and they live in
`lab/fixtures/` as JSON, not here. This directory exists as a documented,
git-tracked placeholder for local, personal, non-committed analysis captures.
