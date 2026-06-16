# CLAUDE.md

Template for a **holistic service**. A developer clones it, runs `./service init <name>`, and
builds out the backend + dashboard plugin. The holistic SDK (`@holistic/ui`) is **consumed
only** — never vendored or modified here.

## Where things are

- `service` — the CLI. Auto-detects the service id from `permissions/<id>.json`; owns
  `init`/`setup`/lifecycle and generates the systemd unit, Caddy route and rights drop-in inline.
- `backend/internal/auth/auth.go` — shared-JWT (`h_access`) validation, live OS group/admin
  resolution, CSRF. Service-agnostic; reuse as-is.
- `backend/internal/api/api.go` — the HTTP surface under `/api/services/<id>/`. The `guard`
  helper does auth → optional right → optional CSRF. Add routes here.
- `backend/internal/rights/` — the `hp_*` group constant(s); mirror `permissions/<id>.json`.
- `ui/index.tsx` — default-exports the `ServicePlugin`; `id` MUST equal the manifest `service`.
- `ui/Dashboard.tsx` — the plugin UI; renders **only** `@holistic/ui`, gates with `userHasRight`.

## Rules

- Enforce every right as `isAdmin || group ∈ user.groups`, in both the backend and the UI.
- Keep three things in sync: `permissions/<id>.json` ⇄ `internal/rights` ⇄ the UI right constant.
- UI may import only `@holistic/ui` and `react` (holistic's `eslint.services.cjs` enforces it).
- The daemon runs unprivileged and escalates nothing. Privileged work needs a narrow sudo
  wrapper (see `sxty9/hostek`), not blanket sudo.

## Verify (from the repo root)

```bash
(cd backend && go build ./... && go vet ./...)
python3 ../holistic/services/dashboard/lib/holistic-perms.py validate ./permissions
```
