# AGENTS.md — olom_scan

## Project overview
- This repository is a Python/FastAPI backend with a React + Vite frontend for network scanning, MikroTik/RouterOS API inventory, device reports, backups, and a local client-side VPN agent.
- Main code areas: `backend/main.py`, `backend/db.py`, `backend/routeros_api.py`, `frontend/src.jsx`, `frontend/style.css`, and tests under `tests/`.
- User-facing text is primarily Persian. Preserve Persian labels and right-to-left layout.

## Working rules for coding agents
1. Before editing, inspect the current branch, relevant files, tests, and recent history. Do not assume older chat summaries reflect the current repository.
2. Keep changes focused and backward-compatible. Do not merge into `main` unless explicitly requested.
3. Never claim tests passed unless they were actually run and their results are available. Distinguish unit/CI tests from real network or Windows VPN tests.
4. Do not log passwords, API credentials, VPN configuration contents, private keys, or other secrets. Avoid persisting sensitive VPN configuration unless the feature explicitly requires it and storage is protected.
5. RouterOS API calls must use bounded timeouts, handle per-device failures independently, and support cancellation for long-running batches.
6. Progress reporting must reflect the whole operation, including database/file persistence after network reads; do not display 100% as finished while post-processing is still running.
7. Prefer bounded concurrency for network operations. Avoid serial network requests or repeated full-database reads in loops.
8. Bind local-only agents to loopback by default. Validate local-agent requests against loopback/Host/Origin as appropriate; never expose arbitrary process-launch endpoints to remote clients.
9. For frontend changes, check loading, empty, error, and success states; ensure controls remain visible and accessible, and keep status updates understandable.
10. Add or update tests for behavioral changes. Run backend tests and frontend build when the environment allows; report any unrun checks explicitly.

## Suggested verification
- Backend: install `requirements.txt`, then run the repository's configured pytest command.
- Frontend: in `frontend/`, run `npm ci` (or `npm install` if no lockfile) and `npm run build`.
- For RouterOS API and VPN features, use mocks for automated tests and separately document any required real-device/Windows verification.
