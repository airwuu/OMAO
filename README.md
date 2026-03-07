# IoT Signal Watch

React + Vite dashboard for monitoring IoT-only home devices with:

- Hub-and-spoke network graph
- Severity-colored nodes (good/suspicious/blocked)
- Per-device metric charts (latency, packet loss, block events)
- Advisory panel (mock outage/security findings)
- CRT-inspired lo-fi hacker UI aesthetic

## Run

```bash
npm install
npm run dev
```

App runs at http://localhost:5173 by default.

## API (mocked inside Vite)

- `GET /api/iot/devices`
- `GET /api/iot/devices/:id/metrics?range=1h`
- `GET /api/iot/devices/:id/advisories`

## Tests

```bash
npm test
npm run test:e2e
```
