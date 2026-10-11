# AGENTS.md

Rules for AI coding agents working in this repo. Also read the org-wide rules in
`../.github/AGENT_RULES.md` (online:
<https://github.com/helix-bedrock/.github/blob/main/AGENT_RULES.md>). Where they
disagree, this file wins for this repo.

## What this repo is

The NetherNet transport for Helix: Minecraft Bedrock connections over WebRTC
data channels, LAN discovery, and signaling. The WebRTC stack itself is Pion.

## Commands

```bash
go build ./...
go vet ./...
golangci-lint run
go test -race ./...
```

## Layout

- Root package: `Listener`, `Dialer`, `Conn`, signaling and negotiation.
- `discovery`: LAN discovery packets and listener.
- `endpoint`: signaling through Minecraft services.
- `examples`: runnable examples.

## Invariants: do not break these

1. Behaviour matches vanilla Bedrock NetherNet.
2. The original copyright line in `LICENSE` stays.
3. Never panic (see the org rules).

## Gotchas

- Imported from go-nethernet; see `CREDITS.md`.
