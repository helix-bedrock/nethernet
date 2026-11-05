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

- Root package: `Listener`, `Dialer`, `Conn`, signaling and negotiation, port mappings (`portmapping.go`, BDS's server-udp-ports), the server identity key file (`identity_key.go`, as BDS keeps it) and limits and pion settings (`limits.go`).
- `discovery`: LAN discovery packets and listener.
- `endpoint`: HTTP signaling as BDS does it (`Handler.ServeListener` is its own HTTP server, with its routes, replies, limits and TLS refusal), and signaling through Minecraft services.
- `signaling`: signing in to Microsoft's signaling service as BDS does (Azure AD token, WebSocket JSON-RPC, ICE servers).
- `examples`: runnable examples.

## Invariants: do not break these

1. Behaviour matches vanilla Bedrock NetherNet for real clients. The limits in `limits.go`, the per-address cap in `endpoint/server.go` and the local-only LAN check in `discovery/local.go` are stricter than BDS on purpose: they only stop floods and oversized input.
2. The original copyright line in `LICENSE` stays.
3. Never panic (see the org rules).

## Gotchas

- Imported from go-nethernet; see `CREDITS.md`.
