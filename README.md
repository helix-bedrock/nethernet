# nethernet

NetherNet for Minecraft: Bedrock Edition: the WebRTC-based transport newer Bedrock
clients use for friends lists, LAN games and Xbox Live joins, with full low-level
access for servers.

**Status as of 2026-10-29:** in development. The API will change as low-level hooks are added. Server identity keys load, save and generate the way BDS 1.26.60 does (`keys/server_identity_key.pem`).

Part of [Helix](https://github.com/helix-bedrock), an open-source Minecraft: Bedrock
Edition server engine in Go. Helix maintains this library.

## Origin

This library started as a copy of [go-nethernet](https://github.com/df-mc/go-nethernet)
by **Dragonfly Tech** (the df-mc team, MIT). Thank you to them for the original work.
Helix maintains and changes it from here on.

It uses [Pion WebRTC](https://github.com/pion/webrtc) for the WebRTC layer.

## Packages

| Package | What it does |
|---|---|
| `nethernet` | Listener, dialer and connections over WebRTC data channels |
| `nethernet/discovery` | LAN discovery: broadcasting and finding servers on the local network |
| `nethernet/endpoint` | Signaling through Xbox Live / Minecraft services |

## Install

```bash
go get github.com/helix-bedrock/nethernet
```

## Hooks

Hooks give full low-level access to every stage of a NetherNet connection. Add or
remove them at any time; a hook that is not registered costs nothing (about 3 ns
and no allocations per check). Hooks can observe, change or drop what passes
through them (`return nethernet.Drop`), and a panicking hook is logged instead of
crashing the server.

```go
remove := listener.OnConnectionAttempt(func(e *nethernet.AttemptEvent) nethernet.Verdict {
    if banned(e.NetworkID) {
        return nethernet.Drop
    }
    return nethernet.Allow
})
defer remove()

conn.OnPacketIn(func(e *nethernet.PacketEvent) nethernet.Verdict {
    log.Printf("%d bytes on %v", len(e.Data), e.Reliability)
    return nethernet.Allow
})
```

| Hook | Listener | Conn | Sees |
|---|---|---|---|
| `OnSignalIn` / `OnSignalOut` | ✓ | | Every signal: offers, answers, ICE candidates, errors |
| `OnConnectionAttempt` | ✓ | | New offers: network ID, connection ID, SDP |
| `OnConnect` / `OnDisconnect` | ✓ | `OnDisconnect` | Connection lifecycle |
| `OnStateChange` | ✓ | ✓ | ICE, DTLS and SCTP state changes |
| `OnMessageIn` / `OnMessageOut` | ✓ | ✓ | Raw data-channel messages (each segment) |
| `OnPacketIn` / `OnPacketOut` | ✓ | ✓ | Complete packets after reassembly / before splitting |

The `discovery` listener has `OnPacketIn` and `OnPacketOut` for LAN discovery
packets, with address, sender ID, decoded packet and raw bytes.

## Contributing

See the [contributing guide](https://github.com/helix-bedrock/.github/blob/main/CONTRIBUTING.md).

## License

MIT. See [`LICENSE`](LICENSE). The original copyright notice from go-nethernet is kept,
as the MIT license requires. Sources are listed in [`CREDITS.md`](CREDITS.md).
