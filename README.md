# nethernet

[![Discord](https://img.shields.io/discord/1568071670097518763?label=discord&logo=discord&logoColor=white&color=5865F2)](https://discord.gg/Fbmc69Gqr7)

NetherNet for Minecraft: Bedrock Edition: the WebRTC-based transport newer Bedrock
clients use for friends lists, LAN games and Xbox Live joins, with full low-level
access for servers.

**Status as of 2026-11-09:** in development. The API will change as low-level hooks are added. `Conn.Close` waits up to 2 seconds for everything sent to be acknowledged, so a last disconnect reaches the client. Server identity keys load, save and generate the way BDS 1.26.60 does (`keys/server_identity_key.pem`).

Part of [Helix](https://github.com/helix-bedrock), a source-available Minecraft: Bedrock
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

Noncommercial use only: [PolyForm Noncommercial 1.0.0](LICENSE) with Helix's
[extra permissions](ADDITIONAL-PERMISSIONS.md). Anyone may use it, run servers with it
(even ones that make money) and sell their own plugins, but nobody may sell Helix or its
code. Helix's game behaviour is re-engineered from Minecraft's Bedrock Dedicated Server;
see [NOTICE.md](NOTICE.md). Not an official Minecraft product. Not approved by or
associated with Mojang or Microsoft.

The initial import from go-nethernet keeps its MIT license; see [CREDITS.md](CREDITS.md)
and [`licenses/`](licenses).
