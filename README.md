# nethernet

NetherNet for Minecraft: Bedrock Edition: the WebRTC-based transport newer Bedrock
clients use for friends lists, LAN games and Xbox Live joins, with full low-level
access for servers.

**Status:** in development. The API will change as low-level hooks are added.

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

## Contributing

See the [contributing guide](https://github.com/helix-bedrock/.github/blob/main/CONTRIBUTING.md).

## License

MIT. See [`LICENSE`](LICENSE). The original copyright notice from go-nethernet is kept,
as the MIT license requires. Sources are listed in [`CREDITS.md`](CREDITS.md).
