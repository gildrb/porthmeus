# Porthmeus

Open your development server on any device in your tailnet. Porthmeus runs your dev command, discovers its loopback port, and prints a private Tailscale Serve HTTPS link. Your browser stays local; code, builds, and the server stay on the development machine.

```sh
curl -fsSL https://porthmeus.com/install | sh   # or: nix profile install github:gildrb/porthmeus
porthmeus vp dev                                # any dev command; open the printed link (short: p vp dev)
```

Everything binds to 127.0.0.1. Only Tailscale exposes HTTPS, Serve never Funnel, under your tailnet access rules; certificate names are public in Certificate Transparency logs, the site is not. Host and Origin must match the route or the request gets 403. Each invocation owns only its own Serve route; exit removes exactly it, and `tailscale serve reset` is never run.

The bridge is one static Rust binary with no runtime: stack buffers and no per-request name resolution, one-thread `poll(2)` relay for WebSocket, discovery that reads `/proc` and the kernel socket tables directly on Linux, and child output in an unlinked temp file — no capture threads.

`porthmeus dashboard` lists every listening server your user owns with its Porthmeus URL, working directory, and command. `x` then `y` stops a row, `x` again offers a force-kill, `r` refreshes, `q` quits.

Requires Tailscale signed in on both devices with MagicDNS, HTTPS certificates, and access rules for the port, plus the project's usual tools. On Linux, once: `sudo tailscale set --operator="$USER"`. Porthmeus uses tailscaled's local socket where one exists, otherwise the `tailscale` CLI (`--tailscale-cli`).

The installer checks the release against `SHA256SUMS`, installs `porthmeus` and `p` in `~/.local/bin`, and never uses sudo. Run it again to update; `sh -s -- 0.4.0` pins a release.

```sh
nix run github:gildrb/porthmeus -- vp dev    # without installing
nix build && ./result/bin/porthmeus vp dev   # or: cargo install --path . (Rust 1.80+)
```

The flake also exports `nixosModules.default`, `darwinModules.default`, `homeManagerModules.default`, and `overlays.default`. Porthmeus is not a daemon: use a persistent terminal to survive an SSH disconnect, and a hard kill can leave child processes alive.

MIT ([LICENSE](LICENSE)).
