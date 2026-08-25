# PicoCap — project notes for Claude Code

Tiny **read-only** PCAP/PCAPNG intake checker (Rust, CLI + embedded web GUI).
Checks a capture against the PCAP Collection Guide: conformance score,
VLAN/GRE/ERSPAN/VXLAN breakdown, encapsulation-chain distribution, and
**SPAN double-capture (TX+RX)** detection. Never rewrites or forwards files.

- Repo: https://github.com/dirnberg/picocap · release `v1.0.0 "Groundhog"`
- Pure Rust: `pcap-parser`, `sha2`, `axum`. No `libpcap`, no system deps.

## Layout
- `src/main.rs` — CLI, decoder, checks, HTTP server, **and the test module** (`#[cfg(test)]`)
- `src/index.html` — web GUI, embedded via `include_str!`
- `picocap.yml` — config + token (**not in git**, `chmod 600`); example: `picocap.example.yml`
- `Dockerfile` / `docker-compose.yml` — hardened image (non-root, read-only, localhost)

## Commands
```bash
cargo test                       # regression suite (synthetic captures incl. VXLAN/QinQ/ERSPAN)
cargo build --release
./target/release/picocap <file>        # text summary
./target/release/picocap --report <f>  # Markdown report to stdout
./target/release/picocap serve         # GUI (default 127.0.0.1:8088)
docker compose up -d                   # token from .env
```

## Conventions
- After a fix, add/extend a test in the `#[cfg(test)] mod tests` in `main.rs`.
- **Never `git commit --amend` once pushed** — make a new commit (avoids force-push).
- Keep secrets out of git: `picocap.yml`, `.env` are git-ignored — never track them.
- Config/thresholds live in `picocap.yml`; env overrides `PICOCAP_TOKEN` / `PICOCAP_LISTEN`.
- Product wording: say "capture", not "customer".
