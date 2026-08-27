# Security

PicoCap only **reads** capture files — it never modifies, deletes or forwards
them, writes nothing to disk when serving, and has no system dependencies.

## Hardening checklist

- **Bind to localhost** (default `listen_addr: 127.0.0.1:8088`). Expose on the LAN
  only with a token set.
- **Set `auth_token`** (or `PICOCAP_TOKEN`) to require a token for the GUI and API.
  Generate one with `head -c 24 /dev/urandom | base64 | tr -d '/+=' | cut -c1-32`.
- **The token is not encryption.** HTTP transmits it in the clear. For access over
  untrusted networks use an SSH tunnel (`ssh -L 8088:127.0.0.1:8088 user@host`) or a
  TLS reverse proxy (Caddy/nginx).
- **Protect `picocap.yml`** — `chmod 600`. It holds the token in plain text and is
  git-ignored so it is never committed.
- **Docker:** run unprivileged and read-only, and bind only to localhost:
  `docker run -p 127.0.0.1:8088:8088 -e PICOCAP_TOKEN=… --read-only --cap-drop ALL
  --security-opt no-new-privileges --tmpfs /tmp picocap:1.4.0`.

## Reporting a vulnerability

Please report security issues privately to the maintainer rather than opening a
public issue.
