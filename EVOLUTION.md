# PicoCap — Evolution log

Every shipped change to what PicoCap detects or how it runs, newest first.
Each entry is backed by `cargo test` and a semantic version bump in `Cargo.toml`.

## v1.3.0 "Wolfhound" — 2026-08-27

**Capture-source fingerprint, mirror-blindness & timestamp-integrity checks, TTL-tolerant double-capture.** Grounded in a review of ~180 vendor/forum field reports on SPAN/mirror/TAP behaviour and confirmed against the local corpus.

- **(A) Capture-source fingerprint** — an informational `Capture source` line infers where the file came from (tunnel mirror ERSPAN/GRE/VXLAN · host capture tcpdump/Wireshark, via NIC offload or the 262144 default snaplen · local SPAN / unknown). Metadata inference, explicitly *not* a device verdict. (Corpus: host vs mirror captures separate cleanly — host = offload + no truncation, mirror = truncation + more drops.)
- **(B) Mirror sees only ARP/broadcast** — a notice when <2 % of frames are unicast and >90 % are ARP/broadcast/multicast: a virtual bridge (Proxmox/ESXi/Hyper-V) is eating the mirror frames, offload is bypassing the sniffer, or the mirror source is wrong. The #1 recurring forum symptom.
- **(C) TTL-tolerant double-capture** — the SPAN double-capture detector now hashes the inner L3 with the router-rewritten fields (IPv4 ToS/TTL/checksum, IPv6 hop limit) masked, so a **routed** both-direction mirror — whose copies differ only in TTL — is caught, not just switched (byte-identical) mirrors. `ERSPAN-BOTH` went 42 % → 43 %.
- **(D) Timestamp-integrity** — a notice for a >1-day inter-frame jump (merged/replayed capture, timing unreliable) and a separate one for astronomical jumps (broken capture clock, e.g. a hardware-timestamping TAP whose dissector plugin is missing → "billions of seconds").

Tests: 17 → 19. Sources: packet-foo, Security Onion, Wireshark/Zeek wikis, Great Scott Gadgets, Profitap, vendor communities.

## v1.2.0 "Foxhound" — 2026-08-27

**More capture-drop evidence, encapsulation RFC conformance, sourced findings, trust note.**

Added detections (all capture-usability / encapsulation-conformance, charter-conform):
- **ACKed-unseen segments** — a receiver ACKs data whose sequence end was never
  captured = capture drop. Folded into the `No capture drops (TCP seq)` check
  alongside sequence gaps. On `openplc_vxlan`: 9,200 ACKed-unseen (tshark
  `ack_lost` ≈ 9,851 — same order).
- **Inner-length truncation** — inner IP total-length > captured bytes (tunnel/MTU
  or snaplen cut), as a notice.
- **NIC offload artifacts** (TSO/GRO super-frames) — notice from the oversize tally.
- **VXLAN on legacy UDP 8472** (vs RFC 7348 port 4789) — decoded and flagged.
- **Malformed VXLAN header** — 'I' flag clear = **RFC 7348 §5 violation**.

Sourcing & trust (per user request):
- Every criterion now carries an authoritative **source** (RFC 9293, RFC 7348,
  Wireshark/Zeek/Suricata, packet-foo, SANS ISC), surfaced in the JSON (`source`
  per check), the Markdown report (`## Sources per finding`), and the GUI (source
  line under each check).
- A **trust note** on every report and in the GUI footer: processed locally, no
  cloud, deterministic local algorithms developed with Claude and calibrated
  against a golden set cross-checked with tshark.
- `docs/CHECKS.md` — per-check explanation of why each check fires, with sources.

Scope boundary reaffirmed: per-application RFC-violation / anomaly detection and
network-fault verdicts remain out of scope (network-side analysis, not capture usability).

Tests: 15 → 17 (ACKed-unseen, inner-length truncation).

## v1.1.0 "Bloodhound" — 2026-08-27

**TCP session integrity + large-file streaming** (capture usability, charter-conform).

Added — one bounded per-flow state map keyed by the canonical 5-tuple:
- **Handshake coverage**: complete (SYN + SYN-ACK) / SYN-only (one-directional
  capture?) / mid-stream (capture started after the session).
- **Capture-drop detection**: forward TCP sequence gaps = segment(s) the
  endpoints exchanged but the file is missing (SPAN/collector drop). New scored
  criterion `No capture drops (TCP seq)` — a gap pulls conformance below 100.
- **Frame-length anomalies**: runt (<60 B) and oversize (>1518 B) tallies.
- Surfaced across **CLI text, JSON API (`session` object), Markdown report, and
  the web GUI** (session/completeness chips).

Large files:
- The CLI now **streams the capture from disk** (`analyze_core<R: Read>`, 16 MB
  reader window, streamed SHA-256) instead of reading the whole file into RAM.
  Peak RSS on a 1.5 GB capture dropped from **3242 MB → 87 MB** (identical
  results); multi-GB captures (e.g. 5.4 GB) are now processable. The GUI upload
  path keeps the in-memory slice (bounded by `max_upload`). Both share
  `analyze_core`, with a regression test asserting streaming == in-memory.

Scope boundary reaffirmed: sequence *gaps* (a capture-usability fact) stay here;
**network-fault verdicts** (retransmission storms, routing loops, DNS/RST-storms,
duplicate-IP) are explicitly **out of scope** (network-side analysis). Validated against a
deduplicated local corpus (669 unique captures) and cross-checked with `tshark`
(e.g. `openplc_vxlan`: 5174 picocap gaps vs 5469 tshark `lost_segment`).

Tests: 12 → 15.

## v1.0.0 "Groundhog" — initial release

Read-only intake checker: container integrity + SHA-256, PCAP Collection Guide
conformance, packet distribution, VLAN/QinQ + GRE/ERSPAN/VXLAN decode,
encapsulation-chain distribution, SPAN double-capture (TX+RX) detection, capture
metadata. Conformance score, CLI + embedded web GUI, hardened Docker image.
