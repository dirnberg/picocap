# PicoCap Manifest — inherited, and only what is actually implemented

PicoCap descends from **APEX.ai**, whose self-evolving OT manifest (seeded in turn
from the *Vibecoding* manifest) defines how the tool is built. This file records
**only the parts of that manifest that PicoCap actually implements** — nothing
aspirational.

## What PicoCap is

A tiny, **read-only** PCAP/PCAPNG *intake checker*. In scope: container integrity
+ SHA-256, PCAP Collection Guide conformance, packet distribution, VLAN/QinQ and
GRE/ERSPAN/VXLAN decode, encapsulation-chain distribution, **SPAN double-capture
(TX+RX)** detection, capture metadata.

**Not in scope** (same exclusions as the parent): active scanning, packet
manipulation, TLS decryption, anomaly ML / detection rules. PicoCap only answers
*"is this capture clean and usable?"*.

## The cycle (as realized)

Each detection (e.g. SPAN double-capture) is backed by a **test** (`cargo test`,
synthetic captures) and shipped under a **semantic version** (`v1.0.0`) — never as
a silent ad-hoc fix. Detection was validated against real ERSPAN captures and
cross-checked with `tshark`.

## Principles — realized

| # | Principle (from the parent manifest) | In PicoCap |
|---|---|---|
| 1 | Understand the real traffic first — no check without a real or synthetic test capture | ✅ verified vs real ERSPAN captures + `tshark`; synthetic tests for VLAN/QinQ/VXLAN/ERSPAN |
| 2 | Security over convenience — passive, no manipulation | ✅ read-only; never rewrites or forwards; localhost by default + optional token |
| 3 | KISS — the simplest thing that works | ✅ pure Rust, no `libpcap`, single binary, GUI embedded via `include_str!` |
| 4 | YAGNI — no speculative features | ✅ checker only; dropped non-verifiable criteria; MVP scope |
| 5 | One responsibility per check | ✅ each collection criterion is a separate, atomic check |
| 6 | DRY | ✅ the assessment report has a single source (Rust `markdown_report`); the CLI `--report` and the GUI both use it |
| 7 | Measure before optimize | ◑ distributions/chains cross-checked with `tshark`; no perf tuning needed yet |
| 8 | Context is code — small diffs, commit after each working state | ✅ (and: no `git --amend` after push) |

## Security principle (non-negotiable) — satisfied

The parent's **three-capabilities rule**: no flow may combine (a) access to
sensitive capture data, (b) foreign alert/config content, and (c) the ability to
send outward. PicoCap **breaks the triad by design** — it never sends anywhere:
no SIEM, no upload, no network egress. It reads one local file and shows a result.
Foreign content (file contents, uploads) is treated as **data, never as
instructions**.

## Wording rules (applied to checks & notices)

Every check/notice is **atomic** (one criterion), **testable** (has a test),
**active** (states what is wrong), **example over description** (real counts, chain
strings, dup %), and **marks obligation** (PASS / DEVIATION / FAIL). No weasel
words.

## Versioning

`MAJOR.MINOR.PATCH` in `Cargo.toml`; release notes in the README.
PATCH = a check refined + test · MINOR = a new check/notice · MAJOR = a check
removed or reversed.

---

*Lineage: Vibecoding manifest → APEX.ai manifest → PicoCap (this file = the
implemented subset).*
