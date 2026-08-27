# Sample captures

## `ot-all-findings-demo.pcap`

A small, **fully anonymized** synthetic OT capture that trips as many PicoCap
findings as can coexist in one file — for demos, screenshots and the QA gate.

```bash
picocap samples/ot-all-findings-demo.pcap
```

**Triggers** (one file): SPAN double-capture **+ egress-tag artifact**, NIC-offload
super-frames (TSO/GRO), inner-length truncation, VXLAN on legacy UDP 8472,
malformed VXLAN header (RFC 7348 §5), timestamp discontinuity (merge/replay), and
TCP capture-drops (sequence gaps + ACKed-unseen). Verdict: **REVIEW**.

**Not triggered** — `mirror_no_unicast` needs <2 % unicast, which is mutually
exclusive with the TCP-rich traffic every other finding needs. You can't have a
capture that is both busy with sessions *and* almost pure ARP.

**Anonymized by construction** — RFC 1918 / RFC 5737 (TEST-NET) addresses only,
locally-administered MACs (`02:…`), dummy payloads. No real hosts, no real data.
Verified: every IP is private/documentation, every MAC has the locally-administered
bit set.

Regenerate deterministically (no randomness) with:

```bash
python3 samples/make-demo-pcap.py samples/ot-all-findings-demo.pcap
```
