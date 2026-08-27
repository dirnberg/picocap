# PicoCap — what each check means and why it fires

PicoCap answers one question: **is this capture clean and usable as evidence?**
Every check below is a deterministic, local algorithm. **No packet data ever
leaves the machine and no cloud service is contacted.** The detection logic was
developed with the help of Claude and calibrated against a *golden set* of real
captures, cross-checked against `tshark`.

Each finding cites a primary source (RFC / vendor / expert) so a reviewer can
verify the reasoning independently.

---

## Collection criteria (scored)

### 1 · Format `.pcap` / `.pcapng`
**Fires when** the file has no valid pcap/pcapng magic or an unknown container.
**Why it matters** a non-capture file cannot be analysed at all.
**Source** pcap/pcapng file format (IETF opsawg pcapng draft; libpcap).

### 2 · Container integrity
**Fires when** the parser cannot reach the end of the file cleanly (truncated tail,
corrupt block, a record longer than the file).
**Why it matters** a damaged container means missing or unreadable packets — the
evidence is incomplete before analysis even starts.
**Source** libpcap/pcapng block structure; `pcapfix`.

### 3 · Full-packet capture (`-s 0`)
**Fires when** frames are truncated (`origlen > caplen`) or the snaplen is below
full-frame. **Why it matters** truncated payload cannot be reassembled, decrypted
or matched against IDS rules. **Source** `tcpdump(1)` snaplen; SANS ISC — snaplen
truncation.

### 4 · Size ≤ limit per file
**Fires when** the file is larger than the configured guideline (default 500 MB) or
implausibly small. **Why it matters** oversized files are unwieldy and often the
sign of an unfiltered capture; tiny files are not representative. **Source** PCAP
Collection Guide; packet-foo.com capture playbook.

### 5 · Multiple end devices
**Fires when** only one (or no) source device is visible. **Why it matters** a
single MAC usually means the SPAN/mirror port or promiscuous mode is wrong and you
are seeing one link direction, not the segment. **Source** Wireshark Wiki —
SPAN/mirror & promiscuous mode; Security Onion sniffing pitfalls.

### 6 · Representative time window
**Fires when** the capture spans less than the configured minimum. **Why it
matters** a few seconds of traffic is not representative of the segment's
behaviour. **Source** packet-foo.com capture playbook.

### 7 · No capture drops (TCP seq)  — *the core capture-completeness check*
**Fires when** TCP **sequence gaps** and/or **ACKed-unseen** segments are present.
- A *sequence gap* = a segment starts beyond the next expected sequence number in
  its direction → a segment the sender transmitted is **missing from the file**.
- An *ACKed-unseen* = a receiver ACKs data whose sequence end was never captured →
  the **capture dropped** that data (the endpoints had it, the file does not).
Both point to a capture/SPAN drop, not a network fault. Sequence math uses on-wire
IP lengths, so it is robust to snaplen truncation.
**Why it matters** dropped segments mean the capture is not a faithful record — it
cannot be used as complete evidence. **Source** RFC 9293 (TCP) §3.4; Wireshark
Expert "ACKed segment that wasn't captured" / "previous segment not captured";
Zeek `capture_loss.log`.

### 8 · TCP session coverage (informational)
Reports, per session: **complete** handshake (SYN + SYN-ACK), **SYN-only** (SYN
but no SYN-ACK → possibly a one-directional capture or a dead service), and
**mid-stream** (data before any SYN → the capture started after the session began).
**Why it matters** it tells you whether the capture window and both directions are
actually covered. **Source** RFC 9293 (TCP) §3.5 three-way handshake; Wireshark
`tcp.analysis`.

---

## Capture-quality notices (encapsulation & RFC conformance)

### SPAN double-capture (TX + RX)
Frames recur within 5 ms whose inner L3 is identical once the router-rewritten
fields (IPv4 ToS/TTL/checksum, IPv6 hop limit) are masked — the mirror captures
both TX and RX, so each frame appears twice (read as spurious retransmissions).
Masking those fields catches a **routed** both-direction mirror too, whose copies
differ only in TTL, not just a switched byte-identical one. Mirror RX-only or
TX-only. When the two copies differ in VLAN tagging (one tagged, one not) the
notice adds that the **egress copy is tag-carrying** — a chipset egress-tag
artifact (HP/Aruba, Cisco SG200, Juniper EX). **Source** Keysight/Gigamon SPAN
de-duplication; packet-foo.com; `editcap(1) -d`.

### Capture source (informational)
A fingerprint of where the file most likely came from — *tunnel mirror*
(ERSPAN/GRE/VXLAN present), *host capture* (NIC-offload super-frames, or the
tcpdump/dumpcap default snaplen 262144), or *local SPAN / unknown*. It is an
inference from the metadata, **not** a verdict on the exact device. **Source**
corpus study (host vs mirror captures separate cleanly); packet-foo.com.

### Almost no unicast — mirror not seeing switched traffic
Fires when <2 % of frames are unicast and >90 % are ARP/broadcast/multicast: the
sniffer sees discovery noise but not the switched unicast conversations — a virtual
bridge (Proxmox/ESXi/Hyper-V) is eating the mirror frames, hardware offload bypasses
the sniffer, or the mirror source is wrong. Verify with a bare laptop + Wireshark.
**Source** packet-foo.com; Security Onion; forum consensus.

### Timestamp discontinuity / implausible timestamps
A >1-day jump between consecutive frames means the file is a **merge/replay** of
separate captures (timing unreliable, analyse the segments apart); an astronomical
jump means a **broken capture clock** (e.g. a hardware-timestamping TAP whose
dissector plugin is missing, so timestamps read as billions of seconds). **Source**
packet-foo Multi-Point Capture; `mergecap(1)`; Profitap ProfiShark KB.

### NIC offload artifacts (TSO/GRO)
Frames far above the 1518 B MTU never existed on the wire — the capture host
reassembled them, breaking target-based IDS reassembly. Disable offload
(`ethtool -K … gso off gro off tso off lro off`) or capture at a TAP.
**Source** Wireshark "Offloading" wiki; Suricata Packet Capture docs.

### VXLAN on legacy UDP 8472
VXLAN carried on the Linux/legacy port 8472 instead of the RFC 7348 port 4789.
4789-only decoders see one giant UDP flow and miss the inner hosts.
**Source** RFC 7348 §5; Suricata `decoder.vxlan`; Zeek `vxlan_ports`.

### Malformed VXLAN header (RFC 7348 violation)
A VXLAN header whose **'I' flag is not set** — RFC 7348 §5 requires it to be 1 for
the VNI to be valid. Strict decoders may reject these frames.
**Source** RFC 7348 §5.

### Truncated segments (inner IP length > captured)
The IP total-length exceeds the bytes actually captured — snaplen or a tunnel/mirror
MTU cut the payload. Raise the mirror-path MTU above the encapsulation overhead
(VXLAN +50 B, ERSPAN +50–62 B). **Source** RFC 7348 / ERSPAN draft-foschiano-erspan;
`tcpdump(1)` snaplen; SANS ISC.

---

## Scope boundary — what PicoCap does **not** do

PicoCap checks **capture usability** and **encapsulation/transport RFC conformance**
(RFC 9293 TCP, RFC 7348 VXLAN). It does **not** run per-application RFC-violation or
anomaly detection (Modbus, DNP3, HTTP, TLS state machines) or network-fault verdicts
(retransmission storms, routing loops, DNS/RST-storms, duplicate-IP) — those are
*findings about the network*, out of scope for a capture-intake checker.
PicoCap reports that a segment is *missing from the file*; it never claims *why the
wire* lost a packet.
