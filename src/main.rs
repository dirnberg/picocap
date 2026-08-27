//! PicoCap — the tiny PCAP/PCAPNG capture intake checker.
//!
//! Loads ONE capture, verifies it against the "PCAP Collection
//! Guide" criteria, and reports container integrity, capture quality and the
//! packet distribution (unicast / multicast / broadcast, GRE / VXLAN / ERSPAN).
//! It only CHECKS a file — it never rewrites or forwards it.
//!
//! Usage:
//!   picocap <file.pcap|file.pcapng>   -> check one file (CLI)
//!   picocap serve [addr]              -> web GUI (default 0.0.0.0:8088)

use pcap_parser::{create_reader, Block, PcapBlockOwned, PcapError};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const CODENAME: &str = "Staghound";

/// All tunable parameters — overridable via a YAML config file.
struct Config {
    listen_addr: String,
    auth_token: String,  // if non-empty, GUI + API require this token
    max_upload: usize,   // bytes accepted by the GUI upload
    size_limit: usize,   // bytes; single file should stay below this
    full_snaplen: u32,   // full-frame snap length (-s 0)
    dup_window: f64,     // seconds; duplicate-detection time window
    dup_notice_pct: u64, // % duplicates that raises the span_double_capture notice
    devices_ok: usize,   // >= this many devices -> pass
    devices_warn: usize, // < this many devices -> fail (else warn)
    duration_min: f64,   // seconds; shorter captures are only a warning
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen_addr: "127.0.0.1:8088".into(),
            auth_token: String::new(),
            max_upload: 768 * 1024 * 1024,
            size_limit: 500 * 1024 * 1024,
            full_snaplen: 65535,
            dup_window: 0.005,
            dup_notice_pct: 10,
            devices_ok: 5,
            devices_warn: 2,
            duration_min: 5.0,
        }
    }
}

impl Config {
    /// Minimal flat-YAML loader: `key: value`, `#` comments, quotes stripped.
    fn load(path: &str) -> Config {
        let mut c = Config::default();
        if let Ok(txt) = std::fs::read_to_string(path) {
            eprintln!("picocap: loaded config {path}");
            Config::apply_yaml(&mut c, &txt);
        }
        // env overrides (handy for Docker: -e PICOCAP_TOKEN=...) — always applied
        if let Ok(t) = std::env::var("PICOCAP_TOKEN") {
            c.auth_token = t;
        }
        if let Ok(a) = std::env::var("PICOCAP_LISTEN") {
            c.listen_addr = a;
        }
        c
    }

    fn apply_yaml(c: &mut Config, txt: &str) {
        for raw in txt.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let k = k.trim();
            let v = v.trim().trim_matches(['"', '\'']).trim();
            match k {
                "listen_addr" => c.listen_addr = v.to_string(),
                "auth_token" => c.auth_token = v.to_string(),
                "max_upload_mb" => {
                    if let Ok(n) = v.parse::<usize>() {
                        c.max_upload = n * 1024 * 1024;
                    }
                }
                "size_limit_mb" => {
                    if let Ok(n) = v.parse::<usize>() {
                        c.size_limit = n * 1024 * 1024;
                    }
                }
                "full_snaplen" => {
                    if let Ok(n) = v.parse() {
                        c.full_snaplen = n;
                    }
                }
                "dup_window_ms" => {
                    if let Ok(n) = v.parse::<f64>() {
                        c.dup_window = n / 1000.0;
                    }
                }
                "dup_notice_pct" => {
                    if let Ok(n) = v.parse() {
                        c.dup_notice_pct = n;
                    }
                }
                "devices_min_ok" => {
                    if let Ok(n) = v.parse() {
                        c.devices_ok = n;
                    }
                }
                "devices_min_warn" => {
                    if let Ok(n) = v.parse() {
                        c.devices_warn = n;
                    }
                }
                "duration_min_s" => {
                    if let Ok(n) = v.parse() {
                        c.duration_min = n;
                    }
                }
                _ => {}
            }
        }
    }
}

static CFG: OnceLock<Config> = OnceLock::new();
fn cfg() -> &'static Config {
    CFG.get_or_init(Config::default)
}

/// One evaluated collection criterion.
struct Check {
    level: &'static str, // pass | warn | fail | info
    label: String,
    detail: String,
}

/// Stats gathered while walking the packets.
#[derive(Default)]
struct Stats {
    decoded: u64, // frames we could decode at L2
    unicast: u64,
    multicast: u64,
    broadcast: u64,
    ipv4: u64,
    ipv6: u64,
    arp: u64,
    vlan: u64,
    l2other: u64,
    gre: u64,
    erspan: u64,
    vxlan: u64,
    geneve: u64,
    macs: HashSet<[u8; 6]>,
    ips: HashSet<u128>,
    ts_first: Option<f64>,
    ts_last: Option<f64>,
    ts_prev: Option<f64>, // last frame's timestamp (for the biggest inter-frame gap)
    ts_maxgap: f64,       // largest forward jump between consecutive frames (merge/replay)
    // duplicate-frame (SPAN double-capture) detection — TTL/ToS/checksum-tolerant,
    // so a routed both-direction mirror (copies differ only in TTL) is caught too.
    seen: HashMap<u64, (f64, bool)>, // key -> (timestamp, was VLAN-tagged)
    dup_frames: u64,
    dup_tag_diff: u64, // duplicate copies that differ in VLAN tagging (egress-tag artifact)
    // VLAN + nested encapsulation
    qinq: u64, // frames with >=2 stacked VLAN tags
    vlan_ids: HashSet<u16>,
    max_depth: u32,               // deepest tunnel nesting seen
    multi_encap: u64,             // frames with >=2 tunnel layers
    chains: HashMap<String, u64>, // encapsulation-chain distribution
    // TCP session integrity (capture usability, not network-fault detection)
    flows: HashMap<u64, FlowState>, // per canonical 5-tuple, bounded
    seq_gaps: u64,                  // forward sequence jumps = segment(s) missing from the file
    runts: u64,                     // on-wire frame length < 60 B (truncation / L2 corruption)
    oversize: u64,                  // on-wire frame length > 1518 B (jumbo / malformed)
    tcp_flows: u64,                 // finalized: distinct TCP sessions
    hs_complete: u64,               // finalized: SYN + SYN-ACK both seen
    hs_syn_only: u64,               // finalized: SYN but no SYN-ACK (one-directional capture?)
    hs_midstream: u64,              // finalized: data before any SYN (capture started late)
    acked_unseen: u64,              // ACK for data never captured = capture drop (RFC 9293 §3.4)
    inner_trunc: u64,               // inner IP total-length > captured bytes = truncated segment
    vxlan_legacy: u64,              // VXLAN on legacy UDP 8472 instead of RFC 7348 port 4789
    vxlan_bad: u64,                 // VXLAN header with 'I' flag clear = RFC 7348 §5 violation
}

/// Minimal per-flow TCP state for handshake coverage + capture-drop detection.
/// Direction index 0/1 = which endpoint of the canonical (sorted) pair is the sender.
#[derive(Default, Clone)]
struct FlowState {
    saw_syn: bool,
    saw_synack: bool,
    saw_data_no_syn: bool,
    next_seq: [Option<u32>; 2], // expected next sequence number per direction
}

/// A capture-quality notice (beyond the pass/fail collection criteria).
struct Notice {
    code: &'static str,
    title: String,
    text: String,
}

/// Full result of checking one capture.
struct Report {
    format: String,
    linktype: String,
    packets: usize,
    consumed: usize,
    total: usize,
    score: f64,
    clean: bool,
    note: String,
    snaplen: u32,
    truncated_pkts: u64,
    src_macs: usize,
    ip_addrs: usize,
    duration: f64,
    has_time: bool,
    // capture metadata
    ver: String,
    endian: &'static str,
    ts_prec: &'static str,
    iface_count: usize,
    wire_bytes: u64,
    stats: Stats,
    checks: Vec<Check>,
    notices: Vec<Notice>,
    intake: &'static str, // ACCEPT | REVIEW | REJECT
    conformance: f64,     // 0-100: 100 only when every criterion passes
}

/// Format a unix epoch (seconds) as UTC calendar time — pure, no deps.
fn fmt_utc(epoch: f64) -> String {
    if epoch <= 0.0 {
        return "-".into();
    }
    let secs = epoch as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02} UTC")
}

/// Byte order + timestamp precision from the magic bytes.
fn magic_info(data: &[u8]) -> (&'static str, &'static str) {
    if data.len() < 4 {
        return ("-", "µs");
    }
    match [data[0], data[1], data[2], data[3]] {
        [0xa1, 0xb2, 0xc3, 0xd4] => ("big-endian", "µs"),
        [0xd4, 0xc3, 0xb2, 0xa1] => ("little-endian", "µs"),
        [0xa1, 0xb2, 0x3c, 0x4d] => ("big-endian", "ns"),
        [0x4d, 0x3c, 0xb2, 0xa1] => ("little-endian", "ns"),
        _ => ("-", "µs"),
    }
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// Detect the container from the first 4 magic bytes; also whether it is a
/// nanosecond-resolution legacy pcap.
fn detect_format(data: &[u8]) -> (Option<&'static str>, f64) {
    if data.len() < 4 {
        return (None, 1e-6);
    }
    match [data[0], data[1], data[2], data[3]] {
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xd4, 0xc3, 0xb2, 0xa1] => (Some("pcap"), 1e-6),
        [0xa1, 0xb2, 0x3c, 0x4d] | [0x4d, 0x3c, 0xb2, 0xa1] => (Some("pcap"), 1e-9), // ns
        [0x0a, 0x0d, 0x0d, 0x0a] => (Some("pcapng"), 1e-6),
        _ => (None, 1e-6),
    }
}

fn linktype_name(lt: i32) -> String {
    match lt {
        0 => "Null/Loopback".into(),
        1 => "Ethernet".into(),
        101 => "Raw IP".into(),
        105 => "IEEE 802.11".into(),
        113 => "Linux SLL".into(),
        127 => "802.11 radiotap".into(),
        _ => format!("LINKTYPE_{lt}"),
    }
}

/// L2: resolve (ethertype, L3 offset), unwrapping VLAN tags. Returns None if
/// the link type carries no Ethernet-style ethertype we understand.
fn l2(f: &[u8], link: i32) -> Option<(u16, usize)> {
    match link {
        1 => {
            let mut et = be16(f, 12)?;
            let mut off = 14usize;
            while et == 0x8100 || et == 0x88a8 {
                et = be16(f, off + 2)?;
                off += 4;
            }
            Some((et, off))
        }
        113 => Some((be16(f, 14)?, 16)), // Linux SLL
        101 => match f.first()? >> 4 {
            // Raw IP
            6 => Some((0x86dd, 0)),
            _ => Some((0x0800, 0)),
        },
        _ => None,
    }
}

fn fnv1a(b: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for &x in b {
        h ^= x as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// FNV-1a over an IP slice with the fields that a router rewrites zeroed out —
/// IPv4 ToS/DSCP (byte 1), TTL (8) and header checksum (10-11); IPv6 hop limit
/// (7). The IP Identification and payload stay in the hash, so a mirror copy of
/// the SAME packet (same ID, different TTL — ingress vs egress of a routed
/// both-direction SPAN) matches, while a real retransmission (new ID) does not.
fn fnv1a_masked(ip: &[u8], is_v6: bool) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for (i, &x) in ip.iter().enumerate() {
        let masked = if is_v6 {
            i == 7
        } else {
            matches!(i, 1 | 8 | 10 | 11)
        };
        h ^= if masked { 0 } else { x as u64 };
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// L2 that also counts VLAN tags (incl. QinQ) and records VLAN ids.
/// Returns (ethertype, L3 offset, vlan tag count).
fn l2v(f: &[u8], link: i32, s: &mut Stats) -> Option<(u16, usize, u32)> {
    match link {
        1 => {
            let mut et = be16(f, 12)?;
            let mut off = 14usize;
            let mut tags = 0u32;
            while et == 0x8100 || et == 0x88a8 {
                tags += 1;
                if let Some(tci) = be16(f, off) {
                    if s.vlan_ids.len() < 4096 {
                        s.vlan_ids.insert(tci & 0x0fff);
                    }
                }
                et = be16(f, off + 2)?;
                off += 4;
            }
            if tags >= 1 {
                s.vlan += 1;
            }
            if tags >= 2 {
                s.qinq += 1;
            }
            Some((et, off, tags))
        }
        113 => Some((be16(f, 14)?, 16, 0)),
        101 => match f.first()? >> 4 {
            6 => Some((0x86dd, 0, 0)),
            _ => Some((0x0800, 0, 0)),
        },
        _ => None,
    }
}

fn proto_name(p: u8) -> &'static str {
    match p {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        2 => "IGMP",
        89 => "OSPF",
        112 => "VRRP",
        _ => "IPproto",
    }
}

/// Peel one layer of tunnel (ERSPAN/GRE, VXLAN). Returns the inner
/// (frame, link, layer-token) and increments the encapsulation counters.
/// The token is `None` when nothing was peeled.
fn decap_once<'a>(f: &'a [u8], link: i32, s: &mut Stats) -> (&'a [u8], i32, Option<&'static str>) {
    let no = (f, link, None);
    let (et, l3) = match l2(f, link) {
        Some(x) => x,
        None => return no,
    };
    // outer must be IPv4 or IPv6 to carry a tunnel
    let (proto, iphdr) = match et {
        0x0800 => {
            let d = match f.get(l3..) {
                Some(d) => d,
                None => return no,
            };
            let ihl = ((d.first().copied().unwrap_or(0) & 0x0f) as usize) * 4;
            if ihl < 20 || d.len() < ihl {
                return no;
            }
            (d[9], l3 + ihl)
        }
        0x86dd => match f.get(l3 + 6) {
            Some(&p) => (p, l3 + 40),
            None => return no,
        },
        _ => return no,
    };

    match proto {
        47 => {
            // GRE
            s.gre += 1;
            let g = match f.get(iphdr..) {
                Some(g) => g,
                None => return no,
            };
            let flags = match be16(g, 0) {
                Some(v) => v,
                None => return no,
            };
            let gtype = match be16(g, 2) {
                Some(v) => v,
                None => return no,
            };
            let mut gl = 4usize;
            if flags & 0x8000 != 0 {
                gl += 4;
            } // checksum(+reserved)
            if flags & 0x4000 != 0 {
                gl += 4;
            } // routing
            if flags & 0x2000 != 0 {
                gl += 4;
            } // key
            if flags & 0x1000 != 0 {
                gl += 4;
            } // sequence
            let (inner_off, tok) = match gtype {
                0x88be => {
                    s.erspan += 1;
                    (iphdr + gl + 8, "GRE/ERSPAN")
                } // ERSPAN II + 8B header
                0x22eb => {
                    s.erspan += 1;
                    (iphdr + gl + 12, "GRE/ERSPAN")
                } // ERSPAN III + 12B header
                0x6558 => (iphdr + gl, "GRE"), // transparent ethernet bridging
                0x0800 => return (f.get(iphdr + gl..).unwrap_or(&[]), 101, Some("GRE")),
                0x86dd => return (f.get(iphdr + gl..).unwrap_or(&[]), 101, Some("GRE")),
                _ => return no,
            };
            (f.get(inner_off..).unwrap_or(&[]), 1, Some(tok)) // inner Ethernet
        }
        17 => {
            // UDP: VXLAN / Geneve
            let u = match f.get(iphdr..) {
                Some(u) => u,
                None => return no,
            };
            match be16(u, 2) {
                Some(p @ (4789 | 8472)) => {
                    // 4789 = RFC 7348 VXLAN; 8472 = Linux/legacy port (decoded too,
                    // but flagged since 4789-only sensors miss it).
                    s.vxlan += 1;
                    if p == 8472 {
                        s.vxlan_legacy += 1;
                    }
                    // RFC 7348 §5: the VXLAN header 'I' flag (0x08) MUST be 1 for a
                    // valid VNI. If it is clear, the encapsulation is malformed.
                    if let Some(vh) = f.get(iphdr + 8..iphdr + 16) {
                        if vh[0] & 0x08 == 0 {
                            s.vxlan_bad += 1;
                        }
                    }
                    (f.get(iphdr + 8 + 8..).unwrap_or(&[]), 1, Some("VXLAN")) // UDP+VXLAN → inner eth
                }
                Some(6081) => {
                    s.geneve += 1;
                    no // variable options — count only
                }
                _ => no,
            }
        }
        _ => no,
    }
}

/// Full per-packet analysis: peel tunnels, then classify the INNER frame's
/// cast / endpoints / traffic mix and feed the duplicate detector.
fn analyze_packet(f: &[u8], link: i32, ts: Option<f64>, s: &mut Stats) {
    let mut chain: Vec<&str> = Vec::with_capacity(8);
    chain.push(match link {
        1 => "Eth",
        101 => "IP",
        113 => "SLL",
        _ => "L2",
    });

    // peel nested tunnels (ERSPAN/GRE, VXLAN), counting depth
    let mut inner = f;
    let mut ilink = link;
    let mut depth = 0u32;
    for _ in 0..4 {
        let (nf, nl, tok) = decap_once(inner, ilink, s);
        match tok {
            Some(t) => {
                chain.push(t);
                if nl == 1 {
                    chain.push("Eth");
                }
                inner = nf;
                ilink = nl;
                depth += 1;
            }
            None => break,
        }
    }
    if depth > s.max_depth {
        s.max_depth = depth;
    }
    if depth >= 2 {
        s.multi_encap += 1;
    }

    // cast + device diversity on the (inner) Ethernet header
    if ilink == 1 {
        if inner.len() < 14 {
            s.l2other += 1;
            record_chain(s, &chain);
            return;
        }
        let dst = &inner[0..6];
        if dst == [0xff; 6] {
            s.broadcast += 1;
        } else if dst[0] & 0x01 == 0x01 {
            s.multicast += 1;
        } else {
            s.unicast += 1;
        }
        if s.macs.len() < 300_000 {
            let mut m = [0u8; 6];
            m.copy_from_slice(&inner[6..12]);
            s.macs.insert(m);
        }
        s.decoded += 1;
    }

    // L2 (counting VLAN/QinQ tags) → ethertype + L3 offset
    let (et, l3off, tags) = match l2v(inner, ilink, s) {
        Some(x) => x,
        None => {
            s.l2other += 1;
            record_chain(s, &chain);
            return;
        }
    };
    if tags >= 2 {
        chain.push("QinQ");
    } else if tags == 1 {
        chain.push("VLAN");
    }

    match et {
        0x0806 => {
            s.arp += 1;
            chain.push("ARP");
        }
        0x0800 => {
            s.ipv4 += 1;
            chain.push("IPv4");
            if let Some(ip) = inner.get(l3off..) {
                if let Some(&p) = ip.get(9) {
                    chain.push(proto_name(p));
                    if p == 6 {
                        tcp_session(ip, false, s);
                    }
                }
                collect_ipv4(ip, s);
                dedup(ip, false, ts, tags > 0, s);
            }
        }
        0x86dd => {
            s.ipv6 += 1;
            chain.push("IPv6");
            if let Some(ip) = inner.get(l3off..) {
                if let Some(&p) = ip.get(6) {
                    chain.push(proto_name(p));
                    if p == 6 {
                        tcp_session(ip, true, s);
                    }
                }
                collect_ipv6(ip, s);
                dedup(ip, true, ts, tags > 0, s);
            }
        }
        _ => {
            s.l2other += 1;
            chain.push("other");
        }
    }
    record_chain(s, &chain);
}

/// Tally one packet's encapsulation chain (capped to bound memory).
fn record_chain(s: &mut Stats, chain: &[&str]) {
    let key = chain.join(">");
    if s.chains.len() < 400 || s.chains.contains_key(&key) {
        *s.chains.entry(key).or_insert(0) += 1;
    }
}

fn collect_ipv4(d: &[u8], s: &mut Stats) {
    if d.len() >= 20 && s.ips.len() < 400_000 {
        s.ips
            .insert(u32::from_be_bytes([d[12], d[13], d[14], d[15]]) as u128);
        s.ips
            .insert(u32::from_be_bytes([d[16], d[17], d[18], d[19]]) as u128);
    }
}

fn collect_ipv6(d: &[u8], s: &mut Stats) {
    if d.len() >= 40 && s.ips.len() < 400_000 {
        let mut a = [0u8; 16];
        a.copy_from_slice(&d[8..24]);
        s.ips.insert(u128::from_be_bytes(a));
        a.copy_from_slice(&d[24..40]);
        s.ips.insert(u128::from_be_bytes(a));
    }
}

/// Hash a canonical (sorted) endpoint pair into a compact flow key.
fn flow_hash(lo: (u128, u16), hi: (u128, u16)) -> u64 {
    let mut b = Vec::with_capacity(36);
    b.extend_from_slice(&lo.0.to_be_bytes());
    b.extend_from_slice(&lo.1.to_be_bytes());
    b.extend_from_slice(&hi.0.to_be_bytes());
    b.extend_from_slice(&hi.1.to_be_bytes());
    fnv1a(&b)
}

/// TCP session integrity: handshake coverage + capture-drop (sequence-gap)
/// detection. This is a *capture-usability* signal — it answers "did the file
/// miss segments the endpoints exchanged?", NOT "is the network faulty" (that
/// is a network-analysis job). Sequence math uses on-wire lengths (IP total length), so
/// it is robust to snaplen truncation. `ip` is the IP header onward.
fn tcp_session(ip: &[u8], is_v6: bool, s: &mut Stats) {
    // Locate L4, on-wire total length, and addresses.
    let (l4off, total_len, saddr, daddr) = if !is_v6 {
        if ip.len() < 20 {
            return;
        }
        let ihl = ((ip[0] & 0x0f) as usize) * 4;
        if ihl < 20 {
            return;
        }
        let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        let sa = u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]]) as u128;
        let da = u32::from_be_bytes([ip[16], ip[17], ip[18], ip[19]]) as u128;
        (ihl, total, sa, da)
    } else {
        if ip.len() < 40 {
            return;
        }
        let payload = u16::from_be_bytes([ip[4], ip[5]]) as usize;
        let mut a = [0u8; 16];
        a.copy_from_slice(&ip[8..24]);
        let sa = u128::from_be_bytes(a);
        a.copy_from_slice(&ip[24..40]);
        let da = u128::from_be_bytes(a);
        (40, 40 + payload, sa, da) // note: IPv6 extension headers are not walked (rare for TCP)
    };
    let l4 = match ip.get(l4off..) {
        Some(x) if x.len() >= 20 => x,
        _ => return,
    };
    let sport = u16::from_be_bytes([l4[0], l4[1]]);
    let dport = u16::from_be_bytes([l4[2], l4[3]]);
    let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
    let ackn = u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]);
    let doff = ((l4[12] >> 4) as usize) * 4;
    let flags = l4[13];
    let (syn, ack, fin) = (flags & 0x02 != 0, flags & 0x10 != 0, flags & 0x01 != 0);
    let payload = total_len.saturating_sub(l4off).saturating_sub(doff);
    // Inner-length truncation: the IP header claims more bytes than were
    // captured — a tunnel/MTU or snaplen cut that loses payload for reassembly.
    if total_len > ip.len() {
        s.inner_trunc += 1;
    }
    // SYN and FIN each consume one sequence number.
    let seg = payload + syn as usize + fin as usize;

    // Canonical key + direction (which endpoint is the sender of this segment).
    let a = (saddr, sport);
    let b = (daddr, dport);
    let (lo, hi, dir) = if a <= b {
        (a, b, 0usize)
    } else {
        (b, a, 1usize)
    };
    let key = flow_hash(lo, hi);
    if !s.flows.contains_key(&key) && s.flows.len() >= 200_000 {
        return; // bound memory
    }
    let f = s.flows.entry(key).or_default();

    if syn && !ack {
        f.saw_syn = true;
    }
    if syn && ack {
        f.saw_synack = true;
    }
    if !syn && payload > 0 && !f.saw_syn && !f.saw_synack {
        f.saw_data_no_syn = true;
    }

    // Sequence-gap = capture drop: this segment starts beyond what we expected
    // next in this direction. A backward/equal seq is a retransmit or reorder,
    // not a missing segment, so it is not counted.
    if let Some(exp) = f.next_seq[dir] {
        let gap = seq.wrapping_sub(exp);
        if gap > 0 && gap < 16_000_000 {
            s.seq_gaps += 1;
        }
    }
    // ACKed-unseen = capture drop: this segment acknowledges peer data whose
    // sequence end we never captured (RFC 9293 §3.4; Wireshark "ACKed segment
    // that wasn't captured"). Counts only a forward jump beyond the highest
    // peer sequence seen, so retransmits/normal ACKs are ignored.
    if ack {
        if let Some(peer_end) = f.next_seq[1 - dir] {
            let ahead = ackn.wrapping_sub(peer_end);
            if ahead > 0 && ahead < 16_000_000 {
                s.acked_unseen += 1;
            }
        }
    }
    let end = seq.wrapping_add(seg as u32);
    match f.next_seq[dir] {
        Some(cur) if end.wrapping_sub(cur) >= 0x8000_0000 => {} // don't move expected backward
        _ => f.next_seq[dir] = Some(end),
    }
}

/// Fold per-flow TCP state into the finalized session tallies.
fn finalize_flows(s: &mut Stats) {
    s.tcp_flows = s.flows.len() as u64;
    for f in s.flows.values() {
        if f.saw_syn && f.saw_synack {
            s.hs_complete += 1;
        } else if f.saw_syn && !f.saw_synack {
            s.hs_syn_only += 1;
        } else if f.saw_data_no_syn {
            s.hs_midstream += 1;
        }
    }
}

/// SPAN double-capture detector: a frame whose inner L3 bytes (addresses, IP
/// id, flags, length, payload) recur within 5 ms is a mirror duplicate, not a
/// real retransmission (which would arrive ≥ one RTO later). `tagged` is whether
/// this copy carried a VLAN tag — if the two mirror copies differ, that is the
/// egress-tag chipset artifact (the tag is applied before the untag step).
fn dedup(ipslice: &[u8], is_v6: bool, ts: Option<f64>, tagged: bool, s: &mut Stats) {
    let ts = match ts {
        Some(t) => t,
        None => return,
    };
    let key = fnv1a_masked(ipslice, is_v6);
    if let Some(&(prev, prev_tagged)) = s.seen.get(&key) {
        let dt = ts - prev;
        if (0.0..=cfg().dup_window).contains(&dt) {
            s.dup_frames += 1;
            if prev_tagged != tagged {
                s.dup_tag_diff += 1;
            }
        }
    }
    if s.seen.len() < 2_000_000 || s.seen.contains_key(&key) {
        s.seen.insert(key, (ts, tagged));
    }
}

/// Parse the whole capture and produce the full report.
/// Analyze an in-memory capture (GUI upload path, and tests).
fn analyze(data: &[u8]) -> Report {
    analyze_core(data, data, data.len())
}

/// Core analyzer over any byte source. `magic` holds the first bytes (for format
/// detection), `src` streams the whole capture, `total` is the file size (for the
/// consumed/total score). Streaming from a `File` keeps multi-GB captures out of
/// RAM; an in-memory slice passes itself as both `magic` and `src`.
fn analyze_core<R: std::io::Read>(magic: &[u8], src: R, total: usize) -> Report {
    let (fmt_opt, ts_scale) = detect_format(magic);

    let mut r = Report {
        format: "unknown".into(),
        linktype: "-".into(),
        packets: 0,
        consumed: 0,
        total,
        score: 0.0,
        clean: false,
        note: String::new(),
        snaplen: 0,
        truncated_pkts: 0,
        src_macs: 0,
        ip_addrs: 0,
        duration: 0.0,
        has_time: false,
        ver: "-".into(),
        endian: magic_info(magic).0,
        ts_prec: magic_info(magic).1,
        iface_count: 0,
        wire_bytes: 0,
        stats: Stats::default(),
        checks: Vec::new(),
        notices: Vec::new(),
        intake: "REJECT",
        conformance: 0.0,
    };

    let format = match fmt_opt {
        Some(f) => f,
        None => {
            r.note = "no pcap/pcapng magic bytes — not a packet capture".into();
            build_checks(&mut r);
            return r;
        }
    };
    r.format = format.into();

    // Bounded reader buffer: streams the source in ≤16 MB windows (refill loop
    // below tops it up), so memory stays flat regardless of capture size.
    let capacity = (total + 65536).min(16 * 1024 * 1024);
    let mut reader = match create_reader(capacity, src) {
        Ok(rd) => rd,
        Err(e) => {
            r.note = format!("reader init failed: {e:?}");
            build_checks(&mut r);
            return r;
        }
    };

    let mut link: i32 = 1;
    let mut interfaces: Vec<i32> = Vec::new();
    let mut incomplete_streak = 0u8;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                incomplete_streak = 0;
                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        r.snaplen = hdr.snaplen;
                        link = hdr.network.0;
                        r.linktype = linktype_name(link);
                        r.ver = format!("{}.{}", hdr.version_major, hdr.version_minor);
                        r.iface_count = 1;
                    }
                    PcapBlockOwned::Legacy(b) => {
                        r.packets += 1;
                        r.wire_bytes += b.origlen as u64;
                        note_framelen(&mut r.stats, b.origlen);
                        if b.origlen > b.caplen {
                            r.truncated_pkts += 1;
                        }
                        let ts = b.ts_sec as f64 + b.ts_usec as f64 * ts_scale;
                        note_ts(&mut r.stats, ts);
                        analyze_packet(b.data, link, Some(ts), &mut r.stats);
                    }
                    PcapBlockOwned::NG(Block::SectionHeader(shb)) => {
                        interfaces.clear();
                        r.ver = format!("{}.{}", shb.major_version, shb.minor_version);
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                        interfaces.push(idb.linktype.0);
                        r.iface_count = interfaces.len();
                        if r.snaplen == 0 {
                            r.snaplen = idb.snaplen;
                        }
                        if r.linktype == "-" {
                            r.linktype = linktype_name(idb.linktype.0);
                        }
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(ep)) => {
                        r.packets += 1;
                        r.wire_bytes += ep.origlen as u64;
                        note_framelen(&mut r.stats, ep.origlen);
                        if ep.origlen > ep.caplen {
                            r.truncated_pkts += 1;
                        }
                        let lk = interfaces.get(ep.if_id as usize).copied().unwrap_or(1);
                        let ts = (((ep.ts_high as u64) << 32) | ep.ts_low as u64) as f64 * 1e-6;
                        note_ts(&mut r.stats, ts);
                        analyze_packet(ep.data, lk, Some(ts), &mut r.stats);
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(sp)) => {
                        r.packets += 1;
                        r.wire_bytes += sp.origlen as u64;
                        note_framelen(&mut r.stats, sp.origlen);
                        let lk = interfaces.first().copied().unwrap_or(1);
                        analyze_packet(sp.data, lk, None, &mut r.stats);
                    }
                    _ => {}
                }
                r.consumed += offset;
                reader.consume(offset);
            }
            Err(PcapError::Eof) => {
                r.clean = true;
                break;
            }
            Err(PcapError::Incomplete(_)) => {
                if incomplete_streak >= 1 {
                    r.note = "truncated: last block is incomplete".into();
                    break;
                }
                incomplete_streak += 1;
                if reader.refill().is_err() {
                    r.note = "truncated: unexpected end of data".into();
                    break;
                }
            }
            Err(PcapError::BufferTooSmall) => {
                r.note = format!(
                    "truncated/corrupt: a block after {} bytes claims more data than the file holds",
                    r.consumed
                );
                break;
            }
            Err(PcapError::UnexpectedEof) => {
                r.note = format!("truncated: file ends mid-block after {} bytes", r.consumed);
                break;
            }
            Err(e) => {
                r.note = format!("parse error after {} bytes: {e:?}", r.consumed);
                break;
            }
        }
    }

    r.score = if total == 0 {
        0.0
    } else {
        (r.consumed as f64 / total as f64 * 100.0).min(100.0)
    };
    if r.clean && r.note.is_empty() {
        r.note = "clean: parsed to end of file".into();
    }
    r.src_macs = r.stats.macs.len();
    r.ip_addrs = r.stats.ips.len();
    if let (Some(a), Some(b)) = (r.stats.ts_first, r.stats.ts_last) {
        r.duration = (b - a).max(0.0);
        r.has_time = true;
    }

    finalize_flows(&mut r.stats);
    build_checks(&mut r);
    build_notices(&mut r);
    r
}

/// Derive capture-quality notices from the gathered stats.
fn build_notices(r: &mut Report) {
    if r.packets > 0 {
        let pct = (r.stats.dup_frames as f64 * 100.0 / r.packets as f64).round() as u64;
        if pct >= cfg().dup_notice_pct {
            // Egress-tag artifact: when the two mirror copies differ in VLAN
            // tagging (one tagged, one not), the switch applied the tag before
            // the untag step — a chipset artifact seen on HP/Aruba, Cisco SG200,
            // Juniper EX. It only shows up *inside* a double-capture, so it is an
            // annotation on this finding, not a separate one.
            let tagged_pct = if r.stats.dup_frames > 0 {
                (r.stats.dup_tag_diff as f64 * 100.0 / r.stats.dup_frames as f64).round() as u64
            } else {
                0
            };
            let egress = if tagged_pct >= 20 {
                format!(" Of the duplicate copies, {tagged_pct}% differ in VLAN tagging (one tagged, one not) — the egress copy carries a tag the ingress copy lacks, a chipset egress-tag artifact (HP/Aruba, Cisco SG200, Juniper EX).")
            } else {
                String::new()
            };
            r.notices.push(Notice {
                code: "span_double_capture",
                title: "SPAN double-capture (TX + RX)".into(),
                text: format!(
                    "{pct}% of frames recur byte-identically (same endpoints, flags, length and payload) within 5 ms — the port-mirror is capturing BOTH TX and RX of the same segment, so each frame appears twice. Wireshark reads the second copy as a TCP retransmission, but these are capture artifacts, not real retransmissions (a real retransmit arrives ≥ one RTO later). Set the SPAN/ERSPAN source to RX-only (or TX-only) to remove them.{egress} [Source: Keysight/Gigamon SPAN de-duplication; packet-foo.com; editcap(1) -d]"
                ),
            });
        }

        // Offload super-frames (TSO/GRO): frames far above the 1518 B Ethernet MTU
        // never existed on the wire — the capture host reassembled them.
        let ov_pct = (r.stats.oversize as f64 * 100.0 / r.packets as f64).round() as u64;
        if r.stats.oversize > 0 && ov_pct >= 1 {
            r.notices.push(Notice {
                code: "offload_superframes",
                title: "NIC offload artifacts (TSO/GRO)".into(),
                text: format!(
                    "{}% of frames exceed the 1518 B Ethernet MTU — captured on an endpoint where TSO/GSO/GRO/LRO hand libpcap 2.9–64 KB pseudo-frames that were never on the wire. This breaks target-based IDS reassembly (insertion/evasion). Disable offload on the capture NIC (ethtool -K if gso off gro off tso off lro off) or capture at a TAP. [Source: Wireshark 'Offloading' wiki; Suricata Packet Capture docs]",
                    ov_pct
                ),
            });
        }

        // VXLAN on the legacy Linux port 8472 instead of the RFC 7348 port 4789.
        if r.stats.vxlan_legacy > 0 {
            r.notices.push(Notice {
                code: "vxlan_legacy_port",
                title: "VXLAN on legacy UDP 8472".into(),
                text: format!(
                    "{} VXLAN frames use UDP port 8472 (Linux/flannel/old-OVS legacy) instead of the IANA/RFC 7348 port 4789. Sensors that only decode 4789 (Wireshark, Suricata, Zeek defaults) would see one giant UDP flow and miss every inner host. Add 8472 to the decoder's VXLAN ports. [Source: RFC 7348 §5; Suricata decoder.vxlan; Zeek vxlan_ports]",
                    grp(r.stats.vxlan_legacy)
                ),
            });
        }

        // RFC 7348 §5 violation: VXLAN header with the 'I' flag clear (invalid VNI).
        if r.stats.vxlan_bad > 0 {
            r.notices.push(Notice {
                code: "vxlan_rfc7348_iflag",
                title: "Malformed VXLAN header (RFC 7348 violation)".into(),
                text: format!(
                    "{} VXLAN frames carry a header whose 'I' flag is not set — RFC 7348 §5 requires it to be 1 for the VNI to be valid. Strict decoders may reject these frames, hiding the inner hosts. [Source: RFC 7348 §5]",
                    grp(r.stats.vxlan_bad)
                ),
            });
        }

        // Inner-length truncation: IP total-length exceeds the captured bytes.
        let it_pct = (r.stats.inner_trunc as f64 * 100.0 / r.packets as f64).round() as u64;
        if r.stats.inner_trunc > 0 && it_pct >= 1 {
            r.notices.push(Notice {
                code: "inner_truncation",
                title: "Truncated segments (inner IP length > captured)".into(),
                text: format!(
                    "{}% of TCP packets carry an IP total-length larger than the bytes actually captured — snaplen or a tunnel/mirror MTU cut the payload. Reassembly, file extraction and IDS content matching run on incomplete data. Capture with -s 0 and raise the mirror-path MTU above the encapsulation overhead (VXLAN +50 B, ERSPAN +50–62 B). [Source: RFC 7348 / ERSPAN draft-foschiano-erspan; tcpdump(1) snaplen; SANS ISC]",
                    it_pct
                ),
            });
        }

        // (B) Mirror sees only ARP/broadcast — almost no unicast reaches the sniffer.
        let noise = r.stats.arp + r.stats.broadcast + r.stats.multicast;
        if r.stats.decoded >= 200 {
            let uni_pct = r.stats.unicast as f64 * 100.0 / r.stats.decoded as f64;
            let noise_pct = noise as f64 * 100.0 / r.stats.decoded as f64;
            if uni_pct < 2.0 && noise_pct > 90.0 {
                r.notices.push(Notice {
                    code: "mirror_no_unicast",
                    title: "Almost no unicast — mirror likely not seeing switched traffic".into(),
                    text: format!(
                        "Only {:.0}% of frames are unicast; {:.0}% are ARP/broadcast/multicast. The sniffer is seeing discovery noise but not the switched unicast conversations — a virtual bridge (Proxmox/ESXi/Hyper-V) is eating the mirror frames, hardware offload is bypassing the sniffer, or the mirror source is wrong. Verify with a bare laptop + Wireshark before trusting the sensor. [Source: packet-foo.com; Security Onion; forum consensus]",
                        uni_pct, noise_pct
                    ),
                });
            }
        }
    }

    // (D) Timestamp discontinuity — a big forward jump means merged/replayed
    // captures (timing unreliable) or, if astronomical, a broken capture clock.
    if r.stats.ts_maxgap > 315_360_000.0 {
        r.notices.push(Notice {
            code: "timestamps_implausible",
            title: "Implausible timestamps (broken capture clock)".into(),
            text: format!(
                "Consecutive frames jump by {:.0} years — the capture clock is wrong (e.g. a hardware-timestamping TAP whose dissector plugin is missing, so timestamps read as billions of seconds). Timing analysis is meaningless until the source is fixed. [Source: packet-foo Frame Timestamps; Profitap ProfiShark KB]",
                r.stats.ts_maxgap / 31_536_000.0
            ),
        });
    } else if r.stats.ts_maxgap > 86_400.0 {
        r.notices.push(Notice {
            code: "timestamps_discontinuous",
            title: "Timestamp discontinuity (merged/replayed capture)".into(),
            text: format!(
                "A {:.0}-day gap splits this capture — it is almost certainly a merge/replay of separate recordings, not one continuous capture. Timing rules and any temporal baseline are unreliable; analyse the segments separately. [Source: packet-foo Multi-Point Capture; mergecap(1)]",
                r.stats.ts_maxgap / 86_400.0
            ),
        });
    }
    // a quality notice downgrades a clean ACCEPT to REVIEW
    if !r.notices.is_empty() && r.intake == "ACCEPT" {
        r.intake = "REVIEW";
    }

    // Conformance score: 100 only when every criterion passes; deviations,
    // failures and quality findings pull it down. Container damage caps it.
    let mut sum = 0.0f64;
    let mut cnt = 0.0f64;
    for c in &r.checks {
        let w = match c.level {
            "pass" => 1.0,
            "warn" => 0.5,
            "fail" => 0.0,
            _ => continue, // info: not scored
        };
        sum += w;
        cnt += 1.0;
    }
    // each quality finding counts as a heavy deviation
    for _ in &r.notices {
        sum += 0.3;
        cnt += 1.0;
    }
    let mean = if cnt > 0.0 { sum / cnt } else { 0.0 };
    r.conformance = (mean * 100.0).min(r.score);
}

/// How PicoCap runs, shown on every report and in the GUI so reviewers know the
/// data never leaves the machine and where the detection logic comes from.
const TRUST_NOTE: &str = "Processed locally — no packet data leaves this machine and no cloud service is contacted. Every check is a deterministic local algorithm, developed with the help of Claude and calibrated against a golden set of real captures cross-checked with tshark.";

/// Authoritative source (RFC / vendor / expert) behind each criterion, shown with
/// the result so a reviewer can verify the reasoning independently.
fn finding_source(label: &str) -> &'static str {
    match label {
        l if l.starts_with("Format") => "pcap/pcapng file format (IETF opsawg pcapng draft; libpcap)",
        l if l.starts_with("Container integrity") => "libpcap/pcapng block structure; pcapfix",
        l if l.starts_with("Full-packet") => "tcpdump(1) snaplen (-s 0); SANS ISC — snaplen truncation",
        l if l.starts_with("Size") => "PCAP Collection Guide (per-file size); packet-foo.com capture playbook",
        l if l.starts_with("Multiple end devices") => "Wireshark Wiki — SPAN/mirror & promiscuous mode; Security Onion sniffing pitfalls",
        l if l.starts_with("Representative") => "packet-foo.com capture playbook (representative window)",
        l if l.starts_with("No capture drops") => "RFC 9293 (TCP) §3.4; Wireshark Expert 'ACKed segment that wasn't captured' / 'previous segment not captured'; Zeek capture_loss.log",
        l if l.starts_with("TCP session coverage") => "RFC 9293 (TCP) §3.5 three-way handshake; Wireshark tcp.analysis",
        _ => "",
    }
}

/// Tally on-wire frame length anomalies (runt = below the 60 B Ethernet floor,
/// oversize = above the 1518 B standard MTU) — a capture/L2 usability signal.
fn note_framelen(s: &mut Stats, origlen: u32) {
    if origlen < 60 {
        s.runts += 1;
    } else if origlen > 1518 {
        s.oversize += 1;
    }
}

fn note_ts(s: &mut Stats, ts: f64) {
    if ts <= 0.0 {
        return;
    }
    // Largest forward jump between consecutive frames — a day-plus gap means the
    // file is a merge/replay of separate captures, not one continuous recording.
    if let Some(prev) = s.ts_prev {
        let gap = ts - prev;
        if gap > s.ts_maxgap {
            s.ts_maxgap = gap;
        }
    }
    s.ts_prev = Some(ts);
    s.ts_first = Some(s.ts_first.map_or(ts, |v| v.min(ts)));
    s.ts_last = Some(s.ts_last.map_or(ts, |v| v.max(ts)));
}

fn human_bytes(n: usize) -> String {
    if n < 1024 {
        return format!("{n} B");
    }
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", units[i])
}

fn human_dur(sec: f64) -> String {
    let s = sec as u64;
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m {}s", s / 60, s % 60)
    } else {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
    }
}

/// Evaluate every collection criterion and set the overall intake verdict.
fn build_checks(r: &mut Report) {
    let mut c: Vec<Check> = Vec::new();

    // 1) Format
    let known = r.format == "pcap" || r.format == "pcapng";
    c.push(Check {
        level: if known { "pass" } else { "fail" },
        label: "Format .pcap / .pcapng".into(),
        detail: if known {
            format!("{} container ({})", r.format.to_uppercase(), r.linktype)
        } else {
            "Not a pcap/pcapng file".into()
        },
    });

    // 2) Container integrity
    let intact = r.score >= 99.9 && r.clean;
    c.push(Check {
        level: if intact { "pass" } else { "fail" },
        label: "Container integrity".into(),
        detail: if intact {
            "Parsed cleanly to end of file".into()
        } else {
            r.note.clone()
        },
    });

    // 3) Full frames (-s 0 / snaplen 65535)
    if known {
        let snap_ok = r.snaplen == 0 || r.snaplen >= cfg().full_snaplen;
        let (lvl, det) = if r.truncated_pkts > 0 {
            (
                "fail",
                format!(
                    "{} of {} packets truncated — recapture with -s 0 (full frames)",
                    r.truncated_pkts, r.packets
                ),
            )
        } else if !snap_ok {
            (
                "warn",
                format!(
                    "snaplen {} < {} — set -s 0 to capture full frames",
                    r.snaplen,
                    cfg().full_snaplen
                ),
            )
        } else {
            (
                "pass",
                if r.snaplen == 0 {
                    "Full frames (unlimited snaplen)".into()
                } else {
                    format!("Full frames (snaplen {})", r.snaplen)
                },
            )
        };
        c.push(Check {
            level: lvl,
            label: "Full-packet capture (-s 0)".into(),
            detail: det,
        });

        // 4) File size / split guideline
        let limit_mb = cfg().size_limit / (1024 * 1024);
        let (lvl, det) = if r.total > cfg().size_limit {
            (
                "warn",
                format!(
                    "{} — exceeds {} MB, split with -C {}",
                    human_bytes(r.total),
                    limit_mb,
                    limit_mb
                ),
            )
        } else if r.total < 64 * 1024 {
            (
                "warn",
                format!(
                    "Only {} — capture longer for representative traffic",
                    human_bytes(r.total)
                ),
            )
        } else {
            (
                "pass",
                format!(
                    "{} — within the {} MB guideline",
                    human_bytes(r.total),
                    limit_mb
                ),
            )
        };
        c.push(Check {
            level: lvl,
            label: format!("Size ≤ {limit_mb} MB per file"),
            detail: det,
        });

        // 5) Endpoint diversity (many devices / promiscuous / SPAN)
        let (lvl, det) = if r.src_macs < cfg().devices_warn {
            (
                "fail",
                "≤1 source device seen — check SPAN/mirror port & promiscuous mode".into(),
            )
        } else if r.src_macs < cfg().devices_ok {
            (
                "warn",
                format!(
                    "{} devices — few endpoints, add more capture points",
                    r.src_macs
                ),
            )
        } else {
            (
                "pass",
                format!(
                    "{} distinct devices, {} IP addresses",
                    r.src_macs, r.ip_addrs
                ),
            )
        };
        c.push(Check {
            level: lvl,
            label: "Multiple end devices".into(),
            detail: det,
        });

        // 6) Duration / representativeness
        if r.has_time {
            let (lvl, det) = if r.duration < cfg().duration_min {
                (
                    "warn",
                    format!("Only {} — capture a longer window", human_dur(r.duration)),
                )
            } else {
                ("pass", format!("Spans {}", human_dur(r.duration)))
            };
            c.push(Check {
                level: lvl,
                label: "Representative time window".into(),
                detail: det,
            });
        }
    }

    // 7) Capture completeness (TCP): sequence gaps = segments the endpoints
    //    exchanged but the file is missing (SPAN/collector drop). Usability, not
    //    a network-fault verdict — network-side loss analysis lives elsewhere.
    if known && r.stats.tcp_flows > 0 {
        let drops = r.stats.seq_gaps + r.stats.acked_unseen;
        let (lvl, det) = if drops == 0 {
            (
                "pass",
                format!(
                    "{} TCP sessions, no sequence gaps or ACKed-unseen segments — capture is byte-complete",
                    r.stats.tcp_flows
                ),
            )
        } else {
            (
                "warn",
                format!(
                    "{} sequence gaps + {} ACKed-unseen segments across {} TCP sessions — segment(s) missing from the file (capture/SPAN drop). Recapture at a point that sees full throughput.",
                    r.stats.seq_gaps, r.stats.acked_unseen, r.stats.tcp_flows
                ),
            )
        };
        c.push(Check {
            level: lvl,
            label: "No capture drops (TCP seq)".into(),
            detail: det,
        });

        // Handshake coverage (informational, not scored).
        c.push(Check {
            level: "info",
            label: "TCP session coverage".into(),
            detail: format!(
                "{} complete handshake, {} SYN-only (one-directional capture?), {} mid-stream (capture started late)",
                r.stats.hs_complete, r.stats.hs_syn_only, r.stats.hs_midstream
            ),
        });
    }

    // (A) Capture-source fingerprint from the metadata (informational, not scored):
    // where the file most likely came from — a tunnel mirror, an endpoint host
    // capture, or a plain local SPAN. It is an inference from format/snaplen/
    // encapsulation/offload, not a proof of the exact device.
    if known {
        let s = &r.stats;
        let offload = r.packets > 0 && s.oversize as f64 / r.packets as f64 >= 0.01;
        let (src, why) = if s.erspan > 0 || s.gre > 0 || s.vxlan > 0 {
            (
                "tunnel mirror (ERSPAN/GRE/VXLAN)",
                "encapsulated remote SPAN — expect MTU truncation and drops",
            )
        } else if offload {
            (
                "host capture (endpoint tcpdump/Wireshark)",
                "NIC offload super-frames present — captured on an endpoint, not a TAP",
            )
        } else if r.snaplen == 262144 {
            (
                "host capture (tcpdump/dumpcap default)",
                "snaplen 262144 is the tcpdump/dumpcap -s0 default",
            )
        } else {
            (
                "local SPAN / unknown",
                "no tunnel and no host-capture signature",
            )
        };
        c.push(Check {
            level: "info",
            label: "Capture source".into(),
            detail: format!("{src} — {why} (fingerprint from metadata, not a device verdict)"),
        });
    }

    // Overall verdict from pass/warn/fail (info ignored).
    let has_fail = c.iter().any(|x| x.level == "fail");
    let has_warn = c.iter().any(|x| x.level == "warn");
    r.intake = if has_fail {
        "REJECT"
    } else if has_warn {
        "REVIEW"
    } else {
        "ACCEPT"
    };
    r.checks = c;
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let mut s = String::with_capacity(64);
    for b in h.finalize() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------- Markdown assessment report (same content as the GUI export) ----------

fn grp(n: u64) -> String {
    let s = n.to_string();
    let b = s.as_bytes();
    let mut out = String::new();
    for (i, c) in b.iter().enumerate() {
        if i > 0 && (b.len() - i).is_multiple_of(3) {
            out.push('.');
        }
        out.push(*c as char);
    }
    out
}

fn md_esc(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn markdown_report(name: &str, sha: &str, r: &Report) -> String {
    use std::fmt::Write;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as f64)
        .unwrap_or(0.0);
    let issued = fmt_utc(now);
    let date = issued.get(..10).unwrap_or("").replace('-', "");
    let rid = format!("PC-{date}-{}", sha.get(..8).unwrap_or("").to_uppercase());
    let (result, statement) = match r.intake {
        "ACCEPT" => ("CONFORMS", "The capture meets the collection requirements and is suitable for onward analysis."),
        "REVIEW" => ("CONFORMS WITH DEVIATIONS", "The capture is usable but exhibits deviations that should be reviewed before use (see findings)."),
        _ => ("DOES NOT CONFORM", "The capture does not meet one or more mandatory collection requirements and should be re-taken."),
    };
    let s = &r.stats;
    let mut o = String::new();
    let _ = writeln!(o, "# Technical Assessment Report — PCAP Capture Intake\n");
    let _ = writeln!(
        o,
        "**Report No.** `{rid}`  ·  **Issued** {issued}  ·  **Classification** CONFIDENTIAL\n"
    );
    let _ = writeln!(o, "| Field | Value |\n|---|---|");
    let _ = writeln!(o, "| Object under test | {} |", md_esc(name));
    let _ = writeln!(o, "| SHA-256 | `{sha}` |");
    let _ = writeln!(
        o,
        "| Size | {} ({} packets, {}) |",
        human_bytes(r.total),
        grp(r.packets as u64),
        r.format.to_uppercase()
    );
    let _ = writeln!(
        o,
        "| Assessment tool | PicoCap v{VERSION} \"{CODENAME}\" — local capture intake checker |\n"
    );
    let _ = writeln!(o, "## Assessment result\n");
    let _ = writeln!(
        o,
        "> ### {result} — Conformance {:.1}%\n>\n> {statement}\n",
        r.conformance
    );
    let _ = writeln!(o, "## 1  Assessment of collection criteria\n");
    let _ = writeln!(
        o,
        "| # | Requirement | Result | Remark |\n|---:|---|:--:|---|"
    );
    for (i, c) in r.checks.iter().enumerate() {
        let lvl = match c.level {
            "pass" => "PASS",
            "fail" => "FAIL",
            "warn" => "DEVIATION",
            _ => "INFO",
        };
        let _ = writeln!(
            o,
            "| {} | {} | **{lvl}** | {} |",
            i + 1,
            md_esc(&c.label),
            md_esc(&c.detail)
        );
    }
    let _ = writeln!(o, "\n## 2  Capture-quality findings\n");
    if r.notices.is_empty() {
        let _ = writeln!(o, "_No capture-quality findings were raised._\n");
    } else {
        for (i, n) in r.notices.iter().enumerate() {
            let _ = writeln!(
                o,
                "### Finding F{} — {}\n\n*Severity: Major · Reference: `{}`*\n\n{}\n",
                i + 1,
                n.title,
                n.code,
                n.text
            );
        }
    }
    let _ = writeln!(o, "## 3  Packet distribution\n");
    let _ = writeln!(o, "| Metric | Values |\n|---|---|");
    let _ = writeln!(
        o,
        "| Layer-2 cast | Unicast {} · Multicast {} · Broadcast {} |",
        grp(s.unicast),
        grp(s.multicast),
        grp(s.broadcast)
    );
    let _ = writeln!(
        o,
        "| Network layer | IPv4 {} · IPv6 {} · ARP {} |",
        grp(s.ipv4),
        grp(s.ipv6),
        grp(s.arp)
    );
    let _ = writeln!(
        o,
        "| Encapsulation | GRE {} · ERSPAN {} · VXLAN {} · Geneve {} |",
        grp(s.gre),
        grp(s.erspan),
        grp(s.vxlan),
        grp(s.geneve)
    );
    let _ = writeln!(
        o,
        "| VLAN | {} tagged · QinQ {} · {} distinct IDs |",
        grp(s.vlan),
        grp(s.qinq),
        s.vlan_ids.len()
    );
    let _ = writeln!(
        o,
        "| Nesting | max tunnel depth {} · multi-encapsulated {} frames |",
        s.max_depth,
        grp(s.multi_encap)
    );
    let _ = writeln!(
        o,
        "| Endpoints | {} distinct MAC · {} IP addresses |",
        grp(r.src_macs as u64),
        grp(r.ip_addrs as u64)
    );
    if s.tcp_flows > 0 {
        let _ = writeln!(
            o,
            "| TCP sessions | {} total · {} complete handshake · {} SYN-only · {} mid-stream |",
            grp(s.tcp_flows),
            grp(s.hs_complete),
            grp(s.hs_syn_only),
            grp(s.hs_midstream)
        );
        let _ = writeln!(
            o,
            "| Capture completeness | {} seq gaps · {} ACKed-unseen · {} inner-truncated · {} runt · {} oversize |\n",
            grp(s.seq_gaps),
            grp(s.acked_unseen),
            grp(s.inner_trunc),
            grp(s.runts),
            grp(s.oversize)
        );
    } else {
        let _ = writeln!(o);
    }
    let _ = writeln!(o, "## 4  Encapsulation chains (count / %)\n");
    let mut cv: Vec<(&String, &u64)> = s.chains.iter().collect();
    cv.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let total: u64 = s.chains.values().sum();
    if cv.is_empty() {
        let _ = writeln!(o, "_No decodable Layer-2 chains._");
    } else {
        let maxpct = cv
            .first()
            .map(|(_, v)| **v as f64 * 100.0 / total.max(1) as f64)
            .unwrap_or(1.0)
            .max(0.1);
        let _ = writeln!(o, "| Chain | Count | % | |\n|---|---:|---:|---|");
        for (k, v) in cv.iter().take(20) {
            let pct = **v as f64 * 100.0 / total.max(1) as f64;
            let bl = ((pct / maxpct * 20.0).round() as usize).max(1);
            let _ = writeln!(
                o,
                "| `{k}` | {} | {pct:.1}% | {} |",
                grp(**v),
                "█".repeat(bl)
            );
        }
    }
    let m = |k: &str, v: String| format!("| {k} | {} |", md_esc(&v));
    let _ = writeln!(o, "\n## 5  Capture metadata\n");
    let _ = writeln!(o, "| Field | Value |\n|---|---|");
    let _ = writeln!(
        o,
        "{}",
        m("Recorded start", fmt_utc(s.ts_first.unwrap_or(0.0)))
    );
    let _ = writeln!(
        o,
        "{}",
        m("Recorded end", fmt_utc(s.ts_last.unwrap_or(0.0)))
    );
    let _ = writeln!(
        o,
        "{}",
        m(
            "Duration",
            if r.has_time {
                human_dur(r.duration)
            } else {
                "-".into()
            }
        )
    );
    let rate = if r.has_time && r.duration > 0.0 {
        format!("{:.2} Mbit/s", r.wire_bytes as f64 * 8.0 / r.duration / 1e6)
    } else {
        "-".into()
    };
    let _ = writeln!(o, "{}", m("Throughput", rate));
    let _ = writeln!(o, "{}", m("pcap version", r.ver.clone()));
    let _ = writeln!(o, "{}", m("Byte order", r.endian.into()));
    let _ = writeln!(o, "{}", m("Timestamp precision", r.ts_prec.into()));
    let _ = writeln!(o, "{}", m("Link type", r.linktype.clone()));
    let _ = writeln!(
        o,
        "{}",
        m(
            "Snap length",
            if r.snaplen == 0 {
                "unlimited".into()
            } else {
                format!("{} B", grp(r.snaplen as u64))
            }
        )
    );
    let _ = writeln!(o, "{}", m("Interfaces", r.iface_count.to_string()));
    let avg = if r.packets > 0 {
        r.wire_bytes / r.packets as u64
    } else {
        0
    };
    let _ = writeln!(o, "{}", m("Average packet", format!("{avg} B")));
    let _ = writeln!(
        o,
        "{}",
        m("Data on wire", human_bytes(r.wire_bytes as usize))
    );
    let _ = writeln!(o, "\n## 6  Sources per finding\n");
    let _ = writeln!(o, "| Requirement | Source |\n|---|---|");
    for c in r.checks.iter() {
        let src = finding_source(&c.label);
        if !src.is_empty() {
            let _ = writeln!(o, "| {} | {} |", md_esc(&c.label), md_esc(src));
        }
    }
    let _ = writeln!(o, "\n## 7  Basis and disclaimer\n");
    let _ = writeln!(o, "Criteria basis: PCAP Collection Guide (format, full-frame capture, per-file size, endpoint diversity and representative duration). TCP session integrity follows RFC 9293 (handshake, sequence numbers); tunnel/encapsulation conformance follows RFC 7348 (VXLAN) and the ERSPAN draft. Thresholds are configurable. This automated report contains no manual review and does not constitute a certification.\n");
    let _ = writeln!(o, "> **How this runs:** {TRUST_NOTE}\n");
    let _ = writeln!(
        o,
        "_Prepared by PicoCap v{VERSION} \"{CODENAME}\" (automated) · {issued}_"
    );
    o
}

// ---------- CLI ----------

/// Stream a file's SHA-256 in 1 MiB windows — never loads the whole file.
fn sha256_file(path: &str) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Analyze a capture by streaming it from disk (bounded memory for multi-GB
/// files). Reads a small header for format detection, then re-joins it with the
/// rest of the file as the parse stream.
fn analyze_reader(path: &str, total: usize) -> std::io::Result<Report> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut magic = vec![0u8; 65536.min(total.max(1))];
    let mut got = 0;
    while got < magic.len() {
        let n = f.read(&mut magic[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    magic.truncate(got);
    let src = std::io::Cursor::new(magic.clone()).chain(f);
    Ok(analyze_core(&magic, src, total))
}

fn run_cli(path: &str) -> i32 {
    let total = match std::fs::metadata(path) {
        Ok(m) => m.len() as usize,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return 2;
        }
    };
    let name = std::path::Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string());
    let sha = match sha256_file(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return 2;
        }
    };
    let r = match analyze_reader(path, total) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return 2;
        }
    };
    let s = &r.stats;

    let bar_len = 28usize;
    let filled = (r.score / 100.0 * bar_len as f64).round() as usize;
    let bar: String = "█".repeat(filled) + &"░".repeat(bar_len - filled);

    println!("PicoCap 🩺  v{VERSION} \"{CODENAME}\"  ·  capture intake");
    println!("  file     : {name}");
    println!("  sha256   : {sha}");
    println!("  format   : {} ({})", r.format, r.linktype);
    println!(
        "  packets  : {}   size: {}",
        r.packets,
        human_bytes(r.total)
    );
    println!("  integrity: [{bar}] {:.1}%  {}", r.score, r.note);
    println!(
        "  conform. : {:.1}%  (100% only when every criterion passes)",
        r.conformance
    );
    println!("  ── Capture metadata ──");
    println!(
        "   recorded : {}  →  {}",
        fmt_utc(s.ts_first.unwrap_or(0.0)),
        fmt_utc(s.ts_last.unwrap_or(0.0))
    );
    if r.has_time {
        println!("   duration : {}", human_dur(r.duration));
    }
    println!(
        "   pcap ver : {}   byte order: {}   ts precision: {}",
        r.ver, r.endian, r.ts_prec
    );
    println!(
        "   linktype : {}   snaplen: {}   interfaces: {}",
        r.linktype, r.snaplen, r.iface_count
    );
    let avg = if r.packets > 0 {
        r.wire_bytes / r.packets as u64
    } else {
        0
    };
    let rate = if r.has_time && r.duration > 0.0 {
        r.wire_bytes as f64 * 8.0 / r.duration / 1e6
    } else {
        0.0
    };
    println!(
        "   avg pkt  : {} B   on-wire: {}   throughput: {:.2} Mbit/s",
        avg,
        human_bytes(r.wire_bytes as usize),
        rate
    );
    println!("  INTAKE   : {}", r.intake);
    println!("  ── Collection criteria ──");
    for ch in &r.checks {
        let m = match ch.level {
            "pass" => "✓",
            "warn" => "!",
            "fail" => "✗",
            _ => "i",
        };
        println!("   [{m}] {:<26} {}", ch.label, ch.detail);
    }
    let cast = s.unicast + s.multicast + s.broadcast;
    println!("  ── Packet distribution ({cast} L2 frames) ──");
    println!(
        "   unicast {}  multicast {}  broadcast {}",
        s.unicast, s.multicast, s.broadcast
    );
    println!(
        "   IPv4 {}  IPv6 {}  ARP {}  VLAN-tagged {}",
        s.ipv4, s.ipv6, s.arp, s.vlan
    );
    println!(
        "   GRE {}  ERSPAN {}  VXLAN {}  Geneve {}",
        s.gre, s.erspan, s.vxlan, s.geneve
    );
    println!(
        "   VLAN-tagged {} (QinQ {}, {} distinct VLAN IDs)  max encap depth {}  multi-encap {}",
        s.vlan,
        s.qinq,
        s.vlan_ids.len(),
        s.max_depth,
        s.multi_encap
    );
    let total_chains: u64 = s.chains.values().sum();
    if total_chains > 0 {
        println!("  ── Encapsulation chains (count / %) ──");
        let mut cv: Vec<(&String, &u64)> = s.chains.iter().collect();
        cv.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        for (k, v) in cv.iter().take(12) {
            let pct = **v as f64 * 100.0 / total_chains as f64;
            let bl = (pct / 100.0 * 24.0).round() as usize;
            let bar: String = "█".repeat(bl) + &"·".repeat(24 - bl);
            println!("   {bar} {:6.1}%  {:>8}  {}", pct, v, k);
        }
    }
    println!("  ── Capture-quality notices ──");
    if r.notices.is_empty() {
        println!("   ✓ no capture-quality notices");
    } else {
        for n in &r.notices {
            println!("   ⚠ {} [{}]", n.title, n.code);
            println!("     {}", n.text);
        }
    }

    match r.intake {
        "ACCEPT" => 0,
        "REVIEW" => 1,
        _ => 2,
    }
}

// ---------- GUI ----------

const INDEX_HTML: &str = include_str!("index.html");

async fn index() -> axum::response::Html<&'static str> {
    axum::response::Html(INDEX_HTML)
}

async fn check(mut mp: axum::extract::Multipart) -> axum::response::Response {
    use axum::response::IntoResponse;
    let mut name = String::from("upload");
    let mut data: Vec<u8> = Vec::new();
    while let Ok(Some(field)) = mp.next_field().await {
        if field.name() == Some("file") {
            if let Some(fname) = field.file_name() {
                name = fname.to_string();
            }
            if let Ok(bytes) = field.bytes().await {
                data = bytes.to_vec();
            }
        }
    }
    let sha = sha256_hex(&data);
    let r = analyze(&data);
    let s = &r.stats;
    // single source of truth: the GUI downloads this instead of rebuilding it
    let report_md = markdown_report(&name, &sha, &r);

    let avg_pkt = if r.packets > 0 {
        r.wire_bytes / r.packets as u64
    } else {
        0
    };
    let rate_bps = if r.has_time && r.duration > 0.0 {
        r.wire_bytes as f64 * 8.0 / r.duration
    } else {
        0.0
    };
    let start = fmt_utc(s.ts_first.unwrap_or(0.0));
    let end = fmt_utc(s.ts_last.unwrap_or(0.0));

    let checks: String = r
        .checks
        .iter()
        .map(|c| {
            format!(
                "{{\"level\":\"{}\",\"label\":{},\"detail\":{},\"source\":{}}}",
                c.level,
                json_str(&c.label),
                json_str(&c.detail),
                json_str(finding_source(&c.label))
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let notices: String = r
        .notices
        .iter()
        .map(|n| {
            format!(
                "{{\"code\":\"{}\",\"title\":{},\"text\":{}}}",
                n.code,
                json_str(&n.title),
                json_str(&n.text)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let dup_pct = if r.packets > 0 {
        r.stats.dup_frames as f64 * 100.0 / r.packets as f64
    } else {
        0.0
    };
    // encapsulation-chain distribution, most frequent first
    let mut chain_vec: Vec<(&String, &u64)> = r.stats.chains.iter().collect();
    chain_vec.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let chain_total: u64 = r.stats.chains.values().sum();
    let chains_json: String = chain_vec
        .iter()
        .take(20)
        .map(|(k, v)| {
            let pct = if chain_total > 0 {
                **v as f64 * 100.0 / chain_total as f64
            } else {
                0.0
            };
            format!(
                "{{\"chain\":{},\"count\":{},\"pct\":{:.1}}}",
                json_str(k),
                v,
                pct
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let json = format!(
        "{{\"name\":{name},\"format\":\"{fmt}\",\"linktype\":{lt},\"packets\":{pk},\"consumed\":{cons},\"total\":{tot},\"score\":{sc:.1},\"conformance\":{conf:.1},\"clean\":{cl},\"note\":{nt},\"sha256\":\"{sha}\",\"intake\":\"{intake}\",\"snaplen\":{snap},\"truncated\":{trunc},\"src_macs\":{macs},\"ip_addrs\":{ips},\"duration\":{dur:.1},\"has_time\":{ht},\"meta\":{{\"ver\":{ver},\"endian\":\"{endian}\",\"ts_prec\":\"{prec}\",\"ifaces\":{ifc},\"snaplen\":{snap},\"linktype\":{lt},\"start\":\"{start}\",\"end\":\"{end}\",\"duration_h\":{dur:.1},\"wire_bytes\":{wire},\"avg_pkt\":{avg},\"rate_bps\":{rate:.0}}},\"dist\":{{\"unicast\":{uni},\"multicast\":{mc},\"broadcast\":{bc},\"ipv4\":{v4},\"ipv6\":{v6},\"arp\":{arp},\"vlan\":{vlan},\"gre\":{gre},\"erspan\":{ers},\"vxlan\":{vx},\"geneve\":{gen},\"decoded\":{dec},\"dup_frames\":{dupf},\"dup_pct\":{dupp:.1},\"qinq\":{qinq},\"vlan_ids\":{vids},\"max_depth\":{mdep},\"multi_encap\":{menc}}},\"session\":{{\"tcp_flows\":{tcpf},\"handshake_complete\":{hsc},\"syn_only\":{hso},\"mid_stream\":{hsm},\"seq_gaps\":{gaps},\"acked_unseen\":{aunseen},\"inner_trunc\":{itrunc},\"vxlan_legacy\":{vxleg},\"runts\":{runt},\"oversize\":{ovsz}}},\"trust\":{trust},\"chains\":[{chains_json}],\"checks\":[{checks}],\"notices\":[{notices}],\"report_md\":{rmd}}}",
        name = json_str(&name),
        fmt = r.format,
        lt = json_str(&r.linktype),
        pk = r.packets,
        cons = r.consumed,
        tot = r.total,
        sc = r.score,
        conf = r.conformance,
        cl = r.clean,
        nt = json_str(&r.note),
        intake = r.intake,
        snap = r.snaplen,
        trunc = r.truncated_pkts,
        macs = r.src_macs,
        ips = r.ip_addrs,
        dur = r.duration,
        ht = r.has_time,
        ver = json_str(&r.ver),
        endian = r.endian,
        prec = r.ts_prec,
        ifc = r.iface_count,
        start = start,
        end = end,
        wire = r.wire_bytes,
        avg = avg_pkt,
        rate = rate_bps,
        uni = s.unicast,
        mc = s.multicast,
        bc = s.broadcast,
        v4 = s.ipv4,
        v6 = s.ipv6,
        arp = s.arp,
        vlan = s.vlan,
        gre = s.gre,
        ers = s.erspan,
        vx = s.vxlan,
        gen = s.geneve,
        dec = s.decoded,
        dupf = s.dup_frames,
        dupp = dup_pct,
        qinq = s.qinq,
        vids = s.vlan_ids.len(),
        mdep = s.max_depth,
        menc = s.multi_encap,
        tcpf = s.tcp_flows,
        hsc = s.hs_complete,
        hso = s.hs_syn_only,
        hsm = s.hs_midstream,
        gaps = s.seq_gaps,
        aunseen = s.acked_unseen,
        itrunc = s.inner_trunc,
        vxleg = s.vxlan_legacy,
        runt = s.runts,
        ovsz = s.oversize,
        trust = json_str(TRUST_NOTE),
        rmd = json_str(&report_md),
    );
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        json,
    )
        .into_response()
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Decode standard base64 (for HTTP Basic auth) — no external crate.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for &c in s.trim().as_bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        buf = (buf << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// True if the request carries the configured token (Bearer or Basic), or if
/// no token is configured (auth disabled).
fn authorized(headers: &axum::http::HeaderMap) -> bool {
    let token = &cfg().auth_token;
    if token.is_empty() {
        return true;
    }
    let Some(h) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    if let Some(b) = h.strip_prefix("Bearer ") {
        return ct_eq(b.trim(), token);
    }
    if let Some(b64) = h.strip_prefix("Basic ") {
        if let Some(dec) = b64_decode(b64) {
            if let Ok(s) = String::from_utf8(dec) {
                let pw = s.split_once(':').map(|(_, p)| p).unwrap_or("");
                return ct_eq(pw, token) || ct_eq(&s, token);
            }
        }
    }
    false
}

async fn auth_mw(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if authorized(req.headers()) {
        next.run(req).await
    } else {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            [(
                axum::http::header::WWW_AUTHENTICATE,
                "Basic realm=\"PicoCap\"",
            )],
            "Unauthorized — provide the PicoCap token.",
        )
            .into_response()
    }
}

async fn serve(addr: &str) {
    let app = axum::Router::new()
        .route("/", axum::routing::get(index))
        .route("/check", axum::routing::post(check))
        .layer(axum::middleware::from_fn(auth_mw))
        .layer(axum::extract::DefaultBodyLimit::max(cfg().max_upload));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    let auth = if cfg().auth_token.is_empty() {
        "no auth (localhost only recommended)"
    } else {
        "token auth ENABLED"
    };
    println!("PicoCap 🩺 v{VERSION} \"{CODENAME}\" — GUI on http://{addr}  [{auth}]");
    axum::serve(listener, app).await.expect("serve");
}

fn main() {
    // Load tunables from YAML (path via $PICOCAP_CONFIG, default ./picocap.yml).
    let cfg_path = std::env::var("PICOCAP_CONFIG").unwrap_or_else(|_| "picocap.yml".into());
    let _ = CFG.set(Config::load(&cfg_path));

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("serve") => {
            let addr = args
                .get(2)
                .cloned()
                .unwrap_or_else(|| cfg().listen_addr.clone());
            let rt = tokio::runtime::Runtime::new().expect("tokio");
            rt.block_on(serve(&addr));
        }
        Some("-V") | Some("--version") => {
            println!("picocap {VERSION} \"{CODENAME}\"");
        }
        Some("--report") | Some("-r") => {
            let Some(path) = args.get(2) else {
                eprintln!("usage: picocap --report <file>   (writes a Markdown report to stdout)");
                std::process::exit(2);
            };
            let total = match std::fs::metadata(path) {
                Ok(m) => m.len() as usize,
                Err(e) => {
                    eprintln!("cannot read {path}: {e}");
                    std::process::exit(2);
                }
            };
            let name = std::path::Path::new(path)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| path.clone());
            let (sha, r) = match (sha256_file(path), analyze_reader(path, total)) {
                (Ok(sha), Ok(r)) => (sha, r),
                _ => {
                    eprintln!("cannot read {path}");
                    std::process::exit(2);
                }
            };
            print!("{}", markdown_report(&name, &sha, &r));
        }
        Some("-h") | Some("--help") | None => {
            eprintln!(
                "PicoCap 🩺 v{VERSION} \"{CODENAME}\" — PCAP/PCAPNG capture intake checker\n"
            );
            eprintln!("  picocap <file>          check one capture file (text summary)");
            eprintln!("  picocap --report <file> write a Markdown assessment report to stdout");
            eprintln!("  picocap serve [addr]    start web GUI (default from picocap.yml)");
            eprintln!("  picocap --version       show version");
            std::process::exit(if args.get(1).is_none() { 1 } else { 0 });
        }
        Some(path) => std::process::exit(run_cli(path)),
    }
}

// ---------- tests ----------
#[cfg(test)]
mod tests {
    use super::*;

    // --- synthetic capture builders (classic pcap, little-endian, Ethernet) ---
    fn pcap(records: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend([0xd4, 0xc3, 0xb2, 0xa1]); // LE magic, µs
        o.extend(2u16.to_le_bytes());
        o.extend(4u16.to_le_bytes());
        o.extend([0u8; 8]); // thiszone + sigfigs
        o.extend(65535u32.to_le_bytes()); // snaplen
        o.extend(1u32.to_le_bytes()); // LINKTYPE_ETHERNET
        for (s, us, f) in records {
            o.extend(s.to_le_bytes());
            o.extend(us.to_le_bytes());
            o.extend((f.len() as u32).to_le_bytes()); // incl_len
            o.extend((f.len() as u32).to_le_bytes()); // orig_len
            o.extend(f);
        }
        o
    }

    const M1: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
    const M2: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
    const BCAST: [u8; 6] = [0xff; 6];
    const MCAST: [u8; 6] = [0x01, 0, 0x5e, 0, 0, 1];

    fn eth(dst: [u8; 6], src: [u8; 6], et: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend(dst);
        f.extend(src);
        f.extend(et.to_be_bytes());
        f.extend(payload);
        f
    }

    // minimal IPv4 header (20 B), src 10.0.0.1 / dst 10.0.0.2, given proto + payload
    fn ipv4(proto: u8, id: u16, payload: &[u8]) -> Vec<u8> {
        let mut h = vec![0x45, 0x00];
        h.extend(((20 + payload.len()) as u16).to_be_bytes());
        h.extend(id.to_be_bytes());
        h.extend([0x40, 0x00, 0x40, proto, 0x00, 0x00]);
        h.extend([10, 0, 0, 1, 10, 0, 0, 2]);
        h.extend(payload);
        h
    }
    fn tcp(pad: u8) -> Vec<u8> {
        vec![pad; 20]
    }
    // an inner Ethernet frame carrying IPv4/TCP
    fn inner_ip_tcp(id: u16, pad: u8) -> Vec<u8> {
        eth(M2, M1, 0x0800, &ipv4(6, id, &tcp(pad)))
    }

    // IPv4 header with explicit src/dst (the fixed-address `ipv4` can't reverse).
    fn ipv4_full(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
        let mut h = vec![0x45, 0x00];
        h.extend(((20 + payload.len()) as u16).to_be_bytes());
        h.extend([0, 0, 0x40, 0x00, 0x40, proto, 0, 0]);
        h.extend(src);
        h.extend(dst);
        h.extend(payload);
        h
    }
    // A 20-byte TCP header (data offset 5) + payload. flags: SYN 0x02, ACK 0x10, FIN 0x01.
    fn tcp_seg(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend(sport.to_be_bytes());
        t.extend(dport.to_be_bytes());
        t.extend(seq.to_be_bytes());
        t.extend(ack.to_be_bytes());
        t.push(0x50); // data offset = 5 words (20 B)
        t.push(flags);
        t.extend(8192u16.to_be_bytes()); // window
        t.extend([0, 0, 0, 0]); // checksum + urgent
        t.extend(payload);
        t
    }
    // A full Ethernet/IPv4/TCP frame between client 10.0.0.1 and server 10.0.0.2.
    fn frame_tcp(
        from_client: bool,
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let (src, dst, smac, dmac) = if from_client {
            ([10, 0, 0, 1], [10, 0, 0, 2], M1, M2)
        } else {
            ([10, 0, 0, 2], [10, 0, 0, 1], M2, M1)
        };
        eth(
            dmac,
            smac,
            0x0800,
            &ipv4_full(
                src,
                dst,
                6,
                &tcp_seg(sport, dport, seq, ack, flags, payload),
            ),
        )
    }

    #[test]
    fn tcp_handshake_and_capture_drop() {
        // SYN, SYN-ACK, ACK, data(100B), then a segment that skips 200 B forward
        // (a captured-side gap) — one complete handshake, one sequence gap.
        let (cp, sp) = (12345u16, 502u16);
        let recs = vec![
            (1u32, 0u32, frame_tcp(true, cp, sp, 1000, 0, 0x02, &[])), // SYN
            (1, 1, frame_tcp(false, sp, cp, 5000, 1001, 0x12, &[])),   // SYN-ACK
            (1, 2, frame_tcp(true, cp, sp, 1001, 5001, 0x10, &[])),    // ACK
            (1, 3, frame_tcp(true, cp, sp, 1001, 5001, 0x18, &[7u8; 100])), // data -> next 1101
            (1, 4, frame_tcp(true, cp, sp, 1301, 5001, 0x18, &[7u8; 50])), // GAP: expected 1101
        ];
        let r = analyze(&pcap(&recs));
        assert_eq!(r.stats.tcp_flows, 1, "one TCP session");
        assert_eq!(r.stats.hs_complete, 1, "complete handshake");
        assert_eq!(r.stats.hs_syn_only, 0);
        assert_eq!(
            r.stats.seq_gaps, 1,
            "one forward sequence gap = capture drop"
        );
        assert!(
            r.checks
                .iter()
                .any(|c| c.label.starts_with("No capture drops") && c.level == "warn"),
            "capture-drop check should warn"
        );
    }

    #[test]
    fn streaming_matches_in_memory() {
        // The CLI streams via analyze_core over a chunked reader; the GUI uses
        // the in-memory slice. Both must yield identical results.
        let (cp, sp) = (12345u16, 502u16);
        let recs = vec![
            (1u32, 0u32, frame_tcp(true, cp, sp, 1000, 0, 0x02, &[])),
            (1, 1, frame_tcp(false, sp, cp, 5000, 1001, 0x12, &[])),
            (1, 2, frame_tcp(true, cp, sp, 1001, 5001, 0x18, &[7u8; 100])),
            (1, 3, frame_tcp(true, cp, sp, 1301, 5001, 0x18, &[7u8; 50])),
        ];
        let bytes = pcap(&recs);
        let mem = analyze(&bytes);
        // stream the same bytes through a small-window reader (magic = first 24 B)
        let magic = &bytes[..24.min(bytes.len())];
        let strm = analyze_core(magic, std::io::Cursor::new(bytes.clone()), bytes.len());
        assert_eq!(mem.packets, strm.packets);
        assert_eq!(mem.stats.tcp_flows, strm.stats.tcp_flows);
        assert_eq!(mem.stats.seq_gaps, strm.stats.seq_gaps);
        assert_eq!(mem.stats.hs_complete, strm.stats.hs_complete);
        assert_eq!(mem.conformance, strm.conformance);
    }

    #[test]
    fn tcp_acked_unseen() {
        // Handshake, then the client ACKs 100 B of server data that the capture
        // never recorded — an ACKed-unseen segment (RFC 9293 §3.4 capture drop).
        let (cp, sp) = (30000u16, 502u16);
        let recs = vec![
            (1u32, 0u32, frame_tcp(true, cp, sp, 1000, 0, 0x02, &[])), // SYN
            (1, 1, frame_tcp(false, sp, cp, 5000, 1001, 0x12, &[])),   // SYN-ACK
            (1, 2, frame_tcp(true, cp, sp, 1001, 5001, 0x10, &[])),    // normal ACK
            // server data 5001..5101 is missing from the capture
            (1, 3, frame_tcp(true, cp, sp, 1001, 5101, 0x10, &[])), // ACK for unseen 100 B
        ];
        let r = analyze(&pcap(&recs));
        assert_eq!(r.stats.acked_unseen, 1, "one ACK for data never captured");
        assert_eq!(r.stats.seq_gaps, 0, "no client-side data gap");
    }

    #[test]
    fn inner_length_truncation() {
        // IP total-length claims 200 B but only a 20 B TCP header is present.
        let mut ip = vec![0x45, 0x00];
        ip.extend(200u16.to_be_bytes()); // total_length = 200 (exceeds captured)
        ip.extend([0, 0, 0x40, 0x00, 0x40, 6, 0, 0]);
        ip.extend([10, 0, 0, 1, 10, 0, 0, 2]);
        ip.extend(tcp_seg(1111, 502, 1, 0, 0x10, &[])); // 20 B L4, no payload
        let frame = eth(M2, M1, 0x0800, &ip);
        let r = analyze(&pcap(&[(1u32, 0u32, frame)]));
        assert_eq!(
            r.stats.inner_trunc, 1,
            "inner IP length exceeds captured bytes"
        );
    }

    #[test]
    fn routed_double_capture_ttl_tolerant() {
        // Two mirror copies of the SAME packet (same IP id) differing only in TTL
        // — a routed both-direction SPAN. The TTL-tolerant dedup must catch it.
        let seg = tcp_seg(1000, 80, 5, 0, 0x10, &[1, 2, 3, 4]);
        let ip1 = ipv4_full([10, 0, 0, 1], [10, 0, 0, 2], 6, &seg);
        let mut ip2 = ip1.clone();
        ip2[8] = 0x3f; // decremented TTL (egress copy of the same frame)
        let f1 = eth(M2, M1, 0x0800, &ip1);
        let f2 = eth(M2, M1, 0x0800, &ip2);
        let r = analyze(&pcap(&[(1u32, 0u32, f1), (1, 10, f2)])); // 10 µs apart
        assert_eq!(
            r.stats.dup_frames, 1,
            "routed mirror copy (TTL differs) detected"
        );
    }

    #[test]
    fn egress_tag_artifact_on_double_capture() {
        // The same inner frame appears twice within the window — once untagged,
        // once 802.1Q-tagged: the egress-copy VLAN-tag chipset artifact.
        let inner = ipv4(6, 42, &tcp_seg(1000, 80, 5, 0, 0x10, &[9u8; 20]));
        let untagged = eth(M2, M1, 0x0800, &inner);
        let tagged = vlan(M2, 100, 0x0800, &inner); // same inner IP, VLAN-tagged
        let r = analyze(&pcap(&[(1u32, 0u32, untagged), (1, 1000, tagged)])); // 1 ms apart
        assert_eq!(
            r.stats.dup_frames, 1,
            "the two copies are the same inner frame"
        );
        assert_eq!(r.stats.dup_tag_diff, 1, "the copies differ in VLAN tagging");
    }

    #[test]
    fn timestamp_discontinuity_flagged() {
        // Two frames > 2 days apart = a merged/replayed capture.
        let f = |id| eth(M2, M1, 0x0800, &ipv4(6, id, &tcp(0)));
        let r = analyze(&pcap(&[(1000u32, 0u32, f(1)), (201000u32, 0u32, f(2))]));
        assert!(
            r.notices
                .iter()
                .any(|n| n.code == "timestamps_discontinuous"),
            "a multi-day inter-frame gap must raise a discontinuity notice"
        );
    }

    /// Guard against stale version references: every `picocap:<x.y.z>` docker tag
    /// in the docs and the README version badge must match the crate version. This
    /// is what caught the docker-compose 1.0.0 pin — it now fails CI, not review.
    #[test]
    fn version_strings_are_consistent() {
        let ver = env!("CARGO_PKG_VERSION");
        let dir = env!("CARGO_MANIFEST_DIR");
        for f in [
            "README.md",
            "SECURITY.md",
            "docker-compose.yml",
            "CLAUDE.md",
        ] {
            let txt = std::fs::read_to_string(format!("{dir}/{f}")).unwrap_or_default();
            let mut rest = txt.as_str();
            while let Some(i) = rest.find("picocap:") {
                let tag: String = rest[i + 8..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                if !tag.is_empty() {
                    assert_eq!(
                        tag, ver,
                        "stale docker tag `picocap:{tag}` in {f} (want {ver})"
                    );
                }
                rest = &rest[i + 8..];
            }
        }
        let readme = std::fs::read_to_string(format!("{dir}/README.md")).unwrap_or_default();
        assert!(
            readme.contains(&format!("version-{ver}")),
            "README version badge does not show {ver}"
        );
    }

    #[test]
    fn tcp_clean_session_no_gap() {
        // A clean, in-order half-session: SYN then contiguous data, no gaps.
        let (cp, sp) = (40000u16, 44818u16);
        let recs = vec![
            (1u32, 0u32, frame_tcp(true, cp, sp, 100, 0, 0x02, &[])), // SYN -> next 101
            (1, 1, frame_tcp(true, cp, sp, 101, 0, 0x10, &[9u8; 40])), // 101..141
            (1, 2, frame_tcp(true, cp, sp, 141, 0, 0x10, &[9u8; 40])), // 141..181 contiguous
        ];
        let r = analyze(&pcap(&recs));
        assert_eq!(r.stats.seq_gaps, 0, "contiguous stream has no gaps");
        assert_eq!(r.stats.hs_syn_only, 1, "SYN seen but no SYN-ACK");
    }

    fn vlan(dst: [u8; 6], vid: u16, inner_et: u16, inner: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend(vid.to_be_bytes());
        p.extend(inner_et.to_be_bytes());
        p.extend(inner);
        eth(dst, M1, 0x8100, &p)
    }
    fn qinq(outer: u16, inner_vid: u16, inner_et: u16, inner: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend(outer.to_be_bytes());
        p.extend(0x8100u16.to_be_bytes());
        p.extend(inner_vid.to_be_bytes());
        p.extend(inner_et.to_be_bytes());
        p.extend(inner);
        eth(M2, M1, 0x88a8, &p)
    }
    fn vxlan_pkt() -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend(1000u16.to_be_bytes()); // src port
        udp.extend(4789u16.to_be_bytes()); // dst port = VXLAN
        udp.extend([0, 0, 0, 0]); // len + csum
        udp.extend([0x08, 0, 0, 0, 0, 0, 0, 0]); // 8-byte VXLAN header
        udp.extend(inner_ip_tcp(1, 7)); // inner frame
        eth(M1, M2, 0x0800, &ipv4(17, 1, &udp))
    }
    fn erspan_pkt(id: u16, pad: u8) -> Vec<u8> {
        let mut gre = Vec::new();
        gre.extend(0x1000u16.to_be_bytes()); // GRE flags: sequence present
        gre.extend(0x88beu16.to_be_bytes()); // proto = ERSPAN II
        gre.extend([0, 0, 0, 0]); // sequence
        gre.extend([0u8; 8]); // ERSPAN II header
        gre.extend(inner_ip_tcp(id, pad)); // inner frame
        eth(M1, M2, 0x0800, &ipv4(47, 1, &gre))
    }

    #[test]
    fn detect_formats() {
        assert_eq!(detect_format(&[0xa1, 0xb2, 0xc3, 0xd4]).0, Some("pcap"));
        assert_eq!(detect_format(&[0xd4, 0xc3, 0xb2, 0xa1]).0, Some("pcap"));
        assert_eq!(detect_format(&[0x0a, 0x0d, 0x0d, 0x0a]).0, Some("pcapng"));
        assert_eq!(detect_format(&[0xa1, 0xb2, 0x3c, 0x4d]).1, 1e-9); // ns
        assert_eq!(detect_format(b"PK\x03\x04").0, None);
    }

    #[test]
    fn not_a_capture_is_rejected() {
        let r = analyze(b"this is not a pcap file at all");
        assert_eq!(r.format, "unknown");
        assert_eq!(r.intake, "REJECT");
        assert_eq!(r.conformance, 0.0);
    }

    #[test]
    fn plain_ethernet_ipv4_tcp() {
        let cap = pcap(&[(0, 0, eth(M2, M1, 0x0800, &ipv4(6, 1, &tcp(0))))]);
        let r = analyze(&cap);
        assert_eq!(r.format, "pcap");
        assert_eq!(r.packets, 1);
        assert_eq!(r.stats.unicast, 1);
        assert_eq!(r.stats.ipv4, 1);
        assert!(r.stats.chains.contains_key("Eth>IPv4>TCP"));
        assert_eq!(r.score, 100.0);
    }

    #[test]
    fn cast_classification() {
        let cap = pcap(&[
            (0, 0, eth(M2, M1, 0x0800, &ipv4(6, 1, &tcp(0)))), // unicast
            (0, 1, eth(BCAST, M1, 0x0806, &[0u8; 28])),        // broadcast ARP
            (0, 2, eth(MCAST, M1, 0x0800, &ipv4(17, 2, &tcp(0)))), // multicast
        ]);
        let r = analyze(&cap);
        assert_eq!(r.stats.unicast, 1);
        assert_eq!(r.stats.broadcast, 1);
        assert_eq!(r.stats.multicast, 1);
        assert_eq!(r.stats.arp, 1);
    }

    #[test]
    fn vlan_tagging_counted() {
        let cap = pcap(&[(0, 0, vlan(M2, 100, 0x0800, &ipv4(6, 1, &tcp(0))))]);
        let r = analyze(&cap);
        assert_eq!(r.stats.vlan, 1, "VLAN frame must be counted");
        assert_eq!(r.stats.qinq, 0);
        assert!(r.stats.vlan_ids.contains(&100));
        assert_eq!(r.stats.ipv4, 1, "inner IPv4 seen through the VLAN tag");
        assert!(r.stats.chains.keys().any(|c| c.contains("VLAN")));
    }

    #[test]
    fn qinq_double_tag() {
        let cap = pcap(&[(0, 0, qinq(200, 300, 0x0800, &ipv4(6, 1, &tcp(0))))]);
        let r = analyze(&cap);
        assert_eq!(r.stats.qinq, 1, "QinQ (>=2 tags) must be detected");
        assert_eq!(r.stats.vlan, 1);
        assert!(r.stats.vlan_ids.contains(&300));
        assert!(r.stats.chains.keys().any(|c| c.contains("QinQ")));
    }

    #[test]
    fn vxlan_decapsulation() {
        let r = analyze(&pcap(&[(0, 0, vxlan_pkt())]));
        assert_eq!(r.stats.vxlan, 1, "VXLAN tunnel must be counted");
        assert_eq!(r.stats.max_depth, 1);
        assert_eq!(r.stats.ipv4, 1, "inner IPv4 analysed, not the outer");
        assert!(r.stats.chains.keys().any(|c| c.contains("VXLAN")));
    }

    #[test]
    fn erspan_decapsulation() {
        let r = analyze(&pcap(&[(0, 0, erspan_pkt(1, 0))]));
        assert_eq!(r.stats.gre, 1);
        assert_eq!(r.stats.erspan, 1);
        assert_eq!(r.stats.max_depth, 1);
        assert_eq!(r.stats.ipv4, 1, "inner IPv4 through GRE/ERSPAN");
        assert!(r.stats.chains.keys().any(|c| c.contains("GRE/ERSPAN")));
    }

    #[test]
    fn span_double_capture_detected() {
        // 5 distinct frames, each duplicated 1 ms later within the 5 ms window
        let mut recs = Vec::new();
        for i in 0..5u32 {
            let f = eth(M2, M1, 0x0800, &ipv4(6, i as u16, &tcp(i as u8)));
            recs.push((i, 0, f.clone()));
            recs.push((i, 1000, f)); // +1 ms
        }
        let r = analyze(&pcap(&recs));
        assert_eq!(r.packets, 10);
        assert_eq!(
            r.stats.dup_frames, 5,
            "second copy of each pair is a duplicate"
        );
        assert!(
            r.notices.iter().any(|n| n.code == "span_double_capture"),
            "50% duplicates must raise the notice"
        );
        assert!(r.conformance < 100.0);
        assert_ne!(r.intake, "ACCEPT");
    }

    #[test]
    fn truncated_capture_scores_below_100() {
        let mut cap = pcap(&[
            (0, 0, eth(M2, M1, 0x0800, &ipv4(6, 1, &tcp(0)))),
            (0, 1, eth(M2, M1, 0x0800, &ipv4(6, 2, &tcp(0)))),
        ]);
        cap.truncate(cap.len() - 20); // cut into the last record's data
        let r = analyze(&cap);
        assert!(r.score < 100.0, "truncated file must not be 100% integrity");
        assert!(!r.clean);
    }

    #[test]
    fn clean_capture_conforms() {
        // >64 KB, 6 distinct devices, spans 6 s, no duplicates -> full pass
        let mut recs = Vec::new();
        for i in 0..1200u32 {
            let src = [0x02, 0, 0, 0, 0, (i % 6) as u8]; // 6 distinct source MACs
            let f = eth(
                M2,
                src,
                0x0800,
                &ipv4(6, (i % 65535) as u16, &[(i % 251) as u8; 40]),
            );
            recs.push((i % 7, i, f)); // timestamps span 0..6 s
        }
        let r = analyze(&pcap(&recs));
        assert!(
            r.total > 64 * 1024,
            "capture must exceed the tiny-file threshold"
        );
        assert!(r.src_macs >= 5, "enough devices for the diversity check");
        assert!(r.notices.is_empty(), "no quality findings expected");
        assert_eq!(r.intake, "ACCEPT");
        assert_eq!(r.conformance, 100.0);
    }

    #[test]
    fn helpers_format_numbers() {
        assert_eq!(grp(197531), "197.531");
        assert_eq!(grp(5), "5");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_bytes(500), "500 B");
        assert!(fmt_utc(0.0).starts_with('-') || fmt_utc(0.0) == "-");
        assert_eq!(fmt_utc(1_000_000_000.0), "2001-09-09 01:46:40 UTC");
    }
}
