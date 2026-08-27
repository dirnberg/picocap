#!/usr/bin/env python3
"""Build ONE anonymized, realistic OT capture that trips as many PicoCap notices
as can coexist in a single file — a demo + deployment QA fixture.

Anonymized: RFC5737 TEST-NET / RFC1918 IPs, locally-administered MACs (02:..).
Triggers: span_double_capture (+egress-tag), NIC offload super-frames, inner-length
truncation, VXLAN on legacy 8472, malformed VXLAN header (I-flag clear),
timestamp discontinuity, and TCP capture-drops (seq gaps + ACKed-unseen).
NOT triggered (mutually exclusive with the above): mirror_no_unicast needs <2%
unicast, which contradicts a TCP-rich capture.
"""
import struct, sys

LE=lambda *a: b"".join(a)
def u16(x): return struct.pack(">H",x)
def u32(x): return struct.pack(">I",x)

def mac(n): return bytes([0x02,0,0,0,0,n])
def eth(dst,src,et,pl): return dst+src+u16(et)+pl
def vlan(dst,src,vid,inner_et,pl): return dst+src+u16(0x8100)+u16(vid)+u16(inner_et)+pl

def ip4(src,dst,proto,pl,total_len=None,ttl=64,tos=0):
    tl = total_len if total_len is not None else 20+len(pl)
    h=bytes([0x45,tos])+u16(tl)+u16(0)+bytes([0x40,0,ttl,proto,0,0])+src+dst
    return h+pl
def tcp(sp,dp,seq,ack,flags,pl=b""):
    return u16(sp)+u16(dp)+u32(seq)+u32(ack)+bytes([0x50,flags])+u16(8192)+b"\x00\x00\x00\x00"+pl
def udp(sp,dp,pl):
    return u16(sp)+u16(dp)+u16(8+len(pl))+u16(0)+pl
def vxlan_hdr(vni,iflag=True):
    flags=0x08 if iflag else 0x00
    return bytes([flags,0,0,0])+bytes([(vni>>16)&0xff,(vni>>8)&0xff,vni&0xff,0])

def IP(a,b,c,d): return bytes([a,b,c,d])

recs=[]  # (ts_sec, ts_usec, frame_bytes)
t=[1_700_000_000, 0]
def emit(frame, dt_us=200):
    recs.append((t[0], t[1], frame)); t[1]+=dt_us
    if t[1]>=1_000_000: t[0]+=1; t[1]-=1_000_000

# --- realistic OT-ish endpoints (anonymized) ---
PLC=IP(10,10,10,10); HMI=IP(10,10,10,20); ENG=IP(10,10,10,30)
SRV=IP(192,0,2,50); CLI=IP(192,0,2,51)   # TEST-NET
MP={PLC:mac(10),HMI:mac(20),ENG:mac(30),SRV:mac(50),CLI:mac(51)}

def frame_tcp(src,dst,sp,dp,seq,ack,flags,pl=b"",tag=None,total=None,ttl=64):
    ipp=ip4(src,dst,6,tcp(sp,dp,seq,ack,flags,pl),total_len=total,ttl=ttl)
    if tag is not None: return vlan(MP[dst],MP[src],tag,0x0800,ipp)
    return eth(MP[dst],MP[src],0x0800,ipp)

# 1) baseline: several complete Modbus/HTTP handshakes (device diversity, clean)
seq=1000
for i in range(6):
    a,b=[(PLC,HMI),(PLC,ENG),(SRV,CLI),(HMI,SRV),(ENG,PLC),(CLI,PLC)][i]
    sp,dp=40000+i,502 if b in (HMI,ENG) else 80
    emit(frame_tcp(a,b,sp,dp,seq,0,0x02))                 # SYN
    emit(frame_tcp(b,a,dp,sp,5000+i,seq+1,0x12))          # SYN-ACK
    emit(frame_tcp(a,b,sp,dp,seq+1,5001+i,0x10))          # ACK
    emit(frame_tcp(a,b,sp,dp,seq+1,5001+i,0x18,b"\x00\x06"*20))  # data
    seq+=100

# 2) span_double_capture + EGRESS-TAG: duplicate ~40 frames within 200us;
#    half of the second copies are VLAN-tagged (egress copy carries a tag).
for i in range(40):
    f=frame_tcp(SRV,CLI,443,50000+i,7000+i*40,0,0x18,b"\xAB"*20)
    emit(f, dt_us=50)                     # original
    # egress copy: same inner IP, but VLAN-tagged on ~half → tag artifact
    if i%2==0:
        f2=frame_tcp(SRV,CLI,443,50000+i,7000+i*40,0,0x18,b"\xAB"*20,tag=100)
    else:
        f2=frame_tcp(SRV,CLI,443,50000+i,7000+i*40,0,0x18,b"\xAB"*20)
    emit(f2, dt_us=150)                   # mirror duplicate ~200us later

# 3) capture-drops: a flow with a forward seq gap AND an ACK for unseen data
emit(frame_tcp(HMI,PLC,33000,102,9000,0,0x02))            # SYN
emit(frame_tcp(PLC,HMI,102,33000,6000,9001,0x12))         # SYN-ACK
emit(frame_tcp(HMI,PLC,102 if False else 33000,102,9001,6001,0x18,b"\x11"*40))  # 9001..9041
emit(frame_tcp(HMI,PLC,33000,102,9200,6001,0x18,b"\x11"*40))  # GAP: expected 9041, seq 9200
emit(frame_tcp(HMI,PLC,33000,102,9241,6300,0x10))         # ACK 6300: acks server bytes never captured

# 4) NIC offload super-frames: a few frames far above 1518 B (endpoint TSO/GRO)
for i in range(3):
    emit(frame_tcp(SRV,CLI,443,50500+i,20000+i,0,0x18,b"\xCD"*3000))  # ~3050 B frame

# 5) inner-length truncation: IP total_len claims 2000 but only ~60 B present
emit(frame_tcp(CLI,SRV,50600,443,30000,0,0x18,b"\x22"*20,total=2000))

# 6) VXLAN on legacy port 8472 (vs RFC 7348 4789), valid I-flag
inner=eth(mac(61),mac(60),0x0800,ip4(IP(172,16,0,1),IP(172,16,0,2),6,tcp(1234,502,1,0,0x10,b"\x00\x06")))
vx=udp(50000,8472, vxlan_hdr(100,iflag=True)+inner)
emit(eth(mac(2),mac(1),0x0800, ip4(IP(10,0,0,1),IP(10,0,0,2),17, vx)))

# 7) malformed VXLAN header (I-flag clear) on standard port 4789
vxb=udp(50001,4789, vxlan_hdr(100,iflag=False)+inner)
emit(eth(mac(2),mac(1),0x0800, ip4(IP(10,0,0,1),IP(10,0,0,2),17, vxb)))

# 8) timestamp discontinuity: final frame > 2 days later (merged/replayed)
t[0]+=200_000
emit(frame_tcp(PLC,HMI,502,40010,12345,0,0x10))

# --- write classic pcap (LE, microseconds, LINKTYPE_ETHERNET) ---
out=bytes([0xd4,0xc3,0xb2,0xa1])+struct.pack("<HH",2,4)+b"\x00"*8+struct.pack("<II",262144,1)
for s,us,f in recs:
    out+=struct.pack("<IIII",s,us,len(f),len(f))+f
open(sys.argv[1] if len(sys.argv)>1 else "mega.pcap","wb").write(out)
print(f"frames={len(recs)} bytes={len(out)} -> {sys.argv[1] if len(sys.argv)>1 else 'mega.pcap'}")
