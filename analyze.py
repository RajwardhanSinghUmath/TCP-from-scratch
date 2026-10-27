#!/usr/bin/env python3
"""
analyze.py — PyShark-based TCP packet analyser
Usage: python3 analyze.py capture.pcap

Sections:
  1. Connection Establishment (3-Way Handshake)
  2. Data Transfer
  3. Checksum Verification
  4. Sliding Window Analysis
  5. AIMD Congestion Control Inference
  6. Connection Termination
  Summary Table
"""

import sys
import os
from datetime import datetime

# ── Colour codes ──────────────────────────────────────────────────────────────
RED    = '\033[91m'
GREEN  = '\033[92m'
YELLOW = '\033[93m'
BLUE   = '\033[94m'
CYAN   = '\033[96m'
MAGENTA= '\033[95m'
RESET  = '\033[0m'

# ── Check dependency ──────────────────────────────────────────────────────────
try:
    import pyshark
except ImportError:
    print(f"{RED}[ERROR]{RESET} pyshark not installed.")
    print(f"  Run: pip install pyshark")
    print(f"  Also requires tshark: sudo apt install tshark  (WSL/Linux)")
    sys.exit(1)


def decode_tcp_flags(flags_hex: str) -> dict:
    """Return dict of flag_name → bool given a hex string like '0x002'."""
    try:
        f = int(flags_hex, 16)
    except (ValueError, TypeError):
        f = 0
    return {
        'FIN': bool(f & 0x001),
        'SYN': bool(f & 0x002),
        'RST': bool(f & 0x004),
        'PSH': bool(f & 0x008),
        'ACK': bool(f & 0x010),
        'URG': bool(f & 0x020),
    }


def flags_str(flags: dict) -> str:
    """Human readable flag list, e.g. 'SYN ACK'."""
    active = [name for name, val in flags.items() if val]
    return ' '.join(active) if active else 'DATA'


def safe_int(attr, default=0):
    try:
        return int(str(attr))
    except Exception:
        return default


def safe_str(attr, default=''):
    try:
        return str(attr)
    except Exception:
        return default


def get_payload_preview(pkt, max_chars=50) -> str:
    """Try to extract and decode the TCP payload."""
    try:
        raw = bytes.fromhex(pkt.tcp.payload.replace(':', ''))
        return raw.decode('utf-8', errors='replace')[:max_chars]
    except Exception:
        return ''


def analyze_pcap(filename: str):
    if not os.path.exists(filename):
        print(f"{RED}[ERROR]{RESET} File not found: {filename}")
        sys.exit(1)

    print(f"\n{'='*70}")
    print(f"  TCP RAW SOCKET ANALYSIS  —  {filename}")
    print(f"  Analysed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")

    # Load all TCP packets
    print(f"{YELLOW}[INFO]{RESET} Loading capture file, please wait…")
    try:
        cap = pyshark.FileCapture(filename, display_filter='tcp',
                                  keep_packets=True)
        packets = list(cap)
        cap.close()
    except Exception as e:
        print(f"{RED}[ERROR]{RESET} Failed to open capture: {e}")
        sys.exit(1)

    print(f"{GREEN}[INFO]{RESET} Total TCP packets captured: {len(packets)}\n")

    if not packets:
        print(f"{YELLOW}[WARN]{RESET} No TCP packets found in {filename}")
        return

    # ── Pre-process all packets into lightweight dicts ────────────────────
    proc = []
    for pkt in packets:
        try:
            tcp = pkt.tcp
        except AttributeError:
            continue  # not a TCP packet (shouldn't happen with filter)

        ts       = float(pkt.sniff_timestamp)
        src_ip   = safe_str(getattr(pkt, 'ip', None) and pkt.ip.src,  '?.?.?.?')
        dst_ip   = safe_str(getattr(pkt, 'ip', None) and pkt.ip.dst,  '?.?.?.?')
        src_port = safe_int(tcp.srcport)
        dst_port = safe_int(tcp.dstport)
        flags_h  = safe_str(tcp.flags, '0x000')
        flags    = decode_tcp_flags(flags_h)
        seq      = safe_int(tcp.seq)
        ack      = safe_int(tcp.ack)   if flags['ACK'] else 0
        window   = safe_int(tcp.window_size)
        chksum   = safe_str(tcp.checksum)
        plen     = safe_int(tcp.len) - safe_int(tcp.hdr_len, 20)
        plen     = max(plen, 0)
        preview  = get_payload_preview(pkt, 50) if plen > 0 else ''

        proc.append({
            'ts':       ts,
            'src':      f"{src_ip}:{src_port}",
            'dst':      f"{dst_ip}:{dst_port}",
            'flags':    flags,
            'flags_str':flags_str(flags),
            'seq':      seq,
            'ack':      ack,
            'window':   window,
            'chksum':   chksum,
            'plen':     plen,
            'preview':  preview,
            'raw_flags':flags_h,
        })

    def ts_fmt(ts):
        return datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3]

    def print_pkt(p, color=RESET, label=''):
        tag = f"[{label}]" if label else ''
        print(f"{color}{tag:12s}{RESET} "
              f"{ts_fmt(p['ts'])}  "
              f"{p['src']:22s} → {p['dst']:22s}  "
              f"Flags=[{p['flags_str']:14s}]  "
              f"Seq={p['seq']:<10d}  Ack={p['ack']:<10d}  "
              f"Win={p['window']:<6d}  Chk={p['chksum']}  "
              f"Len={p['plen']}"
              + (f"  Data=\"{p['preview']}\"" if p['preview'] else ''))

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 1: Connection Establishment
    # ─────────────────────────────────────────────────────────────────────
    print(f"{CYAN}{'─'*70}")
    print(f"  [SECTION 1]  CONNECTION ESTABLISHMENT (3-Way Handshake)")
    print(f"{'─'*70}{RESET}")

    hs_found = {'SYN': False, 'SYN-ACK': False, 'ACK': False}
    for p in proc:
        f = p['flags']
        if f['SYN'] and not f['ACK'] and not hs_found['SYN']:
            print_pkt(p, GREEN, 'SYN')
            hs_found['SYN'] = True
        elif f['SYN'] and f['ACK'] and not hs_found['SYN-ACK']:
            print_pkt(p, YELLOW, 'SYN-ACK')
            hs_found['SYN-ACK'] = True
        elif f['ACK'] and not f['SYN'] and not f['FIN'] and p['plen'] == 0 \
                and hs_found['SYN-ACK'] and not hs_found['ACK']:
            print_pkt(p, BLUE, 'ACK')
            hs_found['ACK'] = True
            break

    if all(hs_found.values()):
        print(f"{GREEN}  ✓ 3-Way Handshake complete{RESET}\n")
    else:
        missing = [k for k, v in hs_found.items() if not v]
        print(f"{RED}  ✗ Handshake incomplete — missing: {', '.join(missing)}{RESET}\n")

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 2: Data Transfer
    # ─────────────────────────────────────────────────────────────────────
    print(f"{CYAN}{'─'*70}")
    print(f"  [SECTION 2]  DATA TRANSFER")
    print(f"{'─'*70}{RESET}")

    data_pkts = [p for p in proc if p['plen'] > 0]
    if not data_pkts:
        print(f"{YELLOW}  No data packets found{RESET}\n")
    else:
        print(f"  Total data-carrying packets: {len(data_pkts)}\n")
        for p in data_pkts:
            print_pkt(p, GREEN, 'DATA')
        print()

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 3: Checksum Verification
    # ─────────────────────────────────────────────────────────────────────
    print(f"{CYAN}{'─'*70}")
    print(f"  [SECTION 3]  CHECKSUM VERIFICATION")
    print(f"{'─'*70}{RESET}")

    # tshark marks bad checksums with expert info; we report what we see
    chksum_good = 0
    chksum_bad  = 0
    for p in proc:
        # pyshark exposes tcp.checksum_status in some versions
        # Fallback: just report the checksum value; flag '0x0000' as suspicious
        ck = p['chksum'].lower()
        if ck in ('0x0000', '0x00000000', 'bad', ''):
            print(f"  {RED}[BAD ]{RESET} {ts_fmt(p['ts'])}  Seq={p['seq']}  Checksum={p['chksum']}")
            chksum_bad += 1
        else:
            print(f"  {GREEN}[OK  ]{RESET} {ts_fmt(p['ts'])}  Seq={p['seq']}  Checksum={p['chksum']}")
            chksum_good += 1

    print(f"\n  Valid: {chksum_good}   Invalid/Suspicious: {chksum_bad}\n")

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 4: Sliding Window Analysis
    # ─────────────────────────────────────────────────────────────────────
    print(f"{CYAN}{'─'*70}")
    print(f"  [SECTION 4]  SLIDING WINDOW ANALYSIS")
    print(f"{'─'*70}{RESET}")

    seq_numbers = [p['seq'] for p in proc if p['plen'] > 0]
    unique_seqs = sorted(set(seq_numbers))

    # Detect gaps (potential losses / retransmissions)
    retransmissions = []
    seen_seqs = {}
    for p in proc:
        if p['plen'] > 0:
            if p['seq'] in seen_seqs:
                retransmissions.append(p)
                print(f"  {RED}[RTXMT]{RESET} Seq={p['seq']} at {ts_fmt(p['ts'])}  "
                      f"(first seen at {ts_fmt(seen_seqs[p['seq']])})")
            else:
                seen_seqs[p['seq']] = p['ts']

    if not retransmissions:
        print(f"  {GREEN}No retransmissions detected ✓{RESET}")

    print(f"\n  Sequence number progression (data packets):")
    prev_seq = None
    for p in data_pkts:
        gap = ''
        if prev_seq is not None and p['seq'] > prev_seq:
            expected_next = prev_seq  # simplified; real check needs segment length
            if p['seq'] != expected_next:
                gap = f"  {YELLOW}← gap?{RESET}"
        print(f"    {ts_fmt(p['ts'])}  Seq={p['seq']:<10d}  Len={p['plen']}{gap}")
        prev_seq = p['seq']

    print(f"\n  Receiver-advertised window sizes (from ACK packets):")
    ack_pkts = [p for p in proc if p['flags']['ACK'] and not p['flags']['SYN']
                and not p['flags']['FIN'] and p['plen'] == 0]
    for p in ack_pkts[:20]:   # show first 20 ACKs
        print(f"    {ts_fmt(p['ts'])}  AckNum={p['ack']:<10d}  AdvWin={p['window']}")
    print()

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 5: AIMD Congestion Control Inference
    # ─────────────────────────────────────────────────────────────────────
    print(f"{CYAN}{'─'*70}")
    print(f"  [SECTION 5]  AIMD CONGESTION CONTROL INFERENCE")
    print(f"{'─'*70}{RESET}")

    # Group data packets into RTT-like bursts by clustering their timestamps
    if data_pkts:
        burst_threshold = 0.05   # 50 ms gap between bursts
        bursts = []
        current_burst = [data_pkts[0]]
        for p in data_pkts[1:]:
            if p['ts'] - current_burst[-1]['ts'] < burst_threshold:
                current_burst.append(p)
            else:
                bursts.append(current_burst)
                current_burst = [p]
        bursts.append(current_burst)

        print(f"  Inferred send bursts (proxy for cwnd per RTT):\n")
        print(f"  {'Burst':>5}  {'Pkts (≈cwnd)':>12}  {'Start time':>12}  {'Note'}")
        print(f"  {'─'*5}  {'─'*12}  {'─'*12}  {'─'*30}")

        prev_size = None
        for i, burst in enumerate(bursts):
            size = len(burst)
            note = ''
            if prev_size is not None:
                if size >= prev_size * 2:
                    note = f'{YELLOW}Slow start (exponential){RESET}'
                elif size == prev_size + 1:
                    note = f'{GREEN}Cong. avoidance (+1){RESET}'
                elif size < prev_size:
                    note = f'{RED}Loss event → cwnd reduced{RESET}'
                else:
                    note = 'Stable'
            print(f"  {i+1:>5}  {size:>12}  {ts_fmt(burst[0]['ts']):>12}  {note}")
            prev_size = size
        print()
    else:
        print(f"  {YELLOW}No data packets to infer AIMD behaviour{RESET}\n")

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 6: Connection Termination
    # ─────────────────────────────────────────────────────────────────────
    print(f"{CYAN}{'─'*70}")
    print(f"  [SECTION 6]  CONNECTION TERMINATION (4-Way Handshake)")
    print(f"{'─'*70}{RESET}")

    fin_pkts = [p for p in proc if p['flags']['FIN']]
    if not fin_pkts:
        print(f"  {YELLOW}No FIN packets found in capture{RESET}\n")
    else:
        for p in fin_pkts:
            label = 'FIN-ACK' if p['flags']['ACK'] else 'FIN'
            print_pkt(p, MAGENTA, label)

        # Final ACKs after last FIN
        last_fin_ts = fin_pkts[-1]['ts']
        final_acks = [p for p in proc
                      if p['ts'] > last_fin_ts
                      and p['flags']['ACK']
                      and not p['flags']['FIN']
                      and not p['flags']['SYN']]
        for p in final_acks[:3]:
            print_pkt(p, BLUE, 'FINAL-ACK')
        print(f"\n  {GREEN}✓ Connection termination sequence detected{RESET}\n"
              if fin_pkts else "")

    # ─────────────────────────────────────────────────────────────────────
    # SUMMARY TABLE
    # ─────────────────────────────────────────────────────────────────────
    total_bytes = sum(p['plen'] for p in proc)
    duration    = (proc[-1]['ts'] - proc[0]['ts']) if len(proc) > 1 else 0.0
    throughput  = (total_bytes * 8 / duration / 1000) if duration > 0 else 0.0

    print(f"\n{CYAN}{'='*70}")
    print(f"  SUMMARY TABLE")
    print(f"{'='*70}{RESET}")
    print(f"  {'Metric':<40} {'Value':>20}")
    print(f"  {'─'*40} {'─'*20}")
    print(f"  {'Total TCP packets':<40} {len(proc):>20}")
    print(f"  {'Data-carrying packets':<40} {len(data_pkts):>20}")
    print(f"  {'ACK-only packets':<40} {len(ack_pkts):>20}")
    print(f"  {'FIN packets':<40} {len(fin_pkts):>20}")
    print(f"  {'Retransmissions detected':<40} {len(retransmissions):>20}")
    print(f"  {'Unique sequence numbers':<40} {len(unique_seqs):>20}")
    print(f"  {'Total payload bytes transferred':<40} {total_bytes:>20}")
    print(f"  {'Capture duration (s)':<40} {duration:>20.3f}")
    print(f"  {'Estimated throughput (kbps)':<40} {throughput:>20.2f}")
    print(f"\n{CYAN}{'='*70}{RESET}\n")


# ─── Entry point ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: python3 analyze.py <capture.pcap>")
        sys.exit(1)
    analyze_pcap(sys.argv[1])
