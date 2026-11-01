# TCP Implementation over Raw Sockets (C++)

## Overview

This project implements a **custom TCP protocol from scratch** using Linux raw sockets in C++. Rather than relying on the OS's built-in TCP stack, every TCP segment — including IP and TCP headers, sequence numbers, checksums, and state machine transitions — is manually constructed and managed. This demonstrates a deep, ground-up understanding of how TCP actually works beneath the socket API.

All six core TCP features are implemented:
- **3-Way Handshake** (connection establishment)
- **Data Transfer** (20 student records from `records.txt`)
- **Internet Checksum** (RFC 793 error detection)
- **Sliding Window / Go-Back-N** (flow control)
- **AIMD Congestion Control** (slow start, congestion avoidance, fast retransmit)
- **4-Way Handshake** (graceful connection termination)

Post-session packet analysis is performed using **PyShark** (Wireshark's Python API) on a `tcpdump` capture.

---

## Project Structure

| File | Role |
|------|------|
| `sender.cpp` | TCP sender (client side) — builds raw IP+TCP headers, manages the state machine (CLOSED → ESTABLISHED → FIN_WAIT → CLOSED), implements the sliding window, AIMD congestion control, retransmission timer, and transmits the 20 records from `records.txt`. |
| `receiver.cpp` | TCP receiver (server side) — listens on a raw socket, handles the 3-way handshake, receives and reassembles data segments (buffering out-of-order), sends cumulative ACKs, advertises receive window, and writes received records to `received_records.txt`. |
| `common.h` | Shared definitions used by both sender and receiver: TCP/IP header structs, TCP state enum, constants (`MSS`, `TIMEOUT_MS`, `MAX_SEQ`), the pseudo-header struct for checksum computation, and the `computeChecksum()` / `verifyChecksum()` functions. |
| `records.txt` | 20 student records (one per line) to be transmitted during the demo. Each record contains a student name, roll number, and marks — providing realistic variable-length payload data. |
| `analyze.py` | Post-session analysis script using PyShark. Reads the `capture.pcap` produced by tcpdump, decodes every TCP packet, groups them by feature (handshake / data / termination), reports checksum values, seq/ack numbers, window sizes, detects retransmissions, and prints a summary statistics table. |
| `Makefile` | Build automation — compiles both `sender` and `receiver` with C++17 and `-Wall -O2`. Provides `make all`, `make sender`, `make receiver`, and `make clean` targets. |

---

## Prerequisites

| Requirement | Install command | Notes |
|-------------|-----------------|-------|
| Linux or WSL2 | — | Raw sockets need WSL **2** (not WSL 1) |
| `g++` C++17 | `sudo apt install g++` | Usually pre-installed |
| `make` | `sudo apt install make` | For the Makefile |
| `tshark` | `sudo apt install tshark` | Required by PyShark |
| `python3.14-venv` | `sudo apt install python3.14-venv` | Needed to create a venv on Ubuntu 25.x |
| Root / `sudo` | — | Raw sockets need `CAP_NET_RAW` |

> **Note:** On modern Ubuntu/Debian (Python 3.12+), `pip install` is blocked system-wide.
> You **must** use a virtual environment — see the one-time setup below.

---

## One-Time Setup (do this once)

```bash
# 1. Install system dependencies
sudo apt install -y g++ make tshark python3.14-venv

# 2. Create a Python virtual environment inside the project folder
python3 -m venv venv

# 3. Activate it  (you must do this every new terminal session)
source venv/bin/activate

# 4. Install PyShark inside the venv
pip install pyshark

# 5. Build the C++ programs
make all
```

Your shell prompt will show `(venv)` when the environment is active.
**Every time you open a new terminal**, re-run `source venv/bin/activate` before using `python3 analyze.py`.

---

## Running the Demo

### On the Same Machine (Loopback)

Open **three** terminals. In each one, `cd` into the project folder first.

**Terminal 1 – Start packet capture FIRST:**
```bash
sudo tcpdump -i lo -w capture.pcap port 54321
```
> Start tcpdump *before* the sender/receiver so the SYN packet is captured.
> Stop it with **Ctrl+C** after the session ends.

**Terminal 2 – Receiver:**
```bash
sudo ./receiver 54321 4
# Args: <port> <window_size_segments>
```

**Terminal 3 – Sender:**
```bash
sudo ./sender 127.0.0.1 54321 4 10
# Args: <receiver_ip> <port> <window_size_segments> <loss_probability_%>
```
The `10` means 10 % simulated packet loss — enough to trigger retransmissions and AIMD.

**After the session completes**, stop tcpdump (Ctrl+C in Terminal 1), then analyse:
```bash
# Make sure the venv is active first!
source venv/bin/activate
python3 analyze.py capture.pcap
```

Verify the received records match the originals:
```bash
diff records.txt received_records.txt
# No output = perfect delivery ✓
```

### On Two Different Machines over Wi-Fi (Wireless LAN)

This is the recommended setup for a proper demo — sender and receiver run on two separate physical laptops connected to the **same Wi-Fi router**.

#### Step 1 — Find each machine's Wi-Fi IP address

Run this on **both machines** and note the IP under the `wlan0` interface:

```bash
ip addr show wlan0
# Look for a line like: inet 192.168.1.X/24
# That X.X.X.X is the machine's Wi-Fi IP address
```

If `wlan0` is not found, try:
```bash
ip addr show        # list all interfaces and find the one with 192.168.x.x
```

You will end up with two IPs, for example:
- **Receiver machine:** `192.168.1.10`
- **Sender machine:**   `192.168.1.20`

---

#### Step 2 — Install and build on both machines

Run the full one-time setup on **both machines**:

```bash
# Clone / copy the project to both machines, then:
sudo apt install -y g++ make tshark python3.14-venv
make all
python3 -m venv venv && source venv/bin/activate && pip install pyshark
```

---

#### Step 3 — Disable the firewall (or open the port)

Raw TCP packets on a custom port (54321) may be blocked by `ufw`. Run on **both machines**:

```bash
# Option A – disable firewall entirely (easiest for a lab demo)
sudo ufw disable

# Option B – just open the port
sudo ufw allow 54321/tcp
sudo ufw allow in proto tcp to any port 54321
```

---

#### Step 4 — Start the packet capture on the receiver machine

Open a terminal on the **receiver machine**. Start tcpdump on the Wi-Fi interface **before** starting either program:

```bash
# Replace wlan0 with your actual Wi-Fi interface name
sudo tcpdump -i wlan0 -w capture.pcap port 54321
```

---

#### Step 5 — Start the receiver

Open a **second terminal** on the **receiver machine**:

```bash
cd "/path/to/EndAssignment"
source venv/bin/activate
sudo ./receiver 54321 4
# Args: <port> <window_size_segments>
```

The receiver will print `[INFO] Listening on port 54321…` and wait.

---

#### Step 6 — Start the sender

Open a terminal on the **sender machine** and use the **receiver's Wi-Fi IP**:

```bash
cd "/path/to/EndAssignment"
sudo ./sender 192.168.1.10 54321 4 10
#              ↑ receiver's Wi-Fi IP
# Args: <receiver_ip> <port> <window_size> <loss_prob_%>
```

> **Important:** You must also update `g_src_ip` in `sender.cpp` (line ~675) to use your
> actual Wi-Fi IP instead of `127.0.0.1`, then rebuild with `make all`:
> ```cpp
> // Change this line in sender.cpp:
> g_src_ip = inet_addr("192.168.1.20");   // ← sender's own Wi-Fi IP
> ```

---

#### Step 7 — Run the analysis

After the session ends, stop tcpdump (Ctrl+C on the receiver machine), then:

```bash
# On the receiver machine (venv must be active):
source venv/bin/activate
python3 analyze.py capture.pcap

# Copy received_records.txt back to the sender machine and diff:
scp received_records.txt user@192.168.1.20:/path/to/EndAssignment/
diff records.txt received_records.txt
```

---

#### Wi-Fi Quick Reference

```
Receiver machine (192.168.1.10)         Sender machine (192.168.1.20)
───────────────────────────────         ──────────────────────────────
T1: sudo tcpdump -i wlan0               (nothing — capture runs on receiver)
    -w capture.pcap port 54321

T2: sudo ./receiver 54321 4             sudo ./sender 192.168.1.10 54321 4 10

T3: python3 analyze.py capture.pcap     diff records.txt received_records.txt
    (after Ctrl+C on tcpdump)
```

#### Common Wi-Fi issues

| Problem | Fix |
|---------|-----|
| Sender says `sendto: Network is unreachable` | Check `g_src_ip` is set to sender's actual Wi-Fi IP, not `127.0.0.1` |
| Receiver never gets SYN | Firewall is blocking — run `sudo ufw disable` on receiver |
| `tcpdump: wlan0: No such device` | Find correct interface with `ip addr show` and use that name |
| Packets visible in tcpdump but receiver ignores them | IP filter mismatch — verify `g_peer_ip` / `g_our_ip` in code match actual IPs |
| Works on loopback but not Wi-Fi | Some routers block raw TCP between clients — try disabling AP isolation in router settings |

### Quick Reference Card

```bash
# ── Every new terminal ────────────────────────────────────
cd "/mnt/d/NIT/Sem 5/CN/EndAssignment"
source venv/bin/activate          # activate Python venv

# ── One-time build ────────────────────────────────────────
make all

# ── Demo: loopback (same machine, three terminals) ────────
# T1:  sudo tcpdump -i lo -w capture.pcap port 54321
# T2:  sudo ./receiver 54321 4
# T3:  sudo ./sender 127.0.0.1 54321 4 10

# ── Demo: Wi-Fi (two machines) ───────────────────────────
# On RECEIVER machine:
#   T1: sudo tcpdump -i wlan0 -w capture.pcap port 54321
#   T2: sudo ./receiver 54321 4
# On SENDER machine:
#   T1: sudo ./sender <RECEIVER_WIFI_IP> 54321 4 10

# ── After session ─────────────────────────────────────────
# (Ctrl+C tcpdump first)
python3 analyze.py capture.pcap
diff records.txt received_records.txt
```

---

## How Each Feature Works

### (a) Connection Establishment – 3-Way Handshake

TCP connection establishment uses a **3-way handshake** to synchronize sequence numbers and agree on connection parameters before any data is exchanged.

**Sequence of events:**

```
Sender (Client)                       Receiver (Server)
CLOSED                                LISTEN

  |──── SYN (Seq=ISN_c, SYN=1) ────►|   LISTEN → SYN_RECEIVED
  |                                    |
  |◄─ SYN-ACK (Seq=ISN_s,            |
  |            Ack=ISN_c+1,           |
  |            SYN=1, ACK=1) ─────── |
  |                                    |
  SYN_SENT → ESTABLISHED               |
  |                                    |
  |──── ACK (Seq=ISN_c+1,            |   SYN_RECEIVED → ESTABLISHED
  |          Ack=ISN_s+1, ACK=1) ───►|
  |                                    |
        [ESTABLISHED on both sides]
```

**Implementation details:**
- **ISN (Initial Sequence Number)** is chosen randomly using `std::random_device` to prevent sequence number prediction attacks (per RFC 793 recommendations).
- The sender sets the `SYN` flag in the TCP header and enters `SYN_SENT` state, then blocks waiting for a `SYN-ACK`.
- The receiver in `LISTEN` state detects the `SYN`, records the client's ISN, generates its own ISN, and replies with `SYN-ACK`.
- The sender validates the `SYN-ACK`: checks that `ack_num == ISN_c + 1` and the `ACK` flag is set, then sends a final `ACK` and transitions to `ESTABLISHED`.
- The receiver upon receiving the final `ACK` transitions from `SYN_RECEIVED` to `ESTABLISHED`.

**Terminal output tags during handshake:**
```
[SYN ] Sender → SYN Seq=1000 sent
[SACK] Receiver → SYN-ACK Seq=5000 Ack=1001 sent
[ACK ] Sender → ACK Seq=1001 Ack=5001 sent
[STAT] Sender state: SYN_SENT → ESTABLISHED
[STAT] Receiver state: SYN_RECEIVED → ESTABLISHED
```

---

### (b) Data Transfer – 20 Records

After the handshake, the sender reads `records.txt` line by line. Each line becomes **one TCP segment payload**.

**Segmentation and sequencing:**
- Sequence numbers advance by the **byte count** of each payload (not by record number), faithfully implementing TCP's byte-stream semantics.
- If a payload exceeds `MSS` (Maximum Segment Size, default 512 bytes), it is fragmented into multiple segments — though the demo records are sized to fit in one MSS each.
- Each segment's TCP header carries the current `seq_num` and the next expected ACK from the receiver.

**Receiver reassembly:**
- The receiver tracks `expected_seq` (the next in-order byte it expects).
- In-order segments are written immediately to `received_records.txt`.
- Out-of-order segments are placed in a **reorder buffer** keyed by sequence number and flushed when the missing segments arrive.
- The receiver sends **cumulative ACKs**: `ack_num = expected_seq` (the next byte it wants), regardless of what is buffered.

**Flow:**
```
Sender                                  Receiver
  |──── DATA Seq=1001, Len=53 ────────►| Record #1 written, ACK 1054
  |──── DATA Seq=1054, Len=53 ────────►| Record #2 written, ACK 1107
  |──── DATA Seq=1107, Len=53 ────────►| ...
```

---

### (c) Error Checking – Internet Checksum

The TCP checksum algorithm is specified in **RFC 793** and uses the **one's complement** arithmetic.

**Algorithm:**
1. Construct a **12-byte pseudo-header** containing:
   - Source IP address (4 bytes)
   - Destination IP address (4 bytes)
   - Zero byte (1 byte, padding)
   - Protocol number = `6` for TCP (1 byte)
   - TCP segment length in bytes (2 bytes)
2. Concatenate pseudo-header + TCP header + payload.
3. If the total byte count is odd, append a zero padding byte.
4. Treat the data as a sequence of **16-bit words**.
5. Compute the **one's complement sum** of all 16-bit words (adding carry bits back in).
6. Take the **one's complement** (bitwise NOT) of the result — this is the checksum.
7. Place it in the `checksum` field of the TCP header (which was set to `0x0000` during computation).

**Verification** (at receiver):
- Repeat the same sum over received data (including the checksum field this time).
- If no corruption occurred, the result will be `0xFFFF` (all ones).
- Any other result indicates a corrupted segment → drop and let the sender retransmit.

**Example terminal output:**
```
[CHKS] Computed checksum: 0xA3F2 for Seq=1001
[CHKS] Verified OK (result=0xFFFF) for Seq=1001
[CHKS] FAILED for Seq=1054 — segment dropped
```

**Why the pseudo-header?**
The pseudo-header binds the checksum to the specific source/destination IP pair, ensuring that a misdelivered segment (correct checksum but wrong destination) is caught at the TCP layer.

---

### (d) Sliding Window Protocol – Go-Back-N

The **Go-Back-N** variant of the sliding window protocol is implemented to allow multiple in-flight segments without waiting for individual ACKs.

**Sender window state:**
- `base` — sequence number of the oldest unacknowledged segment.
- `next_seq` — sequence number of the next segment to send.
- The **effective window** = `min(cwnd, advertised_rwnd, WINDOW_SIZE)` where `cwnd` is the congestion window and `advertised_rwnd` is the receiver's advertised window.
- Segments with sequence numbers in `[base, base + effective_window)` may be in flight simultaneously.

**Sliding window diagram:**
```
Sequence space:
 ──────────────────────────────────────────────────────────────────
 |  ACKED  |  SENT, NOT ACKED  |  CAN SEND  |  CANNOT SEND YET  |
 ──────────────────────────────────────────────────────────────────
           ↑                   ↑             ↑
          base              next_seq    base + window

After receiving ACK for base:
 ──────────────────────────────────────────────────────────────────
 |    ACKED    |  SENT, NOT ACKED  |  CAN SEND  |  CANNOT SEND   |
 ──────────────────────────────────────────────────────────────────
              ↑                    ↑             ↑
            base+1             next_seq    base+1 + window
             (window slides right)
```

**ACK semantics:**
- ACKs are **cumulative**: `ACK N` means all bytes up to `N-1` have been received; the receiver wants byte `N` next.
- Receiving `ACK N` advances `base` to `N` and slides the window forward.

**Retransmission (Go-Back-N behavior):**
- A **retransmission timer** is started when `base` segment is sent.
- On **timeout**: retransmit **all** segments from `base` to `next_seq - 1` (Go-Back-N: no selective retransmit).
- `[RTRX]` tag is printed for each retransmitted segment.

**Out-of-order at receiver:**
- Buffered (up to window size), but only a **cumulative ACK** for the last in-order byte is sent.
- `[OORD]` tag is printed when an out-of-order segment is buffered.

---

### (e) Congestion Control – AIMD

**Additive Increase, Multiplicative Decrease (AIMD)** is implemented with three phases:

#### Slow Start
- `cwnd` begins at **1 MSS**.
- For each ACK received, `cwnd += 1 MSS` (effectively **doubling** per RTT).
- This continues until `cwnd >= ssthresh` (slow-start threshold, initially set high).
- `[AIMD]` tag: `SS: cwnd=2 ssthresh=8`

#### Congestion Avoidance
- Once `cwnd >= ssthresh`, switch to linear growth.
- Per ACK: `cwnd += MSS * (MSS / cwnd)` — approximately **+1 MSS per RTT**.
- `[AIMD]` tag: `CA: cwnd=5 ssthresh=4`

#### Multiplicative Decrease (on loss / timeout)
- `ssthresh = max(cwnd / 2, 2 * MSS)`
- `cwnd = 1 MSS`
- Re-enter Slow Start.
- `[AIMD]` tag: `LOSS: cwnd→1 ssthresh→4`

#### Fast Retransmit
- If **3 duplicate ACKs** are received for the same sequence number, retransmit that segment **immediately** (without waiting for timeout).
- After fast retransmit: `ssthresh = cwnd / 2`, `cwnd = ssthresh + 3 MSS` (fast recovery).
- This avoids the full Slow Start penalty for a single lost segment.

**cwnd evolution over time (ASCII):**
```
cwnd
 8 |               *
 7 |             *
 6 |           *
 5 |         *           *
 4 |       *     ╌╌╌╌╌ *   *
 3 |     *             *     *
 2 |   *             *         *
 1 | *           *                 *───►
   └───────────────────────────────────── time
     │  Slow  │  Cong  │  Loss  │  Slow  │  Cong
     │  Start │  Avoid │  Event │  Start │  Avoid
```

---

### (f) Connection Termination – 4-Way Handshake

TCP uses a **4-way handshake** for graceful termination, allowing both sides to independently close their half of the connection (since TCP is full-duplex).

```
Sender                                  Receiver
ESTABLISHED                             ESTABLISHED

  |──── FIN (Seq=N, FIN=1) ───────────►| ESTABLISHED → CLOSE_WAIT
  |                                      |
  |◄─── ACK (Ack=N+1) ─────────────────|
  | FIN_WAIT_1 → FIN_WAIT_2             |
  |                                      | (receiver finishes sending)
  |◄─── FIN (Seq=M, FIN=1) ────────────| CLOSE_WAIT → LAST_ACK
  |                                      |
  |──── ACK (Ack=M+1) ─────────────────►| LAST_ACK → CLOSED
  | FIN_WAIT_2 → TIME_WAIT              |
  |                                      |
  | [wait 2 × MSL]                      |
  | TIME_WAIT → CLOSED                  |
```

**State transitions:**
- **Sender (active close)**: `ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED`
- **Receiver (passive close)**: `ESTABLISHED → CLOSE_WAIT → LAST_ACK → CLOSED`

**TIME_WAIT (2 × MSL):**
- The sender waits for **2 × MSL** (Maximum Segment Lifetime, typically 60s–120s) before fully closing.
- This ensures: (1) the final ACK is not lost (receiver would re-send FIN if it were); (2) any delayed duplicate segments from the old connection expire and don't interfere with a new connection on the same port.
- In the demo, `MSL` is reduced to a few seconds for practical demonstration.

**Terminal output:**
```
[FIN ] Sender → FIN Seq=2340 sent
[TERM] Receiver state: ESTABLISHED → CLOSE_WAIT
[ACK ] Receiver → ACK Ack=2341 sent
[FIN ] Receiver → FIN Seq=7890 sent
[TERM] Receiver state: CLOSE_WAIT → LAST_ACK
[ACK ] Sender → ACK Ack=7891 sent
[TERM] Sender state: FIN_WAIT_2 → TIME_WAIT (waiting 2xMSL)
[TERM] Receiver state: LAST_ACK → CLOSED
[TERM] Sender state: TIME_WAIT → CLOSED
```

---

## PyShark Analysis

`analyze.py` provides post-session analysis of the captured packet trace:

1. **Reads** the `capture.pcap` file produced by `tcpdump` using PyShark's `FileCapture`.
2. **Decodes** all TCP packets, extracting: flags, seq/ack numbers, window size, checksum, payload length.
3. **Groups** packets by phase:
   - **Handshake phase**: packets with SYN or SYN+ACK flags.
   - **Data transfer phase**: packets with PSH flag or non-zero payload length.
   - **Termination phase**: packets with FIN flag.
4. **Detects retransmissions**: same sequence number sent more than once.
5. **Detects out-of-order**: seq numbers arriving non-monotonically.
6. **Reports** checksum field values per packet (note: checksums may show as offloaded if using NIC hardware checksum offload — use `--no-offload` or loopback where this doesn't apply).
7. **Prints** a summary table:

```
╔════════════════════════════════════════════════════════════╗
║              PyShark TCP Analysis Summary                  ║
╠════════════════════╦═══════════════════════════════════════╣
║ Total packets      ║ 58                                    ║
║ SYN packets        ║ 2  (handshake)                        ║
║ Data packets       ║ 24 (20 records + retransmissions)     ║
║ ACK-only packets   ║ 25                                    ║
║ FIN packets        ║ 2  (termination)                      ║
║ Retransmissions    ║ 3  (duplicate seq numbers detected)   ║
║ Out-of-order       ║ 1  (reordering event)                 ║
║ Checksum errors    ║ 0  (or N if simulated loss involved)  ║
╚════════════════════╩═══════════════════════════════════════╝
```

---

## Understanding the Output

Each line of sender/receiver terminal output is prefixed with a **colored tag** (using ANSI escape codes) indicating the event type:

| Tag | Meaning |
|-----|---------|
| `[SYN ]` | SYN packet sent or received (connection request) |
| `[SACK]` | SYN-ACK packet sent or received |
| `[ACK ]` | Pure acknowledgment (no data payload) |
| `[SEND]` | Data segment sent by sender |
| `[RECV]` | Data segment received and accepted by receiver (in order) |
| `[OORD]` | Out-of-order segment received and buffered |
| `[DUPL]` | Duplicate segment received and dropped |
| `[LOSS]` | Simulated packet loss triggered (or timeout occurred) |
| `[RTRX]` | Retransmission of a segment |
| `[CHKS]` | Checksum computation or verification result |
| `[WIND]` | Sliding window state update (base, next_seq, effective window) |
| `[AIMD]` | Congestion window (cwnd) update — phase and new value |
| `[FLOW]` | Flow control event — receiver's advertised window (rwnd) |
| `[FIN ]` | FIN packet sent or received (connection teardown) |
| `[TERM]` | Connection termination step / state transition |
| `[STAT]` | General TCP state machine transition |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Operation not permitted` | Run with `sudo` — raw sockets require root privileges |
| `Address already in use` | Wait ~30 seconds for `TIME_WAIT` to expire, or use a different port number |
| `No packets captured` | Ensure tcpdump uses the correct interface: `lo` for loopback (same machine), `eth0` for LAN |
| Receiver misses all packets | On some kernels, loopback raw sockets need `IPPROTO_TCP` instead of `IPPROTO_RAW` — see note in `common.h` |
| `pip install pyshark` blocked | Ubuntu 23+ blocks system-wide pip. Run `sudo apt install python3.14-venv` then `python3 -m venv venv && source venv/bin/activate && pip install pyshark` |
| `No such file: venv/bin/activate` | `python3.14-venv` package was not installed yet — run `sudo apt install python3.14-venv` first |
| `There is no current event loop` | Fixed in `analyze.py` (asyncio patch at top of file). Ensure you are running the latest version of the file |
| `asyncio has no attribute 'set_child_watcher'` | Python 3.12+ removed this API; PyShark 0.6 still calls it. Fixed in `analyze.py` with a no-op monkey-patch before `import pyshark` |
| `pyshark` import error | Install tshark: `sudo apt install tshark`; PyShark requires it as a backend |
| Checksum always fails | Verify that `IP_HDRINCL` is set and the pseudo-header uses network byte order (use `htons`/`htonl`) |
| Sender hangs after handshake | Check that both processes are using the same port and IP; verify no firewall rules blocking raw packets |
| `received_records.txt` is empty | Receiver may have terminated early — check for checksum failures or window size = 0 |

---

## Technical Notes

- **Raw sockets** require `CAP_NET_RAW` capability or running as root. The socket is created with `socket(AF_INET, SOCK_RAW, IPPROTO_TCP)`.
- **`IP_HDRINCL`** socket option is set so that the application manually constructs the IP header (including IP checksum, TTL, protocol field). Without this, the OS fills in the IP header automatically.
- **TCP checksum** uses a **12-byte pseudo-header** per RFC 793 (source IP, destination IP, zero, protocol=6, TCP length). This is included in the checksum computation but **not** transmitted.
- **Window sizes** are tracked in **bytes** internally (as per TCP spec), though the CLI argument `<window_size>` is in segments (converted by multiplying by `MSS`).
- **Sequence numbers** are byte-based per TCP specification (not segment-based).
- **Simulated packet loss** is implemented at the sender: before transmitting, a random number in `[0, 100)` is generated; if it falls below `loss_probability_%`, the segment is silently dropped (not sent). This simulates an unreliable network for testing retransmission and congestion control.
- **Byte order**: all multi-byte fields in headers are stored in **network byte order** (big-endian) using `htons()` and `htonl()`. Received values are converted back with `ntohs()` / `ntohl()`.

---

## References

- RFC 793 — Transmission Control Protocol (original specification): https://tools.ietf.org/html/rfc793
- RFC 5681 — TCP Congestion Control (AIMD, slow start, fast retransmit): https://tools.ietf.org/html/rfc5681
- Kurose & Ross, *Computer Networking: A Top-Down Approach*, 8th Edition — Chapters 3.4–3.7
- Stevens, *TCP/IP Illustrated, Volume 1*, Chapters 17–24
- Linux `man 7 raw` — raw socket documentation
- Linux `man 7 ip` — IP socket options including `IP_HDRINCL`
# TCP-from-scratch
"# TCP-from-scratch" 
