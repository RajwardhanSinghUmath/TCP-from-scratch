/*
 * sender.cpp — TCP sender using raw sockets (Linux / WSL)
 *
 * Build:  g++ -std=c++17 -Wall -O2 -o sender sender.cpp
 * Run:    sudo ./sender <receiver_ip> [port] [window_size] [loss_prob_percent]
 *
 * Features implemented:
 *   A. 3-way handshake (SYN → SYN-ACK → ACK)
 *   B. State machine  (CLOSED → SYN_SENT → ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED)
 *   C. Read records.txt (20 student records)
 *   D. Sliding window + AIMD congestion control (Go-Back-N)
 *   E. Detailed stdout logging
 *   F. Checksum verification + simulated corruption for demo
 *   G. 4-way connection termination
 *   H. tcpdump / analyze.py hints
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cerrno>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <chrono>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "common.h"

// ─── TCP connection state ─────────────────────────────────────────────────────
enum class State {
    CLOSED, LISTEN, SYN_SENT, SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1, FIN_WAIT_2, TIME_WAIT,
    CLOSE_WAIT, LAST_ACK
};

static const char* state_name(State s)
{
    switch (s) {
        case State::CLOSED:       return "CLOSED";
        case State::LISTEN:       return "LISTEN";
        case State::SYN_SENT:     return "SYN_SENT";
        case State::SYN_RECEIVED: return "SYN_RECEIVED";
        case State::ESTABLISHED:  return "ESTABLISHED";
        case State::FIN_WAIT_1:   return "FIN_WAIT_1";
        case State::FIN_WAIT_2:   return "FIN_WAIT_2";
        case State::TIME_WAIT:    return "TIME_WAIT";
        case State::CLOSE_WAIT:   return "CLOSE_WAIT";
        case State::LAST_ACK:     return "LAST_ACK";
    }
    return "UNKNOWN";
}

static void print_state(State old_s, State new_s)
{
    printf(YELLOW "[STATE] %s → %s\n" RESET, state_name(old_s), state_name(new_s));
    fflush(stdout);
}

// ─── Globals (set from args) ──────────────────────────────────────────────────
static int    g_sock          = -1;
static uint16_t g_src_port    = 0;
static uint16_t g_dst_port    = DEFAULT_PORT;
static uint32_t g_src_ip      = 0;
static uint32_t g_dst_ip      = 0;
static uint32_t g_isn         = 0;    // initial sequence number (sender)
static uint32_t g_peer_isn    = 0;    // initial sequence number (receiver)
static int    g_loss_prob     = 0;    // percentage 0-100
static uint32_t g_max_window  = WINDOW_SIZE;

// ─── Utility: current time in ms ─────────────────────────────────────────────
static int64_t now_ms()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1'000'000LL;
}

// ─── Build a complete IP+TCP packet into buf ──────────────────────────────────
//     Returns total packet size.
static size_t build_packet(uint8_t*    buf,
                           uint32_t    seq,
                           uint32_t    ack,
                           uint8_t     flags,
                           uint16_t    window,
                           const char* payload,
                           uint16_t    payload_len)
{
    memset(buf, 0, sizeof(IPHeader) + sizeof(TCPHeader) + payload_len);

    uint16_t total = static_cast<uint16_t>(sizeof(IPHeader) + sizeof(TCPHeader) + payload_len);

    // ── IP header ──────────────────────────────────────────────────────────
    IPHeader* ip  = reinterpret_cast<IPHeader*>(buf);
    ip->version_ihl  = (4 << 4) | 5;     // IPv4, IHL=5 (20 bytes)
    ip->tos          = 0;
    ip->total_length = htons(total);
    ip->id           = htons(static_cast<uint16_t>(rand() & 0xFFFF));
    ip->frag_offset  = 0;
    ip->ttl          = 64;
    ip->protocol     = 6;                // TCP
    ip->checksum     = 0;               // kernel will fill if IP_HDRINCL
    ip->src_ip       = g_src_ip;
    ip->dst_ip       = g_dst_ip;

    // ── TCP header ─────────────────────────────────────────────────────────
    TCPHeader* tcp = reinterpret_cast<TCPHeader*>(buf + sizeof(IPHeader));
    tcp->src_port    = htons(g_src_port);
    tcp->dst_port    = htons(g_dst_port);
    tcp->seq_num     = htonl(seq);
    tcp->ack_num     = htonl(ack);
    tcp->data_offset = static_cast<uint8_t>(5 << 4);  // 5 * 4 = 20 bytes header
    tcp->flags       = flags;
    tcp->window_size = htons(window);
    tcp->checksum    = 0;
    tcp->urgent_ptr  = 0;

    // ── Payload ────────────────────────────────────────────────────────────
    if (payload && payload_len > 0)
        memcpy(buf + sizeof(IPHeader) + sizeof(TCPHeader), payload, payload_len);

    // ── TCP checksum ───────────────────────────────────────────────────────
    tcp->checksum = tcp_checksum(g_src_ip, g_dst_ip, tcp,
                                 reinterpret_cast<const uint8_t*>(payload),
                                 payload_len);

    return total;
}

// ─── Send a packet ────────────────────────────────────────────────────────────
static bool send_packet(uint32_t seq, uint32_t ack, uint8_t flags,
                        uint16_t window,
                        const char* payload = nullptr, uint16_t payload_len = 0)
{
    uint8_t buf[sizeof(IPHeader) + sizeof(TCPHeader) + MAX_SEGMENT_SIZE + 64];
    size_t pkt_len = build_packet(buf, seq, ack, flags, window, payload, payload_len);

    struct sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = g_dst_ip;

    TCPHeader* tcp = reinterpret_cast<TCPHeader*>(buf + sizeof(IPHeader));

    ssize_t sent = sendto(g_sock, buf, pkt_len, 0,
                          reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst));
    if (sent < 0) {
        perror(RED "[ERROR] sendto" RESET);
        return false;
    }
    return true;
}

// ─── Wait for a packet matching a predicate (with timeout) ───────────────────
//     Returns true if a matching packet was received; fills out seq/ack/flags/payload.
struct ReceivedPacket {
    uint32_t seq, ack;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum_in_pkt;
    uint16_t payload_len;
    char     payload[MAX_SEGMENT_SIZE + 1];
};

// recv_filtered: reads until we get a TCP packet directed at us (dst_port == g_src_port)
//                and from the peer (src_port == g_dst_port, src_ip == g_dst_ip),
//                or returns false on timeout.
static bool recv_filtered(ReceivedPacket& pkt, int timeout_ms = 2000)
{
    // set socket receive timeout
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t buf[65535];

    for (;;) {
        ssize_t n = recv(g_sock, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                return false;  // timeout
            perror(RED "[ERROR] recv" RESET);
            return false;
        }
        if (static_cast<size_t>(n) < sizeof(IPHeader) + sizeof(TCPHeader))
            continue;

        IPHeader*  ip  = reinterpret_cast<IPHeader*>(buf);
        int ip_hdr_len = (ip->version_ihl & 0x0F) * 4;
        if (static_cast<size_t>(n) < static_cast<size_t>(ip_hdr_len) + sizeof(TCPHeader))
            continue;

        TCPHeader* tcp = reinterpret_cast<TCPHeader*>(buf + ip_hdr_len);

        // Filter: must be addressed to us and from the peer
        if (ntohs(tcp->dst_port) != g_src_port) continue;
        if (ntohs(tcp->src_port) != g_dst_port) continue;
        if (ip->src_ip != g_dst_ip)             continue;

        uint16_t total_len   = ntohs(ip->total_length);
        int      tcp_hdr_len = ((tcp->data_offset >> 4) & 0x0F) * 4;
        int      data_len    = static_cast<int>(total_len) - ip_hdr_len - tcp_hdr_len;
        if (data_len < 0) data_len = 0;
        if (data_len > MAX_SEGMENT_SIZE) data_len = MAX_SEGMENT_SIZE;

        pkt.seq           = ntohl(tcp->seq_num);
        pkt.ack           = ntohl(tcp->ack_num);
        pkt.flags         = tcp->flags;
        pkt.window        = tcp->window_size;          // still in network order
        pkt.checksum_in_pkt = tcp->checksum;
        pkt.payload_len   = static_cast<uint16_t>(data_len);
        memset(pkt.payload, 0, sizeof(pkt.payload));
        if (data_len > 0)
            memcpy(pkt.payload,
                   buf + ip_hdr_len + tcp_hdr_len,
                   data_len);

        // ── Checksum verification ─────────────────────────────────────────
        uint16_t saved_ck = tcp->checksum;
        tcp->checksum = 0;
        uint16_t calc_ck = tcp_checksum(ip->src_ip, ip->dst_ip, tcp,
                                         reinterpret_cast<uint8_t*>(buf) + ip_hdr_len + tcp_hdr_len,
                                         static_cast<uint16_t>(data_len));
        tcp->checksum = saved_ck;

        // Simulate ~20% checksum corruption for demo (only on data packets)
        if ((pkt.flags & ~ACK_FLAG) == 0 && pkt.payload_len > 0 && (rand() % 100 < 20)) {
            printf(RED "[ERR ] Simulating checksum corruption on Seq=%u for demo"
                       " (expected=0x%04X, injecting=0x%04X) → Drop\n" RESET,
                   pkt.seq, ntohs(calc_ck), ntohs(saved_ck) ^ 0xDEAD);
            fflush(stdout);
            continue;  // drop this packet
        }

        if (calc_ck != saved_ck) {
            printf(RED "[ERR ] Checksum mismatch on Seq=%u"
                       " (expected=0x%04X got=0x%04X) → Drop\n" RESET,
                   pkt.seq, ntohs(calc_ck), ntohs(saved_ck));
            fflush(stdout);
            continue;  // drop
        }

        printf(CYAN "[CHKSUM] Seq=%-8u Checksum=0x%04X → VALID\n" RESET,
               pkt.seq, ntohs(saved_ck));
        fflush(stdout);
        return true;
    }
}

// ─── Load records from file ───────────────────────────────────────────────────
static std::vector<std::string> load_records(const char* path)
{
    std::vector<std::string> records;
    std::ifstream f(path);
    if (!f.is_open()) {
        fprintf(stderr, RED "[ERROR] Cannot open %s\n" RESET, path);
        return records;
    }
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty())
            records.push_back(line);
    }
    return records;
}

// ─── 3-Way Handshake ─────────────────────────────────────────────────────────
static bool do_handshake(State& state)
{
    printf(CYAN "\n╔══════════════════════════════════════════════════════════╗\n" RESET);
    printf(CYAN "║          3-WAY HANDSHAKE — CONNECTION ESTABLISHMENT      ║\n" RESET);
    printf(CYAN "╚══════════════════════════════════════════════════════════╝\n\n" RESET);

    // ── Step 1: Send SYN ──────────────────────────────────────────────────
    g_isn = static_cast<uint32_t>(rand());
    printf(GREEN "[SEND] SYN  Seq=%-10u ISN=%u\n" RESET, g_isn, g_isn);
    fflush(stdout);
    if (!send_packet(g_isn, 0, SYN_FLAG, static_cast<uint16_t>(g_max_window)))
        return false;

    State old_state = state;
    state = State::SYN_SENT;
    print_state(old_state, state);

    // ── Step 2: Wait for SYN-ACK ──────────────────────────────────────────
    for (int attempt = 0; attempt < 5; attempt++) {
        ReceivedPacket pkt{};
        printf(YELLOW "[WAIT] Waiting for SYN-ACK (attempt %d/5)…\n" RESET, attempt + 1);
        fflush(stdout);

        if (!recv_filtered(pkt, 3000)) {
            printf(RED "[TIMEOUT] No SYN-ACK received, retransmitting SYN…\n" RESET);
            fflush(stdout);
            send_packet(g_isn, 0, SYN_FLAG, static_cast<uint16_t>(g_max_window));
            continue;
        }

        // Validate SYN+ACK flags
        if ((pkt.flags & (SYN_FLAG | ACK_FLAG)) != (SYN_FLAG | ACK_FLAG)) {
            printf(RED "[ERR ] Expected SYN-ACK, got flags=0x%02X — retrying\n" RESET, pkt.flags);
            fflush(stdout);
            continue;
        }
        // Validate ack_num == ISN + 1
        if (pkt.ack != g_isn + 1) {
            printf(RED "[ERR ] SYN-ACK ack_num=%u expected=%u — retrying\n" RESET,
                   pkt.ack, g_isn + 1);
            fflush(stdout);
            continue;
        }

        g_peer_isn = pkt.seq;
        printf(GREEN "[RECV] SYN-ACK Seq=%-10u AckNum=%-10u PeerISN=%u\n" RESET,
               pkt.seq, pkt.ack, g_peer_isn);
        fflush(stdout);

        // ── Step 3: Send ACK ──────────────────────────────────────────────
        uint32_t ack_seq = g_isn + 1;
        uint32_t ack_ack = g_peer_isn + 1;
        printf(GREEN "[SEND] ACK  Seq=%-10u AckNum=%u\n" RESET, ack_seq, ack_ack);
        fflush(stdout);
        send_packet(ack_seq, ack_ack, ACK_FLAG, static_cast<uint16_t>(g_max_window));

        old_state = state;
        state = State::ESTABLISHED;
        print_state(old_state, state);
        printf(GREEN "\n[INFO] Connection ESTABLISHED ✓\n\n" RESET);
        fflush(stdout);
        return true;
    }

    printf(RED "[ERROR] Handshake failed after 5 attempts\n" RESET);
    return false;
}

// ─── Data Transmission with Sliding Window + AIMD ────────────────────────────
static void transmit_records(const std::vector<std::string>& records)
{
    printf(CYAN "\n╔══════════════════════════════════════════════════════════╗\n" RESET);
    printf(CYAN "║         DATA TRANSMISSION — SLIDING WINDOW + AIMD       ║\n" RESET);
    printf(CYAN "╚══════════════════════════════════════════════════════════╝\n\n" RESET);

    int    total_segs     = static_cast<int>(records.size());
    double cwnd           = 1.0;
    double ssthresh       = static_cast<double>(INITIAL_SSTHRESH);
    int    base           = 0;           // oldest unacked segment index
    int    next_seg       = 0;           // next segment to send
    int    dup_ack_count  = 0;
    uint32_t last_ack_seq = 0;

    // per-segment send time for timeout tracking
    std::map<int, int64_t>      send_time;
    std::map<int, std::string>  seg_data;
    std::map<int, uint32_t>     seg_seq;   // segment index → seq number

    // Sequence numbers (byte-based)
    // SYN consumed ISN, so data starts at ISN+1
    uint32_t next_seq_num = g_isn + 1;
    uint32_t peer_ack     = g_peer_isn + 1;  // ack we send for receiver's seq

    // Pre-compute sequence numbers for all segments
    {
        uint32_t s = next_seq_num;
        for (int i = 0; i < total_segs; i++) {
            seg_seq[i] = s;
            s += static_cast<uint32_t>(records[i].size());
        }
    }

    constexpr int TIMEOUT_MS = 500;
    int rtt_segments_acked = 0;   // track RTT for cwnd update

    printf(BLUE "[INFO] Total segments to send: %d  MSS: %u  Initial cwnd: %.0f  ssthresh: %.0f\n\n" RESET,
           total_segs, MAX_SEGMENT_SIZE, cwnd, ssthresh);
    fflush(stdout);

    while (base < total_segs) {
        int effective_window = static_cast<int>(std::min(cwnd, static_cast<double>(g_max_window)));
        effective_window     = std::min(effective_window, total_segs - base);

        printf(BLUE "[WINDOW] base=%d next=%d cwnd=%.1f ssthresh=%.1f effective_window=%d\n" RESET,
               base, next_seg, cwnd, ssthresh, effective_window);
        fflush(stdout);

        // ── Send segments within window ───────────────────────────────────
        while (next_seg < base + effective_window && next_seg < total_segs) {
            const std::string& rec = records[next_seg];
            seg_data[next_seg]     = rec;
            uint32_t seq           = seg_seq[next_seg];
            uint16_t plen          = static_cast<uint16_t>(rec.size());
            uint8_t  flags         = PSH_FLAG | ACK_FLAG;

            // ── Simulated packet loss ─────────────────────────────────────
            bool simulated_loss = (g_loss_prob > 0) && (rand() % 100 < g_loss_prob);
            if (simulated_loss) {
                printf(YELLOW "[SIM-LOSS] Simulating drop of Seg=%d Seq=%u\n" RESET,
                       next_seg, seq);
                fflush(stdout);
                send_time[next_seg] = now_ms();  // still track timer
                next_seg++;
                continue;
            }

            // ── Actually send ─────────────────────────────────────────────
            if (!send_packet(seq, peer_ack, flags,
                             static_cast<uint16_t>(g_max_window - (next_seg - base)),
                             rec.c_str(), plen)) {
                fprintf(stderr, RED "[ERROR] Failed to send segment %d\n" RESET, next_seg);
            }

            send_time[next_seg] = now_ms();

            // Print send info
            std::string preview = rec.substr(0, 60);
            printf(GREEN "[SEND] Seg=%-3d Seq=%-10u Flags=%-12s Len=%-4u Chk=computed  Data=\"%s\"\n" RESET,
                   next_seg, seq, flags_str(flags), plen, preview.c_str());
            fflush(stdout);

            next_seg++;
        }

        // ── Wait for ACKs ─────────────────────────────────────────────────
        bool got_new_ack = false;
        for (int attempt = 0; attempt < 3; attempt++) {
            ReceivedPacket pkt{};
            bool received = recv_filtered(pkt, TIMEOUT_MS);

            if (!received) {
                // ── Timeout ───────────────────────────────────────────────
                // Find the oldest unacked segment that has timed out
                int timeout_seg = -1;
                for (int i = base; i < next_seg; i++) {
                    if (send_time.count(i) &&
                        now_ms() - send_time[i] >= TIMEOUT_MS) {
                        timeout_seg = i;
                        break;
                    }
                }
                if (timeout_seg < 0) break;

                ssthresh = std::max(cwnd / 2.0, 1.0);
                cwnd     = 1.0;
                printf(RED "[LOSS] Timeout on Seg=%d Seq=%u → Retransmit"
                           " (ssthresh=%.1f cwnd=%.1f)\n" RESET,
                       timeout_seg, seg_seq[timeout_seg], ssthresh, cwnd);
                fflush(stdout);

                // Go-Back-N: retransmit from timeout_seg
                for (int i = timeout_seg; i < next_seg; i++) {
                    const std::string& rd = seg_data[i];
                    uint32_t rs = seg_seq[i];
                    uint16_t rl = static_cast<uint16_t>(rd.size());
                    printf(YELLOW "[RTXMT] Seg=%-3d Seq=%u\n" RESET, i, rs);
                    fflush(stdout);
                    send_packet(rs, peer_ack, PSH_FLAG | ACK_FLAG,
                                static_cast<uint16_t>(g_max_window),
                                rd.c_str(), rl);
                    send_time[i] = now_ms();
                }
                dup_ack_count = 0;
                break;
            }

            // ── Got a packet ──────────────────────────────────────────────
            if (!(pkt.flags & ACK_FLAG)) continue;

            printf(BLUE "[ACK ] Seq=%-10u AckNum=%-10u Window=%-5u Flags=[%s]\n" RESET,
                   pkt.seq, pkt.ack, ntohs(pkt.window), flags_str(pkt.flags));
            fflush(stdout);

            if (pkt.ack == last_ack_seq) {
                dup_ack_count++;
                printf(YELLOW "[DUPACK] Duplicate ACK #%d for AckNum=%u\n" RESET,
                       dup_ack_count, pkt.ack);
                fflush(stdout);
                if (dup_ack_count == 3) {
                    // Fast retransmit
                    ssthresh = std::max(cwnd / 2.0, 1.0);
                    cwnd     = ssthresh;
                    printf(RED "[FAST-RTXMT] 3 duplicate ACKs → Fast Retransmit Seq=%u"
                               " (ssthresh=%.1f cwnd=%.1f)\n" RESET,
                           pkt.ack, ssthresh, cwnd);
                    fflush(stdout);

                    // Find which segment this corresponds to and retransmit
                    for (int i = base; i < next_seg; i++) {
                        if (seg_seq[i] == pkt.ack) {
                            const std::string& rd = seg_data[i];
                            uint16_t rl = static_cast<uint16_t>(rd.size());
                            send_packet(seg_seq[i], peer_ack,
                                        PSH_FLAG | ACK_FLAG,
                                        static_cast<uint16_t>(g_max_window),
                                        rd.c_str(), rl);
                            send_time[i] = now_ms();
                            break;
                        }
                    }
                    dup_ack_count = 0;
                }
                continue;
            }

            // ── New (advancing) ACK ───────────────────────────────────────
            dup_ack_count = 0;
            last_ack_seq  = pkt.ack;

            // Count how many segments this ACK covers
            int newly_acked = 0;
            for (int i = base; i < total_segs; i++) {
                // segment i is acked if its seq + len <= pkt.ack
                if (seg_data.count(i) == 0) break;
                uint32_t seg_end = seg_seq[i] + static_cast<uint32_t>(seg_data[i].size());
                if (seg_end <= pkt.ack) {
                    newly_acked++;
                } else {
                    break;
                }
            }

            if (newly_acked > 0) {
                printf(GREEN "[SLIDE] Window slides by %d segment(s). base: %d → %d\n" RESET,
                       newly_acked, base, base + newly_acked);
                fflush(stdout);
                base              += newly_acked;
                rtt_segments_acked += newly_acked;
                got_new_ack        = true;

                // ── AIMD update ───────────────────────────────────────────
                if (cwnd < ssthresh) {
                    // Slow start: exponential increase
                    cwnd += newly_acked;
                    printf(MAGENTA "[AIMD] Slow Start: cwnd %.1f → %.1f (ssthresh=%.1f)\n" RESET,
                           cwnd - newly_acked, cwnd, ssthresh);
                } else {
                    // Congestion avoidance: linear increase
                    cwnd += 1.0 * newly_acked / cwnd;
                    printf(MAGENTA "[AIMD] Cong. Avoid.: cwnd %.2f → %.2f (ssthresh=%.1f)\n" RESET,
                           cwnd - 1.0 * newly_acked / cwnd, cwnd, ssthresh);
                }
                fflush(stdout);
            }

            if (got_new_ack) break;
        }

        // small yield to avoid busy-loop
        if (!got_new_ack && next_seg >= base + effective_window)
            usleep(10000);
    }

    printf(GREEN "\n[INFO] All %d records transmitted successfully ✓\n\n" RESET, total_segs);
    fflush(stdout);
}

// ─── 4-Way Connection Termination ────────────────────────────────────────────
static void do_termination(State& state, uint32_t& cur_seq, uint32_t& cur_ack)
{
    printf(CYAN "\n╔══════════════════════════════════════════════════════════╗\n" RESET);
    printf(CYAN "║        CONNECTION TERMINATION — 4-WAY HANDSHAKE         ║\n" RESET);
    printf(CYAN "╚══════════════════════════════════════════════════════════╝\n\n" RESET);

    // ── Step 1: Send FIN ──────────────────────────────────────────────────
    printf(GREEN "[SEND] FIN  Seq=%-10u AckNum=%u\n" RESET, cur_seq, cur_ack);
    fflush(stdout);
    send_packet(cur_seq, cur_ack, FIN_FLAG | ACK_FLAG, static_cast<uint16_t>(g_max_window));

    State old = state;
    state = State::FIN_WAIT_1;
    print_state(old, state);

    // ── Step 2: Wait for ACK of FIN ───────────────────────────────────────
    for (int attempt = 0; attempt < 5; attempt++) {
        ReceivedPacket pkt{};
        if (!recv_filtered(pkt, 3000)) {
            printf(RED "[TIMEOUT] No ACK for FIN, retransmitting…\n" RESET);
            fflush(stdout);
            send_packet(cur_seq, cur_ack, FIN_FLAG | ACK_FLAG,
                        static_cast<uint16_t>(g_max_window));
            continue;
        }
        if (pkt.flags & ACK_FLAG) {
            printf(BLUE "[RECV] ACK  Seq=%-10u AckNum=%u\n" RESET, pkt.seq, pkt.ack);
            fflush(stdout);
            old   = state;
            state = State::FIN_WAIT_2;
            print_state(old, state);
            cur_ack = pkt.seq + 1;
            break;
        }
    }

    // ── Step 3: Wait for FIN from receiver ───────────────────────────────
    for (int attempt = 0; attempt < 5; attempt++) {
        ReceivedPacket pkt{};
        printf(YELLOW "[WAIT] Waiting for FIN from receiver (attempt %d/5)…\n" RESET,
               attempt + 1);
        fflush(stdout);
        if (!recv_filtered(pkt, 3000)) {
            printf(RED "[TIMEOUT] No FIN received\n" RESET);
            fflush(stdout);
            continue;
        }
        if (pkt.flags & FIN_FLAG) {
            printf(BLUE "[RECV] FIN  Seq=%-10u AckNum=%u\n" RESET, pkt.seq, pkt.ack);
            fflush(stdout);
            cur_ack = pkt.seq + 1;

            // ── Step 4: Send final ACK ─────────────────────────────────
            cur_seq++;   // FIN consumed 1 seq
            printf(GREEN "[SEND] ACK  Seq=%-10u AckNum=%u  (final)\n" RESET,
                   cur_seq, cur_ack);
            fflush(stdout);
            send_packet(cur_seq, cur_ack, ACK_FLAG,
                        static_cast<uint16_t>(g_max_window));

            old   = state;
            state = State::TIME_WAIT;
            print_state(old, state);

            // TIME_WAIT: 2 * MSL = ~4 seconds (using 2s for demo)
            printf(YELLOW "[INFO] TIME_WAIT: waiting 2 seconds (2*MSL)…\n" RESET);
            fflush(stdout);
            sleep(2);

            old   = state;
            state = State::CLOSED;
            print_state(old, state);
            break;
        }
    }
}

// ─── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[])
{
    srand(static_cast<unsigned>(time(nullptr)));

    if (argc < 2) {
        fprintf(stderr,
                "Usage: sudo %s <receiver_ip> [port] [window_size] [loss_prob_percent]\n",
                argv[0]);
        return 1;
    }

    const char* receiver_ip = argv[1];
    if (argc >= 3) g_dst_port   = static_cast<uint16_t>(atoi(argv[2]));
    if (argc >= 4) g_max_window = static_cast<uint32_t>(atoi(argv[3]));
    if (argc >= 5) g_loss_prob  = atoi(argv[4]);

    // Ephemeral source port
    g_src_port = static_cast<uint16_t>(40000 + rand() % 10000);

    // Resolve IPs
    g_dst_ip = inet_addr(receiver_ip);
    if (g_dst_ip == INADDR_NONE) {
        fprintf(stderr, RED "[ERROR] Invalid receiver IP: %s\n" RESET, receiver_ip);
        return 1;
    }

    // Determine our source IP (use loopback if destination is loopback)
    if (strcmp(receiver_ip, "127.0.0.1") == 0 || strncmp(receiver_ip, "127.", 4) == 0)
        g_src_ip = inet_addr("127.0.0.1");
    else
        g_src_ip = inet_addr("127.0.0.1");  // Replace with your actual outgoing IP if needed

    printf(CYAN "╔══════════════════════════════════════════════════════════╗\n" RESET);
    printf(CYAN "║        TCP RAW SOCKET SENDER — Academic Demo             ║\n" RESET);
    printf(CYAN "╚══════════════════════════════════════════════════════════╝\n\n" RESET);
    printf(BLUE "[INFO] Sender IP:Port   = %s:%u\n" RESET, inet_ntoa(*(in_addr*)&g_src_ip), g_src_port);
    printf(BLUE "[INFO] Receiver IP:Port = %s:%u\n" RESET, receiver_ip, g_dst_port);
    printf(BLUE "[INFO] Window size      = %u\n" RESET, g_max_window);
    printf(BLUE "[INFO] Loss probability = %d%%\n\n" RESET, g_loss_prob);

    printf(YELLOW "[INFO] Start tcpdump with:\n" RESET);
    printf(YELLOW "       sudo tcpdump -i lo -w capture.pcap port %u\n\n" RESET, g_dst_port);

    // ── Create raw socket ─────────────────────────────────────────────────
    g_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (g_sock < 0) {
        perror(RED "[ERROR] socket()" RESET);
        fprintf(stderr, RED "        Are you running as root (sudo)?\n" RESET);
        return 1;
    }

    // Enable IP_HDRINCL so we provide our own IP header
    int one = 1;
    if (setsockopt(g_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror(RED "[ERROR] setsockopt(IP_HDRINCL)" RESET);
        close(g_sock);
        return 1;
    }

    printf(GREEN "[INFO] Raw socket created (fd=%d), IP_HDRINCL enabled ✓\n\n" RESET, g_sock);
    fflush(stdout);

    // ── Load records ──────────────────────────────────────────────────────
    auto records = load_records("records.txt");
    if (records.empty()) {
        fprintf(stderr, RED "[ERROR] No records loaded — check records.txt\n" RESET);
        close(g_sock);
        return 1;
    }
    printf(GREEN "[INFO] Loaded %zu record(s) from records.txt ✓\n\n" RESET, records.size());
    for (size_t i = 0; i < records.size(); i++)
        printf("       [%2zu] %s\n", i + 1, records[i].c_str());
    printf("\n");
    fflush(stdout);

    // ── State machine ─────────────────────────────────────────────────────
    State state = State::CLOSED;

    // ── 3-way handshake ───────────────────────────────────────────────────
    if (!do_handshake(state)) {
        close(g_sock);
        return 1;
    }

    // ── Data transmission ─────────────────────────────────────────────────
    transmit_records(records);

    // ── 4-way termination ─────────────────────────────────────────────────
    // Compute current seq/ack after all data
    uint32_t cur_seq = g_isn + 1;
    for (const auto& r : records)
        cur_seq += static_cast<uint32_t>(r.size());
    uint32_t cur_ack = g_peer_isn + 1;

    do_termination(state, cur_seq, cur_ack);

    close(g_sock);

    printf(CYAN "\n╔══════════════════════════════════════════════════════════╗\n" RESET);
    printf(CYAN "║                 TRANSMISSION COMPLETE ✓                 ║\n" RESET);
    printf(CYAN "╚══════════════════════════════════════════════════════════╝\n\n" RESET);
    printf(YELLOW "[INFO] To analyse the captured traffic run:\n" RESET);
    printf(YELLOW "       python3 analyze.py capture.pcap\n\n" RESET);
    fflush(stdout);

    return 0;
}
