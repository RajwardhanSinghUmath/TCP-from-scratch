/*
 * receiver.cpp — TCP receiver using raw sockets (Linux / WSL)
 *
 * Build:  g++ -std=c++17 -Wall -O2 -o receiver receiver.cpp
 * Run:    sudo ./receiver [port] [window_size]
 *
 * Features implemented:
 *   A. Listen for connection  (LISTEN → SYN_RECEIVED → ESTABLISHED)
 *   B. Sliding window receive buffer with out-of-order support
 *   C. Checksum verification on every received segment
 *   D. Flow control — advertise rwnd
 *   E. Reassembly and output to received_records.txt
 *   F. 4-way connection termination
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cerrno>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <algorithm>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "common.h"

// ─── TCP connection state ─────────────────────────────────────────────────────
enum class State {
    CLOSED, LISTEN, SYN_RECEIVED, ESTABLISHED,
    FIN_WAIT_1, FIN_WAIT_2, TIME_WAIT,
    CLOSE_WAIT, LAST_ACK
};

static const char* state_name(State s)
{
    switch (s) {
        case State::CLOSED:       return "CLOSED";
        case State::LISTEN:       return "LISTEN";
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

// ─── Globals ──────────────────────────────────────────────────────────────────
static int       g_sock       = -1;
static uint16_t  g_our_port   = DEFAULT_PORT;
static uint32_t  g_our_ip     = 0;
static uint32_t  g_peer_ip    = 0;
static uint16_t  g_peer_port  = 0;
static uint32_t  g_our_isn    = 0;   // our initial sequence number
static uint32_t  g_peer_isn   = 0;   // peer's initial sequence number
static uint32_t  g_max_window = WINDOW_SIZE;

// ─── Build a packet (receiver side — src/dst are swapped vs sender) ───────────
static size_t build_packet(uint8_t*    buf,
                            uint32_t    seq,
                            uint32_t    ack,
                            uint8_t     flags,
                            uint16_t    window,
                            const char* payload     = nullptr,
                            uint16_t    payload_len = 0)
{
    memset(buf, 0, sizeof(IPHeader) + sizeof(TCPHeader) + payload_len);
    uint16_t total = static_cast<uint16_t>(sizeof(IPHeader) + sizeof(TCPHeader) + payload_len);

    IPHeader* ip    = reinterpret_cast<IPHeader*>(buf);
    ip->version_ihl = (4 << 4) | 5;
    ip->tos         = 0;
    ip->total_length = htons(total);
    ip->id           = htons(static_cast<uint16_t>(rand() & 0xFFFF));
    ip->frag_offset  = 0;
    ip->ttl          = 64;
    ip->protocol     = 6;
    ip->checksum     = 0;
    ip->src_ip       = g_our_ip;
    ip->dst_ip       = g_peer_ip;

    TCPHeader* tcp  = reinterpret_cast<TCPHeader*>(buf + sizeof(IPHeader));
    tcp->src_port   = htons(g_our_port);
    tcp->dst_port   = htons(g_peer_port);
    tcp->seq_num    = htonl(seq);
    tcp->ack_num    = htonl(ack);
    tcp->data_offset = static_cast<uint8_t>(5 << 4);
    tcp->flags      = flags;
    tcp->window_size = htons(window);
    tcp->checksum   = 0;
    tcp->urgent_ptr = 0;

    if (payload && payload_len > 0)
        memcpy(buf + sizeof(IPHeader) + sizeof(TCPHeader), payload, payload_len);

    tcp->checksum = tcp_checksum(g_our_ip, g_peer_ip, tcp,
                                  reinterpret_cast<const uint8_t*>(payload),
                                  payload_len);
    return total;
}

static bool send_packet(uint32_t seq, uint32_t ack, uint8_t flags,
                         uint16_t window,
                         const char* payload = nullptr, uint16_t payload_len = 0)
{
    uint8_t buf[sizeof(IPHeader) + sizeof(TCPHeader) + MAX_SEGMENT_SIZE + 64];
    size_t pkt_len = build_packet(buf, seq, ack, flags, window, payload, payload_len);

    struct sockaddr_in dst{};
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = g_peer_ip;

    ssize_t sent = sendto(g_sock, buf, pkt_len, 0,
                          reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst));
    if (sent < 0) {
        perror(RED "[ERROR] sendto" RESET);
        return false;
    }
    return true;
}

// ─── Receive one TCP packet directed at us, from the peer ────────────────────
struct RawPacket {
    uint32_t seq, ack;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum_pkt;
    uint16_t payload_len;
    char     payload[MAX_SEGMENT_SIZE + 1];
    uint32_t src_ip;
    uint16_t src_port;
    bool     checksum_ok;
};

static bool recv_one(RawPacket& pkt, int timeout_ms = 5000,
                     bool accept_any_src = false)
{
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t buf[65535];

    for (;;) {
        ssize_t n = recv(g_sock, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return false;
            perror(RED "[ERROR] recv" RESET);
            return false;
        }
        if (static_cast<size_t>(n) < sizeof(IPHeader) + sizeof(TCPHeader))
            continue;

        IPHeader*  ip      = reinterpret_cast<IPHeader*>(buf);
        int ip_hdr_len     = (ip->version_ihl & 0x0F) * 4;
        if (static_cast<size_t>(n) < static_cast<size_t>(ip_hdr_len) + sizeof(TCPHeader))
            continue;

        TCPHeader* tcp     = reinterpret_cast<TCPHeader*>(buf + ip_hdr_len);

        // Filter: packet must be destined to our port
        if (ntohs(tcp->dst_port) != g_our_port) continue;

        // If we already know the peer, filter by peer too
        if (!accept_any_src) {
            if (g_peer_ip   != 0 && ip->src_ip           != g_peer_ip)   continue;
            if (g_peer_port != 0 && ntohs(tcp->src_port) != g_peer_port) continue;
        }

        // Ignore packets WE sent (src_ip == our_ip AND src_port == our_port)
        if (ip->src_ip == g_our_ip && ntohs(tcp->src_port) == g_our_port) continue;

        uint16_t total_len   = ntohs(ip->total_length);
        int      tcp_hdr_len = ((tcp->data_offset >> 4) & 0x0F) * 4;
        int      data_len    = static_cast<int>(total_len) - ip_hdr_len - tcp_hdr_len;
        if (data_len < 0) data_len = 0;
        if (data_len > MAX_SEGMENT_SIZE) data_len = MAX_SEGMENT_SIZE;

        pkt.seq         = ntohl(tcp->seq_num);
        pkt.ack         = ntohl(tcp->ack_num);
        pkt.flags       = tcp->flags;
        pkt.window      = tcp->window_size;
        pkt.checksum_pkt = tcp->checksum;
        pkt.src_ip      = ip->src_ip;
        pkt.src_port    = ntohs(tcp->src_port);
        pkt.payload_len = static_cast<uint16_t>(data_len);
        memset(pkt.payload, 0, sizeof(pkt.payload));
        if (data_len > 0)
            memcpy(pkt.payload,
                   buf + ip_hdr_len + tcp_hdr_len,
                   data_len);

        // ── Checksum verification ─────────────────────────────────────────
        uint16_t saved_ck = tcp->checksum;
        tcp->checksum     = 0;
        uint16_t calc_ck  = tcp_checksum(ip->src_ip, ip->dst_ip, tcp,
                                          reinterpret_cast<uint8_t*>(buf) +
                                              ip_hdr_len + tcp_hdr_len,
                                          static_cast<uint16_t>(data_len));
        tcp->checksum = saved_ck;

        pkt.checksum_ok = (calc_ck == saved_ck);

        if (pkt.checksum_ok) {
            printf(CYAN "[CHKSUM] Seq=%-8u Checksum=0x%04X → VALID\n" RESET,
                   pkt.seq, ntohs(saved_ck));
        } else {
            printf(RED "[CHKSUM] Seq=%-8u Checksum=0x%04X (expected=0x%04X) → INVALID, dropping\n" RESET,
                   pkt.seq, ntohs(saved_ck), ntohs(calc_ck));
            fflush(stdout);
            continue;  // drop corrupt packet
        }
        fflush(stdout);
        return true;
    }
}

// ─── 3-Way Handshake (receiver side) ─────────────────────────────────────────
static bool do_handshake(State& state)
{
    printf(CYAN "\n╔══════════════════════════════════════════════════════════╗\n" RESET);
    printf(CYAN "║        3-WAY HANDSHAKE — WAITING FOR CONNECTION         ║\n" RESET);
    printf(CYAN "╚══════════════════════════════════════════════════════════╝\n\n" RESET);

    printf(YELLOW "[INFO] Listening on port %u…\n\n" RESET, g_our_port);
    fflush(stdout);

    state = State::LISTEN;

    // ── Step 1: Wait for SYN ──────────────────────────────────────────────
    for (;;) {
        RawPacket pkt{};
        if (!recv_one(pkt, 30000, true)) {
            printf(RED "[TIMEOUT] Still waiting for SYN…\n" RESET);
            fflush(stdout);
            continue;
        }
        if (!(pkt.flags & SYN_FLAG)) continue;
        if (pkt.flags & ACK_FLAG)    continue;   // not a bare SYN

        g_peer_ip   = pkt.src_ip;
        g_peer_port = pkt.src_port;
        g_peer_isn  = pkt.seq;

        struct in_addr pa; pa.s_addr = g_peer_ip;
        printf(GREEN "[RECV] SYN  Seq=%-10u  from %s:%u\n" RESET,
               pkt.seq, inet_ntoa(pa), g_peer_port);
        fflush(stdout);

        State old = state;
        state = State::SYN_RECEIVED;
        print_state(old, state);

        // ── Step 2: Send SYN-ACK ──────────────────────────────────────────
        g_our_isn = static_cast<uint32_t>(rand());
        uint32_t syn_ack_seq = g_our_isn;
        uint32_t syn_ack_ack = g_peer_isn + 1;

        printf(GREEN "[SEND] SYN-ACK  Seq=%-10u  AckNum=%-10u\n" RESET,
               syn_ack_seq, syn_ack_ack);
        fflush(stdout);
        send_packet(syn_ack_seq, syn_ack_ack, SYN_FLAG | ACK_FLAG,
                    static_cast<uint16_t>(g_max_window));

        // ── Step 3: Wait for ACK ──────────────────────────────────────────
        for (int attempt = 0; attempt < 5; attempt++) {
            RawPacket ack_pkt{};
            printf(YELLOW "[WAIT] Waiting for ACK (attempt %d/5)…\n" RESET, attempt + 1);
            fflush(stdout);
            if (!recv_one(ack_pkt, 3000)) {
                printf(RED "[TIMEOUT] No ACK, retransmitting SYN-ACK…\n" RESET);
                fflush(stdout);
                send_packet(syn_ack_seq, syn_ack_ack, SYN_FLAG | ACK_FLAG,
                            static_cast<uint16_t>(g_max_window));
                continue;
            }
            if (!(ack_pkt.flags & ACK_FLAG))  continue;
            if (ack_pkt.flags & SYN_FLAG)     continue;

            printf(GREEN "[RECV] ACK  Seq=%-10u AckNum=%-10u\n" RESET,
                   ack_pkt.seq, ack_pkt.ack);
            fflush(stdout);

            State old2 = state;
            state = State::ESTABLISHED;
            print_state(old2, state);
            printf(GREEN "\n[INFO] Connection ESTABLISHED ✓\n\n" RESET);
            fflush(stdout);
            return true;
        }

        // If we get here restart listening
        printf(RED "[WARN] ACK never received — restarting listen\n" RESET);
        fflush(stdout);
        state = State::LISTEN;
    }
}

// ─── Data Reception with Sliding Window ──────────────────────────────────────
static std::vector<std::string> receive_data(State& /*state*/)
{
    printf(CYAN "\n╔══════════════════════════════════════════════════════════╗\n" RESET);
    printf(CYAN "║      DATA RECEPTION — SLIDING WINDOW RECEIVE BUFFER     ║\n" RESET);
    printf(CYAN "╚══════════════════════════════════════════════════════════╝\n\n" RESET);

    // expected sequence number = peer_isn + 1 (SYN consumed 1)
    uint32_t expected_seq = g_peer_isn + 1;
    uint32_t our_seq      = g_our_isn  + 1;    // next seq we use when ACKing

    // In-order collected records (payload strings)
    std::vector<std::string> records;

    // Out-of-order buffer: seq_num → payload
    std::map<uint32_t, std::string> ooo_buffer;

    // Receive window tracking
    uint16_t rwnd = static_cast<uint16_t>(g_max_window);

    int total_expected = 20;   // we expect 20 records

    while (static_cast<int>(records.size()) < total_expected) {
        RawPacket pkt{};

        if (!recv_one(pkt, 10000)) {
            printf(YELLOW "[WARN] Receive timeout — waiting…\n" RESET);
            fflush(stdout);
            continue;
        }

        // FIN during data phase? Handle termination signal
        if (pkt.flags & FIN_FLAG) {
            printf(YELLOW "[INFO] Received FIN during data phase — storing for termination\n" RESET);
            fflush(stdout);
            // push a sentinel and break
            break;
        }

        // Control-only packets (pure ACK)
        if (pkt.payload_len == 0 && !(pkt.flags & FIN_FLAG)) continue;

        uint32_t seg_seq = pkt.seq;
        std::string data(pkt.payload, pkt.payload_len);

        // ── Duplicate check ───────────────────────────────────────────────
        if (seg_seq < expected_seq) {
            printf(MAGENTA "[DUPL] Seq=%-10u already received (expected=%u) — resend ACK\n" RESET,
                   seg_seq, expected_seq);
            fflush(stdout);
            send_packet(our_seq, expected_seq, ACK_FLAG, rwnd);
            continue;
        }

        // ── In-order segment ──────────────────────────────────────────────
        if (seg_seq == expected_seq) {
            printf(GREEN "[RECV] Seq=%-10u Len=%-4u Data=\"%s\"  → In-Order ✓\n" RESET,
                   seg_seq, pkt.payload_len, data.c_str());
            fflush(stdout);

            records.push_back(data);
            expected_seq += pkt.payload_len;

            // Drain out-of-order buffer for any contiguous segments
            while (ooo_buffer.count(expected_seq)) {
                std::string& buffered = ooo_buffer[expected_seq];
                printf(GREEN "[DRAIN] Seq=%-10u Len=%-4u Data=\"%s\"  → From OOO buffer ✓\n" RESET,
                       expected_seq, static_cast<unsigned>(buffered.size()),
                       buffered.c_str());
                fflush(stdout);
                records.push_back(buffered);
                expected_seq += static_cast<uint32_t>(buffered.size());
                ooo_buffer.erase(ooo_buffer.begin());
            }

            // Update rwnd
            int buffered_count = static_cast<int>(ooo_buffer.size());
            rwnd = static_cast<uint16_t>(
                    std::max(1, static_cast<int>(g_max_window) - buffered_count));

            printf(BLUE "[FLOW] Advertised window = %u\n" RESET, rwnd);
            fflush(stdout);

            // Send cumulative ACK
            printf(GREEN "[SEND] ACK  Seq=%-10u AckNum=%-10u Window=%u\n" RESET,
                   our_seq, expected_seq, rwnd);
            fflush(stdout);
            send_packet(our_seq, expected_seq, ACK_FLAG, rwnd);

        } else {
            // ── Out-of-order segment ──────────────────────────────────────
            printf(YELLOW "[OORD] Seq=%-10u buffered (expected=%u) Len=%u Data=\"%s\"\n" RESET,
                   seg_seq, expected_seq, pkt.payload_len, data.c_str());
            fflush(stdout);

            ooo_buffer[seg_seq] = data;

            // Send duplicate ACK for last in-order seq
            printf(GREEN "[SEND] DupACK  AckNum=%-10u (OOO buffer size=%zu)\n" RESET,
                   expected_seq, ooo_buffer.size());
            fflush(stdout);
            send_packet(our_seq, expected_seq, ACK_FLAG, rwnd);
        }
    }

    printf(GREEN "\n[INFO] Data reception complete. Records received: %zu\n\n" RESET,
           records.size());
    fflush(stdout);

    return records;
}

// ─── 4-Way Termination (receiver side) ───────────────────────────────────────
static void do_termination(State& state, uint32_t our_seq, uint32_t peer_next_seq)
{
    printf(CYAN "\n╔══════════════════════════════════════════════════════════╗\n" RESET);
    printf(CYAN "║        CONNECTION TERMINATION — 4-WAY HANDSHAKE         ║\n" RESET);
    printf(CYAN "╚══════════════════════════════════════════════════════════╝\n\n" RESET);

    // Wait for FIN from sender (might already be queued)
    bool got_fin = false;
    for (int attempt = 0; attempt < 10 && !got_fin; attempt++) {
        RawPacket pkt{};
        printf(YELLOW "[WAIT] Waiting for FIN from sender (attempt %d/10)…\n" RESET,
               attempt + 1);
        fflush(stdout);
        if (!recv_one(pkt, 3000)) continue;
        if (!(pkt.flags & FIN_FLAG)) continue;

        printf(BLUE "[RECV] FIN  Seq=%-10u AckNum=%u\n" RESET, pkt.seq, pkt.ack);
        fflush(stdout);

        State old = state;
        state = State::CLOSE_WAIT;
        print_state(old, state);

        // Send ACK for FIN
        uint32_t fin_ack_num = pkt.seq + 1;
        printf(GREEN "[SEND] ACK  Seq=%-10u AckNum=%u  (ACK for FIN)\n" RESET,
               our_seq, fin_ack_num);
        fflush(stdout);
        send_packet(our_seq, fin_ack_num, ACK_FLAG,
                    static_cast<uint16_t>(g_max_window));

        // Send our own FIN
        printf(GREEN "[SEND] FIN  Seq=%-10u AckNum=%u\n" RESET, our_seq, fin_ack_num);
        fflush(stdout);

        old   = state;
        state = State::LAST_ACK;
        print_state(old, state);

        send_packet(our_seq, fin_ack_num, FIN_FLAG | ACK_FLAG,
                    static_cast<uint16_t>(g_max_window));
        got_fin = true;
    }

    if (!got_fin) {
        printf(RED "[WARN] Never received FIN — sending our FIN anyway\n" RESET);
        fflush(stdout);
        send_packet(our_seq, peer_next_seq, FIN_FLAG | ACK_FLAG,
                    static_cast<uint16_t>(g_max_window));
        State old = state;
        state = State::LAST_ACK;
        print_state(old, state);
    }

    // Wait for final ACK from sender
    for (int attempt = 0; attempt < 5; attempt++) {
        RawPacket pkt{};
        printf(YELLOW "[WAIT] Waiting for final ACK (attempt %d/5)…\n" RESET, attempt + 1);
        fflush(stdout);
        if (!recv_one(pkt, 3000)) continue;
        if (!(pkt.flags & ACK_FLAG)) continue;
        if (pkt.flags & (SYN_FLAG | FIN_FLAG)) continue;

        printf(BLUE "[RECV] ACK  Seq=%-10u AckNum=%u  (final ACK)\n" RESET,
               pkt.seq, pkt.ack);
        fflush(stdout);

        State old = state;
        state = State::CLOSED;
        print_state(old, state);
        printf(GREEN "[INFO] Connection cleanly CLOSED ✓\n\n" RESET);
        fflush(stdout);
        return;
    }

    // If we never got the final ACK still move to CLOSED
    State old = state;
    state = State::CLOSED;
    print_state(old, state);
    printf(YELLOW "[WARN] Final ACK not received — assuming CLOSED\n\n" RESET);
    fflush(stdout);
}

// ─── Save records ─────────────────────────────────────────────────────────────
static void save_records(const std::vector<std::string>& records, const char* path)
{
    std::ofstream f(path);
    if (!f.is_open()) {
        fprintf(stderr, RED "[ERROR] Cannot create %s\n" RESET, path);
        return;
    }
    for (const auto& r : records)
        f << r << "\n";
    f.close();
    printf(GREEN "[INFO] Saved %zu record(s) to %s ✓\n" RESET, records.size(), path);
    fflush(stdout);
}

// ─── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[])
{
    srand(static_cast<unsigned>(time(nullptr)));

    if (argc >= 2) g_our_port   = static_cast<uint16_t>(atoi(argv[1]));
    if (argc >= 3) g_max_window = static_cast<uint32_t>(atoi(argv[2]));

    // For loopback use 127.0.0.1
    g_our_ip = inet_addr("127.0.0.1");

    printf(CYAN "╔══════════════════════════════════════════════════════════╗\n" RESET);
    printf(CYAN "║        TCP RAW SOCKET RECEIVER — Academic Demo           ║\n" RESET);
    printf(CYAN "╚══════════════════════════════════════════════════════════╝\n\n" RESET);
    printf(BLUE "[INFO] Listening IP:Port = 127.0.0.1:%u\n" RESET, g_our_port);
    printf(BLUE "[INFO] Window size       = %u\n\n" RESET, g_max_window);

    printf(YELLOW "[INFO] Start tcpdump with:\n" RESET);
    printf(YELLOW "       sudo tcpdump -i lo -w capture.pcap port %u\n\n" RESET, g_our_port);
    fflush(stdout);

    // ── Create raw socket ─────────────────────────────────────────────────
    g_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (g_sock < 0) {
        perror(RED "[ERROR] socket()" RESET);
        fprintf(stderr, RED "        Are you running as root (sudo)?\n" RESET);
        return 1;
    }

    int one = 1;
    if (setsockopt(g_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror(RED "[ERROR] setsockopt(IP_HDRINCL)" RESET);
        close(g_sock);
        return 1;
    }

    printf(GREEN "[INFO] Raw socket created (fd=%d), IP_HDRINCL enabled ✓\n\n" RESET, g_sock);
    fflush(stdout);

    State state = State::CLOSED;

    // ── 3-way handshake ───────────────────────────────────────────────────
    if (!do_handshake(state)) {
        close(g_sock);
        return 1;
    }

    // ── Data reception ────────────────────────────────────────────────────
    auto records = receive_data(state);

    // ── Print reassembled records ─────────────────────────────────────────
    printf(CYAN "\n╔══════════════════════════════════════════════════════════╗\n" RESET);
    printf(CYAN "║             REASSEMBLED STUDENT RECORDS                  ║\n" RESET);
    printf(CYAN "╚══════════════════════════════════════════════════════════╝\n\n" RESET);
    for (size_t i = 0; i < records.size(); i++)
        printf("  [%2zu] %s\n", i + 1, records[i].c_str());
    printf("\n");
    fflush(stdout);

    // ── Save to file ──────────────────────────────────────────────────────
    save_records(records, "received_records.txt");

    // ── 4-way termination ─────────────────────────────────────────────────
    uint32_t our_seq = g_our_isn + 1;
    uint32_t peer_next = g_peer_isn + 1;
    for (const auto& r : records)
        peer_next += static_cast<uint32_t>(r.size());

    do_termination(state, our_seq, peer_next);

    close(g_sock);

    printf(CYAN "\n╔══════════════════════════════════════════════════════════╗\n" RESET);
    printf(CYAN "║              RECEIVER FINISHED ✓                        ║\n" RESET);
    printf(CYAN "╚══════════════════════════════════════════════════════════╝\n" RESET);
    fflush(stdout);

    return 0;
}
