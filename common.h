#pragma once
#ifndef COMMON_H
#define COMMON_H

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// ─── ANSI colour codes ────────────────────────────────────────────────────────
#define RED     "\033[91m"
#define GREEN   "\033[92m"
#define YELLOW  "\033[93m"
#define BLUE    "\033[94m"
#define CYAN    "\033[96m"
#define MAGENTA "\033[95m"
#define RESET   "\033[0m"

// ─── Protocol constants ───────────────────────────────────────────────────────
constexpr uint16_t DEFAULT_PORT       = 54321;
constexpr uint16_t MAX_SEGMENT_SIZE   = 512;   // bytes of payload per segment
constexpr uint32_t WINDOW_SIZE        = 4;     // max outstanding segments
constexpr uint32_t INITIAL_SSTHRESH   = 8;     // slow-start threshold

// ─── TCP flag bit-masks ───────────────────────────────────────────────────────
constexpr uint8_t FIN_FLAG = 0x01;
constexpr uint8_t SYN_FLAG = 0x02;
constexpr uint8_t RST_FLAG = 0x04;
constexpr uint8_t PSH_FLAG = 0x08;
constexpr uint8_t ACK_FLAG = 0x10;
constexpr uint8_t URG_FLAG = 0x20;

// ─── Custom IP header (20 bytes, no options) ──────────────────────────────────
struct __attribute__((packed)) IPHeader {
    uint8_t  version_ihl;      // version (4 bits) + IHL (4 bits)
    uint8_t  tos;              // type of service
    uint16_t total_length;     // total packet length (host order before htons)
    uint16_t id;               // identification
    uint16_t frag_offset;      // flags + fragment offset
    uint8_t  ttl;              // time to live
    uint8_t  protocol;         // 6 = TCP
    uint16_t checksum;         // IP header checksum (0 → kernel fills)
    uint32_t src_ip;           // source IP
    uint32_t dst_ip;           // destination IP
};

// ─── Custom TCP header (20 bytes, no options) ─────────────────────────────────
struct __attribute__((packed)) TCPHeader {
    uint16_t src_port;         // source port
    uint16_t dst_port;         // destination port
    uint32_t seq_num;          // sequence number
    uint32_t ack_num;          // acknowledgement number
    uint8_t  data_offset;      // upper 4 bits = header length in 32-bit words; lower 4 = reserved
    uint8_t  flags;            // URG ACK PSH RST SYN FIN
    uint16_t window_size;      // receive window
    uint16_t checksum;         // TCP checksum
    uint16_t urgent_ptr;       // urgent pointer
};

// ─── Pseudo-header used for TCP checksum computation ─────────────────────────
struct __attribute__((packed)) TCPPseudoHeader {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t  zero;             // must be 0
    uint8_t  protocol;         // 6
    uint16_t tcp_length;       // TCP header + data length
};

// ─── Internet checksum (RFC 1071) ─────────────────────────────────────────────
inline uint16_t compute_checksum(const uint8_t* data, size_t len)
{
    uint32_t sum = 0;
    const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) {                           // odd byte
        uint16_t last = 0;
        *reinterpret_cast<uint8_t*>(&last) = *reinterpret_cast<const uint8_t*>(ptr);
        sum += last;
    }
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);   // fold carries

    return static_cast<uint16_t>(~sum);
}

// ─── TCP checksum: pseudo-header + TCP header + payload ──────────────────────
inline uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                              const TCPHeader* tcp_hdr,
                              const uint8_t*  payload,
                              uint16_t        payload_len)
{
    // TCP segment size = 20-byte header + payload
    uint16_t tcp_len = static_cast<uint16_t>(sizeof(TCPHeader) + payload_len);

    // Build a buffer: pseudo-header + TCP header (checksum field = 0) + payload
    size_t buf_len = sizeof(TCPPseudoHeader) + tcp_len;
    uint8_t* buf   = new uint8_t[buf_len]();

    // Fill pseudo-header
    TCPPseudoHeader psh{};
    psh.src_ip     = src_ip;
    psh.dst_ip     = dst_ip;
    psh.zero       = 0;
    psh.protocol   = 6;
    psh.tcp_length = htons(tcp_len);

    size_t offset = 0;
    memcpy(buf + offset, &psh, sizeof(psh));
    offset += sizeof(psh);

    // Copy TCP header with checksum field zeroed
    TCPHeader tmp_hdr = *tcp_hdr;
    tmp_hdr.checksum  = 0;
    memcpy(buf + offset, &tmp_hdr, sizeof(tmp_hdr));
    offset += sizeof(tmp_hdr);

    // Copy payload
    if (payload && payload_len > 0)
        memcpy(buf + offset, payload, payload_len);

    uint16_t result = compute_checksum(buf, buf_len);
    delete[] buf;
    return result;
}

// ─── Helper: decode flags into human-readable string ─────────────────────────
inline const char* flags_str(uint8_t flags)
{
    static char buf[32];
    buf[0] = '\0';
    if (flags & SYN_FLAG) strcat(buf, "SYN ");
    if (flags & ACK_FLAG) strcat(buf, "ACK ");
    if (flags & FIN_FLAG) strcat(buf, "FIN ");
    if (flags & RST_FLAG) strcat(buf, "RST ");
    if (flags & PSH_FLAG) strcat(buf, "PSH ");
    if (flags & URG_FLAG) strcat(buf, "URG ");
    if (buf[0] == '\0')   strcat(buf, "DATA");
    // trim trailing space
    size_t l = strlen(buf);
    if (l > 0 && buf[l-1] == ' ') buf[l-1] = '\0';
    return buf;
}

// ─── Helper: timestamp string (HH:MM:SS.mmm) ─────────────────────────────────
inline const char* timestamp_now()
{
    static char buf[32];
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm* tm_info = localtime(&ts.tv_sec);
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03ld",
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
             ts.tv_nsec / 1000000L);
    return buf;
}

// ─── Print a single-line packet summary ──────────────────────────────────────
inline void print_packet_summary(const char* tag,
                                 const char* color,
                                 uint32_t    seq,
                                 uint32_t    ack,
                                 uint8_t     flags,
                                 uint16_t    window,
                                 uint16_t    chksum,
                                 uint16_t    payload_len = 0)
{
    printf("%s[%s] %s[%s]%s Seq=%-10u Ack=%-10u Win=%-5u Chk=0x%04X Len=%-5u Flags=[%s]\n",
           RESET,
           timestamp_now(),
           color, tag, RESET,
           seq, ack, ntohs(window), ntohs(chksum),
           payload_len,
           flags_str(flags));
    fflush(stdout);
}

#endif // COMMON_H
