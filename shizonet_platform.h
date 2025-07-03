#pragma once

#include <string>
#include <cstring>
#include <vector>
#include <functional>
#include <map>
#include <unordered_map>
#include <queue>
#include <memory>
#include <bitset>

//#define SHIZONET_DEBUG

#include "shizonet_platform_os.h"

#ifdef ARDUINO
#define SHZNET_PKT_MAX_QUEUES 0
#define SHZNET_PKT_MAX_ASYNC 2
#define SHZNET_PKT_MAX_ASYNC_DIAG 2
#define SHZNET_MAX_STREAMS 8
#else
#define SHZNET_PKT_MAX_QUEUES 0
#define SHZNET_PKT_MAX_ASYNC 512
#define SHZNET_PKT_MAX_ASYNC_DIAG SHZNET_PKT_MAX_ASYNC
#define SHZNET_MAX_STREAMS 256
#endif

#ifndef _WIN32
#if (__cplusplus <= 201103)

namespace std
{
    template<typename T, typename... Args>
    std::unique_ptr<T> make_unique(Args&&... args)
    {
        return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
    }
}

#endif
#endif

#define ART_NET_PORT 6454
#define ARTNET_UNIVERSE_MAX 16

#if defined(ARDUINO)

#define SHZNET_PKT_MAX 1400

#include <Arduino.h>
#ifdef SHIZONET_DEBUG
#define NETPRNT(str) Serial.println(str)
#define NETPRNT_FMT(str,...) Serial.printf(str, __VA_ARGS__)
#define NETPRNT_ERR(str) Serial.printf(str, __VA_ARGS__)
#else
#define NETPRNT(str)
#define NETPRNT_FMT(str,...)
#define NETPRNT_ERR(str)
#endif
#define PACKED_ATTR __attribute__((packed))
#else

#define SHZNET_PKT_MAX 1400

#ifdef SHIZONET_DEBUG
#define NETPRNT(str) printf("%s\n", str);
#define NETPRNT_FMT(str,...) printf(str, __VA_ARGS__)
#define NETPRNT_ERR(str) printf("%s\n", str);
#else
#define NETPRNT(str)
#define NETPRNT_FMT(str,...)
#define NETPRNT_ERR(str)
#endif
#define PACKED_ATTR
#ifdef __linux__
#define PACKED_ATTR __attribute__((packed))
#endif
#endif

#define ART_POLL 0x2000
#define ART_POLL_REPLY 0x2100
#define ART_DMX 0x5000
#define ART_SYNC 0x5200
#define MAX_BUFFER_ARTNET 530
#define ART_NET_ID "Art-Net\0"
#define ART_DMX_START 18

typedef unsigned char byte;
typedef unsigned int shznet_sessionid;
typedef unsigned long long shznet_ticketid;

void* shznet_malloc(size_t size);

template<class T> inline T* shznet_alloc()
{
    T* res = (T*)shznet_malloc(sizeof(T));
    new (res) T();
    return res;
}

//make union PacketBuffer & ArtnetPacket

#pragma pack(push, 1)

struct shznet_ipv4
{
    byte ip[4];

    shznet_ipv4(byte a, byte b, byte c, byte d)
    {
        ip[0] = a;
        ip[1] = b;
        ip[2] = c;
        ip[3] = d;
    }
    shznet_ipv4(void* adr)
    {
        memcpy(ip, adr, 4);
    }

    shznet_ipv4() //broadcast
    {
        memset(ip, 0xFF, 4);
    }

    bool operator ==(const shznet_ipv4& b) const
    {
        return memcmp(ip, b.ip, 4) == 0;
    }
    bool operator !=(const shznet_ipv4& b) const
    {
        return !(memcmp(ip, b.ip, 4) == 0);
    }
    bool operator < (const shznet_ipv4& b) const {
        uint32_t rt1 = *(uint32_t*)&ip[0];
        uint32_t rt2 = *(uint32_t*)&b.ip[0];
        return rt1 < rt2;
    }
    bool operator > (const shznet_ipv4& b) const {
        uint32_t rt1 = *(uint32_t*)&ip[0];
        uint32_t rt2 = *(uint32_t*)&b.ip[0];
        return rt1 > rt2;
    }
    bool operator <= (const shznet_ipv4& b) const {
        uint32_t rt1 = *(uint32_t*)&ip[0];
        uint32_t rt2 = *(uint32_t*)&b.ip[0];
        return rt1 <= rt2;
    }
    bool operator >= (const shznet_ipv4& b) const {
        uint32_t rt1 = *(uint32_t*)&ip[0];
        uint32_t rt2 = *(uint32_t*)&b.ip[0];
        return rt1 >= rt2;
    }

    std::string str() {
        return std::string(std::to_string((int32_t)ip[0]) + "."
            + std::to_string((int32_t)ip[1]) + "."
            + std::to_string((int32_t)ip[2]) + "."
            + std::to_string((int32_t)ip[3]));
    }

}PACKED_ATTR;

struct shznet_ip
{
    byte ip[4];
    int16_t port;

    shznet_ip(byte a, byte b, byte c, byte d, int16_t _port)
    {
        ip[0] = a;
        ip[1] = b;
        ip[2] = c;
        ip[3] = d;
        port = _port;
    }
    shznet_ip(void* adr, int16_t _port)
    {
        memcpy(ip, adr, 4);
        port = _port;
    }

    shznet_ip(int16_t _port) //broadcast
    {
        memset(ip, 0xFF, 4);
        port = _port;
    }

    shznet_ip() { memset(ip, 0, 4); port = 0; }

    bool compare_ip(const shznet_ip& b) //compare without port
    {
        return memcmp(ip, b.ip, 4) == 0;
    }

    bool is_broadcast()
    {
        return memcmp(ip, "\xFF\xFF\xFF\xFF", 4) == 0;
    }

    uint64_t get_unique_num() const
    {
        char buffer[sizeof(uint64_t)] = { 0 };
        memcpy(&buffer[0], ip, 4);
        memcpy(&buffer[4], &port, 2);
        uint64_t v = *(uint64_t*)&buffer[0];
        return v;
    }

    bool operator ==(const shznet_ip& b) const
    {
        return get_unique_num() == b.get_unique_num();
    }
    bool operator !=(const shznet_ip& b) const
    {
        return get_unique_num() != b.get_unique_num();
    }
    bool operator < (const shznet_ip& b) const {
        auto rt1 = get_unique_num();
        auto rt2 = b.get_unique_num();
        return rt1 < rt2;
    }
    bool operator > (const shznet_ip& b) const {
        auto rt1 = get_unique_num();
        auto rt2 = b.get_unique_num();
        return rt1 > rt2;
    }
    bool operator <= (const shznet_ip& b) const {
        auto rt1 = get_unique_num();
        auto rt2 = b.get_unique_num();
        return rt1 <= rt2;
    }
    bool operator >= (const shznet_ip& b) const {
        auto rt1 = get_unique_num();
        auto rt2 = b.get_unique_num();
        return rt1 >= rt2;
    }

    std::string str() {
        return std::string(std::to_string((int32_t)ip[0]) + "."
            + std::to_string((int32_t)ip[1]) + "."
            + std::to_string((int32_t)ip[2]) + "."
            + std::to_string((int32_t)ip[3]));
    }
}PACKED_ATTR;
struct shznet_mac
{
    byte mac[6] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
    shznet_mac(byte* _mac = 0) {
        if (_mac)
            memcpy(mac, _mac, 6);
        else
            memset(mac, 0, 6);
    }

    bool compare(byte* other_mac)
    {
        return memcmp(mac, other_mac, 6) == 0;
    }

    bool operator ==(const shznet_mac& b) const
    {
        return memcmp(mac, b.mac, 6) == 0;
    }
    bool operator !=(const shznet_mac& b) const
    {
        return memcmp(mac, b.mac, 6) != 0;
    }
    bool operator < (const shznet_mac& b) const {
        unsigned long long rt1 = 0;
        unsigned long long rt2 = 0;
        memcpy(&rt1, mac, 6);
        memcpy(&rt2, b.mac, 6);
        return rt1 < rt2;
    }
    bool operator > (const shznet_mac& b) const {
        unsigned long long rt1 = 0;
        unsigned long long rt2 = 0;
        memcpy(&rt1, mac, 6);
        memcpy(&rt2, b.mac, 6);
        return rt1 > rt2;
    }
    bool operator <= (const shznet_mac& b) const {
        unsigned long long rt1 = 0;
        unsigned long long rt2 = 0;
        memcpy(&rt1, mac, 6);
        memcpy(&rt2, b.mac, 6);
        return rt1 <= rt2;
    }
    bool operator >= (const shznet_mac& b) const {
        unsigned long long rt1 = 0;
        unsigned long long rt2 = 0;
        memcpy(&rt1, mac, 6);
        memcpy(&rt2, b.mac, 6);
        return rt1 >= rt2;
    }

    std::string str()
    {
        char tmp[32];
        snprintf(tmp, sizeof(tmp), "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return tmp;
    }
}PACKED_ATTR;
struct shznet_adr
{
    shznet_ip ip;
    shznet_mac mac;

    shznet_adr() {}

    shznet_adr(byte* _ip, byte* _mac = 0, int16_t port = 0)
    {
        if (_ip) memcpy(ip.ip, _ip, 4);
        if (_mac) memcpy(mac.mac, _mac, 6);
        if (port) ip.port = port;
    }

    bool operator ==(const shznet_adr& b) const
    {
        return mac == b.mac; //just check mac, manually update IP and port accordingly
    }
    bool operator !=(const shznet_adr& b) const
    {
        return (mac != b.mac); //just check mac, manually update IP and port accordingly
    }
    bool operator < (const shznet_adr& b) const {
        return mac < b.mac;
    };
    bool operator > (const shznet_adr& b) const {
        return mac > b.mac;
    };
    bool operator <= (const shznet_adr& b) const {
        return mac <= b.mac;
    };
    bool operator >= (const shznet_adr& b) const {
        return mac >= b.mac;
    };
}PACKED_ATTR;

uint64_t shznet_millis();
uint32_t shznet_hash(char* data, size_t size);
uint32_t shznet_hash(const char* str);
uint32_t shznet_hash(std::string& str);

extern shznet_ip shznet_broadcast_ip;
extern shznet_mac shznet_broadcast_mac;

enum shznet_pkt_type : byte
{
    SHZNET_PKT_INVALID = 0,
    SHZNET_PKT_ARTNET = 1,
    SHZNET_PKT_ARTNET_POLL = 2,
    SHZNET_PKT_GENERIC = 23,
    SHZNET_PKT_RECEIVED = 24,
    SHZNET_PKT_SUCCESS = 25,
    SHZNET_PKT_FAIL = 26,
    SHZNET_PKT_CAST = 27,
    SHZNET_PKT_PROCESSING = 28,

    SHZNET_PKT_AUTH_BEACON,
    SHZNET_PKT_AUTH_BEACON_REPLY,
    SHZNET_PKT_AUTH_REQ,
    SHZNET_PKT_AUTH_REPL,
    SHZNET_PKT_ALIVE_CHECK,
    SHZNET_PKT_ALIVE_CHECK_REPL,

    SHZNET_PKT_OOB,
    SHZNET_PKT_DIAGNOSTICS,
    SHZNET_PKT_DIAGNOSTICS_REQUEST,

    SHZNET_PKT_ACK,
    SHZNET_PKT_ACK_REQ,

    SHZNET_PKT_STREAM,
    SHZNET_PKT_TYPE_MAX
};
enum shznet_pkt_flags : byte
{
    SHZNET_PKT_FLAGS_NONE = 0,
    SHZNET_PKT_FLAGS_UNRELIABLE = 1,
    SHZNET_PKT_FLAGS_RECEIVER_ONLY = 2,
};
enum shznet_pkt_dataformat : byte
{
    SHZNET_PKT_FMT_DATA = 0,
    SHZNET_PKT_FMT_STRING,
    SHZNET_PKT_FMT_JSON, //internal shizoscript data format for json vars
    SHZNET_PKT_FMT_KEY_VALUE, //like JSON, just way more primitive, no nestings just key value (use with shznet_kv_writer / reader
    SHZNET_PKT_FMT_INT16,
    SHZNET_PKT_FMT_INT32,
    SHZNET_PKT_FMT_INT64,
    SHZNET_PKT_FMT_INT16_ARRAY,
    SHZNET_PKT_FMT_INT32_ARRAY,
    SHZNET_PKT_FMT_INT64_ARRAY,
    SHZNET_PKT_FMT_FLOAT32,
    SHZNET_PKT_FMT_FLOAT64,
    SHZNET_PKT_FMT_FLOAT32_ARRAY,
    SHZNET_PKT_FMT_FLOAT64_ARRAY,
    SHZNET_PKT_FMT_INVALID
};

inline shznet_pkt_flags operator |=(shznet_pkt_flags a, shznet_pkt_flags b)
{
    return a = (shznet_pkt_flags)((uint16_t)a | (uint16_t)b);
}

struct shznet_pkt_header
{
    char id[3] = { 'S','H','Z' };
    shznet_pkt_type type;
    shznet_pkt_flags flags = SHZNET_PKT_FLAGS_NONE;
    shznet_pkt_dataformat data_format = SHZNET_PKT_FMT_DATA;
    uint16_t queries = 0;
    uint32_t chksum = 0;
    shznet_sessionid sessionid = -1;
    shznet_ticketid  ticketid = 0;
    uint32_t        cmd_hash = 0;
    uint32_t seq = 0;
    uint32_t seq_max = 0;
    byte macid_target[6] = { 0 };
    byte macid_source[6] = { 0 };
    uint32_t data_chksum = 0;
    uint32_t data_size = 0;
    uint64_t data_max_size = 0;

    shznet_pkt_header() {
        memset(macid_target, 0xFF, 6);
    }
}PACKED_ATTR; //current header size is exactly 64 bytes which makes is nicely dividable by 8 do not change size of this struct !!!

#define SHZNET_PKT_HEADER_SIZE sizeof(shznet_pkt_header)
#define SHZNET_PKT_DATA_SIZE (SHZNET_PKT_MAX - SHZNET_PKT_HEADER_SIZE)

struct shznet_pkt
{
    shznet_pkt_header header;
    byte data[SHZNET_PKT_DATA_SIZE];


    bool check_packet(uint32_t pkt_size, bool force_checksum = false) //memcpy recv buffer over this struct then call this function
    {
        if (pkt_size < SHZNET_PKT_HEADER_SIZE || pkt_size > (sizeof(shznet_pkt_header) + SHZNET_PKT_DATA_SIZE))
        {
            NETPRNT("invalid size!");
            return false;
        }
        if (header.id[0] != 'S' || header.id[1] != 'H' || header.id[2] != 'Z')
        {
            NETPRNT("invalid id!");
            return false;
        }
        if (header.type >= SHZNET_PKT_TYPE_MAX)
            return false;

        //no checksum check for streams, handle that later to save ressources
        if (!force_checksum && header.type == SHZNET_PKT_STREAM)
            return true;

        uint32_t real_chksum = header.chksum;
        header.chksum = 0;
        if (shznet_hash((char*)&header, SHZNET_PKT_HEADER_SIZE) != real_chksum)
        {
            NETPRNT("invalid checksum header");
            return false;
        }
        if (!(header.flags & SHZNET_PKT_FLAGS_UNRELIABLE))
        {
            if (shznet_hash((char*)data, pkt_size - SHZNET_PKT_HEADER_SIZE) != header.data_chksum)
            {
                NETPRNT("invalid checksum data");
                NETPRNT_FMT("chskum: %i : %i\n", header.data_chksum, shznet_hash((char*)data, pkt_size - SHZNET_PKT_HEADER_SIZE));
                NETPRNT_FMT("size: %i : %i\n", pkt_size, header.data_size + SHZNET_PKT_HEADER_SIZE);
                NETPRNT_FMT("type: %i : %i\n", (int)header.type, (int)header.data_format);
                NETPRNT_FMT("seq: %i : %i\n", (int)header.seq, (int)header.seq_max);
                return false;
            }
        }
        pkt_size -= SHZNET_PKT_HEADER_SIZE;
        return !(header.data_size > pkt_size);
    }

    void packet_begin(shznet_pkt_type type, shznet_mac& src, shznet_mac& dest, shznet_ticketid ticketid = 0, shznet_sessionid sessionid = -1)
    {
        header.id[0] = 'S';
        header.id[1] = 'H';
        header.id[2] = 'Z';
        header.flags = SHZNET_PKT_FLAGS_NONE;
        header.data_format = SHZNET_PKT_FMT_DATA;
        header.queries = 0;
        header.chksum = 0;
        header.type = type;
        header.ticketid = ticketid;
        header.cmd_hash = 0;
        header.sessionid = sessionid;
        header.seq = 0;
        header.seq_max = 0;
        header.data_max_size = 0;
        header.data_size = 0;
        memcpy(header.macid_source, src.mac, 6);
        memcpy(header.macid_target, dest.mac, 6);
        header.data_chksum = 0;
    }

    void packet_set_cmd(char* cmd)
    {
        header.cmd_hash = shznet_hash(cmd, strlen(cmd));
    }

    void packet_set_cmd(uint32_t hash)
    {
        header.cmd_hash = hash;
    }

    uint32_t packet_get_cmd_hash(char* cmd)
    {
        return shznet_hash(cmd, strlen(cmd));
    }

    uint32_t packet_set_data(byte* _data, uint32_t size, uint64_t max_size = 0, uint64_t offset = 0) //returns how much of the data has fit into the packet (with cmd set etc)
    {
        uint32_t max_pkt_size = SHZNET_PKT_DATA_SIZE;
        if (size + offset > max_pkt_size)
        {
            NETPRNT("warning: truncating packet data!");
            size = max_pkt_size - offset;
        }
        if(_data) memcpy(&data[offset], _data, size);
        header.data_max_size = max_size;
        header.data_size = size + offset;

        return size;
    }

    template<class T> uint32_t packet_set_data(T& _data)
    {
        return packet_set_data((byte*)&_data, sizeof(T));
    }

    void packet_set_unreliable()
    {
        header.flags |= SHZNET_PKT_FLAGS_UNRELIABLE;
    }

    void packet_set_format(shznet_pkt_dataformat fmt)
    {
        header.data_format = fmt;
    }

    void packet_set_seq(int seq, int max_seq)
    {
        header.seq = seq;
        header.seq_max = max_seq;
    }

    uint32_t packet_end() //returns total packet size in bytes
    {
        header.chksum = 0;
        header.data_chksum = 0;

        if (!(header.flags & SHZNET_PKT_FLAGS_UNRELIABLE))
        {
            header.data_chksum = shznet_hash((char*)data, header.data_size);
        }

        header.chksum = shznet_hash((char*)&header, SHZNET_PKT_HEADER_SIZE);

        return get_packet_size();
    }

    uint32_t get_packet_size()
    {
        return SHZNET_PKT_HEADER_SIZE + header.data_size;
    }

    uint32_t get_cmd()
    {
        return header.cmd_hash;
    }
    byte* get_data()
    {
        return data;
    }
    uint32_t get_data_size()
    {
        return header.data_size;
    }
    uint32_t get_data_size_max()
    {
        return header.data_max_size;
    }

    byte* source_mac() { return header.macid_source; }
    byte* target_mac() { return header.macid_target; }

}PACKED_ATTR;

struct shznet_pkt_big
{
    shznet_pkt_header header;
    byte data[SHZNET_PKT_DATA_SIZE];


    bool check_packet(uint32_t pkt_size) //memcpy recv buffer over this struct then call this function
    {
        if (pkt_size < SHZNET_PKT_HEADER_SIZE || pkt_size > (sizeof(shznet_pkt_header) + SHZNET_PKT_DATA_SIZE))
        {
            return false;
        }
        if (header.id[0] != 'S' || header.id[1] != 'H' || header.id[2] != 'Z')
        {
            return false;
        }
        uint32_t real_chksum = header.chksum;
        header.chksum = 0;
        if (shznet_hash((char*)&header, SHZNET_PKT_HEADER_SIZE) != real_chksum)
        {
            //NETPRNT("invalid checksum header");
            return false;
        }
        if (!(header.flags & SHZNET_PKT_FLAGS_UNRELIABLE))
        {
            if (shznet_hash((char*)data, pkt_size - SHZNET_PKT_HEADER_SIZE) != header.data_chksum)
            {
                //NETPRNT("invalid checksum data");
                return false;
            }
        }
        pkt_size -= SHZNET_PKT_HEADER_SIZE;
        return !(header.data_size > pkt_size);
    }

    void packet_begin(shznet_pkt_type type, shznet_mac& src, shznet_mac& dest, shznet_ticketid ticketid = 0, shznet_sessionid sessionid = -1)
    {
        header.id[0] = 'S';
        header.id[1] = 'H';
        header.id[2] = 'Z';
        header.flags = SHZNET_PKT_FLAGS_NONE;
        header.data_format = SHZNET_PKT_FMT_DATA;
        header.queries = 0;
        header.chksum = 0;
        header.type = type;
        header.ticketid = ticketid;
        header.cmd_hash = 0;
        header.sessionid = sessionid;
        header.seq = 0;
        header.seq_max = 0;
        header.data_max_size = 0;
        header.data_size = 0;
        memcpy(header.macid_source, src.mac, 6);
        memcpy(header.macid_target, dest.mac, 6);
        header.data_chksum = 0;
    }

    void packet_set_cmd(char* cmd)
    {
        header.cmd_hash = shznet_hash(cmd, strlen(cmd));
    }

    uint32_t packet_set_data(byte* _data, uint32_t size, uint64_t max_size = 0) //returns how much of the data has fit into the packet (with cmd set etc)
    {
        uint32_t max_pkt_size = SHZNET_PKT_DATA_SIZE;
        if (size > max_pkt_size) size = max_pkt_size;
        memcpy(&data[0], _data, size);
        header.data_max_size = max_size;
        header.data_size = size;

        return size;
    }

    template<class T> uint32_t packet_set_data(T& _data)
    {
        return packet_set_data((byte*)&_data, sizeof(T));
    }

    void packet_set_unreliable()
    {
        header.flags |= SHZNET_PKT_FLAGS_UNRELIABLE;
    }

    void packet_set_format(shznet_pkt_dataformat fmt)
    {
        header.data_format = fmt;
    }

    void packet_set_seq(int seq, int max_seq)
    {
        header.seq = seq;
        header.seq_max = max_seq;
    }

    uint32_t packet_end() //returns total packet size in bytes
    {
        header.chksum = 0;
        header.data_chksum = 0;

        if (!(header.flags & SHZNET_PKT_FLAGS_UNRELIABLE))
        {
            header.data_chksum = shznet_hash((char*)data, header.data_size);
        }

        header.chksum = shznet_hash((char*)&header, SHZNET_PKT_HEADER_SIZE);

        return get_total_size();
    }

    uint32_t get_total_size()
    {
        return SHZNET_PKT_HEADER_SIZE + header.data_size;
    }

    uint32_t get_cmd()
    {
        return header.cmd_hash;
    }
    byte* get_data()
    {
        return data;
    }
    uint32_t get_data_size()
    {
        return header.data_size;
    }

    byte* source_mac() { return header.macid_source; }
    byte* target_mac() { return header.macid_target; }

}PACKED_ATTR;

enum shznet_ack_request_type : uint16_t
{
    shznet_ack_request_complete,
    shznet_ack_request_delete_buffer,
    shznet_ack_request_invalid_sessionid,
    shznet_ack_request_ping,
    shznet_ack_request_quick_resend,
    shznet_ack_request_resend,
    shznet_ack_request_busy, 
    shznet_ack_request_too_big
};

struct shznet_pkt_ack
{
    byte id[4] = { 'S','H','A', 0 };
    shznet_sessionid sessionid;
    shznet_ticketid ticketid;
    uint64_t missing_start_id;
    uint64_t missing_end_id;
    uint32_t checksum;
    shznet_ack_request_type type;
    byte mac[6];
    uint32_t ack_id = 0;

    bool is_valid()
    {
        auto tmp_checksum = checksum;
        checksum = 0;
        bool check = tmp_checksum == shznet_hash((char*)this, sizeof(shznet_pkt_ack)) && (id[0] == 'S' && id[1] == 'H' && id[2] == 'A' && id[3] == 0);
        checksum = tmp_checksum;
        return check;
    }

    void make_checksum()
    {
        checksum = 0;
        checksum = shznet_hash((char*)this, sizeof(shznet_pkt_ack));
    }

}PACKED_ATTR;

struct shznet_pkt_ack_request
{
    byte id[4] = { 'S','H','A','R' };
    shznet_sessionid sessionid;
    shznet_ticketid ticketid;
    uint32_t checksum;
    shznet_ack_request_type type;
    byte mac[6];
    uint32_t ack_id = 0;

    bool is_valid()
    {
        auto tmp_checksum = checksum;
        checksum = 0;
        bool check = tmp_checksum == shznet_hash((char*)this, sizeof(shznet_pkt_ack_request)) && (id[0] == 'S' && id[1] == 'H' && id[2] == 'A' && id[3] == 'R');
        checksum = tmp_checksum;
        return check;
    }

    void make_checksum()
    {
        checksum = 0;
        checksum = shznet_hash((char*)this, sizeof(shznet_pkt_ack_request));
    }

}PACKED_ATTR;

struct shznet_pkt_diagnostic
{
    byte id[4] = { 'S','H','D', 0 };
    uint32_t diag_id = 0;
    uint32_t packets_received = 0;  
    uint32_t checksum = 0;
    uint64_t timestamp = 0;
    uint64_t timestamp_remote = 0;
    uint32_t timestamp_delay = 0;

    bool is_valid()
    {
        auto tmp_checksum = checksum;
        checksum = 0;
        bool check = tmp_checksum == shznet_hash((char*)this,sizeof(shznet_pkt_diagnostic)) &&  (id[0] == 'S' && id[1] == 'H' && id[2] == 'D' && id[3] == 0);
        checksum = tmp_checksum;
        return check;
    }

    void make_checksum()
    {
        checksum = 0;
        checksum = shznet_hash((char*)this, sizeof(shznet_pkt_diagnostic));
    }

}PACKED_ATTR;

enum shznet_pkt_diagnostic_request_type : uint32_t
{
    SHZNET_PKT_DIAG_REQ_DEFAULT,
    SHZNET_PKT_DIAG_REQ_RESET_BUFFERS, //other endpoint is still sending buffered data from a prev session, tell it to stop. 
};

struct shznet_pkt_diagnostic_request
{
    byte id[4] = { 'S','H','R',0 };
    uint32_t diag_id = 0;
    uint32_t checksum = 0;
    shznet_pkt_diagnostic_request_type type = SHZNET_PKT_DIAG_REQ_DEFAULT; //if set, this is an emergency check because the original ack cmd did not seem to come through
    uint64_t timestamp = 0;
    
    bool is_valid()
    {
        auto tmp_checksum = checksum;
        checksum = 0;
        bool check = tmp_checksum == shznet_hash((char*)this, sizeof(shznet_pkt_diagnostic_request)) && (id[0] == 'S' && id[1] == 'H' && id[2] == 'R' && id[3] == 0);
        checksum = tmp_checksum;
        return check;
    }

    void make_checksum()
    {
        checksum = 0;
        checksum = shznet_hash((char*)this, sizeof(shznet_pkt_diagnostic_request));
    }

}PACKED_ATTR;

struct shznet_pkt_auth_req
{
    shznet_sessionid sessionid;

    shznet_pkt_auth_req(shznet_sessionid id) : sessionid(id) {}
}PACKED_ATTR;

struct shznet_pkt_auth_reply
{
    char name[32] = { 0 };
    char type[64] = { 0 };
    int max_parallel_queues = SHZNET_PKT_MAX_QUEUES;
    int max_data_size = SHZNET_PKT_DATA_SIZE;
}PACKED_ATTR;

struct shznet_command_defs
{
    uint32_t hash;
    uint16_t type;
    uint16_t reserved;
}PACKED_ATTR;

struct shznet_buffer_defs
{
    uint32_t hash;
    uint32_t type;
    uint32_t size;
}PACKED_ATTR;

#pragma pack(pop) // Restore the previous packing

//std::unordered_map compatibility

// Custom hash function using FNV-1a
struct shznet_mac_hash {
    std::size_t operator()(const shznet_mac& m) const {
        // Use preprocessor to choose between 32-bit and 64-bit variants.
#if SIZE_MAX == UINT32_MAX
        // 32-bit FNV-1a constants.
        std::size_t hash = 2166136261U;
        for (int i = 0; i < 6; ++i) {
            hash ^= m.mac[i];
            hash *= 16777619U;
        }
        return hash;
#elif SIZE_MAX == UINT64_MAX
        // 64-bit FNV-1a constants.
        std::size_t hash = 14695981039346656037ULL;
        for (int i = 0; i < 6; ++i) {
            hash ^= m.mac[i];
            hash *= 1099511628211ULL;
        }
        return hash;
#else
#error "Unsupported size_t size"
#endif
    }
};

// Custom hash function for shznet_ip using FNV-1a.
struct shznet_ip_hash {
    std::size_t operator()(const shznet_ip& addr) const {
        // We will hash the 6 bytes (4 bytes for ip and 2 for port)
        const unsigned char* data = reinterpret_cast<const unsigned char*>(&addr);
        // Since the structure is packed, these 6 bytes are contiguous.
        const std::size_t numBytes = 6;
        std::size_t hash = 0;

#if SIZE_MAX == UINT32_MAX
        // 32-bit FNV-1a
        hash = 2166136261U;
        for (std::size_t i = 0; i < numBytes; ++i) {
            hash ^= data[i];
            hash *= 16777619U;
        }
#elif SIZE_MAX == UINT64_MAX
        // 64-bit FNV-1a
        hash = 14695981039346656037ULL;
        for (std::size_t i = 0; i < numBytes; ++i) {
            hash ^= data[i];
            hash *= 1099511628211ULL;
        }
#else
#   error "Unsupported size_t size"
#endif
        return hash;
    }
};

namespace std {
    template <>
    struct hash<shznet_mac> {
        std::size_t operator()(const shznet_mac& m) const {
            return shznet_mac_hash()(m);
        }
    };
    template <>
    struct hash<shznet_ip> {
        std::size_t operator()(const shznet_ip& addr) const {
            return shznet_ip_hash()(addr);
        }
    };
}

class shznet_timer
{
    uint64_t start_time = 0;
    uint64_t wait_time = 0;
public:

    shznet_timer(uint64_t ms = 0)
    {
        start_time = shznet_millis();
        wait_time = ms;
    }

    void set_interval(uint16_t ms)
    {
        wait_time = ms;
        reset();
    }

    void reset(uint64_t new_time = -1)
    {
        start_time = new_time == -1 ? shznet_millis() : new_time;
    }

    bool update()
    {
        if (wait_time == 0)
            return false;

        uint64_t current_time = shznet_millis();
        if (current_time >= start_time + wait_time)
        {
            start_time = current_time;
            return true;
        }

        return false;
    }

    bool timeout() //same as update, but resets the timer everytime it is called
    {
        if (wait_time == 0)
            return false;

        uint64_t current_time = shznet_millis();
        if (current_time >= start_time + wait_time)
        {
            start_time = current_time;
            return true;
        }
        start_time = current_time;
        return false;
    }

    bool check()
    {
        if (wait_time == 0)
            return false;
        uint64_t current_time = shznet_millis();
        if (current_time >= start_time + wait_time)
            return true;
        return false;
    }

    uint64_t delay()
    {
        return shznet_millis() - start_time;
    }

    uint64_t delay_reset()
    {
        auto n = shznet_millis();
        auto res = n - start_time;
        start_time = n;
        return res;
    }

    uint64_t get_wait_time()
    {
        return wait_time;
    }
};

class shznet_timer_exp //exponential timer
{
    uint64_t start_time = 0;
    uint64_t wait_time = 0;
    int32_t max_steps = 0;
    int32_t cur_steps = 0;
public:

    shznet_timer_exp(uint64_t _wait_time = 1, int32_t _max_steps = 10)
    {
        set_interval(_wait_time, _max_steps);
    }

    void set_interval(uint64_t _wait_time, int32_t _max_steps)
    {
        wait_time = _wait_time;
        max_steps = _max_steps;
        cur_steps = 0;
        start_time = shznet_millis() - _wait_time;
    }

    void reset()
    {
        start_time = shznet_millis();
    }

    bool update()
    {
        if (wait_time == 0)
            return false;

        uint64_t current_time = shznet_millis();
        if (current_time >= start_time + wait_time)
        {
            start_time = current_time;
            if (cur_steps < max_steps)
            {
                cur_steps++;
                wait_time *= 2;
            }
            return true;
        }

        return false;
    }

    bool check()
    {
        if (wait_time == 0)
            return false;
        uint64_t current_time = shznet_millis();
        if (current_time >= start_time + wait_time)
            return true;
        return false;
    }

};

#ifdef ARDUINO
#include <Arduino.h>
#include <mutex>
template <class T>
struct shznet_smart_alloc {
    typedef T value_type;
    shznet_smart_alloc() = default;
    template <class U> constexpr shznet_smart_alloc(const shznet_smart_alloc<U>&) noexcept {}
    [[nodiscard]] T* allocate(std::size_t n) {
        if (n > std::size_t(-1) / sizeof(T)) throw std::bad_alloc();
        if (auto p = static_cast<T*>(shznet_malloc(n * sizeof(T)))) return p;
        throw std::bad_alloc();
    }
    void deallocate(T* p, std::size_t) noexcept { std::free(p); }
};
template <class T, class U>
bool operator==(const shznet_smart_alloc<T>&, const shznet_smart_alloc<U>&) { return true; }
template <class T, class U>
bool operator!=(const shznet_smart_alloc<T>&, const shznet_smart_alloc<U>&) { return false; }

template <class T> using shznet_vector = std::vector<T, shznet_smart_alloc<T>>;
#else
template <class T> using shznet_vector = std::vector<T>;
#endif

#ifndef ARDUINO
#include <mutex>
#endif

template<class T>
class shznet_recycler
{
    shznet_vector<T*>	m_garbage;
    uint32_t		    m_count = 0;
    uint32_t            m_in_use = 0;
public:

    ~shznet_recycler()
    {
        for (auto it : m_garbage)
            delete it;
    }

    uint32_t total_count()
    {
        return m_count;
    }

    uint32_t in_use()
    {
        return m_in_use;
    }

    void recycle(T* object)
    {
        if (!object)
            return;
        //TODO implement upper limits for various platforms....
#ifdef ARDUINO
        if (object->total_size() > 1024 * 10 || m_garbage.size() > 16) //10kb
        {
            delete object;
            return;
        }
#endif
        m_in_use--;
        m_garbage.push_back(object);
    }

    T* get()
    {
        m_in_use++;
        if (m_garbage.size())
        {
            T* result = m_garbage.back();
            m_garbage.pop_back();
            return result;
        }
        m_count++;
        return shznet_alloc<T>();
    }
};

template<class T>
class shznet_recycler_locked
{
#if defined(__XTENSA__) || !defined(ARDUINO)
    std::mutex m_lock;
#endif
    shznet_vector<T*>	m_garbage;
    uint32_t		    m_count = 0;
public:

    ~shznet_recycler_locked()
    {
        for (auto it : m_garbage)
            delete it;
    }

    uint32_t total_count()
    {
        return m_count;
    }

    void recycle(T* object)
    {
        if (!object)
            return;
#if defined(__XTENSA__) || !defined(ARDUINO)
        std::unique_lock<std::mutex> _grd{ m_lock };
#endif
        //TODO implement upper limits for various platforms....
        m_garbage.push_back(object);
    }

    T* get()
    {
#if defined(__XTENSA__) || !defined(ARDUINO)
        std::unique_lock<std::mutex> _grd{ m_lock };
#endif
        if (m_garbage.size())
        {
            T* result = m_garbage.back();
            m_garbage.pop_back();
            return result;
        }
        m_count++;
        return shznet_alloc<T>();
    }
};

enum network_buffer_static_type
{
    NETWORK_BUFFER_STATIC_DATA = 0,
    NETWORK_BUFFER_STATIC_LEDS_1CH = 1,
    NETWORK_BUFFER_STATIC_LEDS_2CH = 2, //Just for convenience, 
    NETWORK_BUFFER_STATIC_LEDS_3CH = 3,
    NETWORK_BUFFER_STATIC_LEDS_4CH = 4
};

template<const int _BUFF_SIZE, const int _BUFF_MAX, class BufferMarkerHeader> class shznet_async_buffer
{
    struct BufferMarker
    {
        volatile bool is_valid;
#ifdef ARDUINO
        volatile int16_t size;
#else
        volatile int32_t size;
#endif
        BufferMarkerHeader header;
    };

    struct BufferChunk
    {
        BufferMarker start;
        volatile int32_t max_size = 0;
        char data[_BUFF_SIZE];
    };

    BufferChunk m_buffers[_BUFF_MAX];

    volatile bool m_circular_begin = true;
    volatile bool m_missed_chunks = false;
    volatile int32_t m_write_index = 0;
    volatile int32_t m_write_part_index = 0;
    volatile int32_t m_read_index = 0;
    volatile int32_t m_read_part_index = 0;

    bool next_write_index()
    {
        int32_t next_write = m_write_index + 1;
        if (next_write == _BUFF_MAX)
            next_write = 0;
        if (next_write == m_read_index && !m_circular_begin)
            return false;
        m_circular_begin = false;
        m_write_index = next_write;
        return true;
    }

public:

    shznet_async_buffer()
    {
        memset(m_buffers, 0, sizeof(BufferChunk) * _BUFF_MAX);
        m_write_index = 0;
        m_read_index = 0;
        m_write_part_index = 0;
        m_read_part_index = 0;
        m_circular_begin = true;
    }

    bool write(byte* data, int32_t size, BufferMarkerHeader* header_data = 0)
    {
        if (size <= 0 || size > _BUFF_SIZE)
        {
            NETPRNT("invalid size in write!");
            return false;
        }

        if (m_write_part_index != 0)
        {
            int32_t rem_size = _BUFF_SIZE - m_write_part_index - size - (int32_t)sizeof(BufferMarker);
            if (rem_size < 0)
            {
                //check if we can use the next free packet (or if we are full return)
                if (!next_write_index())
                {
                    m_missed_chunks = true;
                    return false;
                }
                m_write_part_index = 0;
            }
        }

        BufferChunk& buf = m_buffers[m_write_index];

        if (m_write_part_index == 0)
        {
            memcpy(buf.data, data, size);
            if (header_data)
                memcpy(&buf.start.header, header_data, sizeof(BufferMarkerHeader));
            buf.start.size = size;
            buf.start.is_valid = 1;
            m_write_part_index = size;
            buf.max_size = m_write_part_index;
        }
        else
        {
            BufferMarker* mark = (BufferMarker*)&buf.data[m_write_part_index];
            memcpy(&buf.data[m_write_part_index + sizeof(BufferMarker)], data, size);
            if (header_data)
                memcpy(&mark->header, header_data, sizeof(BufferMarkerHeader));
            mark->size = size;
            mark->is_valid = 1;
            m_write_part_index += sizeof(BufferMarker) + size;
            buf.max_size = m_write_part_index;
        }

        return true;
    }

    bool empty()
    {
        BufferChunk& buf = m_buffers[m_read_index];

        if (m_read_part_index >= buf.max_size)
        {
            return m_read_index == m_write_index;
        }

        return false;
    }

    //read data of next buffer but DO NOT mark it as free yet!
    char* read_peek(int32_t* max_len = 0, BufferMarkerHeader* header_data = 0)
    {
        if(max_len)
            *max_len = 0;
        //pre read check
        if (m_missed_chunks)
        {
            //NETPRNT("could not receive some packets (overflow)!");
            m_missed_chunks = false;
        }

        auto read_index = m_read_index;
        auto read_part_index = m_read_part_index;

        {
            BufferChunk& buf = m_buffers[read_index];

            if (read_part_index >= buf.max_size)
            {
                //to avoid race condition, check if there actually is data in the new buffer,
                //else the other thread might write data to THIS buffer right now
                if (read_index != m_write_index)
                {
                    int32_t next_read = read_index + 1;
                    if (next_read == _BUFF_MAX)
                        next_read = 0;
                    //no new data...
                    if (!m_buffers[next_read].max_size)
                        return 0;

                    //do one last sanity check wether data was written in this very moment...
                    if (read_part_index < buf.max_size)
                        return 0; //return and let the next call to this function handle this situation...

                    read_part_index = 0;
                    read_index = next_read;
                }
                else
                {
                    return 0;
                }
            }
        }

        //now do real read
        BufferChunk& buf = m_buffers[read_index];

        if (read_part_index >= buf.max_size)
            return 0;

        if (read_part_index == 0)
        {
            if (!buf.start.is_valid)
                return 0;

            if (header_data) memcpy(header_data, &buf.start.header, sizeof(BufferMarkerHeader));
            if (max_len)
            {
                *max_len = buf.start.size;
                if (*max_len > _BUFF_SIZE)
                {
                    NETPRNT_FMT("invalid size error 1 %i!", *max_len);
                    *max_len = _BUFF_SIZE;
                }
                if (*max_len < 0)
                {
                    NETPRNT_FMT("invalid size error 2 %i!", *max_len);
                    *max_len = 0;
                }
            }
            return buf.data;
        }

        BufferMarker* mark = (BufferMarker*)&buf.data[read_part_index];
        char* mark_data = &buf.data[read_part_index + sizeof(BufferMarker)];

        if (!mark->is_valid)
            return 0;

        if (header_data) memcpy(header_data, &mark->header, sizeof(BufferMarkerHeader));
        if (max_len)
        {
            *max_len = mark->size;
            if (*max_len > _BUFF_SIZE)
            {
                NETPRNT_FMT("invalid size error 3 %i!", *max_len);
                *max_len = _BUFF_SIZE;
            }
            if (*max_len < 0)
            {
                NETPRNT_FMT("invalid size error 4 %i!", *max_len);
                *max_len = 0;
            }
        }
        return mark_data;
    }

    //this can be used to flush (free) a buffer peek'd by read_peek, its better to not use it directly as its not thread safe in case
    //of a buffer overrun
    char* read(int32_t* max_len = 0, BufferMarkerHeader* header_data = 0)
    {
        //pre read check
        if (m_missed_chunks)
        {
            //NETPRNT("could not receive some packets (overflow)!");
            m_missed_chunks = false;
        }

        {
            BufferChunk& buf = m_buffers[m_read_index];

            if (m_read_part_index >= buf.max_size)
            {
                //to avoid race condition, check if there actually is data in the new buffer,
                //else the other thread might write data to THIS buffer right now
                if (m_read_index != m_write_index)
                {
                    int32_t next_read = m_read_index + 1;
                    if (next_read == _BUFF_MAX)
                        next_read = 0;
                    //no new data...
                    if (!m_buffers[next_read].max_size)
                        return 0;

                    //do one last sanity check wether data was written in this very moment...
                    if (m_read_part_index < buf.max_size)
                        return 0; //return and let the next call to this function handle this situation...

                    buf.max_size = 0;
                    m_read_part_index = 0;
                    m_read_index = next_read;
                }
                else
                {
                    return 0;
                }
            }
        }

        //now do real read
        BufferChunk& buf = m_buffers[m_read_index];

        if (m_read_part_index >= buf.max_size)
            return 0;

        if (m_read_part_index == 0)
        {
            if (!buf.start.is_valid)
                return 0;

            if (header_data) memcpy(header_data, &buf.start.header, sizeof(BufferMarkerHeader));          
            if (max_len) *max_len = buf.start.size;

            buf.start.is_valid = 0;
            m_read_part_index = buf.start.size;

            return buf.data;
        }

        BufferMarker* mark = (BufferMarker*)&buf.data[m_read_part_index];
        char* mark_data = &buf.data[m_read_part_index + sizeof(BufferMarker)];

        if (!mark->is_valid)
            return 0;

        if(header_data) memcpy(header_data, &mark->header, sizeof(BufferMarkerHeader));
        if (max_len) *max_len = mark->size;

        mark->is_valid = 0;
        m_read_part_index += sizeof(BufferMarker) + mark->size;

        return mark_data;
    }
};

class GenericUDPSocket
{
protected:
    shznet_adr m_localadr;

    virtual int max_parallel_queries() = 0;

    shznet_pkt_type verify_packet(byte* packet_data, uint32_t size)
    {

        if (size <= MAX_BUFFER_ARTNET && size >= 8)
        {
            if ((packet_data[0] == 'a' || packet_data[0] == 'A') &&
                (packet_data[1] == 'r' || packet_data[1] == 'R') &&
                (packet_data[2] == 't' || packet_data[2] == 'T') &&
                (packet_data[3] == '-') &&
                (packet_data[4] == 'n' || packet_data[4] == 'N') &&
                (packet_data[5] == 'e' || packet_data[5] == 'E') &&
                (packet_data[6] == 't' || packet_data[6] == 'T'))
            {
                uint16_t opcode = packet_data[8] | packet_data[9] << 8;
                return opcode == ART_POLL ? SHZNET_PKT_ARTNET_POLL : SHZNET_PKT_ARTNET;
            }
        }
        shznet_pkt* pkt = (shznet_pkt*)packet_data;
        if (size >= sizeof(shznet_pkt_header))
        {
            if (!m_localadr.mac.compare(pkt->source_mac()))
            {
                if (pkt->check_packet(size) && pkt->header.data_size <= SHZNET_PKT_DATA_SIZE && pkt->header.seq <= pkt->header.seq_max)
                    return pkt->header.type;
                NETPRNT("invalid pkt");
                return SHZNET_PKT_INVALID;
            }
            return SHZNET_PKT_INVALID;
        }

        if (size == sizeof(shznet_pkt_diagnostic))
        {
            shznet_pkt_diagnostic* pkt = (shznet_pkt_diagnostic*)packet_data;
            if (pkt->is_valid())
                return SHZNET_PKT_DIAGNOSTICS;
            else
            {
                NETPRNT("invalid diags");
            }
        }
        if (size == sizeof(shznet_pkt_diagnostic_request))
        {
            shznet_pkt_diagnostic_request* pkt = (shznet_pkt_diagnostic_request*)packet_data;
            if (pkt->is_valid())
                return SHZNET_PKT_DIAGNOSTICS_REQUEST;
            else
            {
                NETPRNT("invalid diags req");
            }
        }
        if (size == sizeof(shznet_pkt_ack))
        {
            shznet_pkt_ack* pkt = (shznet_pkt_ack*)packet_data;
            if (pkt->is_valid())
                return SHZNET_PKT_ACK;
            else
            {
                NETPRNT("invalid ack");
            }
        }
        if (size == sizeof(shznet_pkt_ack_request))
        {
            shznet_pkt_ack_request* pkt = (shznet_pkt_ack_request*)packet_data;
            if (pkt->is_valid())
                return SHZNET_PKT_ACK_REQ;
            else
            {
                NETPRNT("invalid ack req");
            }
        }

        NETPRNT("invalid pkt size!");
        NETPRNT_FMT("%i\n", (int)size);
        return SHZNET_PKT_INVALID;
    }

    struct shznet_async_header
    {
        shznet_ip ip;
        uint64_t timestamp_recv = 0;
        shznet_async_header(shznet_ip _ip = shznet_ip(), uint64_t _timestep_recv = 0) : ip(_ip), timestamp_recv(_timestep_recv) {}
    };

    shznet_timer m_sendbuffer_wait = shznet_timer(1);
    shznet_async_buffer<SHZNET_PKT_MAX, SHZNET_PKT_MAX_ASYNC, shznet_ip> m_sendbuffer;
    shznet_async_buffer<SHZNET_PKT_MAX, SHZNET_PKT_MAX_ASYNC, shznet_ip> m_sendbuffer_prio;
    shznet_async_buffer<sizeof(shznet_pkt_diagnostic), SHZNET_PKT_MAX_ASYNC_DIAG, shznet_async_header> m_sendbuffer_diagnostic;

    bool sendbuffer_queue_free()
    {
        return m_sendbuffer.empty() && m_sendbuffer_prio.empty() && m_sendbuffer_diagnostic.empty();
    }

    virtual void handle_diagnostics(shznet_ip& adr, shznet_pkt_diagnostic* diags) {}

    struct diagnostic_endpoint
    {
        shznet_timer timeout = shznet_timer(1000 * 60);
        uint32_t last_id = 0;
        uint32_t packets_received = 0;
    };
    
    //THIS MIGHT BE CALLED EXCLUSIVELY FROM THE RECV THREAD
    //the following fields & functions could be called from the recv thread on some platforms.
    shznet_timer m_diags_update = shznet_timer(1000 * 30);
    std::unordered_map<shznet_ip, std::unique_ptr<diagnostic_endpoint>> m_diag_endpoints;
    shznet_pkt_diagnostic m_diag_pkt;

    void handle_diagnostics_request(shznet_ip& adr, shznet_pkt_diagnostic_request* req)
    {
        if (req->type == SHZNET_PKT_DIAG_REQ_RESET_BUFFERS)
        {
            NETPRNT("todo: clear sendbuffers for IP here");
            return;
        }

        uint64_t timestamp_start = shznet_millis();

        diagnostic_endpoint* endpoint = 0;

        auto endpoint_iter = m_diag_endpoints.find(adr);
        if (endpoint_iter == m_diag_endpoints.end())
        {
            m_diag_endpoints[adr] = std::make_unique<diagnostic_endpoint>();
            endpoint = m_diag_endpoints[adr].get();
        }
        else
        {
            endpoint = endpoint_iter->second.get();
        }

        m_diag_pkt.diag_id = endpoint->last_id;
        m_diag_pkt.packets_received = endpoint->packets_received;
        m_diag_pkt.timestamp = req->timestamp;

        send_buffered_diagnostic(adr, &m_diag_pkt, timestamp_start);

        endpoint->last_id = req->diag_id;
        endpoint->packets_received = 0;

        endpoint->timeout.reset();

        if (m_diags_update.update())
        {
            for (auto it = m_diag_endpoints.begin(); it != m_diag_endpoints.end();)
            {
                if (it->second->timeout.update())
                    it = m_diag_endpoints.erase(it);
                else
                    it++;
            }
        }
    }

    void update_diagnostics(shznet_ip& adr)
    {
        if (adr.is_broadcast())
            return;
        auto it = m_diag_endpoints.find(adr);
        if (it == m_diag_endpoints.end())
            return;
        it->second->packets_received++;
    }

    //returns true if the packet was already consumed by this function and does not need further processing (EDIT: this is really fucing confusing maybe reverse logic?)
    virtual bool preprocess_packet(shznet_ip& adr, byte* data, int32_t size)
    {
        if (size > SHZNET_PKT_MAX)
            return true;

        if (adr.compare_ip(m_localadr.ip) && adr.port == m_localadr.ip.port)
            return true;

        auto pkt_type = this->verify_packet(data, size);
        if (pkt_type == SHZNET_PKT_INVALID)
            return true;

        if (pkt_type == SHZNET_PKT_DIAGNOSTICS_REQUEST)
        {
            //NETPRNT("diag REQUEST!");
            handle_diagnostics_request(adr, (shznet_pkt_diagnostic_request*)data);
            return true;
        }
        if (pkt_type == SHZNET_PKT_DIAGNOSTICS)
        {
            //NETPRNT("diag RESP!");
            handle_diagnostics(adr, (shznet_pkt_diagnostic*)data);
            return true;
        }

        if (!adr.is_broadcast() && pkt_type != SHZNET_PKT_ARTNET && pkt_type != SHZNET_PKT_ARTNET_POLL)
        {
            update_diagnostics(adr);
        }

        if (preprocess_hook) return preprocess_hook(adr, pkt_type, pkt_type > SHZNET_PKT_ARTNET_POLL ? (shznet_pkt*)data : 0, size);

        return false;
    }

public:

    std::function<bool(shznet_ip& adr, shznet_pkt_type type, shznet_pkt* pkt, uint32_t size)> preprocess_hook = 0;

    GenericUDPSocket()
    {
        
    }

    virtual ~GenericUDPSocket()
    {

    }

    virtual bool init() = 0;
    virtual bool bind(int32_t port) = 0;

	virtual char* read_packet(shznet_ip& info, int32_t* max_len, uint64_t* recv_time) = 0;
    virtual void flush_packet() = 0; //CALL THIS AFTER read_packet to release the last read packet !!!
	virtual bool send_packet(shznet_ip& info, unsigned char* buffer, int32_t len) = 0;
    virtual bool send_packet_prio(shznet_ip& info, unsigned char* buffer, int32_t len) {
        return send_packet(info, buffer, len);
    }

    //change to send_packet_diagnostics and send_packet_diagnostics_request set timestamps!!! also dont forget ESP32
    virtual bool send_packet_diagnostic(shznet_ip& info, shznet_pkt_diagnostic* pkt, uint64_t recv_timestamp) {
        pkt->timestamp_remote = shznet_millis();
        pkt->timestamp_delay = pkt->timestamp_remote - recv_timestamp;
        pkt->make_checksum();
        return send_packet(info, (byte*)pkt, sizeof(shznet_pkt_diagnostic));
    }
    virtual bool send_packet_artnet(shznet_ip& info, unsigned char* buffer, int32_t len)
    {
        return send_packet(info, buffer, len);
    }

    virtual void update()
    {
        int32_t max_len = 0;
        char* data = 0;

        shznet_async_header adr_async;

        while ((data = m_sendbuffer_diagnostic.read_peek(&max_len, &adr_async)) != 0)
        {
            if (!send_packet_diagnostic(adr_async.ip, (shznet_pkt_diagnostic*)data, adr_async.timestamp_recv))
            {
                m_sendbuffer_wait.reset();
                return;
            }
            m_sendbuffer_diagnostic.read();
        }

        shznet_ip adr;

        while ((data = m_sendbuffer_prio.read_peek(&max_len,&adr)) != 0)
        {
            if (!send_packet_prio(adr, (byte*)data, max_len))
            {
                m_sendbuffer_wait.reset();
                return;
            }
            m_sendbuffer_prio.read();
        }
        while ((data = m_sendbuffer.read_peek(&max_len, &adr)) != 0)
        {
            if (!send_packet_prio(adr, (byte*)data, max_len))
            {
                m_sendbuffer_wait.reset();
                return;
            }
            m_sendbuffer.read();
        }
    }

    virtual bool send_buffered(shznet_ip& info, unsigned char* buffer, int32_t len)
    {
        if (sendbuffer_queue_free() && send_packet(info, buffer, len))
            return true;

        return m_sendbuffer.write(buffer, len, &info);
    }
    virtual bool send_buffered_prio(shznet_ip& info, unsigned char* buffer, int32_t len)
    {
        if (sendbuffer_queue_free() && send_packet_prio(info, buffer, len))
            return true;

        return m_sendbuffer_prio.write(buffer, len, &info);
    }
    virtual bool send_buffered_diagnostic(shznet_ip& info, shznet_pkt_diagnostic* pkt, uint64_t recv_timestamp)
    {
        if (send_packet_diagnostic(info, pkt, recv_timestamp))
            return true;
        auto async_hdr = shznet_async_header(info, recv_timestamp);
        return m_sendbuffer_diagnostic.write((byte*)pkt, sizeof(shznet_pkt_diagnostic), &async_hdr);
    }

    //IMPORTANT DONT FORGET TO FILL MAC ADDRESS !!!
	virtual shznet_adr& local_adr() = 0;

    virtual void flush_send_buffer(bool force = false) {};

    virtual void invalidate_threads() {};
};

template<class T>
class shznet_small_allocator
{
    T* mPtr = 0;
public:
    inline T& get()
    {
        if (mPtr == 0)
        {
            mPtr = shznet_alloc<T>();
        }
        return *mPtr;
    }
    inline T* operator->()
    {
        return &get();
    }
    inline bool allocated()
    {
        return mPtr != 0;
    }
    inline void release()
    {
        if (mPtr)
            delete mPtr;
        mPtr = 0;
    }
    ~shznet_small_allocator()
    {
        release();
    }
};

//its recommend to allocate this class static, if not used in multithreading
class shznet_kv_writer
{
    shznet_vector<byte> buffer;

    //byte key_size
    //byte FMT
    //bytes key
    //uint32 value_size
    //bytes value

    void push_data(const byte* data, size_t size)
    {
        for (int i = 0; i < size; i++) buffer.push_back(data[i]);
    }

    template <class T> void push_data(T data) { push_data((const byte*)&data, sizeof(T)); }

public:

    void add_data(const char* key, const byte* data, size_t size, shznet_pkt_dataformat fmt = SHZNET_PKT_FMT_DATA) //make sure the key size does not exceed 255 !!!
    {
        auto key_len = strlen(key) + 1;
        if (key_len >= 255)
        {
            NETPRNT("key too long!");
            return;
        }

        buffer.push_back(key_len); //push back 1 byte key len
        buffer.push_back(fmt);

        push_data((byte*)key, key_len);
        push_data<uint32_t>((uint32_t)size);
        push_data(data, size);
    }

    void add_string(const char* key, const char* str)
    {
        add_data(key, (byte*)str, strlen(str) + 1, SHZNET_PKT_FMT_STRING);
    }
    void add_int32(const char* key, int32_t value)
    {
        add_data(key, (byte*)&value, sizeof(value), SHZNET_PKT_FMT_INT32);
    }
    void add_float32(const char* key, float value)
    {
        add_data(key, (byte*)&value, sizeof(value), SHZNET_PKT_FMT_FLOAT32);
    }
    void add_int64(const char* key, int64_t value)
    {
        add_data(key, (byte*)&value, sizeof(value), SHZNET_PKT_FMT_INT64);
    }
    void add_float64(const char* key, double value)
    {
        add_data(key, (byte*)&value, sizeof(value), SHZNET_PKT_FMT_FLOAT64);
    }

    void add_kv(const char* key, shznet_kv_writer& other)
    {
        add_data(key, other.get_buffer().data(), other.get_buffer().size(), SHZNET_PKT_FMT_KEY_VALUE);
    }

    void clear()
    {
        buffer.clear();
    }

    shznet_vector<byte>& get_buffer() { return buffer; }
};

class shznet_kv_reader
{
    byte* data;
    size_t size;
    size_t index = 0;
    const char* key;

    shznet_pkt_dataformat fmt;
    byte* value = 0;
    size_t value_size = 0;

public:

    shznet_kv_reader(byte* _data = 0, size_t _size = 0)
    {
        key = "";
        init(_data, _size);
    }

    void init(byte* _data, size_t _size)
    {
        data = _data;
        size = _size;
        index = 0;
        if (_data && _size)
            key = (char*)&data[index];
        else
            key = "";
    }

    bool read()
    {
        if (index >= size) return 0;
        uint32_t key_len = data[index];
        index++; if (index >= size) return 0;
        fmt = (shznet_pkt_dataformat)data[index];
        index++; if (index >= size) return 0;
        if (!key_len || key_len >= 255) return 0;
        data[index + (key_len - 1)] = 0;
        key = (char*)&data[index];
        index += key_len; if (index >= size) return 0;
        value_size = *(uint32_t*)&data[index];
        index += sizeof(uint32_t); if (index >= size) return 0;
        if (index + value_size > size) return 0;
        value = &data[index];
        index += value_size;
        return true;
    }

    bool read_key(const char* key)
    {
        if (strcmp(get_key(), key) == 0)
            return true;

        while (read())
        {
            if (strcmp(get_key(), key) == 0)
                return true;
        }

        //reset index and try again...
        index = 0;
        while (read())
        {
            if (strcmp(get_key(), key) == 0)
                return true;
        }
        return false;
    }

    //call these function in the order they are defined here!
    const char* get_key()
    {
        return key;
    }
    shznet_pkt_dataformat get_fmt()
    {
        return fmt;
    }
    byte* get_value()
    {
        return value;
    }
    size_t get_value_size()
    {
        return value_size;
    }
    template<class T> T get_value_type()
    {
        return *(T*)get_value();
    }

    const char* read_string(const char* key)
    {
        if (!read_key(key)) return "";
        return (const char*)get_value();
    }

    const byte* read_data(const char* key)
    {
        if (!read_key(key)) return 0;
        return (const byte*)get_value();
    }

    int16_t read_int16(const char* key)
    {
        if (!read_key(key)) return 0;
        switch (get_fmt())
        {
        case SHZNET_PKT_FMT_INT16:
            return get_value_type<int16_t>();
            break;
        case SHZNET_PKT_FMT_INT32:
            return get_value_type<int32_t>();
            break;
        case SHZNET_PKT_FMT_INT64:
            return get_value_type<int64_t>();
            break;
        case SHZNET_PKT_FMT_FLOAT32:
            return get_value_type<float>();
            break;
        case SHZNET_PKT_FMT_FLOAT64:
            return get_value_type<double>();
            break;
        default:
            break;
        }
        return 0;
    }
    int32_t read_int32(const char* key)
    {
        if (!read_key(key)) return 0;
        switch (get_fmt())
        {
        case SHZNET_PKT_FMT_INT16:
            return get_value_type<int16_t>();
            break;
        case SHZNET_PKT_FMT_INT32:
            return get_value_type<int32_t>();
            break;
        case SHZNET_PKT_FMT_INT64:
            return get_value_type<int64_t>();
            break;
        case SHZNET_PKT_FMT_FLOAT32:
            return get_value_type<float>();
            break;
        case SHZNET_PKT_FMT_FLOAT64:
            return get_value_type<double>();
            break;
        default:
            break;
        }
        return 0;
    }
    int64_t read_int64(const char* key)
    {
        if (!read_key(key)) return 0;
        switch (get_fmt())
        {
        case SHZNET_PKT_FMT_INT16:
            return get_value_type<int16_t>();
            break;
        case SHZNET_PKT_FMT_INT32:
            return get_value_type<int32_t>();
            break;
        case SHZNET_PKT_FMT_INT64:
            return get_value_type<int64_t>();
            break;
        case SHZNET_PKT_FMT_FLOAT32:
            return get_value_type<float>();
            break;
        case SHZNET_PKT_FMT_FLOAT64:
            return get_value_type<double>();
            break;
        default:
            break;
        }
        return 0;
    }
    double read_float(const char* key)
    {
        if (!read_key(key)) return 0;
        switch (get_fmt())
        {
        case SHZNET_PKT_FMT_INT16:
            return get_value_type<int16_t>();
            break;
        case SHZNET_PKT_FMT_INT32:
            return get_value_type<int32_t>();
            break;
        case SHZNET_PKT_FMT_INT64:
            return get_value_type<int64_t>();
            break;
        case SHZNET_PKT_FMT_FLOAT32:
            return get_value_type<float>();
            break;
        case SHZNET_PKT_FMT_FLOAT64:
            return get_value_type<double>();
            break;
        default:
            break;
        }
        return 0;
    }

    shznet_kv_reader read_kv(const char* key)
    {
        auto kv_data = read_data(key);
        if (get_fmt() != SHZNET_PKT_FMT_KEY_VALUE)
            return shznet_kv_reader();
        return shznet_kv_reader((byte*)kv_data, get_value_size());
    }
};

#ifdef __XTENSA__
#ifdef ESP_ETH
    //#include <Ethernet.h>
    #include <ETH.h>
#endif

    #include "WiFi.h"
    #include "AsyncUDP.h"

    #include <chrono>
    #include <mutex>
    #include "esp_mac.h"

    #define MAX_ESP_BUFFERS 12

    class GenericESPSocket : public GenericUDPSocket
    {

#pragma pack(push, 1)
        struct packet_buffer_header
        {
            volatile byte ip[4];
            volatile uint64_t recv_time;
            volatile int16_t port;
            volatile bool is_broadcast;
        }PACKED_ATTR;
#pragma pack(pop)

        shznet_async_buffer<SHZNET_PKT_MAX, MAX_ESP_BUFFERS, packet_buffer_header> m_asyncbuffer;

        AsyncUDP m_udp;

        bool missed_packets = false;

    public:

        int max_parallel_queries() override
        {
            return 4;
        }

        bool init() override
        {
            return true;
        }

        bool bind(int32_t port) override
        {
            m_localadr.ip.port = port;
            if (m_udp.listen(port))
            {
                m_udp.onPacket([this](AsyncUDPPacket &packet) {

                    auto rm_ip = packet.remoteIP();
                    shznet_ip rm_ip_shz(packet.remotePort());

                    memcpy(&rm_ip_shz.ip[0], &rm_ip[0], 4);

                    if (preprocess_packet(rm_ip_shz, packet.data(), packet.length()))
                        return;

                    packet_buffer_header header;
                    header.ip[0] = rm_ip[0];
                    header.ip[1] = rm_ip[1];
                    header.ip[2] = rm_ip[2];
                    header.ip[3] = rm_ip[3];
                    header.port = packet.remotePort();
                    header.is_broadcast = packet.isBroadcast();
                    header.recv_time = shznet_millis();
                    if (!m_asyncbuffer.write(packet.data(), packet.length(), &header))
                    {
                        Serial.println("packet overflow!");
                        missed_packets = true;
                    }

                    });
                return true;
            }

            return false;
        }

        char* read_packet(shznet_ip& info, int32_t* max_len, uint64_t* recv_time) override
        {
            //pre read check
            if (missed_packets)
            {
                missed_packets = false;
            }

            packet_buffer_header header;

            auto data = m_asyncbuffer.read_peek(max_len, &header);

            if (recv_time) *recv_time = header.recv_time;

            if (!data)
                return 0;

            memcpy(info.ip, (void*)&header.ip[0], 4);
            info.port = header.port;

            return data;
        }

        void flush_packet() override
        {
            m_asyncbuffer.read();
        }

        shznet_timer max_looper_timeout = shznet_timer(5000);
        shznet_timer max_pps = shznet_timer(10);
        uint32_t pps_current = 0;
        bool send_packet(shznet_ip& info, unsigned char* buffer, int32_t len) override
        {
            if (!len || !buffer)
                return true;
            IPAddress tmp(info.ip[0], info.ip[1], info.ip[2], info.ip[3]);
           
            auto res = m_udp.writeTo(buffer, len, tmp, info.port);
            
            //rausfinden was genau der sendet das es so langsam wird ??? woran hängt es?
            /*
            if (!max_pps.timeout())
            {
                pps_current++;
                if (pps_current > 10)
                {
                    pps_current = 0;
                    NETPRNT("send limit!");
                    //NETPRNT_FMT("wifi tx buff: %i\n", WiFi.getTxBufferFree());
                    vTaskDelay(100);
                }
            }
            else
                pps_current = 0;
            */
            if (res != len) 
            { 
                Serial.printf("sendto failed (%i)! %s\n", len, info.str().c_str()); 
                vTaskDelay(1);
            }

            return res == len;
        }

        void update() override
        {
            GenericUDPSocket::update();
        }

        bool _local_adr_get = true;
        shznet_adr& local_adr() override
        {
#ifdef ESP_ETH
            IPAddress adr;
            if (!ETH.linkUp())
                adr = WiFi.localIP();
            else
                adr = ETH.localIP();
#else
            IPAddress adr = WiFi.localIP();
#endif
            for (int32_t i = 0; i < 4; i++)
                m_localadr.ip.ip[i] = adr[i];
            if (_local_adr_get)
            {
                esp_read_mac(m_localadr.mac.mac, ESP_MAC_EFUSE_FACTORY);
            }
            _local_adr_get = false;
            return m_localadr;
        }
    };

    typedef GenericESPSocket shznet_udp;

#elif ARDUINO

    typedef GenericEthernetUDPSocket shznet_udp;
    template <class T> using shznet_vector = std::vector<T>;

#else

#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>

//TODO m_sendbuffer etc lockfree structure machen (pkt_chunker ??? oder wie bei ESP read) fur
//handle_recv_reply und da auch direkt acks zurücksenden bei ESP in udpcallback und hier mit nem extra blocked recvthread !!!
//avg speed diags mb/s anhand der bytes in pkt (counten)
//extra send endpoints (shared ptr lockfree?) um datenrate zu devices zu beschränken, und global datenrate???
// //auch ack über send_buffered buffern!!
// //max data rate dynamisch ermitteln auch für alle pakete? aber auch per device !!!
//shizoscript auto type compile...wenn keyword "var" dann keine auto class auch wenn zb var img = bmp()??

//bandbreite nur an die einzenlen geräte anpassen nicht global (geht autom. dadurch)
//REQUEST_ACK flag in shzpkt was internal hier geparsed wird??? auch ESP kompatibel machen!!!

class shznet_timer_high_resolution
{
    uint64_t start_time = 0;
    uint64_t wait_time = 0;

    uint64_t now() //this was chatGPT generated
    {
        auto now = std::chrono::high_resolution_clock::now();

        // Convert time point to duration since epoch, then to microseconds
        auto microseconds_since_epoch = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();

        return microseconds_since_epoch;

    }

public:

    shznet_timer_high_resolution(uint64_t microsecond_delay = 0)
    {
        set_delay(microsecond_delay);
        reset();
    }

    void set_delay(uint64_t delay)
    {
        wait_time = delay;
    }

    void reset()
    {
        start_time = now();
    }
    void reset_ready()
    {
        start_time = now() - wait_time;
    }

    bool ready()
    {
        if ((now() - start_time) >= wait_time)
        {
            start_time += wait_time;
            return true;
        }
        return false;
    }
    uint64_t ready_in()
    {
        auto n = now();
        if ((n - start_time) >= wait_time)
            return 0;
        return wait_time - (n - start_time);
    }

    uint64_t delay()
    {
        return now() - start_time;
    }
    uint64_t delay_reset()
    {
        auto n = now();
        auto res = n - start_time;
        start_time = n;
        return res;
    }
};

class shznet_pps_diagnostics
{
    shznet_timer_high_resolution m_packet_timer;
    uint32_t m_packet_counter = 0;
    uint32_t m_packet_size_counter = 0;

    uint32_t m_packets_per_second = 0;
    uint32_t m_bytes_per_second = 0;
public:

    shznet_pps_diagnostics() {};

    void on_packet(uint32_t size)
    {
        m_packet_counter++;
        m_bytes_per_second += size;
        double delay_ms = m_packet_timer.delay() / 1000.0;
        delay_ms /= 1000.0;
        if (delay_ms > 1.0) //1 sec
        {
            m_packet_timer.reset();

            auto pps = (double)m_packet_counter / delay_ms;
            auto bps = (double)m_packet_size_counter / delay_ms;

            if (pps >= m_packets_per_second)
                m_packets_per_second = pps;
            else
                m_packets_per_second = m_packets_per_second * 0.9 + pps * 0.1;

            if (bps >= m_bytes_per_second)
                m_bytes_per_second = bps;
            else
                m_bytes_per_second = m_packets_per_second * 0.9 + bps * 0.1;

            m_packet_counter = 0;
            m_packet_size_counter = 0;
        }
    }

    uint32_t pps()
    {
        return m_packets_per_second;
    }
    uint32_t bps()
    {
        return m_bytes_per_second;
    }

};


class GenericOSUDPSocket : public GenericUDPSocket
{
    UniversalUDP m_udp;
    bool macbufferset = 0;

    struct packet_buffer_header
    {
        shznet_ip ip;
        uint64_t recv_time;
    }PACKED_ATTR;

    shznet_async_buffer<SHZNET_PKT_MAX, 1024*10, packet_buffer_header> m_asyncbuffer; //asyncrecv
    shznet_async_buffer<SHZNET_PKT_MAX, 1024*10, shznet_ip> m_asyncsend;
    shznet_async_buffer<SHZNET_PKT_MAX, 256, shznet_ip> m_asyncsend_artnet;
    shznet_async_buffer<SHZNET_PKT_MAX, 256, shznet_ip> m_asyncsend_prio;
    shznet_async_buffer<sizeof(shznet_pkt_diagnostic), 256, shznet_async_header> m_asyncsend_diagnostic;

    shznet_async_buffer<sizeof(shznet_pkt_diagnostic), 256, shznet_async_header> m_async_diag_response;


    volatile bool       m_threads_active = 1;
    volatile bool       m_sendloop_active = 0;
    volatile bool       m_recvloop_active = 0;
    std::thread         m_sendloop;
    std::thread         m_recvloop;
    bool                m_sendflush = false;

    std::mutex	m_sendmutex;
    std::condition_variable m_sendsignal;

    struct send_flush_buffer
    {
        send_flush_buffer(std::vector<byte>* _buffer)
        {
            buffer = _buffer;
            timestamp = shznet_millis();
        }

        std::vector <byte>* buffer;
        uint64_t timestamp;
    };

    enum send_pkt_priority
    {
        SEND_PKT_NORMAL,
        SEND_PKT_PRIO,
        SEND_PKT_DIAGNOSTIC //highest prio
    };

    class send_endpoint
    {
        shznet_timer    m_timeout = shznet_timer(1000 * 30);
        shznet_ip       m_adr;
        GenericOSUDPSocket* m_socket;

        shznet_sessionid m_sessionid = SHZNET_PKT_INVALID;
        shznet_pps_diagnostics m_pps;

        shznet_timer_high_resolution m_pkt_delay_timer = shznet_timer_high_resolution(0);
        double          m_pkt_delay = 0.0; //delay packets in microseconds
        bool            m_pkt_reset = false;
   
        shznet_timer    m_needs_ack_timeout = shznet_timer(1000); //1000ms ping max
        bool            m_needs_ack = false;
        bool            m_force_ack = false;
        shznet_timer_exp m_force_ack_timer = shznet_timer_exp();

        shznet_pkt_diagnostic_request m_diag_pkt;
        uint32_t                        m_diag_pkt_id = 0;
        uint32_t                        m_diag_counter = 0;
        const uint32_t                  m_diag_per_pkt = 64; //send diag packet every 32 packets MAKE SURE THIS IS DIVIDABLE BY 2 !!!!

        std::queue<send_flush_buffer> m_send_flush;
        std::vector<byte> m_send_flush_diag;
        bool              m_send_flush_diag_response = false;
        uint64_t          m_send_flush_diag_timestamp = 0;

        bool m_disable_bandwidth_checks = false;

        uint32_t m_packet_batch = 0;
        bool can_send_packet_now()
        {
            return m_disable_bandwidth_checks || m_pkt_delay_timer.ready();

            /*if (!m_pkt_delay_timer.ready())
            {
                if (m_packet_batch < 4)
                {
                    m_packet_batch++;
                    return true;
                }
            }
            m_packet_batch = 0;
            return true;
            */
        }

        bool send_diag_req()
        {
            if (!can_send_packet_now())
                return false;

            m_diag_pkt_id++;
            if (m_diag_pkt_id == 0)
                m_diag_pkt_id++;

            m_diag_pkt.diag_id = m_diag_pkt_id;
            m_diag_pkt.timestamp = shznet_millis();
            m_diag_pkt.make_checksum();
            if (!send_direct((byte*)&m_diag_pkt, sizeof(m_diag_pkt)))
            {
                NETPRNT("cannot send ack request!");
                return false;
            }
            m_needs_ack = true;
            m_needs_ack_timeout.reset();
            m_pps.on_packet(sizeof(m_diag_pkt));
            return true;
        }

        bool send_with_ack(byte* buffer, uint32_t size)
        {
            if (!can_send_packet_now())
                return false;

            if (m_diag_counter == 0 || m_force_ack)
            {
                if (!send_diag_req() || m_force_ack)
                    return false;
            }

            m_diag_counter++;
            if (m_diag_counter == m_diag_per_pkt)
                m_diag_counter = 0;

            if (!send_direct(buffer, size))
                return false;

            m_pps.on_packet(size);
            set_pkt_delay(m_pkt_delay - 1.0);

            return true;
        }

        bool send_diagnostic_pkt(shznet_pkt_diagnostic* pkt, uint64_t recv_timestamp)
        {
            if (!can_send_packet_now())
                return false;

            pkt->timestamp_remote = shznet_millis();
            pkt->timestamp_delay = pkt->timestamp_remote - recv_timestamp;
            pkt->make_checksum();

            if (!send_direct((byte*)pkt, sizeof(shznet_pkt_diagnostic)))
                return false;

            m_pps.on_packet(sizeof(shznet_pkt_diagnostic));
            set_pkt_delay(m_pkt_delay - 0.01);

            return true;
        }

        bool send_with_prio(byte* buffer, uint32_t size, send_pkt_priority prio, uint64_t recv_timestamp = 0)
        {
            if (prio == SEND_PKT_DIAGNOSTIC)
                return send_diagnostic_pkt((shznet_pkt_diagnostic*)buffer, recv_timestamp);
            return send_with_ack(buffer, size);
        }

        void set_pkt_delay(double delay)
        {
            if (delay < 0.0)
                delay = 0.0;
            if (delay > 1000.0 * 100.0)
                delay = 1000.0 * 100.0;
            m_pkt_delay_timer.set_delay(delay * 0.01);
            m_pkt_delay = delay;
        }

        uint32_t m_last_diag_id = 0;

        double m_ping = 0;
        uint64_t m_remote_time = 0;
        uint64_t m_remote_time_local = 0;

    public:

        uint64_t get_remote_time_now()
        {
            auto delta = shznet_millis() - m_remote_time_local;
            return m_remote_time + delta;
        }

        send_endpoint(GenericOSUDPSocket* socket, shznet_ip& ip)
        {
            m_socket = socket;
            m_adr = ip;
        }

        bool try_send(byte* buffer, uint32_t size, send_pkt_priority prio, uint64_t recv_timestamp = 0)
        {
            m_timeout.reset();
            //update send diagnostics if we can send here too !!!

            if (prio == SEND_PKT_DIAGNOSTIC || (m_send_flush.empty() && !m_force_ack))
            {
                if (send_with_prio(buffer, size, prio, recv_timestamp))
                    return true;
            }
            //cannot send pkt yet, put it into the queue buffer...
            return get_free_buffer(buffer, size, prio, recv_timestamp);
        }

        shznet_timer debug_timer = shznet_timer(5000);
        bool update_send()
        {
            if (m_force_ack)
            {
                if (m_force_ack_timer.check())
                {
                    NETPRNT("force ack!");
                    if (send_diag_req())
                    {
                        m_force_ack_timer.update();
                    }
                    set_pkt_delay(m_pkt_delay + 10.0);
                }

                return !m_send_flush.empty();
            }

               
            if (m_pkt_reset || m_pkt_delay_timer.delay() > 1000 * 100) //100ms delay....
            {
                m_pkt_reset = false;
                if (m_pkt_delay_timer.ready())
                    m_pkt_delay_timer.reset_ready();
            }
                
            //NETPRNT_FMT("test: %i\n", missed_pkt_resets);
                
            if (!m_send_flush.empty() && debug_timer.update())
            {
                NETPRNT_FMT("%i pps, %i bps, %f tt, %i in.\n", m_pps.pps(), m_pps.bps(), (float)m_pkt_delay, (int)m_send_flush.size());
            }

            auto current_time = shznet_millis();

            if (m_send_flush_diag_response)
            {                  
                if (send_diagnostic_pkt((shznet_pkt_diagnostic*)m_send_flush_diag.data(), m_send_flush_diag_timestamp))
                {
                    m_send_flush_diag_response = false;
                }
                else
                    return true;
            }

            if (m_needs_ack && !m_force_ack && m_needs_ack_timeout.update())
            {
                NETPRNT("forcing ack...");
                m_force_ack = true;
                m_force_ack_timer.set_interval(1, 10);
                send_diag_req();
                return !m_send_flush.empty();
            }

            while (!m_send_flush.empty())
            {
                if (!send_with_ack(m_send_flush.front().buffer->data(), m_send_flush.front().buffer->size()))
                {
                    break;
                }
                free_buffer(m_send_flush.front().buffer);
                m_send_flush.pop();
            }

            if (m_send_flush.empty())
            {
                m_pkt_reset = true;
            }

            return !m_send_flush.empty();
        }

        uint64_t ready_in() { return m_pkt_delay_timer.ready_in(); } //returns how much microseconds to wait till next pkt

        void handle_diagnostics_endpoint(shznet_pkt_diagnostic* diags, uint64_t timestamp_recv)
        {

            m_needs_ack = false;
            m_force_ack = false;

            if (diags->diag_id == 0)
                return;

            auto local_delay = timestamp_recv >= diags->timestamp ? timestamp_recv - diags->timestamp : 0;
            int64_t ping = local_delay >= diags->timestamp_delay ? (local_delay - diags->timestamp_delay) / 2 : 0;
                
            if (ping < 0) ping = 0;

            m_ping = m_ping * 0.9 + ping * 0.1;

            if (std::abs((int64_t)m_ping - ping) < 5)
            {
                m_remote_time_local = shznet_millis();
                m_remote_time = diags->timestamp_remote + (m_remote_time_local - timestamp_recv) + ping;
            }
            //also calculate device_time based on a timestamp from the device - ping delay or smth
            //with function get_device_time(timestamp)
            //printf("diag ping: %i : %i\n", (int)m_ping, (int)ping);

            if ((diags->packets_received % m_diag_per_pkt) != 0)
            {
                //NETPRNT_FMT("missed packets: %i : %i from (%i : %i) %f\n", diags->packets_received, m_diag_per_pkt, diags->diag_id, m_diag_pkt_id, m_pkt_delay);
                set_pkt_delay(m_pkt_delay + 10.0);
            }
            else if (diags->diag_id == m_last_diag_id + 1)
            {

                m_last_diag_id = diags->diag_id;
                set_pkt_delay(m_pkt_delay - 1.0);
            }
            else
            {
                //NETPRNT_FMT("invalid id: %i : %i\n", diags->diag_id, m_last_diag_id);
                set_pkt_delay(m_pkt_delay - 0.1);
            }
        }

        bool inactive()
        {
            return m_timeout.check();
        }

    private:

        uint32_t m_buffer_count = 0;

        uint32_t m_buffer_safety = 0;
        uint32_t m_buffer_safety_counter = 0;

        bool get_free_buffer(byte* data, uint32_t size, send_pkt_priority prio, uint64_t recv_timestamp = 0)
        {
            if (prio == SEND_PKT_DIAGNOSTIC)
            {
                m_send_flush_diag.resize(size);
                memcpy(m_send_flush_diag.data(), data, size);
                m_send_flush_diag_timestamp = recv_timestamp;
                m_send_flush_diag_response = true;
                return true;
            }


            //TODO: if total latency from pushing into buffer to real sending is bigge than 5ms
            //clear all send_flush buffers !!!
            //size of the buffer array doesnt matter just latency time

            const int max_normal_pkts = 1024 * 10;
            const int max_prio_pkts = max_normal_pkts + 10;

            if (prio == SEND_PKT_PRIO)
            {
                if (m_buffer_count > max_prio_pkts)
                {
                    NETPRNT("network prio buffer overrun!");
                    update_send();
                    return false;
                }
            }
            else
            {
                if (m_buffer_count > max_normal_pkts)
                {
                    NETPRNT("network normal buffer overrun!");
                    update_send();
                    return false;
                }
            }

            std::vector<byte>* res = 0;
            if (m_socket->m_send_endpoint_free_buffers.size() == 0)
            {
                res = new std::vector<byte>();
            }
            else
            {
                res = m_socket->m_send_endpoint_free_buffers.back();
                m_socket->m_send_endpoint_free_buffers.pop_back();
            }

            if (m_send_flush.size() > m_buffer_safety)
            {
                m_buffer_safety_counter++;
                if (m_buffer_safety_counter > 3)
                {
                    if (m_send_flush.back().buffer->size() == size && memcmp(m_send_flush.back().buffer->data(), data, size) == 0)
                    {
                        //NETPRNT("double packet detected, skipping...");
                        return true;
                    }

                    //NETPRNT("warning, send buffer increase detected!");
                    set_pkt_delay(m_pkt_delay + 10.0);
                    update_send();
                    return false;
                }
            }
            else
                m_buffer_safety_counter = 0;

            res->resize(size);
            memcpy(res->data(), data, size);

            m_buffer_safety = m_send_flush.size();

            m_send_flush.push(res);

            m_buffer_count++;

            return true;
        }

        void free_buffer(std::vector<byte>* buff)
        {
            m_socket->m_send_endpoint_free_buffers.push_back(buff);
            m_buffer_count--;
        }

        bool send_direct(byte* buffer, uint32_t len)
        {

            return m_socket->send_packet_to_interface(m_adr, buffer, len);
        }
    };

    //these fields here is not thread safe! use it from send_loop only !!!
    std::unordered_map<shznet_ip, std::unique_ptr<send_endpoint>> m_send_endpoints;
    std::vector<std::vector<byte>*> m_send_endpoint_free_buffers;
    shznet_timer m_send_loop_cleanup_check = shznet_timer(1000 * 60);

    void send_loop_cleanup()
    {
        for (auto it = m_send_endpoints.begin(); it != m_send_endpoints.end(); )
        {
            if (it->second->inactive())
                it = m_send_endpoints.erase(it);
            else
                it++;
        }
    }

    bool send_loop_try_send(shznet_ip& adr, byte* buffer, uint32_t size, send_pkt_priority prio, uint64_t recv_timestamp = 0)
    {           
        if (adr.is_broadcast())
        {
            if (!send_packet_to_interface(adr, buffer, size))
            {
                NETPRNT("cannot send broadcast packet!");
                return false;
            }

            return true;
        }

        auto endpoint = m_send_endpoints.find(adr);

        if (endpoint == m_send_endpoints.end())
        {
            m_send_endpoints[adr] = std::make_unique<send_endpoint>(this, adr);
            return m_send_endpoints[adr]->try_send(buffer, size, prio, recv_timestamp);
        }

        return endpoint->second->try_send(buffer, size, prio, recv_timestamp);
    }

    void send_loop()
    {
        std::unique_lock<std::mutex> _grd{ m_sendmutex };

        NETPRNT("start high resolution timer...");
        start_high_resolution_timer();
        NETPRNT("high resolution timer started.");

        bool shuffle_devices = false; // this is used to avoid starving other instances on the same IP to death
        shznet_timer test_timer;

        bool is_sending_data = false;
        bool keep_thread_alive = false; //keep thread 100milliseconds alive after last send
        shznet_timer keep_alive_timer = shznet_timer(100);

        while (m_threads_active)
        {
            int32_t max_len = 0;
            shznet_ip adr;

            const int wait_time = 1000;

            while (m_threads_active)
            {
                shznet_async_header hdr;
                shznet_pkt_diagnostic* diag_pkt = (shznet_pkt_diagnostic*)m_async_diag_response.read(&max_len, &hdr);
                if (!diag_pkt) 
                    break;

                auto it = m_send_endpoints.find(hdr.ip);
                if (it != m_send_endpoints.end())
                    it->second->handle_diagnostics_endpoint(diag_pkt, hdr.timestamp_recv);
            }

            if (m_send_loop_cleanup_check.update())
                send_loop_cleanup();

            if (!m_send_endpoints.empty())
            {
                //doesnt work with unordered_map
                /*if (shuffle_devices)
                {
                    auto it = m_send_endpoints.end();
                    it--;
                    for (; it != m_send_endpoints.begin(); it--)
                        is_sending_data |= it->second->update_send();
                }
                else
                */
                {
                    for (auto it = m_send_endpoints.begin(); it != m_send_endpoints.end(); it++)
                        is_sending_data |= it->second->update_send();
                }
            }

            shuffle_devices ^= 1;

            auto chunk = m_asyncsend_artnet.read_peek(&max_len, &adr);
            if (chunk)
            {
                is_sending_data = true;
                if (send_packet_to_interface(adr, (byte*)chunk, max_len))
                {
                    m_asyncsend_artnet.read();
                    continue;
                }
            }

            shznet_async_header adr_async;
            chunk = m_asyncsend_diagnostic.read_peek(&max_len, &adr_async);
            if (chunk)
            {
                is_sending_data = true;
                if (send_loop_try_send(adr_async.ip, (byte*)chunk, max_len, SEND_PKT_DIAGNOSTIC, adr_async.timestamp_recv))
                {
                    m_asyncsend_diagnostic.read();
                    continue;
                }
                high_resolution_wait(wait_time);
                continue;
            }
            chunk = m_asyncsend_prio.read_peek(&max_len, &adr);
            if (chunk)
            {
                is_sending_data = true;
                if (send_loop_try_send(adr, (byte*)chunk, max_len, SEND_PKT_PRIO))
                {
                    m_asyncsend_prio.read();
                    continue;
                }
                high_resolution_wait(wait_time);
                continue;
            }
            chunk = m_asyncsend.read_peek(&max_len, &adr);
            if (chunk)
            {
                is_sending_data = true;
                if (send_loop_try_send(adr, (byte*)chunk, max_len, SEND_PKT_NORMAL))
                {
                    m_asyncsend.read();                         
                    continue;
                }
                high_resolution_wait(wait_time);
                continue;
            }
               
#ifdef _WIN32
            high_resolution_wait(wait_time);
#else
            if (is_sending_data)
            {
                is_sending_data = false;
                keep_thread_alive = true;
                keep_alive_timer.reset();
            }

            if (keep_thread_alive)
            {
                if (keep_alive_timer.update())
                {
                    keep_thread_alive = false;
                }
                high_resolution_wait(wait_time);
                continue;
            }

            m_sendsignal.wait_for(_grd, std::chrono::milliseconds(1));
#endif
        }
        NETPRNT("send thread ended.");
        stop_high_resolution_timer();

        m_sendloop_active = false;
    }

    void recv_loop()
    {
        ipinfo tmp;
        ipinfo local_ip;
        int32_t rs = 0;

        byte m_recv_buffer[SHZNET_PKT_MAX + 1] = { 0 };

        while (m_threads_active)
        {
            rs = m_udp.sock_receive(m_recv_buffer, SHZNET_PKT_MAX, tmp, local_ip);

            if (!m_threads_active)
                break;

            if (rs <= 0)
            {
                //NETPRNT_FMT("recv error! %i\n", errno);
                continue;
            }             
            uint64_t recv_time = shznet_millis();
            shznet_ip rm_ip(tmp.port);
            memcpy(&rm_ip.ip[0], &tmp.adr.ip[0], 4);
            if (preprocess_packet(rm_ip, m_recv_buffer, rs))
                continue;
            packet_buffer_header hdr;
            hdr.ip = rm_ip;
            hdr.recv_time = recv_time;
            m_asyncbuffer.write(m_recv_buffer, rs, &hdr);
        }
        m_recvloop_active = false;
    }

    uint32_t m_send_fail_counter = 0;
    bool send_packet_to_interface(shznet_ip& info, unsigned char* buffer, int32_t len)
    {
        ipinfo tmp;
        memcpy(tmp.adr.ip, info.ip, 4);
        tmp.port = info.port;
        bool send_result = m_udp.sock_send(buffer, len, tmp) == len;
        //experimental, try to give the network increasingly more time (might be bad due to more and more increasing buffers...)
        //maybe at diagnostics to calculate real netrate vs what we're trying to send and give a warning
        if (!send_result)
        {
            m_send_fail_counter++;
            std::this_thread::sleep_for(std::chrono::milliseconds(m_send_fail_counter > 100 ? 100 : m_send_fail_counter));
        }
        else
            m_send_fail_counter = 0;
        return send_result;
    }

    void handle_diagnostics(shznet_ip& adr, shznet_pkt_diagnostic* diags) override 
    {
        shznet_async_header hdr(adr, shznet_millis());
        m_async_diag_response.write((byte*)diags, sizeof(shznet_pkt_diagnostic), &hdr);
        flush_send_buffer(true);
    }


    bool preprocess_packet(shznet_ip& adr, byte* data, int32_t size) override
    {
        auto res = GenericUDPSocket::preprocess_packet(adr, data, size);
        if(res) flush_send_buffer(true);
        return res;
    }

#ifdef _WIN32
    HANDLE m_win_timer = 0;
    HANDLE m_win_interrupt = 0;
#endif

    void start_high_resolution_timer();
    void stop_high_resolution_timer();
    void high_resolution_wait(uint32_t microseconds);

public:

    GenericOSUDPSocket()
    {

    }

    virtual ~GenericOSUDPSocket()
    {
            
        m_threads_active = false;
        NETPRNT("join sendloop...");
        while (m_sendloop_active || m_recvloop_active)
        {
            m_sendsignal.notify_one();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if(m_sendloop.joinable()) m_sendloop.join();
        if (m_recvloop.joinable()) m_recvloop.join();

        while (m_send_endpoint_free_buffers.size())
        {
            delete m_send_endpoint_free_buffers.back();
            m_send_endpoint_free_buffers.pop_back();
        }
    }

    virtual void invalidate_threads() override
    {
        m_threads_active = false;
        while (m_recvloop_active)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    int max_parallel_queries() override
    {
        return 64;
    }

    bool init() override
    {
        m_udp.sock_init();
        return true;
    }
    bool bind(int32_t port) override
    {
        memset(m_localadr.ip.ip, 0, 4);
        m_localadr.ip.port = port;
        auto res = false;
        try
        {
            res = m_udp.sock_bind_noclose(0, port);
        }
        catch (const std::exception&)
        {
            res = false;
        }
         
        if (!res)
            return false;

        if (!m_sendloop_active)
        {
            local_adr(); //call this once to init stuff on win/linux

            m_threads_active = true;
            m_sendloop_active = true;
            m_recvloop_active = true;
            m_sendloop = std::thread(&GenericOSUDPSocket::send_loop, this);
            m_recvloop = std::thread(&GenericOSUDPSocket::recv_loop, this);
        }

        return true;

    }

    char* read_packet(shznet_ip& info, int32_t* max_len, uint64_t* recv_time) override
    {
        packet_buffer_header hdr;
        auto pkt_data = m_asyncbuffer.read_peek(max_len, &hdr);
        info = hdr.ip;
        if (recv_time) *recv_time = hdr.recv_time;
        return pkt_data;
    }

    void flush_packet() override
    {
        m_asyncbuffer.read();
    }

    bool send_packet(shznet_ip& info, unsigned char* buffer, int32_t len) override
    {
        auto res = m_asyncsend.write(buffer, len, &info);
        m_sendflush = true;
        return res;
    }
    bool send_packet_prio(shznet_ip& info, unsigned char* buffer, int32_t len) override
    {         
        auto res = m_asyncsend_prio.write(buffer, len, &info);
        flush_send_buffer(true);
        return res;
    }
    bool send_packet_diagnostic(shznet_ip& info, shznet_pkt_diagnostic* pkt, uint64_t recv_timestamp) override
    {
        shznet_async_header async_hdr(info, recv_timestamp);
        auto res = m_asyncsend_diagnostic.write((byte*)pkt, sizeof(shznet_pkt_diagnostic), &async_hdr);
        flush_send_buffer(true);
        return res;
    }
    bool send_packet_artnet(shznet_ip& info, unsigned char* buffer, int32_t len) override
    {
        auto res = m_asyncsend_artnet.write(buffer, len, &info);
        m_sendflush = true;
        return res;
    }

    void update() override
    {
        GenericUDPSocket::update();
        flush_send_buffer();
    }

    void flush_send_buffer(bool force = false) override
    {
        if (m_sendflush || force)
        {
            if(!force) m_sendflush = 0;
#ifdef _WIN32
            SetEvent(m_win_interrupt);
#else
            m_sendsignal.notify_one();
#endif
        }
    }

    shznet_adr& local_adr() override
    {
#if defined(_WIN32)
        if (!macbufferset)
        {
            macbufferset = true;
            IP_ADAPTER_INFO AdapterInfo[16];       // Allocate information
            // for up to 16 NICs
            DWORD dwBufLen = sizeof(AdapterInfo);  // Save memory size of buffer

            DWORD dwStatus = GetAdaptersInfo(      // Call GetAdapterInfo
                AdapterInfo,                 // [out] buffer to receive data
                &dwBufLen);                  // [in] size of receive data buffer
            assert(dwStatus == ERROR_SUCCESS);  // Verify return value is
            // valid, no buffer overflow

            PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo; // Contains pointer to
            // current adapter info
            if (pAdapterInfo)
            {
                memcpy(m_localadr.mac.mac, pAdapterInfo->Address, 6);

                *(int32_t*)&m_localadr.mac.mac[0] += m_localadr.ip.port - ART_NET_PORT;
            }                // Terminate if last adapter
        }
#else
        if (!macbufferset)
        {
            macbufferset = true;
            srand(time(0));
            for (int32_t i = 0; i < 6; i++)
                m_localadr.mac.mac[i] = rand();
        }
#endif

        return m_localadr;
    }
};

typedef GenericOSUDPSocket shznet_udp;

#endif

template<typename T>
T reverse_bits(T num)
{
    uint32_t NO_OF_BITS = sizeof(num) * 8;
    T reverse_num = 0;
    int32_t i;
    for (i = 0; i < NO_OF_BITS; i++) {
        if ((num & (1 << i)))
            reverse_num |= 1 << ((NO_OF_BITS - 1) - i);
    }
    return reverse_num;
}

#pragma pack(push, 1)
struct artnet_poll_reply {
    uint8_t  id[8];
    uint16_t opCode;
    uint8_t  ip[4];
    uint16_t port;
    uint8_t  verH;
    uint8_t  ver;
    uint8_t  subH;
    uint8_t  sub;
    uint8_t  oemH;
    uint8_t  oem;
    uint8_t  ubea;
    uint8_t  status;
    uint8_t  etsaman[2];
    uint8_t  shortname[18];
    uint8_t  longname[64];
    uint8_t  nodereport[64];
    uint8_t  numbportsH;
    uint8_t  numbports;
    uint8_t  porttypes[4];//max of 4 ports per node
    uint8_t  goodinput[4];
    uint8_t  goodoutput[4];
    uint8_t  swin[4];
    uint8_t  swout[4];
    uint8_t  swvideo;
    uint8_t  swmacro;
    uint8_t  swremote;
    uint8_t  sp1;
    uint8_t  sp2;
    uint8_t  sp3;
    uint8_t  style;
    uint8_t  mac[6];
    uint8_t  bindip[4];
    uint8_t  bindindex;
    uint8_t  status2;
    uint8_t  filler[26];
}PACKED_ATTR;

struct artnet_poll
{
    uint8_t ID[8] = { 'A', 'r', 't', '-', 'N', 'e', 't' };     // protocol ID = "Art - Net"
    uint16_t OpCode = ART_POLL;   // == OpPoll
    uint8_t ProtVerHi = 0; // 0
    uint8_t ProtVerLo = 14; // protocol version, set to ProtocolVersion
    uint8_t TalkToMe = 0;  // bit 0 = not used

    // bit 1 = 0 then Node only sends ArtPollReply when polled
    // bit 1 = 1 then Node sends ArtPollReply when it needs to

    // bit 2 = 0 Do not send me disagnostic messages
    // bit 2 = 1 Send me diagnostics messages

    // bit 3 = 0 (If Bit 2 then) broadcast diagnostics messages
    // bit 3 = 1 (If Bit 2 then) unicast diagnostics messages

    // bit 4 = 0 Enable VLC transmission
    // bit 4 = 1 Disable VLC transmission

    uint8_t Priority = 0; // Set the lowest priority of diagnostics message that node should send. See DpXxx defines above.
} PACKED_ATTR;

struct artnet_sync
{
    // Protocol ID: "Art-Net"
    uint8_t ID[8] = { 'A', 'r', 't', '-', 'N', 'e', 't' };

    // OpCode for ART_SYNC (usually defined as 0x0008)
    uint16_t OpCode = ART_SYNC;

    // Protocol version, high and low bytes (set to ProtocolVersion, here 14)
    uint8_t ProtVerHi = 0;
    uint8_t ProtVerLo = 14;

    // Spare: must be zero
    uint8_t Spare = 0;
} PACKED_ATTR;

struct artnet_dmx
{
    char ID[8] = "Art-Net";
    int16_t opcode = ART_DMX;
    int16_t prot_ver = reverse_bits<int16_t>(14);
    byte seq = 0;
    byte phy = 0;
    int16_t universe = 0;
    int16_t length = 0;
    byte data[512] = { 0 };
}PACKED_ATTR;

#pragma pack(pop)