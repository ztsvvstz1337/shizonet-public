#pragma once

#include "shizonet_platform.h"
#define SHZNET_COMPAT_VERSION 14
#undef min

#ifdef __XTENSA__
//TODO: find a better (secure) way to do this...
#define ESP32_OTA
extern char* ota_class;
extern char* ota_subclass;
#define SHZNET_MAX_RECV (1024 * 10) //10kb
#define SHZNET_MAX_RECV_BUFFERS (3) //3 Buffers (~30kb)
#define SHZNET_MAX_RECV_OOB (1024 * 10) //10kb OOB data 
#define SHZNET_PACKET_PACING_COUNT 5 //Send X packets at once and then wait for the microcontroller to process them before sending more
                                    //This is based on the arduino pacing code which sends packets every 4 ms (to get 60 FPS at 16ms total window, sending 4*4 universes over that window)
                                    //You can send a total of SHZNET_PACKET_PACING_COUNT * 4 per frame before it will start to lag (sadly RECVMSGBOXSIZE in ESP IDF is pretty low...)
#else
#define SHZNET_MAX_RECV (-1)
#define SHZNET_MAX_RECV_BUFFERS (-1)
#define SHZNET_MAX_RECV_OOB (1024 * 1024) //1mb OOB data 
#define SHZNET_PACKET_PACING_COUNT 0
#endif

#define INVALID_SESSIONID shznet_sessionid(-1)
#define INVALID_TICKETID shznet_ticketid(-1)

struct shznet_config
{
    uint64_t max_recv = SHZNET_MAX_RECV; //Maximum number of mb that can be requested by a client
    uint64_t max_recv_buffers = SHZNET_MAX_RECV_BUFFERS;
    uint64_t max_recv_oob = SHZNET_MAX_RECV_OOB;
};

struct shznet_channel_buffer
{
    shznet_ticketid last_id = 0;
    uint32_t seq = 0;
    uint32_t max_seq = 0;
    shznet_vector<byte> buffer;

    size_t data_index = 0;

    void reset()
    {
        last_id = 0;
        seq = 0;
        max_seq = 0;
        buffer.clear();
        data_index = 0;
    }
    void reset_seq(shznet_ticketid new_id)
    {
        last_id = new_id;
        seq = 0;
        max_seq = 0;
        data_index = 0;
        buffer.clear();
    }

    void write_data(byte* data, size_t size)
    {
        if (data_index + size > buffer.size())
            return;
        memcpy(&buffer[data_index], data, size);
        data_index += size;
    }

};

typedef shznet_vector<byte> shznet_order_buffer_data;

struct shznet_order_buffer
{
    shznet_adr address;
    shznet_ticketid ticketid = -1;
    shznet_order_buffer_data* data = 0;
    shznet_vector<bool> data_map; //std::vector<bool> is optimized by C++ lib to be a bitset
    size_t data_count = 0;
    size_t data_per_pkt_size = 0;
    uint64_t last_id = 0;
    shznet_timer timeout;
    uint32_t ack_id = 0;
    bool complete = false;
    bool should_complete = false;

    ~shznet_order_buffer()
    {
        if (data)
            delete data;
    }

    void reset()
    {
        ticketid = -1;
        data_count = 0;
        if (data) delete data;
        data = 0;
        data_map.clear();
        last_id = 0;
        complete = false;
        should_complete = false;
        ack_id = 0;
    }

    size_t total_size()
    {
        return sizeof(shznet_order_buffer) + data_map.capacity() + (data ? data->size() : 0);
    }
};

struct shznet_endpoint_s
{
    shznet_sessionid sessionid = INVALID_SESSIONID;
    //RESET THIS ON EVERY PACKET!!!
    shznet_timer timeout = shznet_timer(1000 * 60 * 10);

    shznet_vector<shznet_channel_buffer> channels;

    shznet_channel_buffer oob;

    std::unordered_map<shznet_ticketid, shznet_order_buffer*> orders;

    void reset()
    {
        sessionid = INVALID_SESSIONID;

        channels.clear();

        oob.reset();

        timeout.reset();

        for (auto it : orders)
            delete it.second;
        orders.clear();
    }

    void reset_timeout()
    {
        timeout.reset();
    }

    ~shznet_endpoint_s()
    {
        reset();
    }

};

struct shznet_stream_endpoint_s
{
    shznet_timer timeout = shznet_timer(1000 * 10);

    shznet_vector<shznet_channel_buffer> channels;

    std::unordered_map<shznet_ticketid, shznet_order_buffer*> orders;

    void reset()
    {
        channels.clear();

        timeout.reset();

        for (auto it : orders)
            delete it.second;
        orders.clear();
    }

    void reset_timeout()
    {
        timeout.reset();
    }

    ~shznet_stream_endpoint_s()
    {
        reset();
    }
};

class shznet_receiver
{
public:

    shznet_config config;

protected:

    shznet_udp m_udp;

    std::string m_nodename = "DEFAULT";
    std::string m_nodetype = "";

    bool m_always_enable_artnet = false;

    shznet_pkt m_send_buffer;
    shznet_pkt m_send_buffer2; //this is needed for the ESP32 two core system for some functions. as m_send_buffer is not thread safe !!! EDIT: also used in win/linux now for calls from the recv thread
    shznet_pkt_big m_send_buffer_big;
    shznet_pkt_diagnostic_request m_send_diag;

    std::unordered_map<shznet_mac, shznet_endpoint_s> m_endpoints;
    std::unordered_map<shznet_mac, shznet_stream_endpoint_s> m_stream_endpoints;

    std::unordered_map<uint32_t, std::function<void(shznet_ip&, byte* data, size_t size, shznet_pkt_header& hdr)>> m_callbacks;

    std::unordered_map<uint32_t, std::string> m_command_names;

    shznet_recycler<shznet_order_buffer>            order_buffers;
    shznet_recycler_locked<shznet_vector<byte>>     order_buffers_data;
    shznet_timer                                    order_update = shznet_timer(1000 * 5);

    uint32_t m_open_streams[SHZNET_MAX_STREAMS] = { 0 }; //kinda thread safe

    bool check_open_stream(uint32_t cmd_name)
    {
        for (int i = 0; i < SHZNET_MAX_STREAMS; i++)
        {
            if (cmd_name == m_open_streams[i])
                return true;
            if (!m_open_streams[i])
                return false;
        }
        return false;
    }

    float           m_artnet_fps = 0;
    float           m_artnet_maxfps = 0;

    int            m_missed_artnet_pkts = 0;
    uint64_t        m_next_frame_recv_time = 0;

    volatile bool m_order_check_flag = 0;

public:

    shznet_receiver()
    {
        //this function call is NOT thread safe!!! (could be called from a different thread than main e.g. on win/linux and ESP32)
        m_udp.preprocess_hook = [this](shznet_ip& adr, shznet_pkt_type type, shznet_pkt* pkt, uint32_t pkt_size)
            {
                switch (type)
                {
                case SHZNET_PKT_ARTNET_POLL:
                    send_art_poll_reply(adr);
                    return true;
                case SHZNET_PKT_GENERIC:
                    handle_shizonet_generic(adr, pkt);
                    return true;
                case SHZNET_PKT_ALIVE_CHECK:
                    handle_shizonet_alive_check(adr, pkt);
                    return true;
                case SHZNET_PKT_ACK_REQ:
                    handle_shizonet_ack_request(adr, (shznet_pkt_ack_request*)pkt);
                    return true;
                case SHZNET_PKT_STREAM:
                    handle_shizonet_stream(adr, pkt, pkt_size);
                    return true;
                }

                return false;
            };
    }

    virtual ~shznet_receiver()
    {
        if (dmx_frame)
            delete dmx_frame;

        while (true)
        {
            command_async_header async_hdr;
            shznet_order_buffer_data* buff_data = (shznet_order_buffer_data*)async_commands.read(0, &async_hdr);
            if (!buff_data) break;
            delete buff_data;
        }
    }

    void set_node_name(std::string name)
    {
        m_nodename = name;
    }

    bool init(std::string node_name, short port = ART_NET_PORT)
    {
        if (node_name.length() > 16)
            node_name = node_name.substr(0, 16);

        m_nodename = node_name;

        m_udp.init();
        if (port == ART_NET_PORT)
        {
            int try_port = port;
            while (!m_udp.bind(try_port))
            {
                try_port++;
                if ((try_port - ART_NET_PORT) > 100)
                    return false;
            }
            return true;
        }

        return m_udp.bind(port);
    }

    virtual void add_command(const char* cmd, std::function<void(shznet_ip&, byte* data, size_t size, shznet_pkt_header& hdr)> cb)
    {
        auto hs = shznet_hash((char*)cmd, strlen(cmd));
        if (m_callbacks.find(hs) != m_callbacks.end() || hs == 0)
        {
            NETPRNT("error: command name collision for");
            NETPRNT(cmd);
        }
        m_callbacks[hs] = cb;
        m_command_names[hs] = cmd;
    }

    virtual void remove_command(const char* cmd)
    {
        auto hs = shznet_hash((char*)cmd, strlen(cmd));
        auto id = m_callbacks.find(hs);
        if (id != m_callbacks.end())
        {
            NETPRNT_FMT("removed cmd %s\n", cmd);
            m_callbacks.erase(id);
        }
    }

    void enable_stream(const char* stream_name)
    {
        for (int i = 0; i < SHZNET_MAX_STREAMS; i++)
        {
            if (!m_open_streams[i])
            {
                m_open_streams[i] = shznet_hash((char*)stream_name, strlen(stream_name));
                return;
            }
        }
        NETPRNT("No more open stream slots!");
    }
    void disable_stream(const char* stream_name)
    {
        auto stream_hash = shznet_hash((char*)stream_name, strlen(stream_name));
        for (int i = 0; i < SHZNET_MAX_STREAMS; i++)
        {
            if (stream_hash == m_open_streams[i])
            {
                m_open_streams[i] = 0;
                for (int j = i; (j + 1) < SHZNET_MAX_STREAMS; j++) //move last valid entry into this slot to avoid empty slots in between
                {
                    if (!m_open_streams[j + 1] && j != i)
                        m_open_streams[i] = m_open_streams[j];
                }
                return;
            }
        }
        NETPRNT("Stream not found.");
    }

    shznet_udp& get_udp()
    {
        return m_udp;
    }

    shznet_pkt& get_sendpacket()
    {
        return m_send_buffer;
    }
    shznet_pkt_big& get_sendpacket_big()
    {
        return m_send_buffer_big;
    }

    virtual void update()
    {
        if (order_update.update())
        {
            m_order_check_flag = true;
        }

        if (artnet_frame_due && artnet_frame_timer.check())
        {
            artnet_frame_due = 0;
            if(art_sync_timer.check())
                art_frame_callback(m_next_frame_recv_time + artnet_frame_timer.get_wait_time());
        }

        for(auto it = m_endpoints.begin(); it != m_endpoints.end();)
        {
            if (it->second.timeout.update())
            {
                it = m_endpoints.erase(it);
                continue;
            }
            it++;
        }
        for (auto it = m_stream_endpoints.begin(); it != m_stream_endpoints.end();)
        {
            if (it->second.timeout.update())
            {
                it = m_stream_endpoints.erase(it);
                continue;
            }
            it++;
        }

        m_udp.update();

        int32_t         packet_len = 0;
        char*           packet_data = 0;
        shznet_ip       packet_ip;
        uint64_t        packet_recv_time = 0;

        int32_t max_packets_cc = 0;

        while (true)
        {
            command_async_header async_hdr;
            shznet_order_buffer_data* buff_data = (shznet_order_buffer_data*)async_commands.read_peek(0, &async_hdr);
            if (!buff_data) break;

            buff_data = *(shznet_order_buffer_data**)buff_data;

            auto cb = m_callbacks.find(async_hdr.cmd);
            if (cb != m_callbacks.end())
                cb->second(async_hdr.ip, buff_data->data(), buff_data->size(), async_hdr.header);
            else
            {
                NETPRNT("invalid cb!");
            }

            async_commands.read();
            order_buffers_data.recycle(buff_data);
        }

        while ((packet_data = m_udp.read_packet(packet_ip, &packet_len, &packet_recv_time)) != 0)
        {
            bool is_artnet = false;
            if (packet_len <= MAX_BUFFER_ARTNET && packet_len >= 8)
            {
                is_artnet = (packet_data[0] == 'a' || packet_data[0] == 'A') &&
                    (packet_data[1] == 'r' || packet_data[1] == 'R') &&
                    (packet_data[2] == 't' || packet_data[2] == 'T') &&
                    (packet_data[3] == '-') &&
                    (packet_data[4] == 'n' || packet_data[4] == 'N') &&
                    (packet_data[5] == 'e' || packet_data[5] == 'E') &&
                    (packet_data[6] == 't' || packet_data[6] == 'T');
            }

            if (is_artnet)
            {
                bool exit_loop = false;
                if (art_dmx_callback || m_always_enable_artnet)
                {
                    exit_loop = handle_artnet(packet_ip, (byte*)packet_data, packet_len, packet_recv_time);
                }
                m_udp.flush_packet();
                packet_ip.port = 0;
#ifdef ARDUINO
                //if (exit_loop) break;
#endif
                continue;
            }

            if (packet_len == sizeof(shznet_pkt_ack))
            {
                shznet_pkt_ack* pkt = (shznet_pkt_ack*)packet_data;
                if (pkt->is_valid())
                    handle_shizonet_ack(packet_ip, pkt);
                else
                {
                    NETPRNT("invalid ack check");
                }
            }
            else
                handle_shizonet_primitive(packet_ip, (shznet_pkt*)packet_data, packet_len);

            m_udp.flush_packet();

            max_packets_cc++;
            if (max_packets_cc > 1000)
                break;
            packet_ip.port = 0;
        }

        if (art_dmx_callback)
        {
            //it is inefficient to broadcast from all connected possible devices?
            //EDIT: Do reply broadcast for BASES ONLY!!
            /*if (m_art_reply_timer.update())
            {
                shznet_ip broadcast(m_udp.local_adr().ip.port);
                send_art_poll_reply(broadcast);
            }
            */

            if (dmx_frame && dmx_update.update())
            {
                dmx_frame->dmx_active = false;
                unsigned int cur_time = shznet_millis();
                for (int i = 0; i < ARTNET_UNIVERSE_MAX; i++)
                {
                    if (dmx_frame->active[i] <= 1)
                        continue;
                    if (!dmx_frame->dmx_active) dmx_frame->dmx_active = true;
                    if (cur_time < dmx_frame->last[i])
                        dmx_frame->last[i] = cur_time;
                    if (cur_time - dmx_frame->last[i] > 1200)
                    {
                        dmx_frame->active[i] = false;
                    }
                }
            }

            if (m_missed_artnet_pkts)
            {
#ifdef ARDUINO
                Serial.print(m_missed_artnet_pkts); Serial.println(" missed artnet packets!");
#endif
                m_missed_artnet_pkts = 0;
            }
        }
    }

    virtual void handle_shizonet_primitive(shznet_ip& adr, shznet_pkt* pkt, uint32_t max_size)
    {
        switch (pkt->header.type)
        {
        case SHZNET_PKT_OOB:
            handle_shizonet_oob(adr, pkt);
            break;
        case SHZNET_PKT_ALIVE_CHECK:
            handle_shizonet_alive_check(adr, pkt);
            break;
        case SHZNET_PKT_ALIVE_CHECK_REPL:
            handle_shizonet_alive_check_reply(adr, pkt);
            break;
        case SHZNET_PKT_AUTH_BEACON:
            handle_shizonet_auth_beacon(adr, pkt);
            break;
        case SHZNET_PKT_AUTH_BEACON_REPLY:
            handle_shizonet_auth_beacon_reply(adr, pkt);
            break;
        case SHZNET_PKT_AUTH_REQ:
            handle_shizonet_auth_request(adr, pkt);
            break;
        case SHZNET_PKT_AUTH_REPL:
            handle_shizonet_auth_reply(adr, pkt);
            break;
        default:
            break;
        }
    }

    virtual void handle_shizonet_oob(shznet_ip& adr, shznet_pkt* pkt)
    {
        shznet_mac target_mac(pkt->source_mac());
        auto endpoint = m_endpoints.find(target_mac);
        if (endpoint == m_endpoints.end())
        {
            NETPRNT("oob packet from unknown origin.");
#ifdef _WIN32
            NETPRNT(adr.str().c_str());
#endif
            m_send_diag.diag_id = 0;
            m_send_diag.type = SHZNET_PKT_DIAG_REQ_RESET_BUFFERS;
            m_send_diag.make_checksum();
            m_udp.send_buffered_prio(adr, (byte*)&m_send_diag, sizeof(m_send_diag));
            return;
        }

        if (endpoint->second.sessionid != pkt->header.sessionid)
        {
            NETPRNT("invalid sessionid");
            return;
        }

        endpoint->second.reset_timeout();

        if (pkt->header.ticketid < endpoint->second.oob.last_id)
        {
            NETPRNT("invalid seq ticketid");
            return;
        }
        if (pkt->header.ticketid == endpoint->second.oob.last_id)
        {
            if (endpoint->second.oob.max_seq == 0)
            {
                //NETPRNT_FMT("invalid seq max_seq %i : %i : %i\n", endpoint->second.oob.max_seq, pkt->header.seq, pkt->header.seq_max);
                return;
            }
            if (pkt->header.seq < endpoint->second.oob.seq)
            {
                NETPRNT("invalid seq double");
                return;
            }
            if (pkt->header.seq != endpoint->second.oob.seq) //no point in filling this buffer when we've missed a packet...
            {
                //NETPRNT("invalid seq skip");
                //NETPRNT_FMT("%i : %i\n", pkt->header.seq, endpoint->second.oob.seq);
                endpoint->second.oob.reset_seq(pkt->header.ticketid);
                return;
            }

            endpoint->second.oob.seq++;
            endpoint->second.oob.write_data(pkt->get_data(), pkt->get_data_size());

            if (pkt->header.seq == endpoint->second.oob.max_seq)
            {
                auto cb = m_callbacks.find(pkt->get_cmd());
                if (cb != m_callbacks.end())
                    cb->second(adr, endpoint->second.oob.buffer.data(), endpoint->second.oob.buffer.size(), pkt->header);

                endpoint->second.oob.reset_seq(pkt->header.ticketid);
            }
            //handle sequence buffer
        }
        else
        {
            if (pkt->header.seq != 0)
            {
                NETPRNT("invalid seq");
                return;
            }
            endpoint->second.oob.reset_seq(pkt->header.ticketid);

            if (pkt->header.seq_max != 0)
            {
                if (!pkt->get_data_size_max())
                    return;

                //fix potential attack point here with setting a max data size etc...
                if (config.max_recv_oob != (-1) && pkt->get_data_size_max() >= config.max_recv_oob)
                {
                    NETPRNT("OOB cmd is too big!");
                    return;
                }

                //no point in allocating a buffer for a cmd which doesnt exist...
                auto cb = m_callbacks.find(pkt->get_cmd());
                if (cb == m_callbacks.end())
                {
                    NETPRNT("cmd not found!");
                    return;
                }

                endpoint->second.oob.seq = 1; //next seq
                endpoint->second.oob.max_seq = pkt->header.seq_max;

                endpoint->second.oob.buffer.resize(pkt->get_data_size_max());

                endpoint->second.oob.write_data(pkt->get_data(), pkt->get_data_size());

                return;
            }

            auto cb = m_callbacks.find(pkt->get_cmd());
            if (cb == m_callbacks.end())
            {
                NETPRNT("received invalid oob cmd!");
                return;
            }

            cb->second(adr, pkt->get_data(), pkt->get_data_size(), pkt->header);           
        }
    }

    virtual void handle_shizonet_alive_check_reply(shznet_ip& adr, shznet_pkt* pkt) {}

    virtual void handle_shizonet_auth_beacon(shznet_ip& adr, shznet_pkt* pkt)
    {
        shznet_mac target_mac(pkt->source_mac());
        //NETPRNT_FMT("auth beacon(1) from: %s (%s:%i)\n", target_mac.str().c_str(), adr.str().c_str(), adr.port);
        auto endpoint = m_endpoints.find(target_mac);
        shznet_sessionid sessid = -1;
        if (endpoint != m_endpoints.end())
        {
            endpoint->second.reset_timeout();
            sessid = endpoint->second.sessionid;
        }
        m_send_buffer.packet_begin(SHZNET_PKT_AUTH_BEACON_REPLY, get_udp().local_adr().mac, target_mac, 0, sessid);
        m_send_buffer.header.flags = SHZNET_PKT_FLAGS_RECEIVER_ONLY;
        uint32_t pkt_size = m_send_buffer.packet_end();
        m_udp.send_buffered_prio(adr, (uint8_t*)&m_send_buffer, pkt_size);
    }

    virtual void handle_shizonet_auth_beacon_reply(shznet_ip& adr, shznet_pkt* pkt) {};

    virtual void handle_shizonet_auth_request(shznet_ip& adr, shznet_pkt* pkt)
    {
        if (pkt->get_data_size() < sizeof(shznet_pkt_auth_req))
        {
            NETPRNT("invalid auth req size!");
            return;
        }

        //NETPRNT("auth request!");

        shznet_pkt_auth_req* req = (shznet_pkt_auth_req*)pkt->get_data();

        shznet_mac target_mac(pkt->source_mac());
        bool found_endpoint = m_endpoints.find(target_mac) != m_endpoints.end();

        auto& endpoint = m_endpoints[target_mac];
        endpoint.reset();

        if (endpoint.sessionid != req->sessionid && found_endpoint)
        {
            //CLEAR ENDPOINT OPEN ORDERS HERE, DEVICE RECONNECTED !!!
            NETPRNT("clear orders todo?");
        }
        NETPRNT_FMT("auth request new sessionid: %llu for %s : %i.\n", req->sessionid, target_mac.str().c_str(), (int)adr.port);
        endpoint.sessionid = req->sessionid;

        shznet_pkt_auth_reply repl;

        memcpy(repl.name, m_nodename.c_str(), m_nodename.length());
        repl.name[m_nodename.length()] = 0;

        memcpy(repl.type, m_nodetype.c_str(), m_nodetype.length());
        repl.type[m_nodetype.length()] = 0;

        repl.max_parallel_queues = m_udp.max_parallel_queries();
        repl.max_data_size = SHZNET_PKT_DATA_SIZE;

        NETPRNT("send auth reply!");
        m_send_buffer.packet_begin(SHZNET_PKT_AUTH_REPL, get_udp().local_adr().mac, target_mac, 0, endpoint.sessionid);
        m_send_buffer.packet_set_data<shznet_pkt_auth_reply>(repl);
        uint32_t pkt_size = m_send_buffer.packet_end();
        m_udp.send_buffered_prio(adr, (uint8_t*)&m_send_buffer, pkt_size);
        endpoint.reset_timeout();
    }

    virtual void handle_shizonet_auth_reply(shznet_ip& adr, shznet_pkt* pkt) {}

    virtual bool handle_artnet(shznet_ip& adr, byte* artnetPacket, int size, uint64_t recv_time)
    {
        uint16_t opcode = artnetPacket[8] | artnetPacket[9] << 8;
        uint8_t sequence;
        uint16_t incomingUniverse;
        uint16_t dmxDataLength;

        if (opcode == ART_DMX)
        {
            sequence = artnetPacket[12];
            incomingUniverse = artnetPacket[14] | artnetPacket[15] << 8;
            dmxDataLength = artnetPacket[17] | artnetPacket[16] << 8;

            if (dmxDataLength > size - ART_DMX_START)
                dmxDataLength = size - ART_DMX_START;

            if (art_dmx_callback) art_dmx_callback(incomingUniverse, dmxDataLength, sequence, artnetPacket + ART_DMX_START, adr);

            if (art_frame_callback && dmx_frame)
            {
                if (incomingUniverse >= ARTNET_UNIVERSE_MAX)
                    return false;

                auto frame_pkt_delay = recv_time - artnet_last_frame_time;
                artnet_last_frame_time = recv_time;

                if (frame_pkt_delay > 10)
                {
                    //start of a new frame (first packet)
                    //reset all universes.
                    for (int i = 0; i < ARTNET_UNIVERSE_MAX; i++)
                    {
                        dmx_frame->rcv1[i] = dmx_frame->rcv2[i];
                    }
                }

                int universe = incomingUniverse;

                dmx_frame->active[incomingUniverse] = 1;

                unsigned int curm = shznet_millis();

                if (dmx_frame->active[universe] == 1 && (curm - dmx_frame->last[universe] < 500 || curm < dmx_frame->last[universe]))
                {
                    dmx_frame->active[universe] = 2;
                }

                uint64_t recv_delta = recv_time - dmx_frame->last_recv_time[universe];
                if (recv_delta < 1) recv_delta = 1;
                if (recv_delta > 1000) recv_delta = 1000;
                float fps = 1000.f / (float)(recv_delta);
                dmx_frame->fps[universe] = fps * 0.1 + dmx_frame->fps[universe] * 0.9;
                m_artnet_fps = fps * 0.01 + m_artnet_fps * 0.99;

                dmx_frame->last_recv_time[universe] = recv_time;
                dmx_frame->last[universe] = curm;

                m_next_frame_recv_time = recv_time;
                bool showframe = true;

                if (dmx_frame->rcv2[universe] == (dmx_frame->rcv1[universe] + 1))
                {
                    m_missed_artnet_pkts++;
                }
                else
                {
                    dmx_frame->rcv2[universe] = dmx_frame->rcv1[universe] + 1;

                    for (int i = 0; i < ARTNET_UNIVERSE_MAX; i++)
                    {
                        if (dmx_frame->active[i] == 2 && dmx_frame->rcv1[i] == dmx_frame->rcv2[i])
                        {
                            showframe = false;
                            return false;
                        }
                    }
                }

                if (showframe)
                {
                    m_artnet_maxfps = 0;
                    for (int i = 0; i < ARTNET_UNIVERSE_MAX; i++)
                    {
                        dmx_frame->rcv1[i] = dmx_frame->rcv2[i];
                        if (dmx_frame->fps[i] > m_artnet_maxfps)
                            m_artnet_maxfps = dmx_frame->fps[i];
                    }
                    artnet_frame_due = true;
                    artnet_frame_timer.reset();
                    return true;
                }
            }

            return false;
        }
        else if (opcode == ART_POLL)
        {
            send_art_poll_reply(adr);
            return false;
        }
        else if (opcode == ART_POLL_REPLY)
        {
            artnet_poll_reply* poll_reply = (artnet_poll_reply*)artnetPacket;
            //if(poll_reply->port)
            //    adr.port = poll_reply->port;
            handle_artnet_reply(adr, poll_reply);
        }
        else if (opcode == ART_SYNC)
        {
            art_sync_timer.reset();
            if (art_frame_callback) art_frame_callback(0);
            return false;
        }

        return false;
    }

    virtual void handle_artnet_reply(shznet_ip& adr, artnet_poll_reply* poll_reply)
    {

    }

    inline void setArtDmxCallback(std::function<void(uint16_t universe, uint16_t length, uint8_t sequence, uint8_t* data, shznet_ip remoteIP)> cb)
    {
        art_dmx_callback = cb;
    }

    inline void setArtFrameCallback(std::function<void(uint64_t)> cb) //this is called when all currently receiving universes are filled
    {
        art_frame_callback = cb;
        if (!dmx_frame)
            dmx_frame = new dmx_cache_s();
        memset(dmx_frame, 0, sizeof(dmx_cache_s));
    }

    //async threaded functions, can be called from recvthread on some platforms! not thread safe!

    //this is called from recv thread !!! when buffers are filled pass data to the main thread and clean up
    struct command_async_header
    {
        shznet_ip ip;
        shznet_pkt_header header;
        uint32_t cmd;
    };
#ifdef ARDUINO
#define MAX_ASYNC_ORDER_BUFFERS 32
#else
#define MAX_ASYNC_ORDER_BUFFERS 1024
#endif
    shznet_async_buffer<sizeof(shznet_order_buffer_data*), MAX_ASYNC_ORDER_BUFFERS, command_async_header> async_commands;
    void push_generic_to_main_thread(shznet_ip& ip, shznet_pkt* pkt, shznet_order_buffer* buffer)
    {
        if (!buffer->data)
        {
            NETPRNT_ERR("invalid buffer data?");
            return;
        }
        //NETPRNT("push cmd to main thread!");
        //IMPORTANT:
        //remove data buffer here, but keep order_buffer in queue until ACK from server to delete it (but push data here before)
        command_async_header hdr;
        hdr.ip = ip;
        hdr.cmd = pkt->get_cmd();
        memcpy(&hdr.header, &pkt->header, sizeof(shznet_pkt_header));
        while (!async_commands.write((byte*)&buffer->data, sizeof(shznet_order_buffer*), &hdr))
        {
            NETPRNT_ERR("too many commands at once!");
#ifndef ARDUINO
            std::this_thread::yield();
#else
            delay(1);
            Serial.println("async command overrun!");
#endif
        }
        buffer->data = 0;
        
    }

    virtual void handle_shizonet_generic(shznet_ip& adr, shznet_pkt* pkt)
    {
        //first, fill buffer, then in main thread check session ID after packets was received fully??
        //use send_buffered_prio which is thread safe for recv thread

        //data map is 64 bits for 64 packet acks as bitmap

        //CLEANUP

        if (m_order_check_flag)
        {
            m_order_check_flag = false;
            for (auto &it : m_endpoints)
            {
                auto& orders = it.second.orders;
                for (auto it = orders.begin(); it != orders.end();)
                {
                    if (it->second->timeout.update())
                    {
                        NETPRNT("order buffer timeout!");
                        order_buffers_data.recycle(it->second->data);
                        it->second->data = 0;
                        it->second->reset();
                        order_buffers.recycle(it->second);
                        it = orders.erase(it);
                    }
                    else
                        ++it;
                }
            }
        }

        shznet_mac target_mac(pkt->source_mac());

        auto ep = m_endpoints.find(target_mac);
        if (ep == m_endpoints.end() || pkt->header.sessionid != ep->second.sessionid)
        {
            NETPRNT_FMT("invalid pkt received! %i : %i\n", pkt->header.sessionid, ep->second.sessionid);
            shznet_pkt_ack ack;
            ack.sessionid = pkt->header.sessionid;
            ack.ticketid = pkt->header.ticketid;
            memcpy(ack.mac, local_mac().mac, 6);
            ack.type = shznet_ack_request_invalid_sessionid;
            ack.missing_start_id = -1;
            ack.missing_end_id = -1;
            ack.make_checksum();
            m_udp.send_buffered_prio(adr, (byte*)&ack, sizeof(shznet_pkt_ack));
            if (ep != m_endpoints.end())
                m_endpoints.erase(ep);
            return;
        }

        auto& orders = ep->second.orders;

        shznet_order_buffer* buff = 0;

        auto entry = orders.find(pkt->header.ticketid);
        if (entry != orders.end())
            buff = entry->second;
        else
        {
            if (config.max_recv_buffers != (-1) && order_buffers.in_use() >= config.max_recv_buffers)
            {
                NETPRNT("Max recv buffers reached!");
                shznet_pkt_ack ack;
                ack.sessionid = pkt->header.sessionid;
                ack.ticketid = pkt->header.ticketid;
                memcpy(ack.mac, local_mac().mac, 6);
                ack.type = shznet_ack_request_busy;
                ack.missing_start_id = -1;
                ack.missing_end_id = -1;
                ack.ack_id = 0;
                ack.make_checksum();
                m_udp.send_buffered_prio(adr, (byte*)&ack, sizeof(shznet_pkt_ack));
                return;
            }
            else if (config.max_recv != (-1) && pkt->header.data_max_size > config.max_recv)
            {
                NETPRNT("Max recv!");
                shznet_pkt_ack ack;
                ack.sessionid = pkt->header.sessionid;
                ack.ticketid = pkt->header.ticketid;
                memcpy(ack.mac, local_mac().mac, 6);
                ack.type = shznet_ack_request_too_big;
                ack.missing_start_id = -1;
                ack.missing_end_id = -1;
                ack.ack_id = 0;
                ack.make_checksum();
                m_udp.send_buffered_prio(adr, (byte*)&ack, sizeof(shznet_pkt_ack));
                return;
            }

            buff = order_buffers.get();
            buff->address.ip = adr;
            buff->address.mac = pkt->source_mac();
            buff->ticketid = pkt->header.ticketid;
            if (buff->data)
            {
                NETPRNT("error: buff still has data?");
            }
            else
                buff->data = order_buffers_data.get();
            buff->last_id = 0;
            buff->complete = false;
            buff->data->resize(pkt->header.data_max_size);
            buff->data_per_pkt_size = pkt->header.data_size;
            if (pkt->header.seq_max && pkt->header.seq == pkt->header.seq_max) //handle 1 special case
                buff->data_per_pkt_size = (pkt->header.data_max_size - pkt->header.data_size) / pkt->header.seq_max;
            buff->data_count = pkt->header.seq_max + 1;
            buff->data_map.resize(buff->data_count, 0);
            buff->data_map.assign(buff->data_map.size(), false);
            buff->ack_id = 0;
            buff->timeout.set_interval(1000 * 30);
            buff->timeout.reset();

            orders[pkt->header.ticketid] = buff;

        }

        buff->timeout.reset();

        //send a ping answer for every first seq in the buffer
        if (pkt->header.seq == 0)
        {
            shznet_pkt_ack ack;
            ack.sessionid = pkt->header.sessionid;
            ack.ticketid = pkt->header.ticketid;
            memcpy(ack.mac, local_mac().mac, 6);
            ack.type = shznet_ack_request_ping;
            ack.missing_start_id = -1;
            ack.missing_end_id = -1;
            ack.ack_id = 0;
            ack.make_checksum();
            m_udp.send_buffered_prio(adr, (byte*)&ack, sizeof(shznet_pkt_ack));
        }

        if (buff->data)
        {
            uint64_t byte_offset = pkt->header.seq * buff->data_per_pkt_size;

            pkt->header.data_size = std::min(pkt->header.data_size, (uint32_t)buff->data_per_pkt_size);

            if (byte_offset + pkt->header.data_size > buff->data->size())
            {
                NETPRNT("error: buffer overrun while receiving.");
                return;
            }

            if (pkt->header.seq >= buff->data_map.size())
            {
                buff->data_map.resize(buff->data_count, 0);
                buff->data_count = pkt->header.seq_max + 1;
            }

            if (buff->data_map[pkt->header.seq])
            {
                NETPRNT("pkt bit already set!");
                return;
            }
            memcpy(&buff->data->data()[byte_offset], pkt->data, pkt->header.data_size);
            buff->data_map[pkt->header.seq] = 1;
            buff->data_count--;
        }
        //when finished, set buff->data to zero and recycle!!!

        if (pkt->header.seq > 0 && pkt->header.seq > buff->last_id + 1)
        {
            //NETPRNT("missing packets ack!");
            //send ack for missing packets here...
            uint64_t missing_start = buff->last_id + 1;
            uint64_t missing_end = pkt->header.seq - 1;

            shznet_pkt_ack ack;
            ack.type = shznet_ack_request_quick_resend;
            ack.sessionid = pkt->header.sessionid;
            ack.ticketid = pkt->header.ticketid;
            ack.missing_start_id = missing_start;
            ack.missing_end_id = missing_end;
            ack.ack_id = 0;
            memcpy(ack.mac, local_mac().mac, 6);
            ack.make_checksum();
            m_udp.send_buffered_prio(adr, (byte*)&ack, sizeof(shznet_pkt_ack));
            buff->last_id = pkt->header.seq;
        }
        else if(pkt->header.seq > buff->last_id)
            buff->last_id = pkt->header.seq;

        if (buff->last_id == pkt->header.seq_max || buff->should_complete)
        {
            if (!buff->complete)
            {
                //bool allTrue = std::all_of(buff->data_map.begin(), buff->data_map.end(), [](bool value) { return value; });
                bool allTrue = buff->data_count == 0;
                if (allTrue)
                {
                    buff->complete = true;
                    push_generic_to_main_thread(adr, pkt, buff);

                    shznet_pkt_ack ack;
                    ack.sessionid = pkt->header.sessionid;
                    ack.ticketid = pkt->header.ticketid;
                    memcpy(ack.mac, local_mac().mac, 6);
                    ack.type = shznet_ack_request_complete;
                    ack.missing_start_id = 0;
                    ack.missing_end_id = -1;
                    ack.ack_id = 0;
                    ack.make_checksum();
                    m_udp.send_buffered_prio(adr, (byte*)&ack, sizeof(shznet_pkt_ack));
                }
            }
        }
    }

    virtual void handle_shizonet_stream(shznet_ip& adr, shznet_pkt* pkt, uint32_t pkt_size)
    {
        if (!check_open_stream(pkt->get_cmd()))
            return;

        if (!pkt->check_packet(pkt_size))
            return;

        shznet_mac target_mac(pkt->source_mac());

        auto &ep = m_stream_endpoints[target_mac];

        auto& orders = ep.orders;

        shznet_order_buffer* buff = 0;

        auto entry = orders.find(pkt->header.ticketid);
        if (entry != orders.end())
            buff = entry->second;
        else if (pkt->header.seq > 0) //we missed packets already, no sense in receiving the rest of the broken packet...
            return;
        else
        {
            buff = order_buffers.get();
            buff->address.ip = adr;
            buff->address.mac = pkt->source_mac();
            buff->ticketid = pkt->header.ticketid;
            if (buff->data)
            {
                NETPRNT("error: buff still has data?");
            }
            else
                buff->data = order_buffers_data.get();
            buff->last_id = 0;
            buff->complete = false;
            buff->data->resize(pkt->header.data_max_size);
            buff->data_per_pkt_size = pkt->header.data_size;
            if (pkt->header.seq_max && pkt->header.seq == pkt->header.seq_max) //handle 1 special case
                buff->data_per_pkt_size = (pkt->header.data_max_size - pkt->header.data_size) / pkt->header.seq_max;
            buff->data_count = pkt->header.seq_max + 1;
            buff->data_map.resize(buff->data_count);
            buff->data_map.assign(buff->data_map.size(), false);
            buff->ack_id = 0;
            buff->timeout.set_interval(1000 * 30);
            buff->timeout.reset();
            orders[pkt->header.ticketid] = buff;

        }

        buff->timeout.reset();

        if (buff->data)
        {
            uint64_t byte_offset = pkt->header.seq * buff->data_per_pkt_size;

            pkt->header.data_size = std::min(pkt->header.data_size, (uint32_t)buff->data_per_pkt_size);

            if (byte_offset + pkt->header.data_size > buff->data->size())
            {
                NETPRNT("error: buffer overrun while receiving.");
                orders.erase(pkt->header.ticketid); //missed packets, no sense in receiving more packets here
                return;
            }

            if (buff->data_map[pkt->header.seq])
            {
                NETPRNT("pkt bit already set!");
                return;
            }
            memcpy(&buff->data->data()[byte_offset], pkt->data, pkt->header.data_size);
            buff->data_map[pkt->header.seq] = 1;
            buff->data_count--;
        }
        //when finished, set buff->data to zero and recycle!!!

        if (pkt->header.seq > 0 && pkt->header.seq > buff->last_id + 1)
        {
            orders.erase(pkt->header.ticketid); //missed packets, no sense in receiving more packets here
            return;
        }
        else if (pkt->header.seq > buff->last_id)
            buff->last_id = pkt->header.seq;

        if (buff->last_id == pkt->header.seq_max || buff->should_complete)
        {
            if (!buff->complete)
            {
                //bool allTrue = std::all_of(buff->data_map.begin(), buff->data_map.end(), [](bool value) { return value; });
                bool allTrue = buff->data_count == 0;
                if (allTrue)
                {
                    buff->complete = true;
                    push_generic_to_main_thread(adr, pkt, buff);
                }
            }
        }
    }

    virtual void handle_shizonet_ack_request(shznet_ip& adr, shznet_pkt_ack_request* pkt)
    {
        shznet_mac target_mac(pkt->mac);

        auto ep = m_endpoints.find(target_mac);
        if (ep == m_endpoints.end() || pkt->sessionid != ep->second.sessionid)
        {
            NETPRNT("invalid ackreq pkt received!");
            shznet_pkt_ack ack;
            ack.sessionid = pkt->sessionid;
            ack.ticketid = pkt->ticketid;
            memcpy(ack.mac, local_mac().mac, 6);
            ack.type = pkt->type;
            ack.missing_start_id = -2;
            ack.missing_end_id = -2;
            ack.ack_id = pkt->ack_id;
            ack.make_checksum();
            m_udp.send_buffered_prio(adr, (byte*)&ack, sizeof(shznet_pkt_ack));
            return;
        }

        auto& orders = ep->second.orders;

        shznet_pkt_ack ack;
        ack.sessionid = pkt->sessionid;
        ack.ticketid = pkt->ticketid;
        memcpy(ack.mac, local_mac().mac, 6);
        ack.type = pkt->type;
        ack.ack_id = pkt->ack_id;
      
        //do ack request ping pong to first check for complete, then check for delete ??
        //check for delete, if missing_start and missing_end == -1 (not found) its ok on server

        auto entry = orders.find(pkt->ticketid);
        if (entry != orders.end())
        {
            auto buff = entry->second;
            buff->timeout.reset();

            bool was_new_ack = buff->ack_id != pkt->ack_id;

            buff->ack_id = pkt->ack_id;

            if (pkt->type == shznet_ack_request_complete)
            {
                buff->should_complete = true;
                //missing start id == -1 and end == -1 means buffer not found
                //missing start == 0 and end == -1 means it has completed

                if (buff->complete)
                {
                    ack.missing_start_id = 0;
                    ack.missing_end_id = -1;
                    ack.make_checksum();
                    m_udp.send_buffered_prio(adr, (byte*)&ack, sizeof(shznet_pkt_ack));
                    return;
                }

                if (buff->data_count == 0)
                    return;


                int64_t missing_start = 0;
                int64_t missing_end = -1;

                //only send missing packets once per unique ack request to counteract network spam...
                if (was_new_ack)
                {
                    for (int64_t i = 0; i < buff->data_map.size(); i++)
                    {
                        if (!buff->data_map[i])
                        {
                            missing_start = i;
                            missing_end = i;
                            for (int64_t j = i + 1; j < buff->data_map.size(); j++)
                            {
                                if (!buff->data_map[j])
                                    missing_end = j;
                                else
                                    break;
                            }
                            ack.missing_start_id = missing_start;
                            ack.missing_end_id = missing_end;
                            ack.type = shznet_ack_request_resend;
                            ack.make_checksum();
                            if (!m_udp.send_buffered_prio(adr, (byte*)&ack, sizeof(shznet_pkt_ack)))
                            {
                                NETPRNT("send buffered failed!");
                                return;
                            }
                            i = missing_end;
                        }
                    }
                }


                ack.type = shznet_ack_request_complete;
                ack.missing_start_id = -3;
                ack.missing_end_id = -3;
                ack.make_checksum();
                m_udp.send_buffered_prio(adr, (byte*)&ack, sizeof(shznet_pkt_ack));
            }
            else if (pkt->type == shznet_ack_request_delete_buffer)
            {
                order_buffers_data.recycle(entry->second->data);
                entry->second->data = 0;
                entry->second->reset();
                order_buffers.recycle(entry->second);
                orders.erase(entry);
                //clear cmd buffer here
                ack.missing_start_id = 0;
                ack.missing_end_id = 0;
                ack.make_checksum();
                m_udp.send_buffered_prio(adr, (byte*)&ack, sizeof(shznet_pkt_ack));
            }
         
        }
        else //order not found, request to resend the whole order...
        {
            ack.missing_start_id = -2;
            ack.missing_end_id = -2;
            ack.make_checksum();
            m_udp.send_buffered_prio(adr, (byte*)&ack, sizeof(shznet_pkt_ack));
        }
    }

    virtual void handle_shizonet_ack(shznet_ip& adr, shznet_pkt_ack* pkt) //override this in base
    {

    }

    virtual void handle_shizonet_alive_check(shznet_ip& adr, shznet_pkt* pkt)
    {
        shznet_mac target_mac(pkt->source_mac());
        auto ep = m_endpoints.find(target_mac);
        shznet_sessionid sid = -1;
        if (ep != m_endpoints.end())
            sid = ep->second.sessionid;
        m_send_buffer2.packet_begin(SHZNET_PKT_ALIVE_CHECK_REPL, get_udp().local_adr().mac, target_mac, 0, sid);
        uint32_t pkt_size = m_send_buffer2.packet_end();
        m_udp.send_buffered_prio(adr, (uint8_t*)&m_send_buffer2, pkt_size);
    }

    void send_art_poll_reply(shznet_ip& adr)
    {
        auto local_ip = m_udp.local_adr();

        uint8_t  node_ip_address[4];
        uint8_t  id[8];

        node_ip_address[0] = local_ip.ip.ip[0];
        node_ip_address[1] = local_ip.ip.ip[1];
        node_ip_address[2] = local_ip.ip.ip[2];
        node_ip_address[3] = local_ip.ip.ip[3];

        sprintf((char*)id, "Art-Net");
        memcpy(art_poll_reply.id, id, sizeof(art_poll_reply.id));
        memcpy(art_poll_reply.ip, node_ip_address, sizeof(art_poll_reply.ip));
        memcpy(art_poll_reply.mac, local_ip.mac.mac, 6);

        art_poll_reply.opCode = ART_POLL_REPLY;
        art_poll_reply.port = m_udp.local_adr().ip.port;

        memset(art_poll_reply.goodinput, 0x08, 4);
        memset(art_poll_reply.goodoutput, 0x80, 4);
        memset(art_poll_reply.porttypes, 0xc0, 4);

        uint8_t shortname[18];
        uint8_t longname[64];
        sprintf((char*)shortname, m_nodename.c_str());
        sprintf((char*)longname, "Artnet -> ShizoNet Bridge");
        memcpy(art_poll_reply.shortname, shortname, sizeof(shortname));
        memcpy(art_poll_reply.longname, longname, sizeof(longname));

        art_poll_reply.etsaman[0] = 0;
        art_poll_reply.etsaman[1] = 0;
        art_poll_reply.verH = 1;
        art_poll_reply.ver = 0;
        art_poll_reply.subH = 0;
        art_poll_reply.sub = 0;
        art_poll_reply.oemH = 0;
        art_poll_reply.oem = 0xFF;
        art_poll_reply.ubea = 0;
        art_poll_reply.status = 0xd2;
        art_poll_reply.swvideo = 0;
        art_poll_reply.swmacro = 0;
        art_poll_reply.swremote = 0;
        art_poll_reply.style = 0;

        art_poll_reply.numbportsH = 0;
        art_poll_reply.numbports = 4;
        art_poll_reply.status2 = 0x08;

        art_poll_reply.bindip[0] = node_ip_address[0];
        art_poll_reply.bindip[1] = node_ip_address[1];
        art_poll_reply.bindip[2] = node_ip_address[2];
        art_poll_reply.bindip[3] = node_ip_address[3];

        uint8_t swin[4] = { 0x01,0x02,0x03,0x04 };
        uint8_t swout[4] = { 0x01,0x02,0x03,0x04 };
        for (uint8_t i = 0; i < 4; i++)
        {
            art_poll_reply.swout[i] = swout[i];
            art_poll_reply.swin[i] = swin[i];
        }
        sprintf((char*)art_poll_reply.nodereport, "%i DMX output universes active.", art_poll_reply.numbports);

        m_udp.send_packet_artnet(adr, (byte*)&art_poll_reply, sizeof(art_poll_reply));
    }

    shznet_mac& local_mac()
    {
        return m_udp.local_adr().mac;
    }
    shznet_ip& local_ip()
    {
        return m_udp.local_adr().ip;
    }

    float artnet_fps()
    {
        return m_artnet_fps;
    }

    float artnet_maxfps()
    {
        return m_artnet_maxfps;
    }

protected:
    artnet_poll_reply art_poll_reply;

    std::function<void(uint16_t universe, uint16_t length, uint8_t sequence, uint8_t* data, shznet_ip remoteIP)> art_dmx_callback = 0;
    std::function<void(uint64_t)> art_frame_callback = 0;
    shznet_timer art_sync_timer = shznet_timer(1000 * 10);

    bool            artnet_frame_due = false;
    shznet_timer    artnet_frame_timer = shznet_timer(4);
    uint64_t        artnet_last_frame_time = 0;

    struct dmx_cache_s
    {
        char             active[ARTNET_UNIVERSE_MAX];
        uint64_t         last[ARTNET_UNIVERSE_MAX];
        uint64_t         last_recv_time[ARTNET_UNIVERSE_MAX];
        float            fps[ARTNET_UNIVERSE_MAX];
        short            rcv1[ARTNET_UNIVERSE_MAX];
        short            rcv2[ARTNET_UNIVERSE_MAX];
        bool             dmx_active = false;
    };

    dmx_cache_s* dmx_frame = 0;
    shznet_timer dmx_update = shznet_timer(300);

};

#ifndef SHIZONET_NO_BASE
#define SHIZONET_BASE

#include <map>

enum shznet_device_type
{
    SHZNET_DEV_ARTNET,
    SHZNET_DEV_DEFAULT
};

enum SHZNET_AUTHSTATE
{
    SHZNET_AUTH_DENIED,
    SHZNET_AUTH_PENDING,
    SHZNET_AUTH_GETINFO,
    SHZNET_AUTH_SUCCESS
};

struct shznet_global_s
{
    shznet_sessionid get_new_sessionid();
    shznet_ticketid get_new_ticketid();
};

extern shznet_global_s shznet_global;

typedef std::function<void(byte* data, size_t size, shznet_pkt_dataformat fmt, bool success)> shznet_response_callback;

class shznet_base_impl;
class shznet_base;

#define SHZNET_TEST_CMD                     "shznet_init_connection"
#define SHZNET_TEST_CMD_RESPONSE            "shznet_finalize_connection"


#define SHZNET_RESPONSE_CMD                 "shznet_cmd"
#define SHZNET_RESPONSE_ACK_CMD_NOTFOUND    "shznet_response_ack_notfound"
#define SHZNET_RESPONSE_ACK_CMD_SUCCESS     "shznet_response_ack_success"
#define SHZNET_RESPONSE_ACK_CMD_FAIL        "shznet_response_ack_fail"

#ifdef _WIN32
#undef min
#undef max
#endif

class shznet_device
{
    struct auth_info_s
    {
        shznet_timer timeout = shznet_timer(1000 * 5);
        shznet_timer resend_timer = shznet_timer(100);
        SHZNET_AUTHSTATE state = SHZNET_AUTH_DENIED;
        shznet_sessionid sessionid;

        shznet_timer connect_guard = shznet_timer(1000 * 5);

        auth_info_s()
        {
            sessionid = shznet_global.get_new_sessionid();
            timeout.reset();
            connect_guard.reset();
        }
    };

    struct command_buffer_s
    {
        shznet_ticketid ticketid;
        uint64_t send_index;
        uint64_t timeout;
        shznet_timer timeout_counter;
        shznet_timer_exp ack_counter;
        shznet_timer start_time;
        shznet_vector<shznet_pkt> pkts;
        shznet_timer ping_timer;

        bool start_ack;
        bool start_cleanup;

        bool device_busy = false;
        shznet_timer device_busy_timer = shznet_timer(1000 * 2);

        std::vector<bool> missing_chunks;
        uint64_t missing_chunk_low = -1;
        uint64_t missing_chunk_high = -1;

        uint64_t error_counter = 0;
        uint32_t ack_id = 1;

        size_t total_size()
        {
            return sizeof(command_buffer_s) + pkts.capacity() * sizeof(shznet_pkt) + missing_chunks.size();
        }
    };

    //only actually allocate the buffer once we start writing (and therefore sending) to it
    //This buffer type has no "sync" functionality, as in it is not synchronized first
    //Add other synced buffer types later, this is mainly to replace artnets "universe" system with something more modern
    struct network_buffer_static_s
    {
        //One chunk size which holds a dirty flag is 256 bytes
        const int single_chunk_size = 256;
        const int max_packet_payload = 1300;

        network_buffer_static_type type;
        std::vector<byte> buffer;
        std::vector<bool> buffer_parts_dirty;
        bool buffer_dirty;
        //Human readable fields
        std::string name;
        std::string description;
        //Machine readable field (for example a json string, implement as you wish)
        std::string setup;
        uint32_t requested_size;
        uint32_t name_hash;

        network_buffer_static_s() = default;
        network_buffer_static_s(const char* buffer_name, network_buffer_static_type buffer_type, uint32_t buffer_size, std::string buffer_desc, std::string buffer_setup)
        {
            type = buffer_type;
            name = buffer_name;
            requested_size = buffer_size;
            description = buffer_desc;
            setup = buffer_setup;
            buffer_dirty = false;
            buffer.resize(0);
            buffer.reserve(0);
            buffer_parts_dirty.resize(0);
            buffer_parts_dirty.reserve(0);

            name_hash = shznet_hash(buffer_name);
        }

        void ensure_init()
        {
            if (buffer.size() != requested_size)
            {
                buffer.resize(requested_size);
                memset(buffer.data(), 0, buffer.size());
                buffer_parts_dirty.resize(requested_size / single_chunk_size + 1);
                for (uint32_t i = 0; i < buffer_parts_dirty.size(); i++)
                    buffer_parts_dirty[i] = true;
                buffer_dirty = true;
            }
        }

        void write_data(uint32_t offset, byte* data, uint32_t size)
        {
            ensure_init();

            if (offset >= buffer.size())
                return;
            if (offset + size > buffer.size())
                size = buffer.size() - offset;

            memcpy(&buffer[offset], data, size);

            set_dirty(offset, size);
        }

        void set_dirty(uint32_t offset, uint32_t size)
        {
            uint32_t chunk_start = offset / single_chunk_size;
            uint32_t chunk_count = size / single_chunk_size + 1;

            for (uint32_t i = chunk_start; i < chunk_start + chunk_count; i++)
            {
                buffer_parts_dirty[i] = true;
            }

            buffer_dirty = true;
        }

        //HANDLING
        bool next_chunk(shznet_kv_writer& writer)
        {
            while (true)
            {
                uint32_t chunk_start = _chunk_index;

                for (; chunk_start < buffer_parts_dirty.size(); chunk_start++)
                {
                    if (buffer_parts_dirty[chunk_start])
                        break;
                }

                if (chunk_start >= buffer_parts_dirty.size())
                {
                    buffer_dirty = std::none_of(buffer_parts_dirty.begin(), buffer_parts_dirty.end(), [](bool b) { return b; });
                    _chunk_index = 0;
                    return true;
                }

                uint32_t chunk_end = chunk_start;
                uint32_t chunk_count = 0;

                for (; chunk_end < buffer_parts_dirty.size(); chunk_end++, chunk_count++)
                {
                    if (!buffer_parts_dirty[chunk_start] || writer.get_buffer().size() + (chunk_count + 1) * single_chunk_size > max_packet_payload)
                        break;
                }

                //We have chunks to send, but next packets payload is too big, so cause back pressure
                if (chunk_count == 0)
                {
                    return false;
                }

                writer.add_int32("name", name_hash);
                writer.add_int32("start", chunk_start);
                uint32_t rest_data_size = buffer.size() - chunk_start * single_chunk_size;
                writer.add_data("data", &buffer[chunk_start * single_chunk_size], std::min(chunk_count * single_chunk_size, rest_data_size));

                for (uint32_t i = chunk_start; i < chunk_end; i++)
                    buffer_parts_dirty[i] = false;

                _chunk_index = chunk_end + 1;
            }

            return true;
        }


        uint32_t _chunk_index = 0;
    };

    struct fetch_command_s
    {
        std::string command;
        std::vector<byte> buffer;
        shznet_pkt_dataformat format;
        shznet_response_callback callback;
        shznet_timer timeout_timer;

        fetch_command_s() = default;
        fetch_command_s(const char* cmd, byte* data, size_t size, shznet_pkt_dataformat fmt, shznet_response_callback cb, uint64_t timeout)
        {
            command = cmd;
            if (data && size)
            {
                buffer.resize(size);
                memcpy(buffer.data(), data, size);
            }
            else
                buffer.resize(0);
            format = fmt;
            callback = cb;
            timeout_timer.set_interval(timeout);
            timeout_timer.reset();
        }
    };

    static shznet_recycler<command_buffer_s>                reliable_buffers;
    std::queue<command_buffer_s*>                           zombie_buffers;
    std::queue<command_buffer_s*>                           ordered_buffers;
    std::vector<command_buffer_s*>                          unordered_buffers;
    //more aggressive commands, do not get cleared when device disconnects, only when timeout runs out (or the command WAS executed)
    //in contrast to the other buffers, this one is NEVER cleared! even if the device disconnects (to ensure continuity)
    std::vector<std::shared_ptr<fetch_command_s>>           fetch_commands;

    //Special: Like artnet universes buffer, but more dynamic
    std::unordered_map<uint32_t, std::shared_ptr<network_buffer_static_s>>      network_buffers_static; //uint32_t is shznet_hash of buffer name
    std::vector<std::shared_ptr<network_buffer_static_s>>                       network_buffers_static_list;
    std::vector<std::shared_ptr<network_buffer_static_s>>                       network_buffers_static_list_leds;
    std::vector<std::shared_ptr<network_buffer_static_s>>                       network_buffers_static_list_data;

    shznet_kv_writer network_buffer_send;
    uint32_t network_buffer_current = 0;

    std::vector<command_buffer_s*>              response_buffers;

    std::vector < std::pair<shznet_ticketid, std::function<void(bool)>>> send_finish_callbacks;
    
    shznet_small_allocator<auth_info_s> auth;

    uint64_t unique_id = 0;

    bool receiver_only = false;

    bool order_valid(shznet_ticketid id)
    {
        if (ordered_buffers.front()->ticketid == id)
            return true;
        for (auto& it : unordered_buffers)
            if (it->ticketid == id)
                return true;
        return false;
    }

protected:
    shznet_base_impl*   base = 0;
    std::string         name;
    std::string         description;
    shznet_adr          address;
    shznet_device_type  type;
    shznet_timer        timeout;
    shznet_timer        offline_timeout;
    shznet_timer_exp    alive_timeout;
    shznet_timer        reconnect_timer = shznet_timer(1000 * 10);
    bool                connected = false;
    bool                was_connected = false;
    uint32_t            max_packets_before_pacing = 0;

    bool m_valid = true;
    bool m_alive_request = false;

    int m_max_parallel_queries = 64;
    int m_max_data_size = 0;

    uint64_t network_measure_timer = 0;
    int pps_counter = 0, bps_counter = 0;
    int pps = 0, bps = 0;
    float error_rate = 0;

    float max_pkts_per_loop = 100.0;
    float current_pkts_per_loop = 0.0;

    int m_ping = 1;
 
    friend class shznet_base_impl;
    friend class shznet_base;

    shznet_ticketid m_ticketid_counter = 1;

    enum command_buffer_state
    {
        command_buffer_send_fail,
        command_buffer_wait_ack,
        command_buffer_sending
    };

    command_buffer_state send_command_buffer(command_buffer_s* buff)
    {
        if (buff->send_index < buff->pkts.size())
        {
            //send 64 packets at a time so unordered packets can shuffle...
            uint64_t current_time = shznet_millis();
            for (uint32_t i = 0; i < 64; i++)
            {
                if (buff->send_index == buff->pkts.size())
                    break;

                if (current_pkts_per_loop >= max_pkts_per_loop || check_packet_pacing(false))
                    return command_buffer_send_fail;

                shznet_pkt& pkt = buff->pkts[buff->send_index];
                
                if (!sendto(&pkt, pkt.get_packet_size()))
                {
                    return command_buffer_send_fail;
                }

                check_packet_pacing();

                if (pkt.header.seq == 0)
                    buff->ping_timer.reset();

                pps_counter++;
                bps_counter += pkt.get_packet_size();
                buff->send_index++;


                current_pkts_per_loop += 1.f;
            }

            //no point in resending missing chunks while the sequence is still being sent
            //will just confuse the receiver
            //However, when we're finished sending we can start sending/flushing etc...
            if(buff->send_index != buff->pkts.size())
                return command_buffer_sending;
        }

        if (buff->missing_chunks.size() && buff->missing_chunk_low != -1 && buff->missing_chunk_high != -1)
        {
            //if (!buff->start_ack)
            {
                for (uint64_t chunk_id = buff->missing_chunk_low, max_count = 0; chunk_id <= buff->missing_chunk_high; chunk_id++, max_count++)
                {
                    if (max_count >= 64)
                        return command_buffer_sending;

                    if (!buff->missing_chunks[chunk_id])
                    {
                        buff->missing_chunk_low = chunk_id + 1;
                        if (buff->missing_chunk_low > buff->missing_chunk_high)
                        {
                            buff->missing_chunk_low = -1;
                            buff->missing_chunk_high = -1;
                            break;
                        }

                        continue;
                    }

                    if (current_pkts_per_loop >= max_pkts_per_loop || check_packet_pacing(false))
                        return command_buffer_send_fail;

                    shznet_pkt& pkt = buff->pkts[chunk_id];
                    if (!sendto(&pkt, pkt.get_packet_size()))
                    {
                        flush_send_buffers();
                        return command_buffer_send_fail;
                    }

                    check_packet_pacing();

                    buff->error_counter++;

                    if (pkt.header.seq == 0)
                        buff->ping_timer.reset();
                    buff->missing_chunks[chunk_id] = 0;
                    buff->missing_chunk_low = chunk_id + 1;
                    if (buff->missing_chunk_low > buff->missing_chunk_high)
                    {
                        buff->missing_chunk_low = -1;
                        buff->missing_chunk_high = -1;
                        break;
                    }

                    pps_counter++;
                    bps_counter += pkt.get_packet_size();
                    current_pkts_per_loop += 1.f;
                }

                buff->missing_chunk_low = -1;
                buff->missing_chunk_high = -1;
            }
        }
        

        if (!buff->start_ack)
        {
            buff->start_ack = true;
            buff->ack_counter.set_interval(2, 9); //exponential increasing interval of requesting the status of this order again
        }
        else if (!buff->ack_counter.update())
            return command_buffer_wait_ack;

        shznet_pkt_ack_request req;
            
        req.type = buff->start_cleanup ? shznet_ack_request_delete_buffer : shznet_ack_request_complete;
        req.sessionid = get_sessionid();
        req.ticketid = buff->ticketid;
        req.ack_id = buff->ack_id;

        memcpy(req.mac, get_local_mac().mac, 6);

        req.make_checksum();
            
        if (!sendto(&req, sizeof(shznet_pkt_ack_request)))
        {
            return command_buffer_send_fail;
        }

        pps_counter++;
        bps_counter += sizeof(shznet_pkt_ack_request);

        return command_buffer_wait_ack;
    }

    void clear_command_buffers();

    void calculate_error_rate(command_buffer_s* buff)
    {
        // Exponential smoothing for error rate measurement
        float current_error = buff->error_counter / float(buff->pkts.size());
        error_rate = error_rate * 0.95f + current_error * 0.05f;
        error_rate = std::max(0.f, std::min(1.f, error_rate));

        if (error_rate > 0.5)
            max_pkts_per_loop *= 0.99f; // reduce by 1%
        else if (error_rate > 0.1)
            max_pkts_per_loop *= 0.999f; // reduce by 0.1%
        // If error is below target, increase sending rate additively
        else if (error_rate < 0.05)
            max_pkts_per_loop += 1.01f; // add a small constant step

        // Clamp the sending rate to acceptable bounds
        max_pkts_per_loop = std::min(1000.f, std::max(max_pkts_per_loop, 0.1f));
    }

    void clear_command_buffer(shznet_ticketid ticketid, bool cmd_failed = false, bool check_responses = true);

    command_buffer_s* get_free_buffer(size_t pkt_size, uint64_t timeout)
    {
        auto cmd_buf = reliable_buffers.get();

        cmd_buf->missing_chunk_low = -1;
        cmd_buf->missing_chunk_high = -1;
        cmd_buf->missing_chunks.clear();

        cmd_buf->send_index = 0;
        cmd_buf->start_ack = 0;
        cmd_buf->start_cleanup = 0;
        cmd_buf->ticketid = get_new_ticketid();
        cmd_buf->timeout = timeout;
        cmd_buf->timeout_counter.set_interval(timeout);
        cmd_buf->pkts.resize(pkt_size);
        cmd_buf->error_counter = 0;
        cmd_buf->ack_id = 1;

        cmd_buf->device_busy = false;

        cmd_buf->start_time.reset();

        return cmd_buf;
    }

    void flush_send_buffers();

public:

    std::unordered_map<uint32_t, std::string> command_map;
    std::unordered_map<uint32_t, std::string> command_response_map;

    shznet_device(shznet_base_impl* _base, shznet_adr& adr, std::string _name = "", std::string _description = "")
    {
        base = _base;
        if (_name.length() > 16)
        {
            NETPRNT_FMT("truncating name (too int): %s\n", _name.c_str());
            _name = _name.substr(0, 16);
        }
        if (_description.length() > 62)
        {
            NETPRNT_FMT("truncating description (too int): %s\n", _description.c_str());
            _description = _description.substr(0, 62);
        }

        name = _name;
        description = _description;

        timeout.set_interval(1000 * 60);

        offline_timeout.set_interval(1000 * 60 * 60 * 24);

        address = adr;

        network_measure_timer = shznet_millis();
    }

    ~shznet_device()
    {
        clear_command_buffers();
    }

    shznet_base_impl* get_base() { return base; }

    int max_parallel_queries()
    {
        return m_max_parallel_queries;
    }
    int max_data_size()
    {
        return m_max_data_size;
    }

    void reconnect_device(shznet_adr& adr, shznet_device_type _type, std::string _name = "", std::string _description = "")
    {
        if (_name.length() > 16)
        {
            NETPRNT_FMT("truncating name (too int): %s\n", _name.c_str());
            _name = _name.substr(0, 16);
        }
        if (_description.length() > 62)
        {
            NETPRNT_FMT("truncating description (too int): %s\n", _description.c_str());
            _description = _description.substr(0, 62);
        }

        name = _name;
        description = _description;
        type = _type;
        if (_type == SHZNET_DEV_ARTNET)
            timeout.set_interval(1000 * 6);
        else
            timeout.set_interval(1000 * 10);

        offline_timeout.set_interval(1000 * 60 * 10);

        reconnect_device(adr);
    }

    void reconnect_device(shznet_adr& adr)
    {
        receiver_only = false;
        address = adr;
        m_valid = true;
        m_alive_request = false;
        if (auth.allocated())
            auth->connect_guard.reset();
        reset_timeout();
        reset_offline_timeout();
        unique_id++;
        network_measure_timer = shznet_millis();
    }

    uint64_t get_unique_id()
    {
        return unique_id; //this increases with every reconnect, use to check if still connected
    }

    void update_address(shznet_adr& adr)
    {
        address = adr;
    }

    void set_invalid() {
        m_valid = false;
        m_alive_request = false;
        connected = false;
        m_ticketid_counter = 1;
        reset_offline_timeout();
        if (auth.allocated())
            auth.release();

        clear_command_buffers();

        for (auto& it : send_finish_callbacks)
            it.second(false);
        send_finish_callbacks.clear();

        reconnect_timer.reset();
    }

    bool valid() {
        return m_valid;
    }

    bool online() {
        return m_valid && connected;
    }

    void reset_timeout()
    {
        timeout.reset();
        m_alive_request = false;
    }

    bool is_timeout()
    {
        return timeout.update();
    }

    void reset_offline_timeout()
    {
        offline_timeout.reset();
    }

    bool is_offline_timeout()
    {
        return offline_timeout.update();
    }

    void set_name(std::string _name) {
        name = _name;
    }
    void set_description(std::string _desc) {
        description = _desc;
    }
    void set_type(shznet_device_type _type) {
        type = _type;
    }
    void set_ip(shznet_ip ip) {
        address.ip = ip;
    }
    void set_mac(shznet_mac mac) {
        address.mac = mac;
    }

    std::string& get_name() {
        return name;
    }
    std::string& get_description() {
        return description;
    }
    shznet_device_type get_type() {
        return type;
    }
    shznet_ip& get_ip() {
        return address.ip;
    }
    shznet_mac& get_mac() {
        return address.mac;
    }
    shznet_adr& get_address() {
        return address;
    }
    shznet_sessionid get_sessionid()
    {
        if (auth.allocated())
            return auth->sessionid;
        return INVALID_SESSIONID;
    }
    shznet_ticketid get_new_ticketid()
    {
        auto tid = m_ticketid_counter;
        m_ticketid_counter++;
        if (m_ticketid_counter == -1)
            m_ticketid_counter = 1;
        return tid;
    }

    std::vector<std::string> get_static_buffer_names()
    {
        std::vector<std::string> result;
        for (auto& it : network_buffers_static)
            result.push_back(it.second->name);
        return result;
    }

    std::string get_static_buffer_desc(std::string& name)
    {
        auto hs = shznet_hash(name);
        auto it = network_buffers_static.find(hs);
        if (it == network_buffers_static.end())
            return "";
        return it->second->description;
    }

    std::string get_static_buffer_setup(std::string& name)
    {
        auto hs = shznet_hash(name);
        auto it = network_buffers_static.find(hs);
        if (it == network_buffers_static.end())
            return "";
        return it->second->setup;
    }

    uint32_t get_static_buffer_size(std::string& name)
    {
        auto hs = shznet_hash(name);
        auto it = network_buffers_static.find(hs);
        if (it == network_buffers_static.end())
            return 0;
        return it->second->requested_size;
    }

    network_buffer_static_type get_static_buffer_type(std::string& name)
    {
        auto hs = shznet_hash(name);
        auto it = network_buffers_static.find(hs);
        if (it == network_buffers_static.end())
            return NETWORK_BUFFER_STATIC_DATA;
        return it->second->type;
    }


    bool send_unreliable(const char* cmd, byte* data, size_t size, shznet_pkt_dataformat fmt = SHZNET_PKT_FMT_DATA)
    {
        if (!size || !data) return 1;
        if (!base) return 0;
        if (type != SHZNET_DEV_DEFAULT)
            return 0;
        if (!m_valid)
            return 0;

        size_t max_data_size = std::min((uint32_t)SHZNET_PKT_DATA_SIZE, (uint32_t)m_max_data_size);

        if (size <= max_data_size)
        {
            auto buf = get_sendpacket();

            buf.packet_begin(SHZNET_PKT_OOB, get_local_mac(), get_mac(), get_new_ticketid(), get_sessionid());
            buf.packet_set_cmd((char*)cmd);
            buf.packet_set_data(data, size);
            buf.packet_set_unreliable();
            buf.packet_set_format(fmt);
            auto total_size = buf.packet_end();
            return sendto((byte*)&buf, total_size);
        }

        //sequence the packet !
        
        uint32_t max_sequence = size / max_data_size;

        //special case
        if (max_sequence * max_data_size == size && max_sequence)
            max_sequence--;

        auto buf = get_sendpacket_big();

        buf.packet_begin(SHZNET_PKT_OOB, get_local_mac(), get_mac(), get_new_ticketid(), get_sessionid());
        buf.packet_set_unreliable();
        buf.packet_set_format(fmt);
        buf.packet_set_cmd((char*)cmd);

        uint32_t data_index = 0;

        for (uint32_t i = 0; i <= max_sequence; i++)
        {
            buf.packet_set_data(&data[data_index], std::min(max_data_size, (size_t)(size - data_index)), size);
            buf.packet_set_seq(i, max_sequence);
            auto total_size = buf.packet_end();
            if (!sendto((byte*)&buf, total_size))
            {
                //NETPRNT("sendto failed!");
                return 0;
            }

            data_index += max_data_size;
                //std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        return 1;
    }

    shznet_ticketid send_reliable(const char* cmd, byte* data, size_t size, shznet_pkt_dataformat fmt = SHZNET_PKT_FMT_DATA, bool sequential = true, uint64_t timeout = 0)
    {
        if (!size || !data) return -1;
        if (!base) return -1;
        if (type != SHZNET_DEV_DEFAULT)
            return -1;
        if (!m_valid)
            return -1;

        //max pkt size obsolete? dont think I will ever need it
        //size_t max_pkt_size = std::min((uint32_t)SHZNET_PKT_DATA_SIZE, (uint32_t)m_max_data_size);
        size_t max_data_size = std::min((uint32_t)SHZNET_PKT_DATA_SIZE, (uint32_t)m_max_data_size);

        if (size <= max_data_size)
        {
            auto cmd_buf = get_free_buffer(1, timeout);

            shznet_pkt& buf = cmd_buf->pkts[0];

            buf.packet_begin(SHZNET_PKT_GENERIC, get_local_mac(), get_mac(), cmd_buf->ticketid, get_sessionid());
            buf.packet_set_cmd((char*)cmd);
            buf.packet_set_data(data, size, size);
            buf.packet_set_format(fmt);
            buf.packet_end();
            if (sequential)
                ordered_buffers.push(cmd_buf);
            else
                unordered_buffers.push_back(cmd_buf);
            update(-1);
            return cmd_buf->ticketid;
        }

        uint32_t max_sequence = size / max_data_size;

        //special case
        if (max_sequence * max_data_size == size && max_sequence)
            max_sequence--;

        auto cmd_buf = get_free_buffer(max_sequence + 1, timeout);

        uint32_t data_index = 0;

        uint32_t cmd_hash = cmd_buf->pkts[0].packet_get_cmd_hash((char*)cmd);

        for (uint32_t i = 0; i <= max_sequence; i++)
        {
            shznet_pkt& buf = cmd_buf->pkts[i];

            buf.packet_begin(SHZNET_PKT_GENERIC, get_local_mac(), get_mac(), cmd_buf->ticketid, get_sessionid());
            buf.packet_set_format(fmt);
            buf.packet_set_cmd(cmd_hash);

            buf.packet_set_data(&data[data_index], std::min(max_data_size, (size_t)(size - data_index)), size);
            buf.packet_set_seq(i, max_sequence);
            auto total_size = buf.packet_end();

            data_index += max_data_size;
            //std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        if (sequential)
            ordered_buffers.push(cmd_buf);
        else
            unordered_buffers.push_back(cmd_buf);
        update(-1);
        return cmd_buf->ticketid;
    }

    shznet_ticketid send_get(const char* cmd, byte* data = 0, size_t size = 0, shznet_pkt_dataformat fmt = SHZNET_PKT_FMT_DATA, shznet_response_callback cb = [](byte*, size_t, shznet_pkt_dataformat, bool) {}, uint64_t timeout = 0);
    void send_fetch(const char* cmd, byte* data = 0, size_t size = 0, shznet_pkt_dataformat fmt = SHZNET_PKT_FMT_DATA, shznet_response_callback cb = [](byte*, size_t, shznet_pkt_dataformat, bool) {}, uint64_t timeout = 0);
    void send_fetch(std::shared_ptr<fetch_command_s> fetch_cmd);

    bool send_finished(shznet_ticketid id, std::function<void(bool)> cb = 0)
    {
        bool found = false;

        if (ordered_buffers.size() && ordered_buffers.back()->ticketid == id)
            found = true;
        if (!found)
        {
            for (auto& it : unordered_buffers)
            {
                if (it->ticketid == id)
                {
                    found = true;
                    break;
                }
            }
        }
        if (!found)
        {
            for (auto& it : response_buffers)
            {
                if (it->ticketid == id)
                {
                    found = true;
                    break;
                }
            }
        }
        if (!found)
            return true;

        if (cb)
        {
            send_finish_callbacks.push_back(std::make_pair(id, cb));
        }

        return false;
    }

    shznet_timer network_measure = shznet_timer(1000 * 3);
    
    bool check_packet_pacing(bool increase_pkt_counter = true)
    {
        auto send_group = m_current_send_group;

        if (!max_packets_before_pacing)
        {
            return false;
        }

        if (send_group >= 0)
        {
            if (send_group != m_last_send_group)
                m_max_packets_pacing_counter = 0;
            m_last_send_group = send_group;
        }

        if (!increase_pkt_counter)
        {
            if (m_max_packets_pacing_counter >= max_packets_before_pacing)
                return true;
            return false;
        }

        if (send_group < 0)
        {
            return true;
        }

        if (m_max_packets_pacing_counter >= max_packets_before_pacing)
            return true;
        
        m_max_packets_pacing_counter++;

        return false;
    }

    void update(int send_group)
    {
        if (!m_valid)
            return;

        if (fetch_commands.size())
        {
            auto tmp_fetch_commands = fetch_commands;
            fetch_commands.clear();
            for (auto it : tmp_fetch_commands)
            {
                if (it->timeout_timer.update())
                {
                    if (it->callback) it->callback(0, 0, SHZNET_PKT_FMT_INVALID, 0);
                    continue;
                }
                send_fetch(it);
            }
        }

        if (max_pkts_per_loop < 1.f)
        {
            current_pkts_per_loop += max_pkts_per_loop;
            if (current_pkts_per_loop < 1.0)
                return;
            current_pkts_per_loop = (current_pkts_per_loop - (float)(int)current_pkts_per_loop) - 1; //-1 because we will add 1 later in send_cmd
        }
        else
            current_pkts_per_loop = 0;

        int max_queries = 0;

        volatile bool keep_sending = true;

        bool flush_buffer = false;

        m_current_send_group = send_group;

        while (keep_sending)
        {
            keep_sending = false;

            if (zombie_buffers.size())
            {
                if (zombie_buffers.front()->timeout && zombie_buffers.front()->timeout_counter.update())
                {
                    NETPRNT("order timed out (zombie).");
                    reliable_buffers.recycle(zombie_buffers.front());
                    zombie_buffers.pop();
                    keep_sending = true;
                }
                if (zombie_buffers.size())
                {
                    auto state = send_command_buffer(zombie_buffers.front());
                    flush_buffer = true;
                    if (state == command_buffer_sending)
                        keep_sending = true;
                    else if (state == command_buffer_send_fail)
                        break;
                    max_queries++; 
                }
            }

            if (m_max_parallel_queries && max_queries == m_max_parallel_queries)
            {
                NETPRNT("max parallel queries reached.");
                break;
            }

            if (response_buffers.size())
            {
                for (auto it = response_buffers.begin(); it != response_buffers.end(); )
                {
                    auto buf = *it;
                    if (buf->timeout && buf->timeout_counter.update())
                    {
                        handle_response_failed(buf->ticketid);
                        NETPRNT_FMT("order timed out (response %i).", (int)buf->timeout);
                        reliable_buffers.recycle(*it);
                        it = response_buffers.erase(it);
                        continue;
                    }

                    if (m_max_parallel_queries && max_queries == m_max_parallel_queries)
                    {
                        NETPRNT("max parallel queries reached.");
                        break;
                    }
                    auto state = send_command_buffer(buf);
                    flush_buffer = true;
                    if (state == command_buffer_sending)
                        keep_sending = true;
                    else if (state == command_buffer_send_fail)
                        break;

                    max_queries++;
                    it++;
                }
            }

            if (m_max_parallel_queries && max_queries == m_max_parallel_queries)
            {
                NETPRNT("max parallel queries reached.");
                break;
            }

            if (ordered_buffers.size())
            {
                if (ordered_buffers.front()->timeout && ordered_buffers.front()->timeout_counter.update())
                {
                    handle_response_failed(ordered_buffers.front()->ticketid);
                    NETPRNT("order timed out (ordered).");
                    reliable_buffers.recycle(ordered_buffers.front());
                    ordered_buffers.pop();
                    keep_sending = true;
                }
                if (ordered_buffers.size())
                {
                    if (!ordered_buffers.front()->device_busy || ordered_buffers.front()->device_busy_timer.update())
                    {
                        ordered_buffers.front()->device_busy = false;

                        auto state = send_command_buffer(ordered_buffers.front());
                        flush_buffer = true;
                        if (state == command_buffer_sending)
                            keep_sending = true;
                        else if (state == command_buffer_send_fail)
                            break;
                        if (ordered_buffers.size() >= 2 && ordered_buffers.front()->start_cleanup)
                        {
                            auto zombie_buffer = ordered_buffers.front();
                            ordered_buffers.pop();
                            zombie_buffers.push(zombie_buffer);
                            keep_sending = true;
                            continue;
                        }

                        max_queries++;
                    }
                }
            }

            if (m_max_parallel_queries && max_queries == m_max_parallel_queries)
            {
                NETPRNT("max parallel queries reached.");
                break;
            }

            if (unordered_buffers.size())
            {
                for (auto it = unordered_buffers.begin(); it != unordered_buffers.end(); )
                {
                    auto buf = *it;
                    
                    if (buf->device_busy && !buf->device_busy_timer.update())
                    {
                        it++;
                        continue;
                    }

                    buf->device_busy = false;

                    if (buf->timeout && buf->timeout_counter.update())
                    {
                        handle_response_failed(buf->ticketid);
                        NETPRNT_FMT("order timed out (unordered %i).", (int)buf->timeout);
                        NETPRNT_ERR("unordered order timeout.");
                        reliable_buffers.recycle(*it);
                        it = unordered_buffers.erase(it);
                        continue;
                    }

                    if (m_max_parallel_queries && max_queries == m_max_parallel_queries)
                    {
                        NETPRNT("max parallel queries reached.");
                        break;
                    }
                    auto state = send_command_buffer(buf);
                    flush_buffer = true;
                    if (state == command_buffer_sending)
                        keep_sending = true;
                    else if (state == command_buffer_send_fail)
                        break;

                    max_queries++;
                    it++;
                }
            }

            if (network_buffers_static_list.size() && send_group >= 0)
            {
                if (network_buffer_current < network_buffers_static_list.size())
                {
                    network_buffer_send.clear();

                    for (; network_buffer_current < network_buffers_static_list.size(); network_buffer_current++)
                    {
                        if (check_packet_pacing(false)) //just read counter
                            break;

                        auto& buf = *network_buffers_static_list[network_buffer_current].get();
                        auto buf_hash = buf.name_hash;

                        if (buf.buffer.size() == 0 || !buf.buffer_dirty) //not yet allocated or changed, skip
                            continue;

                        if (buf.next_chunk(network_buffer_send)) //if this returns true, we can just go to the next buffer and keep filling data in
                            continue;

                        //next chunk didnt return true so we have to flush and send the buffer now
                        //max single packet size: 1200
                        this->send_unreliable("SHZSET_STATIC_BUFFER", network_buffer_send.get_buffer().data(), network_buffer_send.get_buffer().size(), SHZNET_PKT_FMT_KEY_VALUE);
                        network_buffer_send.clear();
                        pps_counter++;
                        bps_counter += network_buffer_send.get_buffer().size();
                        current_pkts_per_loop += 1.f;
                        check_packet_pacing(); //now increase counter
                    }

                    if (network_buffer_send.get_buffer().size())
                    { 
                        this->send_unreliable("SHZSET_STATIC_BUFFER", network_buffer_send.get_buffer().data(), network_buffer_send.get_buffer().size(), SHZNET_PKT_FMT_KEY_VALUE);
                        pps_counter++;
                        bps_counter += network_buffer_send.get_buffer().size();
                        current_pkts_per_loop += 1.f;
                        check_packet_pacing();
                    }
                }
                else if (send_group == 0)
                    network_buffer_current = 0;
            }
        }

        if(flush_buffer)
            flush_send_buffers();

        if (pps_counter && bps_counter && network_measure.update())
        {
            auto cur = shznet_millis();
            auto delta = (cur - network_measure_timer) / 1000.0;
            pps = pps_counter / delta;
            bps = bps_counter / delta;

            // Convert bytes per second (bps) to megabytes per second (MB/s)
            double mbps = bps / 1000000.0;

            pps_counter = 0;
            bps_counter = 0;
            network_measure_timer = cur;

            // Print in megabytes per second
            NETPRNT_FMT("device: %s %i pps, %.2f MB/s, %i zombies. err = %f\n", get_name().c_str(), pps, mbps, (int)zombie_buffers.size(), error_rate);
        }
    }

    void handle_ack(shznet_pkt_ack* pkt)
    {
        command_buffer_s* cmd_buff = 0;

        if (zombie_buffers.size() && zombie_buffers.front()->ticketid == pkt->ticketid)
        {
            cmd_buff = zombie_buffers.front();
        }

        if (!cmd_buff)
        {
            if (ordered_buffers.size() && ordered_buffers.front()->ticketid == pkt->ticketid)
            {
                cmd_buff = ordered_buffers.front();
            }
        }

        if (!cmd_buff)
        {
            for (auto it : unordered_buffers)
            {
                if (it->ticketid == pkt->ticketid)
                {
                    cmd_buff = it;
                    break;
                }
            }
        }

        if (!cmd_buff)
        {
            for (auto it : response_buffers)
            {
                if (it->ticketid == pkt->ticketid)
                {
                    cmd_buff = it;
                    break;
                }
            }
        }

        if (!cmd_buff)
        {
            //NETPRNT("invalid ack!");
            return;
        }

        if (pkt->type == shznet_ack_request_delete_buffer)
        {
            //NETPRNT("cmd executed and freed!");
            clear_command_buffer(pkt->ticketid);
            return;
        }

        if (pkt->type == shznet_ack_request_ping)
        {
            auto new_ping = std::min(999, std::max(1, (int)(cmd_buff->ping_timer.delay())));
            m_ping = (float)new_ping * 0.1 + (float)m_ping * 0.9;
            //if (new_ping >= m_ping)
            //    m_ping = new_ping;
            //else
            //    m_ping = (float)new_ping * 0.1 + (float)m_ping * 0.9;
            NETPRNT_FMT("received ping: %i\n", m_ping);
        }
        else if ((pkt->type == shznet_ack_request_quick_resend) || pkt->type == shznet_ack_request_resend)
        {
            if (pkt->type == shznet_ack_request_resend && pkt->ack_id != cmd_buff->ack_id)
                return;

            if (cmd_buff->missing_chunks.size() != cmd_buff->pkts.size())
            {
                cmd_buff->missing_chunks.resize(cmd_buff->pkts.size());
                std::fill(cmd_buff->missing_chunks.begin(), cmd_buff->missing_chunks.end(), false);

            }

            for (uint64_t chunk_id = pkt->missing_start_id; chunk_id <= std::min(pkt->missing_end_id, (uint64_t)cmd_buff->pkts.size() - 1); chunk_id++) cmd_buff->missing_chunks[chunk_id] = 1;

            if (cmd_buff->missing_chunk_low == -1)
                cmd_buff->missing_chunk_low = pkt->missing_start_id;
            else
                cmd_buff->missing_chunk_low = std::min(pkt->missing_start_id, cmd_buff->missing_chunk_low);

            if (cmd_buff->missing_chunk_high == -1)
                cmd_buff->missing_chunk_high = pkt->missing_end_id;
            else
                cmd_buff->missing_chunk_high = std::max(pkt->missing_end_id, cmd_buff->missing_chunk_high);
        }
        else if (pkt->type == shznet_ack_request_complete || pkt->type == shznet_ack_request_too_big)
        {
            if (pkt->missing_start_id == -2 && pkt->missing_end_id == -2) //order not found (no pkt arrived on single packet cmds for example)
            {
                NETPRNT("order not found! resending whole order...");

                cmd_buff->send_index = 0;
                cmd_buff->start_ack = 0;
                cmd_buff->start_cleanup = 0;
                cmd_buff->missing_chunk_low = -1;
                cmd_buff->missing_chunk_high = -1;
                return;
            }

            bool pkt_failed = pkt->missing_start_id == -1 && pkt->missing_end_id == -1;
            bool pkt_finished = pkt->missing_start_id == 0 && pkt->missing_end_id == -1;

            if (pkt_failed || pkt_finished)
            {
                for (auto it = send_finish_callbacks.begin(); it != send_finish_callbacks.end(); it++)
                {
                    if (it->first == pkt->ticketid)
                    {
                        it->second(!pkt_failed);
                        send_finish_callbacks.erase(it);
                        break;
                    }
                }
            }

            if (pkt_finished)
            {
                //NETPRNT_FMT("cmd executed! time: %llu\n", cmd_buff->start_time.delay());
                cmd_buff->start_cleanup = true;
                cmd_buff->ack_counter.set_interval(1, 8);
                return;
            }
            else if(pkt_failed)
            {
                NETPRNT_ERR("cmd failed to execute on device!");
                clear_command_buffer(pkt->ticketid, true);
                return;
            }

            if (pkt->ack_id != cmd_buff->ack_id)
                return;
            
            if (pkt->missing_start_id == -3 && pkt->missing_end_id == -3) //there are still packets missing...
            {
                cmd_buff->start_ack = false;
                cmd_buff->ack_id++;
                return;
            }
        }
        else if (pkt->type == shznet_ack_request_busy)
        {
            cmd_buff->device_busy = true;
            cmd_buff->device_busy_timer.reset();
        }
        
    }

    bool sendto(void* buffer, size_t size);

    shznet_pkt& get_sendpacket();
    shznet_pkt_big& get_sendpacket_big();

    shznet_mac& get_local_mac();
    shznet_ip& get_local_ip();

    std::queue<command_buffer_s*>& get_ordered_buffers()
    {
        return ordered_buffers;
    }
    std::vector<command_buffer_s*>& get_unordered_buffers()
    {
        return unordered_buffers;
    }

    uint32_t num_zombie_buffers() { return zombie_buffers.size(); }

    template<class T>
    shznet_ticketid send_response(const char* cmd, T extra_data, byte* data, size_t size, shznet_pkt_dataformat fmt = SHZNET_PKT_FMT_DATA, bool regular_buffer = false)
    {
        if (!base)
        {
            NETPRNT("No base!");
            return INVALID_TICKETID;
        }
        if (type != SHZNET_DEV_DEFAULT)
        {
            NETPRNT("No shizonet device!");
            return INVALID_TICKETID;
        }
        if (!m_valid)
        {
            NETPRNT("Not valid!");
            return INVALID_TICKETID;
        }

        size_t max_data_size = std::min((uint32_t)SHZNET_PKT_DATA_SIZE, (uint32_t)m_max_data_size);

        if (size + sizeof(extra_data) <= max_data_size)
        {
            auto cmd_buf = get_free_buffer(1, 0);

            shznet_pkt& buf = cmd_buf->pkts[0];

            buf.packet_begin(SHZNET_PKT_GENERIC, get_local_mac(), get_mac(), cmd_buf->ticketid, get_sessionid());
            buf.packet_set_cmd((char*)cmd);
            buf.packet_set_data(extra_data);
            buf.packet_set_data(data, size, size + sizeof(extra_data), sizeof(extra_data));
            buf.packet_set_format(fmt);
            buf.packet_end();
            if (regular_buffer)
                unordered_buffers.push_back(cmd_buf);
            else
                response_buffers.push_back(cmd_buf);
            update(-1);
            return cmd_buf->ticketid;
        }

        uint32_t max_sequence = (size+sizeof(extra_data)) / max_data_size;

        //special case
        if ((max_sequence * max_data_size == (size + sizeof(extra_data))) && max_sequence)
            max_sequence--;

        auto cmd_buf = get_free_buffer(max_sequence + 1, 0);

        uint32_t data_index = 0;

        uint32_t cmd_hash = cmd_buf->pkts[0].packet_get_cmd_hash((char*)cmd);

        for (uint32_t i = 0; i <= max_sequence; i++)
        {
            shznet_pkt& buf = cmd_buf->pkts[i];

            buf.packet_begin(SHZNET_PKT_GENERIC, get_local_mac(), get_mac(), cmd_buf->ticketid, get_sessionid());
            buf.packet_set_format(fmt);
            buf.packet_set_cmd(cmd_hash);
            if (i == 0)
            {
                buf.packet_set_data(extra_data);
                buf.packet_set_data(&data[data_index], std::min((size_t)(max_data_size - sizeof(extra_data)), (size_t)(size - data_index)), size+sizeof(extra_data), sizeof(extra_data));
            }
            else
                buf.packet_set_data(&data[data_index], std::min(max_data_size, (size_t)(size - data_index)), size + sizeof(extra_data));
            buf.packet_set_seq(i, max_sequence);
            auto total_size = buf.packet_end();
            data_index += (i == 0 ? max_data_size - sizeof(extra_data) : max_data_size);
            //std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (regular_buffer)
            unordered_buffers.push_back(cmd_buf);
        else
            response_buffers.push_back(cmd_buf);
        update(-1);
        return cmd_buf->ticketid;
    }

    void set_static_buffer_leds(network_buffer_static_s &nb, int start_adr, byte* data_buffer, size_t data_size, size_t data_offset,
        int input_channels = 1)
    {
        if (!data_size)
            return;

        nb.ensure_init();

        size_t rem_bytes = data_size;
        int target_channels = nb.type;

        data_buffer += data_offset;
        start_adr *= target_channels;

        size_t buffer_offset = start_adr;
        size_t bytes_written = 0;
        for (; (bytes_written + target_channels <= data_size) && buffer_offset + target_channels <= nb.buffer.size(); buffer_offset += target_channels)
        {
            copy_pixel(data_buffer, &nb.buffer[buffer_offset], input_channels, target_channels);
            bytes_written += target_channels;
            data_buffer += input_channels;
        }
        nb.set_dirty(start_adr, bytes_written);
    }

    void set_static_buffer_leds(int buffer_index, int start_adr, byte* data_buffer, size_t data_size, size_t data_offset,
        int input_channels = 1)
    {
        if (buffer_index < 0 || buffer_index >= network_buffers_static_list_leds.size())
            return;

        auto& nb = *network_buffers_static_list_leds[buffer_index].get();

        set_static_buffer_leds(nb, start_adr, data_buffer, data_size, data_offset, input_channels);
    }

    void set_static_buffer_leds(const char* name, int start_adr, byte* data_buffer, size_t data_size, size_t data_offset,
        int input_channels = 1)
    {
        auto name_hash = shznet_hash(name);
        auto nb_entry = network_buffers_static.find(name_hash);
        if (nb_entry != network_buffers_static.end())
        {
            auto& nb = *nb_entry->second.get();
            set_static_buffer_leds(nb, start_adr, data_buffer, data_size, data_offset, input_channels);
        }
    }

    void copy_pixel(byte* src, byte* dst, int input_size, int output_size) //copy a single pixel from one to another buffer
    {
        //dont need to handle output or input size == 2 (no use)
        if (input_size == output_size)
        {
            if (output_size == 4) //Assume RGBW
            {
                byte w = std::min(std::min(src[0], src[1]), src[2]);
                dst[0] = src[0] - w;
                dst[1] = src[1] - w;
                dst[2] = src[2] - w;
                dst[3] = w;
            }
            else
            {
                memcpy(dst, src, input_size);
            }
        }
        else if (input_size == 1)
        {
            if (output_size == 3)
            {
                dst[0] = src[0];
                dst[1] = src[0];
                dst[2] = src[0];
            }
            else if (output_size == 4) //Assume RGBW, only set white channel
            {
                dst[0] = 0;
                dst[1] = 0;
                dst[2] = 0;
                dst[3] = src[0];
            }
        }
        else if (input_size == 3)
        {
            if (output_size == 1)
            {
                dst[0] = ((((int)src[0] + (int)src[1] + (int)src[2])) / 3);
            }
            else if (output_size == 4) //Assume RGBW, only set white channel
            {
                byte w = std::min(std::min(src[0], src[1]), src[2]);
                dst[0] = src[0] - w;
                dst[1] = src[1] - w;
                dst[2] = src[2] - w;
                dst[3] = w;
            }
        }
        else if (input_size == 4)
        {
            if (output_size == 1)
            {
                dst[0] = ((((int)src[0] + (int)src[1] + (int)src[2] + (int)src[3])) / 4);
            }
            else if (output_size == 3)
            {
                byte w = std::min(std::min(src[0], src[1]), src[2]);
                dst[0] = src[0] - w;
                dst[1] = src[1] - w;
                dst[2] = src[2] - w;
                dst[3] = w;
            }
        }
    }

    void handle_response_failed(shznet_ticketid id);

    float get_error_rate() { return error_rate; }
    float get_packets_per_ms() { return max_pkts_per_loop; }

    bool _has_shizoscript_json = false;

    uint32_t _init_connection_attempts = 0;

protected:
    int m_current_send_group = -1;
    int m_last_send_group = -1;
    int m_max_packets_pacing_counter = 0;
};

class shznet_artnet_device
{
    struct artnet_buffer_s
    {
        std::vector<byte> universe_buffer;
        bool			  dirty[16];

        artnet_buffer_s()
        {
            universe_buffer = std::vector<byte>(512 * 17); //+1 just in case someone buffer overruns
            memset(universe_buffer.data(), 0, universe_buffer.size());
            memset(dirty, 0, 16);
        }
    };

    shznet_small_allocator<artnet_buffer_s> artnet_buffer;
   
protected:
    shznet_base_impl*   base = 0;
    std::string         name;
    std::string         description;
    shznet_adr          address;

    friend class shznet_base_impl;
    friend class shznet_base;

public:

    shznet_artnet_device(shznet_base_impl* _base, shznet_adr& adr, std::string _name = "", std::string _description = "")
    {
        base = _base;
        if (_name.length() > 16)
        {
            NETPRNT_FMT("truncating name (too int): %s\n", _name.c_str());
            _name = _name.substr(0, 16);
        }
        if (_description.length() > 62)
        {
            NETPRNT_FMT("truncating description (too int): %s\n", _description.c_str());
            _description = _description.substr(0, 62);
        }

        name = _name;
        description = _description;
        address = adr;
    }

    ~shznet_artnet_device()
    {

    }

    shznet_base_impl* get_base() { return base; }

    void update_address(shznet_adr& adr)
    {
        address = adr;
    }

    void set_name(std::string _name) {
        name = _name;
    }
    void set_description(std::string _desc) {
        description = _desc;
    }
    void set_ip(shznet_ip ip) {
        address.ip = ip;
    }
    void set_mac(shznet_mac mac) {
        address.mac = mac;
    }

    std::string& get_name() {
        return name;
    }
    std::string& get_description() {
        return description;
    }
    shznet_ip& get_ip() {
        return address.ip;
    }
    shznet_mac& get_mac() {
        return address.mac;
    }
    shznet_adr& get_address() {
        return address;
    }

    void copy_pixel(byte* src, byte* dst, int input_size, int output_size) //copy a single pixel from one to another buffer
    {
        //dont need to handle output or input size == 2 (no use)
        if (input_size == output_size)
        {
            if (output_size == 4) //Assume RGBW
            {
                byte w = std::min(std::min(src[0], src[1]), src[2]);
                dst[0] = src[0] - w;
                dst[1] = src[1] - w;
                dst[2] = src[2] - w;
                dst[3] = w;
            }
            else
            {
                memcpy(dst, src, input_size);
            }
        }
        else if (input_size == 1)
        {
            if (output_size == 3)
            {
                dst[0] = src[0];
                dst[1] = src[0];
                dst[2] = src[0];
            }
            else if (output_size == 4) //Assume RGBW, only set white channel
            {
                dst[0] = 0;
                dst[1] = 0;
                dst[2] = 0;
                dst[3] = src[0];
            }
        }
        else if (input_size == 3)
        {
            if (output_size == 1)
            {
                dst[0] = ((((int)src[0] + (int)src[1] + (int)src[2])) / 3);
            }
            else if (output_size == 4) //Assume RGBW, only set white channel
            {
                byte w = std::min(std::min(src[0], src[1]), src[2]);
                dst[0] = src[0] - w;
                dst[1] = src[1] - w;
                dst[2] = src[2] - w;
                dst[3] = w;
            }
        }
        else if (input_size == 4)
        {
            if (output_size == 1)
            {
                dst[0] = ((((int)src[0] + (int)src[1] + (int)src[2] + (int)src[3])) / 4);
            }
            else if (output_size == 3)
            {
                byte w = std::min(std::min(src[0], src[1]), src[2]);
                dst[0] = src[0] - w;
                dst[1] = src[1] - w;
                dst[2] = src[2] - w;
                dst[3] = w;
            }
        }
    }

    void clear_artnet_buffer(bool set_dirty)
    {
        memset(artnet_buffer->universe_buffer.data(), 0, artnet_buffer->universe_buffer.size());
        if (set_dirty)
        {
            for (int i = 0; i < 16; i++)
                artnet_buffer->dirty[i] = true;
        }
    }

    void set_artnet_buffer(int universe, int start_adr, byte* data_buffer, size_t data_size, size_t data_offset,
        bool led_wrap = false, int input_channels = 1, int target_channels = 1)
    {
        if (!data_size || universe < 0)
            return;

        // Determine the maximum number of DMX channels per universe.
        //int dmx_max = led_wrap ? (170 * 3) : 512;
        int dmx_max = 512;

        // Adjust starting address to be within the current universe.
        while (start_adr >= dmx_max)
        {
            universe++;
            start_adr -= dmx_max;
        }

        data_buffer += data_offset;

        size_t rem_bytes = data_size;

        //First, fill first universe

        if (universe >= 16)
            return;

        size_t buffer_offset = universe * 512 + start_adr;
        size_t bytes_written = 0;
        for (; (bytes_written + target_channels <= data_size) && buffer_offset + target_channels <= artnet_buffer->universe_buffer.size(); buffer_offset += target_channels)
        {
            copy_pixel(data_buffer, &artnet_buffer->universe_buffer.data()[buffer_offset], input_channels, target_channels);
            bytes_written += target_channels;
            data_buffer += input_channels;
        }

        for (size_t i = 0; i * 512 < start_adr + bytes_written; i++)
        {
            if (universe + i >= 16)
                break;
            artnet_buffer->dirty[universe + i] = true;
        }
    }

    void set_artnet_buffer(int universe, int start_adr, byte data_value, size_t data_size, size_t data_offset,
        bool led_wrap = false)
    {
        // Determine the maximum number of DMX channels per universe.
        int dmx_max = led_wrap ? (170 * 3) : 512;

        // Adjust starting address to be within the current universe.
        while (start_adr >= dmx_max)
        {
            universe++;
            start_adr -= dmx_max;
        }

        while (data_size)
        {
            if (universe >= 16)
                return;

            artnet_buffer->dirty[universe] = true;

            size_t max_size = std::min((size_t)(dmx_max - start_adr), data_size);

            memset(&artnet_buffer->universe_buffer.data()[universe * 512 + start_adr], data_value, max_size);

            start_adr = 0;

            data_size -= max_size;
            data_offset += max_size;
            universe++;
        }

        return;
    }

    uint8_t get_artnet_buffer(int universe, int start_adr)
    {
        int dmx_max = 512;

        // Adjust starting address to be within the current universe.
        while (start_adr >= dmx_max)
        {
            universe++;
            start_adr -= dmx_max;
        }

        if (universe < 0 || universe >= 16)
            return 0;

        if (start_adr < 0 || start_adr >= 512)
            return 0;

        return artnet_buffer->universe_buffer[universe * 512 + start_adr];
    }

    void send_art_current(int artnet_send_group) //4*4 = 16 universes sent sequentially
    {
        if (!artnet_buffer.allocated())
            return;

        for (int cc = 0; cc < 4; cc++)
        {
            int idx = artnet_send_group * 4 + cc;
            if (artnet_buffer->dirty[idx])
            {
                artnet_buffer->dirty[idx] = false;
                send_art_universe(idx, &artnet_buffer->universe_buffer.data()[idx * 512], 512);
            }
        }
    }

    void send_art_universe(int universe, byte* data, int len);

    void update(int artnet_send_group)
    {
        if (artnet_send_group >= 0)
        {
            send_art_current(artnet_send_group);
        }
    }
};


//TODO in ESP32 wifi socket class, check if the receiving ticket is in the last 10 recv. ticket list, if so, discard directly!!! (dont fill buffer)

typedef std::shared_ptr<shznet_device> shznet_device_ptr;
typedef std::shared_ptr<shznet_artnet_device> shznet_artnet_device_ptr;


class shznet_command
{
    shznet_device_ptr   _dev;
    shznet_pkt_header*  _hdr;
    byte*               _data;
    size_t              _size;
public:
    shznet_command(shznet_device_ptr dev, shznet_pkt_header* hdr, byte* data, size_t size) : _dev(dev), _hdr(hdr), _data(data), _size(size) {};

    byte*                   data() { return _data; }
    size_t                  size() { return _size; }
    shznet_pkt_dataformat   format() { return _hdr->data_format; }
    shznet_pkt_header&      header() { return *_hdr; }
    shznet_device*     device() { return _dev.get(); }

    shznet_ip&  ip() { return _dev->get_ip(); }
    shznet_mac& mac() { return _dev->get_mac(); }
    uint16_t    port() { return _dev->get_ip().port; }
};

class shznet_base_impl : public shznet_receiver
{
protected:

    friend class shznet_device;

    struct pending_device_respond_msg
    {
        uint32_t        cmd;
        shznet_ticketid id;
        shznet_sessionid sid;
        shznet_mac      device;
        shznet_timer    timeout = shznet_timer(1000 * 60);
        shznet_vector<byte>   data;
        shznet_pkt_dataformat fmt;

        pending_device_respond_msg(uint32_t _cmd, shznet_ticketid _id, shznet_mac mac, shznet_sessionid _sid, shznet_pkt_dataformat _fmt) : cmd(_cmd), id(_id), device(mac), sid(_sid), fmt(_fmt) { timeout.reset(); }
    };

    struct response_wait
    {
        shznet_ticketid id;
        shznet_mac dev;
        shznet_response_callback cb;
        uint64_t timeout_start = 0;
        uint64_t timeout = 0;

        response_wait(shznet_ticketid _id, shznet_mac _dev, shznet_response_callback _cb, uint64_t _timeout = 0) : id(_id), dev(_dev), cb(_cb), timeout(_timeout) { if (timeout) timeout_start = shznet_millis(); };
    };

    std::unordered_map<shznet_mac, shznet_artnet_device_ptr> m_artnet_devices;
    //std::unordered_map<shznet_mac, shznet_device_ptr> m_artnet_devices_offline; //artnet devices should never go offline, even if they are unreachable.

    std::unordered_map<shznet_mac, shznet_device_ptr> m_devices;
    std::unordered_map<shznet_mac, shznet_device_ptr> m_devices_offline;
    std::unordered_map<shznet_mac, shznet_device_ptr> m_devices_pending;

    std::vector < std::pair<shznet_mac, const char*>> m_pending_disconnect;

    std::vector<shznet_device_ptr> m_devices_temp;

    artnet_poll     art_poll;
    artnet_sync     art_sync;
    artnet_dmx      art_dmx_buffer;

    shznet_timer    m_device_update;

    shznet_ticketid m_ticketid_counter = 1;

    std::vector<response_wait> m_wait_responses;

    std::vector<response_wait> m_wait_responses_tmp;
    std::vector<response_wait> m_wait_responses_tmp2;

    shznet_timer m_wait_responses_timeout_check = shznet_timer(1000 * 5);

    virtual void on_device_connect(shznet_device_ptr dev_info) 
    {
    }

    virtual void on_device_connect(shznet_artnet_device_ptr dev_info)
    {
    }

    virtual void on_device_disconnect(shznet_device_ptr dev_info) 
    {
        
    }

    shznet_timer check_device_timer;
    std::vector<shznet_device_ptr> check_device_connections;
    std::vector<shznet_device_ptr> finalize_device_connections;
    void on_device_connect_internal(shznet_device_ptr dev_info)
    {
        dev_info->was_connected = false;
        dev_info->_init_connection_attempts = 0;
        check_device_connections.push_back(dev_info);
    }

    void on_device_connect_internal(shznet_artnet_device_ptr dev_info)
    {
        this->on_device_connect(dev_info);
    }

    void on_device_disconnect_internal(shznet_device_ptr dev_info, const char* reason)
    {
        handle_response_disconnect(dev_info);

        if (dev_info->was_connected)
        {
            NETPRNT_FMT("%s device disconnected: %s (%s)\n", dev_info->type == SHZNET_DEV_ARTNET ? "artnet" : "shznet", dev_info->get_name().c_str(), dev_info->get_address().mac.str().c_str());
            if (reason) { NETPRNT_FMT("reason: %s\n", reason); }
            on_device_disconnect(dev_info);
        }
    }

    virtual void handle_response_disconnect(shznet_device_ptr &dev_ptr) {}
    virtual void handle_response_failed(shznet_ticketid id) {}
    virtual void handle_response_add(response_wait rw) {}

    shznet_ticketid get_new_ticketid()
    {
        auto tid = m_ticketid_counter;
        m_ticketid_counter++;
        if (m_ticketid_counter == -1)
            m_ticketid_counter = 1;
        return tid;
    }

    int             m_poll_probe = 1; //for different PORTS

    bool            send_artnet_sync = true;
    int             artnet_send_group = 0;
    shznet_timer    artnet_delay = shznet_timer(2); //target to send 16 universes at 60 FPS with 4 universes every 2 milliseconds

    bool            m_shizonet_enabled = true;

                    //This is not used yet, the correct way for this to work
                    //would be to obtain all IP addresses from all interfaces
                    //And send broadcast messages to all of that addresses from all interfaces
    bool            m_poll_broadcast_subnet_switch = false;

public:

    shznet_base_impl()
    {
        m_always_enable_artnet = true;
        m_device_update.set_interval(1000);
        check_device_timer.set_interval(500);
    }

    virtual ~shznet_base_impl() {};

    //weird, this is needed so the compiler can find the function even tho it is declared in the derived class?
    void add_command(const char* cmd, std::function<void(shznet_ip&, byte* data, size_t size, shznet_pkt_header& hdr)> cb) override
    {
        shznet_receiver::add_command(cmd, cb);
    }

    void add_command(const char* cmd, std::function<void(shznet_command& data)> cb)
    {
        shznet_receiver::add_command(cmd, [this, cb](shznet_ip& ip, byte* data, size_t size, shznet_pkt_header& hdr)
            {
                auto dev = find_device(hdr.macid_source);
                if (dev)
                {
                    shznet_command cd(dev, &hdr, data, size);
                    cb(cd);
                }
            });
    }

    void cancel_ticket(shznet_ticketid tid)
    {
        NETPRNT_ERR("ticket cancelled.");
        m_devices_temp.clear();
        for (auto it : m_devices)
        {
            if(it.second)
                m_devices_temp.push_back(it.second);
        }

        for (auto it : m_devices_temp)
        {
            if(it)
                it->clear_command_buffer(tid, true, false);
        }
        m_devices_temp.clear();
    }

    virtual void update() override
    {
        if (m_shizonet_enabled)
        {
            if (check_device_connections.size() && check_device_timer.update())
            {
                auto tmp_devs = check_device_connections;
                check_device_connections.clear();
                for (auto dev_ptr : tmp_devs)
                {
                    if (!dev_ptr->valid())
                        continue;
                    send_shz_poll(dev_ptr->get_address());
                    NETPRNT_FMT("testing device %s.\n", dev_ptr->get_name().c_str());
                    auto tid = dev_ptr->send_get(
                        SHZNET_TEST_CMD,
                        0,0,
                        SHZNET_PKT_FMT_DATA,
                        [this, dev_ptr](byte* data, size_t size, shznet_pkt_dataformat fmt, bool success) {
                            if (!success || !size) {
                                //disconnect_device(dev_ptr->get_mac(), "init connection failed.");
                                NETPRNT("init connection failed.");
                                if (dev_ptr->_init_connection_attempts < 3)
                                {
                                    check_device_connections.push_back(dev_ptr);
                                    dev_ptr->_init_connection_attempts++;
                                }
                                else
                                    disconnect_device(dev_ptr->get_mac(), "init connection failed.");

                                return;
                            }

                            dev_ptr->command_map.clear();
                            dev_ptr->command_response_map.clear();
                            dev_ptr->network_buffers_static.clear();
                            dev_ptr->network_buffers_static_list.clear();
                            dev_ptr->network_buffers_static_list_leds.clear();
                            dev_ptr->network_buffers_static_list_data.clear();

                            shznet_kv_reader kvr(data, size);

                            if (!kvr.read()) {
                                disconnect_device(dev_ptr->get_mac(), "init connection failed (invalid kv).");
                                return;
                            }

                            if (kvr.get_value_size() != sizeof(uint32_t)) {
                                disconnect_device(dev_ptr->get_mac(), "init connection failed (invalid kv version size).");
                                return;
                            }

                            //This is kinda ugly and we could do better, but keep it for now for compatibility (deprecated, use kvr.read_int32() in future)
                            auto version = *(uint32_t*)kvr.get_value();

                            if (version != 1)
                            {
                                auto cmds = kvr.read_kv("commands");
                                while (cmds.read())
                                {
                                    shznet_command_defs* def = (shznet_command_defs*)cmds.get_value();
                                    if (def && cmds.get_value_size() == sizeof(shznet_command_defs))
                                    {
                                        if (!def->type) {
                                            dev_ptr->command_map[def->hash] = cmds.get_key();
                                        }
                                        else {
                                            dev_ptr->command_response_map[def->hash] = cmds.get_key();
                                        }
                                    }
                                }

                                auto buffers = kvr.read_kv("static_buffers");
                                auto buffer_desc = kvr.read_kv("static_buffers_desc");
                                auto buffer_setups = kvr.read_kv("static_buffers_setup");                               

                                while (buffers.read())
                                {
                                    shznet_buffer_defs* def = (shznet_buffer_defs*)buffers.get_value();
                                    if (def && buffers.get_value_size() == sizeof(shznet_buffer_defs))
                                    {            
                                        //GCC fix
                                        auto def_type = def->type;
                                        auto def_size = def->size;

                                        dev_ptr->network_buffers_static[def->hash] = std::make_shared<shznet_device::network_buffer_static_s>(
                                            buffers.get_key(),
                                            (network_buffer_static_type)def_type,
                                            def_size,
                                            buffer_desc.read_string(buffers.get_key()),
                                            buffer_setups.read_string(buffers.get_key())
                                        );

                                        dev_ptr->network_buffers_static_list.push_back(dev_ptr->network_buffers_static[def->hash]);
                                        
                                        if(def->type == network_buffer_static_type::NETWORK_BUFFER_STATIC_DATA)
                                            dev_ptr->network_buffers_static_list_data.push_back(dev_ptr->network_buffers_static[def->hash]);
                                        else if(def->type >= NETWORK_BUFFER_STATIC_LEDS_1CH && def->type <= NETWORK_BUFFER_STATIC_LEDS_4CH)
                                            dev_ptr->network_buffers_static_list_leds.push_back(dev_ptr->network_buffers_static[def->hash]);

                                    }
                                }
                            }
                            else //old compatibility
                            {
                                while (kvr.read()) {
                                    if (kvr.get_value_size() != sizeof(shznet_command_defs)) {
                                        NETPRNT("command def invalid size!");
                                        continue;
                                    }
                                    shznet_command_defs* def = (shznet_command_defs*)kvr.get_value();
                                    if (!def->type) {
                                        dev_ptr->command_map[def->hash] = kvr.get_key();
                                    }
                                    else {
                                        dev_ptr->command_response_map[def->hash] = kvr.get_key();
                                    }
                                }
                            }

                            dev_ptr->_has_shizoscript_json = kvr.read_int32("has_json");
                            dev_ptr->max_packets_before_pacing = kvr.read_int32("pacing");

                            dev_ptr->was_connected = true;

                            finalize_device_connections.push_back(dev_ptr);
                        },
                        1000 * 8
                    );
                }
            }
            if (finalize_device_connections.size())
            {
                for (auto& it : finalize_device_connections)
                {
                    NETPRNT_FMT("%s device connected: %s (%s)\n", it->type == SHZNET_DEV_ARTNET ? "artnet" : "shznet", it->get_name().c_str(), it->get_address().mac.str().c_str());
                    it->connected = true;
                    on_device_connect(it);
                }
                finalize_device_connections.clear();
            }
        }

        shznet_receiver::update();

        if (m_shizonet_enabled && m_device_update.update())
        {
            /*for (auto it = m_artnet_devices.begin(); it != m_artnet_devices.end(); )
            {
                if (it->second->is_timeout())
                {
                    if (it->second->m_alive_request)
                    {
                        NETPRNT_FMT("artnet device timeout: %s\n", it->second->get_name().c_str());
                        this->on_device_disconnect_internal(it->second, "artnet timeout.");
                        it->second->set_invalid();
                        m_artnet_devices_offline[it->first] = it->second;
                        it = m_artnet_devices.erase(it);
                        continue;
                    }

                    //NETPRNT("send alive request...");
                    it->second->reset_timeout();
                    it->second->m_alive_request = true;
                    send_art_poll(it->second->get_address().ip);
                }
                it++;
            }
            for (auto it = m_artnet_devices_offline.begin(); it != m_artnet_devices_offline.end(); )
            {
                if (it->second->is_offline_timeout())
                {
                    NETPRNT_FMT("artnet device off timeout: %s\n", it->second->get_name().c_str());
                    it = m_artnet_devices_offline.erase(it);
                }
                else
                    it++;
            }*/

            for (auto it = m_devices.begin(); it != m_devices.end(); )
            {
                if (it->second->is_timeout())
                {
                    if (it->second->m_alive_request)
                    {
                        auto mac = it->second->get_mac();
                        disconnect_device(mac, "shznet timeout.");
                        return; //dont continue, heap error
                    }
                    //NETPRNT("send alive request...");
                    send_shz_alive_check(it->second->get_address());
                    send_shz_poll(it->second->get_address());

                    it->second->reset_timeout();
                    it->second->m_alive_request = true;
                    it->second->alive_timeout.set_interval(1, 10);
                }
                else if (it->second->m_alive_request && it->second->alive_timeout.update())
                {
                    send_shz_alive_check(it->second->get_address());
                }

                it++;
            }
            for (auto it = m_devices_offline.begin(); it != m_devices_offline.end(); )
            {
                if (it->second->is_offline_timeout())
                {
                    NETPRNT_FMT("shznet device off timeout: %s\n", it->second->get_name().c_str());
                    it = m_devices_offline.erase(it);
                }
                else
                    it++;
            }
            for (auto it = m_devices_pending.begin(); it != m_devices_pending.end(); )
            {
                if (it->second->auth->timeout.update())
                {
                    NETPRNT_FMT("shznet auth timeout: %s\n", it->second->get_name().c_str());
                    it->second->set_invalid();
                    it = m_devices_pending.erase(it);
                }
                else
                    it++;
            }
        }

        if (m_shizonet_enabled && m_wait_responses_timeout_check.update())
        {
            m_wait_responses_tmp.clear();

            uint64_t current_time = shznet_millis();
            for (auto it = m_wait_responses.begin(); it != m_wait_responses.end();)
            {
                if (it->timeout && current_time - it->timeout_start >= it->timeout)
                {
                    m_wait_responses_tmp.push_back(*it);
                    it = m_wait_responses.erase(it);
                }
                else
                    ++it;
            }

            for (auto it : m_wait_responses_tmp)
            {
                cancel_ticket(it.id);
                if(it.cb) it.cb(0, 0, SHZNET_PKT_FMT_INVALID, 0);
            }
        }
      
        auto send_grp = artnet_send_group >= 0 ? artnet_send_group : 3;

        if (send_grp >= 0)
        {
            if (artnet_delay.update())
            {
                for (auto it : m_artnet_devices)
                {
                    it.second->update(send_grp);
                }

                artnet_send_group++;

                if (artnet_send_group >= 4)
                {
                    artnet_send_group = -1;
                }
            }
        }

        if (m_shizonet_enabled)
        {
            for (auto& it : m_devices)
                it.second->update(send_grp);

            for (auto& it : m_devices_pending)
            {
                if (it.second->auth->resend_timer.update())
                    send_auth_req(it.second);
            }
        }
    }

    void artnet_sync_now()
    {
        if (artnet_send_group != -1)
        {
            for (int i = artnet_send_group; i < 4; i++)
            {
                for (auto &it : m_artnet_devices)
                {
                    it.second->update(i);
                }

                for (auto& it : m_devices)
                    it.second->update(i);
            }
        }

        if (send_artnet_sync)
        {
            send_art_sync(shznet_broadcast_ip);
            artnet_delay.reset();
        }

        //framesync now and start sending next data (one frame delay? can that be avoided?)
        artnet_send_group = 0;
    }

    void disconnect_device(shznet_mac& id, const char* reason)
    {
        NETPRNT_ERR("disconnect device!");
        NETPRNT_ERR(reason);

        shznet_device_ptr dev = 0;
        bool was_online = false;
        auto online_dev = m_devices.find(id);
        if (online_dev != m_devices.end())
        {
            dev = online_dev->second;
            m_devices.erase(online_dev);
            was_online = true;
        }

        auto pending_dev = m_devices_pending.find(id);
        if (pending_dev != m_devices_pending.end())
        {
            if (!dev) dev = pending_dev->second;
            m_devices_pending.erase(pending_dev);
        }

        if (dev)
        {
            m_devices_offline[id] = dev;
            if(was_online) this->on_device_disconnect_internal(dev, reason);
            dev->set_invalid();
        }
    }

    void handle_shizonet_alive_check_reply(shznet_ip& dev_ip, shznet_pkt* pkt) override
    {
        shznet_adr adr(dev_ip.ip, pkt->source_mac(), dev_ip.port);
        auto active_dev = m_devices.find(adr.mac);
        if (active_dev != m_devices.end())
        {
            active_dev->second->reset_timeout();
            active_dev->second->update_address(adr);
        }
    }

    void handle_shizonet_auth_beacon(shznet_ip& adr, shznet_pkt* pkt) override
    {
        shznet_mac target_mac(pkt->source_mac());
        //NETPRNT_FMT("auth beacon(2) from: %s (%s:%i)\n", target_mac.str().c_str(), adr.str().c_str(), adr.port);
        auto endpoint = m_endpoints.find(target_mac);
        shznet_sessionid sessid = -1;
        if (endpoint != m_endpoints.end())
        {
            endpoint->second.reset_timeout();
            sessid = endpoint->second.sessionid;
        }
        m_send_buffer.packet_begin(SHZNET_PKT_AUTH_BEACON_REPLY, get_udp().local_adr().mac, target_mac, 0, sessid);
        uint32_t pkt_size = m_send_buffer.packet_end();
        m_udp.send_buffered_prio(adr, (uint8_t*)&m_send_buffer, pkt_size);
        auto dev = m_devices.find(target_mac);
        if (dev == m_devices.end())
        {
            shznet_adr test_adr;
            test_adr.mac = target_mac;
            test_adr.ip = adr;
            test_adr.ip.port = adr.port;
            send_shz_poll(test_adr);
        }
        else
        {
            dev->second->reset_timeout();
        }
    }

    void handle_shizonet_auth_beacon_reply(shznet_ip& dev_ip, shznet_pkt* pkt) override
    {
        shznet_adr adr(dev_ip.ip, pkt->source_mac(), dev_ip.port);
        auto active_dev = m_devices.find(adr.mac);
        if (active_dev != m_devices.end())
        {
            active_dev->second->reset_timeout();
            active_dev->second->update_address(adr);

            active_dev->second->receiver_only = pkt->header.flags & SHZNET_PKT_FLAGS_RECEIVER_ONLY;

            if (pkt->header.sessionid == -1 || pkt->header.sessionid != active_dev->second->auth->sessionid)
            {
                if (active_dev->second->auth->connect_guard.check())
                {
                    disconnect_device(active_dev->second->get_mac(), "connect_guard invalid sessionid.");
                    NETPRNT_FMT("%s -> %s %i\n", active_dev->second->get_mac().str().c_str(), adr.mac.str().c_str(), (int)dev_ip.port);
                }
            }
            return;
        }

        shznet_device_ptr dev = 0;

        auto pending_dev = m_devices_pending.find(adr.mac);
        if (pending_dev == m_devices_pending.end())
        {

            auto offline_dev = m_devices_offline.find(adr.mac);
            if (offline_dev != m_devices_offline.end())
            {
                dev = offline_dev->second;
                
                //10 secs safety reconnect timer
                if (!dev->reconnect_timer.update())
                    return;
                
                dev->reset_offline_timeout();
                m_devices_offline.erase(offline_dev);
            }
            if (!dev)
                dev = std::make_shared<shznet_device>(this, adr, "", "");
            
            dev->set_invalid();
            
            auto old_sessionid = pkt->header.sessionid;
            while (dev->auth->sessionid == old_sessionid)
                dev->auth->sessionid = shznet_global.get_new_sessionid();
            NETPRNT_FMT("new sessionid: %llu old: %llu for %s.\n", dev->auth->sessionid, old_sessionid, dev->get_mac().str().c_str());;
            dev->auth->resend_timer.reset();
            m_devices_pending[adr.mac] = dev;
        }
        else
            dev = pending_dev->second;

        if (!dev)
            return;

        dev->update_address(adr);

        dev->receiver_only = pkt->header.flags & SHZNET_PKT_FLAGS_RECEIVER_ONLY;

        send_auth_req(dev);

        dev->auth->connect_guard.reset();
    }

    void handle_shizonet_auth_reply(shznet_ip& dev_ip, shznet_pkt* pkt) override
    {
        if (pkt->get_data_size() < sizeof(shznet_pkt_auth_reply))
        {
            NETPRNT_FMT("auth invalid size %i : %i\n", pkt->get_data_size(), (int)sizeof(shznet_pkt_auth_reply));
            return;
        }
        shznet_adr adr(dev_ip.ip, pkt->source_mac(), dev_ip.port);
        auto active_dev = m_devices_pending.find(adr.mac);

        if (active_dev == m_devices_pending.end())
        {
            NETPRNT_FMT("received invalid auth reply from %s test: %i\n", adr.mac.str().c_str(), (int)m_devices_pending.size());
            return;
        }

        shznet_pkt_auth_reply* reply = (shznet_pkt_auth_reply*)pkt->get_data();

        if (pkt->header.sessionid != active_dev->second->auth->sessionid)
        {
            disconnect_device(adr.mac, "auth invalid sessionid.");
            return;
        }

        reply->name[32 - 1] = 0;
        reply->type[64 - 1] = 0;

        active_dev->second->reconnect_device(adr, SHZNET_DEV_DEFAULT, reply->name, reply->type);
        active_dev->second->m_max_parallel_queries = (reply->max_parallel_queues);
        active_dev->second->m_max_data_size = (reply->max_data_size);
        active_dev->second->auth->state = SHZNET_AUTH_SUCCESS;
        m_devices[adr.mac] = active_dev->second;
        m_devices_pending.erase(active_dev);
        NETPRNT("accepted pending device.");
        on_device_connect_internal(m_devices[adr.mac]);
    }

    void handle_shizonet_ack(shznet_ip& ip, shznet_pkt_ack* pkt) override 
    {
        if (pkt->type == shznet_ack_request_invalid_sessionid)
        {
            NETPRNT_ERR("invalid sessionid!");
            shznet_mac dev_mac(pkt->mac);
            disconnect_device(dev_mac, "ack invalid sessionid.");
            return;
        }

        //NETPRNT("ACK!!!");
        shznet_adr adr(ip.ip, pkt->mac, ip.port);
        auto active_dev = m_devices.find(adr.mac);

        if (active_dev == m_devices.end())
        {
            active_dev = m_devices_pending.find(adr.mac);
            if (active_dev == m_devices_pending.end())
            {
                NETPRNT("received invalid ack!");
                return;
            }
        }

        active_dev->second->handle_ack(pkt);
    }

    void send_shz_alive_check(shznet_adr& adr)
    {
        m_send_buffer.packet_begin(SHZNET_PKT_ALIVE_CHECK, get_udp().local_adr().mac, adr.mac);
        uint32_t pkt_size = m_send_buffer.packet_end();
        m_udp.send_buffered_prio(adr.ip, (uint8_t*)&m_send_buffer, pkt_size);
    }

    void handle_artnet_reply(shznet_ip& adr, artnet_poll_reply* poll_reply) override
    {
        if (memcmp(poll_reply->mac, "\x00\x00\x00\x00\x00\x00", 6) == 0)
        {
            memcpy(poll_reply->mac, adr.ip, 4);
            memcpy(&poll_reply->mac[4], &adr.port, 2);
        }

        shznet_receiver::handle_artnet_reply(adr, poll_reply); //unneccessary but maybe for the future

        shznet_adr art_adr(adr.ip, poll_reply->mac, adr.port);

        if (m_udp.local_adr() == art_adr)
            return;

        auto dev_it = m_artnet_devices.find(art_adr.mac);

        if (dev_it != m_artnet_devices.end())
        {
            dev_it->second->update_address(art_adr);
            dev_it->second->set_name((char*)poll_reply->shortname);
            dev_it->second->set_description((char*)poll_reply->longname);
            return;
        }

        /*auto offline_dev = m_artnet_devices_offline.find(art_adr.mac);

        if (offline_dev != m_artnet_devices_offline.end())
        {
            m_artnet_devices[art_adr.mac] = offline_dev->second;
            m_artnet_devices_offline.erase(offline_dev);
            offline_dev->second->reconnect_device(art_adr);
            this->on_device_connect_internal(offline_dev->second);
        }
        else
        */
        {
            poll_reply->shortname[18-1] = 0;
            poll_reply->longname[64 - 1] = 0;
            poll_reply->nodereport[64 - 1] = 0;
            auto new_dev = std::make_shared<shznet_artnet_device>(this, art_adr, (char*)poll_reply->shortname, (char*)poll_reply->longname);
            m_artnet_devices[art_adr.mac] = new_dev;
            this->on_device_connect_internal(new_dev);
            NETPRNT_FMT("new artnet device: %s\n", poll_reply->shortname);
        }
    }

    void send_art_poll()
    {
        if (!m_poll_broadcast_subnet_switch)
        {
            shznet_ip adr((short)ART_NET_PORT);
            m_udp.send_packet_artnet(adr, (uint8_t*)&art_poll, sizeof(artnet_poll));
        }
        else
        {
            shznet_ip adr = local_ip();
            adr.ip[3] = 255;
            adr.port = ART_NET_PORT;
            m_udp.send_packet_artnet(adr, (uint8_t*)&art_poll, sizeof(artnet_poll));
        }

        if (m_udp.local_adr().ip.port != ART_NET_PORT)
        {
            shznet_ip adr2(m_udp.local_adr().ip.port);
            m_udp.send_packet_artnet(adr2, (uint8_t*)&art_poll, sizeof(artnet_poll));

        }

#ifdef _WIN32
        {
            shznet_ip adr((short)ART_NET_PORT);
            adr.ip[0] = 127;
            adr.ip[1] = 0;
            adr.ip[2] = 0;
            adr.ip[3] = 1;
            m_udp.send_packet_artnet(adr, (uint8_t*)&art_poll, sizeof(artnet_poll));
        }
#endif
    }

    void send_art_poll(shznet_ip& adr)
    {
        m_udp.send_packet_artnet(adr, (uint8_t*)&art_poll, sizeof(artnet_poll));
    }

    void send_art_sync(shznet_ip& adr)
    {
        m_udp.send_packet_artnet(adr, (uint8_t*)&art_sync, sizeof(artnet_sync));
    }

    void send_shz_poll()
    {
        m_send_buffer.packet_begin(SHZNET_PKT_AUTH_BEACON, get_udp().local_adr().mac, shznet_broadcast_mac);

        uint32_t pkt_size = m_send_buffer.packet_end();

        if (!m_poll_broadcast_subnet_switch)
        {
            shznet_ip adr((short)ART_NET_PORT);
            m_udp.send_packet(adr, (uint8_t*)&m_send_buffer, pkt_size);
        }
        else
        {
            shznet_ip adr = local_ip();
            adr.ip[3] = 255;
            adr.port = ART_NET_PORT;
            m_udp.send_packet(adr, (uint8_t*)&m_send_buffer, pkt_size);
        }

        if (m_udp.local_adr().ip.port != ART_NET_PORT)
        {
            shznet_ip adr((short)ART_NET_PORT);
            adr.port = m_udp.local_adr().ip.port;
            m_udp.send_packet(adr, (uint8_t*)&m_send_buffer, pkt_size);
            int port_delta = m_udp.local_adr().ip.port - ART_NET_PORT;
            if (port_delta > 1)
            {
                adr.port = ART_NET_PORT + m_poll_probe;
                m_udp.send_packet(adr, (uint8_t*)&m_send_buffer, pkt_size);
                m_poll_probe++;
                if (m_poll_probe >= port_delta) m_poll_probe = 1;
            }
        }
    }

    void send_shz_poll(shznet_adr& adr)
    {
        m_send_buffer.packet_begin(SHZNET_PKT_AUTH_BEACON, get_udp().local_adr().mac, adr.mac);
        uint32_t pkt_size = m_send_buffer.packet_end();
        m_udp.send_buffered_prio(adr.ip, (uint8_t*)&m_send_buffer, pkt_size);
    }

    void send_art_universe(shznet_ip& adr, int universe, byte* data, int len)
    {
        art_dmx_buffer.universe = universe;
        art_dmx_buffer.length = len > 512 ? 512 : len;
        memcpy(art_dmx_buffer.data, data, len);
        int total_size = ART_DMX_START + art_dmx_buffer.length;
        art_dmx_buffer.length = reverse_bits<short>(art_dmx_buffer.length);
        m_udp.send_packet_artnet(adr, (byte*) & art_dmx_buffer, total_size);
    }

    //low level API
    bool sendto(shznet_ip& ip, void* buffer, size_t size)
    {
        return get_udp().send_buffered(ip, (byte*)buffer, size);
    }

    void send_auth_req(shznet_device_ptr dev)
    {
        shznet_pkt_auth_req req(dev->auth->sessionid);

        NETPRNT_FMT("send auth request with id: %i to %s:%i %s test: %i\n", dev->auth->sessionid, dev->get_ip().str().c_str(), (int)dev->get_address().ip.port, dev->get_mac().str().c_str(), (int)m_devices_pending.size());

        m_send_buffer.packet_begin(SHZNET_PKT_AUTH_REQ, get_udp().local_adr().mac, dev->get_mac());
        m_send_buffer.packet_set_data<shznet_pkt_auth_req>(req);
        uint32_t pkt_size = m_send_buffer.packet_end();
        m_udp.send_buffered_prio(dev->get_ip(), (uint8_t*)&m_send_buffer, pkt_size);
    }

    bool send_stream_broadcast(const char* cmd, byte* data, size_t size, shznet_pkt_dataformat fmt = SHZNET_PKT_FMT_DATA)
    {
        if (!size || !data) return 1;

        size_t max_data_size = SHZNET_PKT_DATA_SIZE;

        if (size <= max_data_size)
        {
            auto buf = get_sendpacket();

            buf.packet_begin(SHZNET_PKT_STREAM, local_mac(), shznet_broadcast_mac, get_new_ticketid(), -1);
            buf.packet_set_cmd((char*)cmd);
            buf.packet_set_data(data, size, size);
            buf.packet_set_unreliable();
            buf.packet_set_format(fmt);
            auto total_size = buf.packet_end();
            return sendto(shznet_broadcast_ip, (byte*)&buf, total_size);
        }

        //sequence the packet !

        uint32_t max_sequence = size / max_data_size;

        //special case
        if (max_sequence * max_data_size == size && max_sequence)
            max_sequence--;

        auto buf = get_sendpacket_big();

        buf.packet_begin(SHZNET_PKT_STREAM, local_mac(), shznet_broadcast_mac, get_new_ticketid(), -1);
        buf.packet_set_unreliable();
        buf.packet_set_format(fmt);
        buf.packet_set_cmd((char*)cmd);

        uint32_t data_index = 0;

        for (uint32_t i = 0; i <= max_sequence; i++)
        {
            buf.packet_set_data(&data[data_index], std::min(max_data_size, (size_t)(size - data_index)), size);
            buf.packet_set_seq(i, max_sequence);
            auto total_size = buf.packet_end();
            if (!sendto(shznet_broadcast_ip, (byte*)&buf, total_size))
            {
                //NETPRNT("sendto failed!");
                return 0;
            }

            data_index += max_data_size;
            //std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        return 1;
    }

    shznet_device_ptr find_device(shznet_mac& mac)
    {
        auto it = m_devices.find(mac);
        if (it == m_devices.end())
            return 0;
        return it->second;
    }
    shznet_device_ptr find_device(byte* mac)
    {
        shznet_mac _mac(mac);
        return find_device(_mac);
    }
    shznet_device_ptr find_device2(shznet_mac mac)
    {
        auto it = m_devices.find(mac);
        if (it == m_devices.end())
            return 0;
        return it->second;
    }
};

//TODO: should it work someday, merge it back with the shznet_base_impl class directly
//this is just here to divide base network impl and command-response stuff

class shznet_responder
{
    shznet_device_ptr _device;
    shznet_ticketid _id;
    byte*           _data;
    size_t          _size;
    shznet_pkt_dataformat _fmt;

    bool has_responded = false;

    bool check_respond()
    {
        if (has_responded)
        {
            NETPRNT("can only respond once!");
            return true;
        }
        has_responded = true;
        return false;
    }

public:

    shznet_responder(shznet_device_ptr _dev, shznet_ticketid _id, byte* _data, size_t _size, shznet_pkt_dataformat _fmt) : _device(_dev), _id(_id), _data(_data), _size(_size), _fmt(_fmt) {}

    void respond(byte* data, size_t size, shznet_pkt_dataformat fmt = SHZNET_PKT_FMT_DATA)
    {
        if (check_respond()) return;
        if (!data || !size)
            fmt = SHZNET_PKT_FMT_INVALID;
        _device->send_response(SHZNET_RESPONSE_ACK_CMD_SUCCESS, _id, data, size, fmt);
    }

    void respond(const char* str)
    {
        if (check_respond()) return;

        _device->send_response(SHZNET_RESPONSE_ACK_CMD_SUCCESS, _id, (byte*)str, strlen(str) + 1, SHZNET_PKT_FMT_STRING);
    }

    void respond(shznet_kv_writer& writer)
    {
        if (check_respond()) return;

        _device->send_response(SHZNET_RESPONSE_ACK_CMD_SUCCESS, _id, writer.get_buffer().data(), writer.get_buffer().size(), SHZNET_PKT_FMT_KEY_VALUE);
    }

    void respond_fail(byte* data, size_t size, shznet_pkt_dataformat fmt = SHZNET_PKT_FMT_DATA)
    {
        if (check_respond()) return;

        _device->send_response(SHZNET_RESPONSE_ACK_CMD_FAIL, _id, data, size, fmt);
    }

    void respond_fail(const char* str)
    {
        if (check_respond()) return;

        _device->send_response(SHZNET_RESPONSE_ACK_CMD_FAIL, _id, (byte*)str, strlen(str) + 1, SHZNET_PKT_FMT_STRING);
    }

    byte* data() { return _data; }
    size_t size() { return _size; }
    shznet_pkt_dataformat format() { return _fmt; }

    shznet_device* device() { return _device.get(); }
    shznet_device_ptr   device_ptr() { return _device; }

    ~shznet_responder()
    {
        if (!has_responded)
        {
            _device->send_response(SHZNET_RESPONSE_ACK_CMD_SUCCESS, _id, 0, 0, SHZNET_PKT_FMT_INVALID);
        }
    }
};

#ifdef ESP32_OTA
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "mbedtls/sha256.h"
#include "esp_task_wdt.h"
#endif

class shznet_base : public shznet_base_impl
{
    struct network_buffer_static_s
    {
        network_buffer_static_type type;
        byte*   data;
        size_t  size;
        std::string description;
        std::string setup;
    };

protected:
    friend class shznet_device;
    
    //local stuff
    std::vector<std::unique_ptr<pending_device_respond_msg>> m_pending_device_responds; //this is used in case another device sends a respond request but is not yet connected to us, execute as soon as it is connected!
   
    std::unordered_map<uint32_t, std::function<void(std::shared_ptr<shznet_responder>)>>    m_response_callbacks;
    std::unordered_map<uint32_t, std::string>                                               m_response_command_names;
    std::unordered_map<uint32_t, network_buffer_static_s>                                   m_network_buffers_static;
    std::unordered_map<uint32_t, std::string>                                               m_network_buffers_static_names;

    void handle_response_recv(shznet_device_ptr dev, uint32_t cmd, shznet_ticketid id, byte* data, size_t size, shznet_pkt_dataformat fmt)
    {
        auto it = m_response_callbacks.find(cmd);
        if (it == m_response_callbacks.end())
        {
            dev->send_reliable(SHZNET_RESPONSE_ACK_CMD_NOTFOUND, (byte*)&id, sizeof(id), SHZNET_PKT_FMT_DATA, false);
            return;
        }

        auto responder = std::make_shared<shznet_responder>(dev, id, data, size, fmt);
        it->second(responder);
    }

    shznet_kv_writer kvw;

    bool _has_shizoscript_json = false;

#ifdef ESP32_OTA
    esp_ota_handle_t ota_update_handle = -1;
    esp_partition_t* ota_update_partition = 0;
    bool ota_reboot = 0;
    shznet_timer ota_reboot_timer = shznet_timer(1000 * 5);

    void get_running_firmware_sha256(uint8_t out_hash[32]) {
        const esp_partition_t* running = esp_ota_get_running_partition();

        if (!running) {
            printf("Failed to get running partition\n");
            return;
        }

        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0); // 0 = SHA-256 (not SHA-224)

        const size_t buffer_size = 1024;
        uint8_t buffer[buffer_size];
        size_t offset = 0;

        while (offset < running->size) {
            size_t read_size = buffer_size;
            if (offset + read_size > running->size) {
                read_size = running->size - offset;
            }

            if (esp_partition_read(running, offset, buffer, read_size) != ESP_OK) {
                printf("Failed to read flash at offset %d\n", (int)offset);
                break;
            }

            mbedtls_sha256_update(&ctx, buffer, read_size);
            offset += read_size;
        }

        mbedtls_sha256_finish(&ctx, out_hash);
        mbedtls_sha256_free(&ctx);
    }

#endif

public:

    shznet_base()
    {
        add_command_respond(SHZNET_TEST_CMD, [this](std::shared_ptr<shznet_responder> responder)
            {
                kvw.clear();

                kvw.add_int32("version", SHZNET_COMPAT_VERSION);
                kvw.add_int32("has_json", _has_shizoscript_json);
                kvw.add_int32("pacing", SHZNET_PACKET_PACING_COUNT);

                shznet_kv_writer kvw_sub;

                for (auto& it : m_command_names)
                {
                    shznet_command_defs def;
                    memset(&def, 0, sizeof(def));
                    def.hash = it.first;
                    def.type = 0;
                    kvw_sub.add_data(it.second.c_str(), (byte*)&def, sizeof(def));
                }
                for (auto& it : m_response_command_names)
                {
                    shznet_command_defs def;
                    memset(&def, 0, sizeof(def));
                    def.hash = it.first;
                    def.type = 1;
                    kvw_sub.add_data(it.second.c_str(), (byte*)&def, sizeof(def));
                }
                kvw.add_kv("commands", kvw_sub);


                kvw_sub.clear();
                for (auto& it : m_network_buffers_static)
                {
                    shznet_buffer_defs bdef;
                    memset(&bdef, 0, sizeof(bdef));
                    bdef.hash = it.first;
                    bdef.size = it.second.size;
                    bdef.type = (uint32_t)it.second.type;
                    kvw_sub.add_data(m_network_buffers_static_names[it.first].c_str(), (byte*)&bdef, sizeof(bdef));
                }
                kvw.add_kv("static_buffers", kvw_sub);


                kvw_sub.clear();
                for (auto& it : m_network_buffers_static)
                {
                    kvw_sub.add_string(m_network_buffers_static_names[it.first].c_str(), it.second.description.c_str());
                }
                kvw.add_kv("static_buffers_desc", kvw_sub);


                kvw_sub.clear();
                for (auto& it : m_network_buffers_static)
                {
                    kvw_sub.add_string(m_network_buffers_static_names[it.first].c_str(), it.second.setup.c_str());
                }
                kvw.add_kv("static_buffers_setup", kvw_sub);

                responder->respond(kvw);
            });

        add_command(SHZNET_RESPONSE_CMD, [this](shznet_ip& ip, byte* data, size_t size, shznet_pkt_header& hdr)
            {
                if (size < sizeof(uint32_t))
                    return;
                
                uint32_t cmd_hash = *(uint32_t*)&data[0];

                data += sizeof(uint32_t);
                size -= sizeof(uint32_t);

                auto dev = find_device(hdr.macid_source);
                if (dev )
                {
                    handle_response_recv(dev, cmd_hash, hdr.ticketid, data, size, hdr.data_format);
                }
                else
                {
                    NETPRNT_ERR("response dev not found!");
                    auto cmd_ticket = hdr.ticketid;
                    auto sid = hdr.sessionid;
                    auto ptr = std::make_unique<pending_device_respond_msg>(cmd_hash, cmd_ticket, hdr.macid_source, sid, hdr.data_format);
                    ptr->data.resize(size);
                    memcpy(ptr->data.data(), data, size);
                    m_pending_device_responds.push_back(std::move(ptr));
                    shznet_adr dev_adr;
                    dev_adr.ip = ip;
                    dev_adr.mac = hdr.macid_source;
                    send_shz_poll(dev_adr);
                }
            });
        add_command(SHZNET_RESPONSE_ACK_CMD_NOTFOUND, [this](shznet_ip& ip, byte* data, size_t size, shznet_pkt_header& hdr)
            {
                if (size < sizeof(shznet_ticketid))
                {
                    NETPRNT("invalid ticketid size in response ack!");
                    return;
                }
                NETPRNT("response command not found.");
                shznet_ticketid id = *(shznet_ticketid*)&data[0];
                data += sizeof(shznet_ticketid);
                size -= sizeof(shznet_ticketid);

                shznet_mac mac = hdr.macid_source;

                for (auto it = m_wait_responses.begin(); it != m_wait_responses.end();)
                {
                    if (it->id == id && it->dev == mac)
                    {
                        auto cb = it->cb;
                        m_wait_responses.erase(it);
                        cb(data, size, hdr.data_format, false);                     
                        break;
                    }
                    else
                        it++;
                }
            });
        add_command(SHZNET_RESPONSE_ACK_CMD_FAIL, [this](shznet_ip& ip, byte* data, size_t size, shznet_pkt_header& hdr)
            {
                NETPRNT("response command failed.");

                if (size < sizeof(shznet_ticketid))
                {
                    NETPRNT("invalid ticketid size in response ack!");
                    return;
                }

                shznet_ticketid id = *(shznet_ticketid*)&data[0];
                data += sizeof(shznet_ticketid);
                size -= sizeof(shznet_ticketid);

                shznet_mac mac = hdr.macid_source;

                for (auto it = m_wait_responses.begin(); it != m_wait_responses.end();)
                {
                    if (it->id == id && it->dev == mac)
                    {
                        auto cb = it->cb;
                        m_wait_responses.erase(it);
                        cb(data, size, hdr.data_format, false);
                        break;
                    }
                    else
                        it++;
                }
            });
        add_command(SHZNET_RESPONSE_ACK_CMD_SUCCESS, [this](shznet_ip& ip, byte* data, size_t size, shznet_pkt_header& hdr)
            {
                if (size < sizeof(shznet_ticketid))
                {
                    NETPRNT("invalid ticketid size in response ack!");
                    return;
                }

                shznet_ticketid id = *(shznet_ticketid*)&data[0];
                data += sizeof(shznet_ticketid);
                size -= sizeof(shznet_ticketid);

                shznet_mac mac = hdr.macid_source;

                for (auto it = m_wait_responses.begin(); it != m_wait_responses.end();)
                {
                    if (it->id == id && it->dev == mac)
                    {
                        auto cb = it->cb;
                        m_wait_responses.erase(it);
                        cb(data, size, hdr.data_format, true);
                        break;
                    }
                    else
                        it++;
                }
            });

        add_command("SHZSET_STATIC_BUFFER", [this](shznet_ip& ip, byte* data, size_t size, shznet_pkt_header& hdr)
            {
                shznet_kv_reader reader(data, size);
            
                while (reader.read())
                {
                    //name_hash, start_chunk, data
                    uint32_t name_hash = reader.get_value_type<uint32_t>();

                    if (!reader.read()) break;

                    uint32_t start_chunk = reader.get_value_type<uint32_t>();

                    if (!reader.read()) break;

                    uint32_t payload_size = reader.get_value_size();
                    byte* payload = reader.get_value();

                    auto nb = m_network_buffers_static.find(name_hash);
                    if (nb == m_network_buffers_static.end())
                        break;

                    auto nbs = nb->second;

                    if (start_chunk * 256 + payload_size <= nbs.size)
                    {
                        memcpy(&nbs.data[start_chunk * 256], payload, payload_size);
                    }
                }
            });
        
#ifdef ESP32_OTA
        add_command_respond("ESP32_OTA_START", [this](std::shared_ptr<shznet_responder> responder)
            {
                kvw.clear();

                TaskHandle_t loopHandle = xTaskGetCurrentTaskHandle();
                esp_task_wdt_delete(loopHandle);  // Unregister loopTask from watchdog

                esp_task_wdt_deinit(); // Removes the watchdog from all tasks (global disable)

                if (ota_update_handle != -1)
                {
                    Serial.println("Closing old OTA handle.");
                    esp_ota_end(ota_update_handle);
                }
                ota_update_handle = -1;
                Serial.println("Getting OTA partition...");
                ota_update_partition = (esp_partition_t*)esp_ota_get_next_update_partition(NULL);
                if (ota_update_partition == NULL) {
                    // Handle error: No update partition found
                    kvw.add_int32("success", 0);
                    kvw.add_string("error", "No OTA partition.");
                    responder->respond(kvw);
                    return;
                }

                uint32_t size = 0;
                
                if(responder->data() && responder->size() == sizeof(uint32_t))
                    size = *(uint32_t*)responder->data();
                else if (responder->data() && responder->size() == sizeof(uint64_t))
                    size = *(uint64_t*)responder->data();



                Serial.print("OTA begin with size: ");
                Serial.println(size);
                esp_err_t err = esp_ota_begin(ota_update_partition, size == 0 ? OTA_SIZE_UNKNOWN : size, &ota_update_handle);
                
                if (err != ESP_OK) {
                    kvw.add_int32("success", 0);
                    kvw.add_string("error", "OTA begin error.");
                    responder->respond(kvw);
                    return;
                }

                Serial.println("OTA open successful.");

                kvw.add_int32("success", 1);

                responder->respond(kvw);
            });

        add_command_respond("ESP32_OTA_END", [this](std::shared_ptr<shznet_responder> responder)
            {
                kvw.clear();

                if (ota_update_handle != -1)
                {
                    auto err = esp_ota_end(ota_update_handle);
                    if (err != ESP_OK) {
                        ESP_LOGE(TAG, "OTA End failed: %s", esp_err_to_name(err));
                        kvw.add_int32("success", 0);
                        kvw.add_string("error", esp_err_to_name(err));
                        responder->respond(kvw);
                        ota_update_handle = -1;
                        return;
                    }

                    // Set boot partition and restart
                    err = esp_ota_set_boot_partition(ota_update_partition);
                    if (err != ESP_OK) {
                        ESP_LOGE(TAG, "Setting boot partition failed: %s", esp_err_to_name(err));
                        kvw.add_int32("success", 0);
                        kvw.add_string("error", esp_err_to_name(err));
                        responder->respond(kvw);
                        ota_update_handle = -1;
                        return;
                    }

                    kvw.add_int32("success", 1);
                    ota_reboot = true;
                    ota_reboot_timer.reset();
                }
                else
                {
                    kvw.add_string("error", "no data uploaded");
                    kvw.add_int32("success", 0);
                }

                ota_update_handle = -1;

                responder->respond(kvw);
            });

        add_command_respond("ESP32_OTA_CHUNK", [this](std::shared_ptr<shznet_responder> responder)
            {
                kvw.clear();
                Serial.println("OTA CHUNK");
                auto err = esp_ota_write(ota_update_handle, responder->data(), responder->size());
                if (err != ESP_OK)
                    kvw.add_int32("success", 0);              
                else
                    kvw.add_int32("success", 1);

                responder->respond(kvw);
            });

        add_command_respond("esp32_ota_enabled", [this](std::shared_ptr<shznet_responder> responder)
            {
                //Serial.println("OTA ENABLE TEST");
                kvw.clear();
                
                uint8_t sha_256[32] = { 0 };
                
                get_running_firmware_sha256(sha_256);
                
                // Convert sha_256 byte array to a hex string
                char sha_str[65] = { 0 }; // 32 bytes * 2 characters + 1 for null terminator
                for (int i = 0; i < 32; i++) {
                    sprintf(sha_str + (i * 2), "%02x", sha_256[i]);
                }

                kvw.add_int32("has_ota", 1);
                kvw.add_string("class", ota_class);
                kvw.add_string("subclass", ota_subclass);

                // Add both the raw data and the string representation
                kvw.add_string("sha256_str", sha_str);
                kvw.add_data("sha256", sha_256, 32);

                responder->respond(kvw);
            });
#endif
    }

    virtual ~shznet_base() {};

    void add_command_respond(const char* cmd, std::function<void(std::shared_ptr<shznet_responder>)> cb)
    {
        auto hs = shznet_hash((char*)cmd, strlen(cmd));
        if (m_response_callbacks.find(hs) != m_response_callbacks.end() || hs == 0)
        {
            NETPRNT("error: command name collision for");
            NETPRNT(cmd);
        }
        m_response_callbacks[hs] = cb;
        m_response_command_names[hs] = cmd;
    }

    virtual void remove_command(const char* cmd) override
    {
        auto hs = shznet_hash((char*)cmd, strlen(cmd));
        shznet_receiver::remove_command(cmd);
        if (m_response_callbacks.find(hs) != m_response_callbacks.end()) m_response_callbacks.erase(hs);
        if (m_response_command_names.find(hs) != m_response_command_names.end()) m_response_command_names.erase(hs);
    }

    void add_buffer_static(network_buffer_static_type type, const char* name, void* static_buffer_ptr, size_t size, const char* description = "", const char* setup = "")
    {
        auto hs = shznet_hash((char*)name, strlen(name));
        m_network_buffers_static[hs] = { type, (byte*)static_buffer_ptr, size, description, setup };
        m_network_buffers_static_names[hs] = name;
    }

    virtual void update() override
    {
#ifdef ESP32_OTA
        if (ota_reboot && ota_reboot_timer.update())
            esp_restart();
#endif

        if (m_pending_disconnect.size())
        {
            for (auto& it : m_pending_disconnect)
            {
                disconnect_device(it.first, it.second);
            }
            m_pending_disconnect.clear();
        }

        for (auto it = m_pending_device_responds.begin(); it != m_pending_device_responds.end();)
        {
            if (it->get()->timeout.update())
            {
                it = m_pending_device_responds.erase(it);
                continue;
            }
            auto dev = find_device(it->get()->device);
            if (dev && dev->connected)
            {
                handle_response_recv(dev, it->get()->cmd, it->get()->id, it->get()->data.data(), it->get()->data.size(), it->get()->fmt);
                it = m_pending_device_responds.erase(it);
                continue;
            }
            it++;
        }

        //call twice to make sure _everything_ gets send at this particular frame
#ifndef ARDUINO
        shznet_base_impl::update();
#endif
        shznet_base_impl::update();
    }

protected:

    void handle_response_add(response_wait rw)
    {
        m_wait_responses.push_back(rw);
    }

    void handle_response_failed(shznet_ticketid tid) override
    {
        for (auto it = m_wait_responses.begin(); it != m_wait_responses.end();)
        {
            if (it->id == tid)
            {
                auto cb = it->cb;
                m_wait_responses.erase(it);
                if(cb) cb(0, 0, SHZNET_PKT_FMT_INVALID, 0);
                break;
            }
            else
                ++it;
        }
    }

    void handle_response_disconnect(shznet_device_ptr& dev_info) override
    {
        m_wait_responses_tmp2.clear();
        for (auto it = m_wait_responses.begin(); it != m_wait_responses.end();)
        {
            if (it->dev == dev_info.get()->get_mac())
            {
                NETPRNT_FMT("response failed for dev: %s\n", dev_info.get()->name.c_str());
                m_wait_responses_tmp2.push_back(*it);
                it = m_wait_responses.erase(it);
            }
            else
                ++it;
        }

        for (auto& it : m_wait_responses_tmp2)
        {
            if(it.cb) it.cb(0, 0, SHZNET_PKT_FMT_DATA, 0);
        }
    }
};

class shznet_client : public shznet_base
{
public:

    shznet_client() : shznet_base()
    {
        
    }

    virtual ~shznet_client() { m_udp.invalidate_threads(); }

};

class shznet_server : public shznet_base
{
    shznet_timer    art_poll_timer = shznet_timer(1000 * 3);

public:

    shznet_server() : shznet_base()
    {
  
    }

    virtual ~shznet_server() { m_udp.invalidate_threads(); }

    virtual void update() override
    {
        shznet_base::update();
        if (art_poll_timer.update())
        {
            send_art_poll();

            if(m_shizonet_enabled)
                send_shz_poll();

            //m_poll_broadcast_subnet_switch ^= 1;

            /*
            shznet_ip broadcast(m_udp.local_adr().ip.port);
            send_art_poll_reply(broadcast);
            if (broadcast.port != ART_NET_PORT)
            {
                broadcast.port = ART_NET_PORT;
                send_art_poll_reply(broadcast);
            }
            */
        }
    }
};


#endif