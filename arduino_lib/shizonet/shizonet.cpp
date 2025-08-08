
/*
 * Copyright (c) 2018–Now Erik Mackrodt. All rights reserved.
 *
 * This file is part of Shizotech™ software, developed and maintained by Erik Mackrodt.
 *
 * For inquiries, please visit: https://shizotech.com
 */

#include "shizonet.h"

void* shznet_malloc(size_t size)
{
#ifdef ARDUINO_ARCH_ESP32
    //check here if we have free SRAM, try to allocate stuff there first
    if (psramInit() && ((ESP.getFreeHeap()+size) < 1024 * 100))
        return ps_malloc(size);
#endif
    return malloc(size);
}

shznet_ip shznet_broadcast_ip = shznet_ip(255, 255, 255, 255, ART_NET_PORT);
shznet_mac shznet_broadcast_mac = shznet_mac((byte*)"\xFF\xFF\xFF\xFF\xFF\xFF");

#if defined(ARDUINO) && !defined(ARDUINO_ARCH_ESP32)
uint64_t shznet_millis()
{
    static uint32_t low32, high32;
    uint32_t new_low32 = millis();
    if (new_low32 < low32) high32++;
    low32 = new_low32;
    return (uint64_t)high32 << 32 | low32;
}
#else
uint64_t shznet_millis()
{
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    return millis;
}
#endif

#ifdef SHIZONET_BASE
shznet_global_s shznet_global;
shznet_recycler<shznet_device::command_buffer_s> shznet_device::reliable_buffers;

void shznet_device::clear_command_buffers()
{
    NETPRNT("clearing cmd buffers...");
    while (zombie_buffers.size())
    {
        handle_response_failed(zombie_buffers.front()->ticketid);
        reliable_buffers.recycle(zombie_buffers.front());
        zombie_buffers.pop();
    }

    while (ordered_buffers.size())
    {
        handle_response_failed(ordered_buffers.front()->ticketid);
        reliable_buffers.recycle(ordered_buffers.front());
        ordered_buffers.pop();
    }

    for (auto it : unordered_buffers)
    {
        handle_response_failed(it->ticketid);
        reliable_buffers.recycle(it);
    }

    unordered_buffers.clear();

}

void shznet_device::clear_command_buffer(shznet_ticketid ticketid, bool cmd_failed, bool check_responses)
{
    if (cmd_failed)
        handle_response_failed(ticketid);

    if (zombie_buffers.size() && zombie_buffers.front()->ticketid == ticketid)
    {
        calculate_error_rate(zombie_buffers.front());
        reliable_buffers.recycle(zombie_buffers.front());
        zombie_buffers.pop();
        return;
    }

    if (ordered_buffers.size() && ordered_buffers.front()->ticketid == ticketid)
    {
        calculate_error_rate(ordered_buffers.front());
        reliable_buffers.recycle(ordered_buffers.front());
        ordered_buffers.pop();
        return;
    }

    for (auto it = unordered_buffers.begin(); it != unordered_buffers.end(); it++)
    {
        if ((*it)->ticketid == ticketid)
        {
            calculate_error_rate(*it);
            reliable_buffers.recycle(*it);
            unordered_buffers.erase(it);
            NETPRNT("cleared unordered command buffer.");
            NETPRNT_ERR("unordered order cleared.");
            return;
        }
    }

    if (check_responses)
    {
        for (auto it = response_buffers.begin(); it != response_buffers.end(); it++)
        {
            if ((*it)->ticketid == ticketid)
            {
                calculate_error_rate(*it);
                reliable_buffers.recycle(*it);
                response_buffers.erase(it);
                NETPRNT("cleared response command buffer.");
                return;
            }
        }
    }
}

void shznet_device::flush_send_buffers()
{
    base->get_udp().flush_send_buffer();
}

shznet_ticketid shznet_device::send_get(const char* cmd, byte* data, size_t size, shznet_pkt_dataformat fmt, shznet_response_callback cb, uint64_t timeout)
{
    auto tid = send_response(SHZNET_RESPONSE_CMD, shznet_hash((char*)cmd,strlen(cmd)), data, size, fmt, true);
    if (tid != INVALID_TICKETID)
    {
        base->handle_response_add(shznet_base_impl::response_wait(tid, get_mac(), cb, timeout));

        send_finished(tid, [this, tid](bool success)
            {
                if (!success)
                {
                    NETPRNT_ERR("response cmd failed!");
                    base->handle_response_failed(tid);
                }
            });
    }

    return tid;
}

void shznet_device::send_fetch(const char* cmd, byte* data, size_t size, shznet_pkt_dataformat fmt, shznet_response_callback cb, uint64_t timeout)
{
    auto fetch = std::make_shared<fetch_command_s>(cmd, data, size, fmt, cb, timeout);

    send_fetch(fetch);
}

void shznet_device::send_fetch(std::shared_ptr<fetch_command_s> fetch_cmd)
{
    if (!fetch_cmd)
        return;

    auto tid = send_response(SHZNET_RESPONSE_CMD, shznet_hash((char*)fetch_cmd->command.c_str(), fetch_cmd->command.length()), fetch_cmd->buffer.data(), fetch_cmd->buffer.size(), fetch_cmd->format, true);

    if (tid != INVALID_TICKETID)
    {
        base->handle_response_add(shznet_base_impl::response_wait(tid, get_mac(), [this, fetch_cmd](byte* data, size_t size, shznet_pkt_dataformat fmt, bool success)
            {
                if (!success)
                    fetch_commands.push_back(fetch_cmd);
                else
                    fetch_cmd->callback(data, size, fmt, success);
            }, 1000 * 10));

        send_finished(tid, [this, tid, fetch_cmd](bool success)
            {
                if (!success)
                {
                    if (fetch_cmd->timeout_timer.update())
                    {
                        NETPRNT_ERR("response cmd failed!");
                        base->handle_response_failed(tid);
                        return;
                    }

                    fetch_commands.push_back(fetch_cmd);
                }
            });
    }
    else
    {
        fetch_commands.push_back(fetch_cmd);
    }
}


void shznet_device::handle_ack(shznet_pkt_ack* pkt)
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

        if (pkt->missing_start_id == -4 && pkt->missing_end_id == -4) //order not found (no pkt arrived on single packet cmds for example)
        {
            NETPRNT("device disconnected (or restarted)");

            base->disconnect_device(get_mac(), "Restarted");
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
        else if (pkt_failed)
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

bool shznet_device::sendto(void* buffer, size_t size)
{
    if (!base) return 0;
    return base->sendto(get_ip(), buffer, size);
}
shznet_pkt& shznet_device::get_sendpacket()
{
    return base->get_sendpacket();
}
shznet_pkt_big& shznet_device::get_sendpacket_big()
{
    return base->get_sendpacket_big();
}

shznet_mac& shznet_device::get_local_mac()
{
    return base->local_mac();
}
shznet_ip& shznet_device::get_local_ip()
{
    return base->local_ip();
}

void shznet_device::handle_response_failed(shznet_ticketid id)
{
    base->handle_response_failed(id);
}

void shznet_artnet_device::send_art_universe(int universe, byte* data, int len)
{
    if (!base) return;
    base->send_art_universe(get_ip(), universe, data, len);
}


#include <random>

uint64_t getRandom64() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dist;
    return dist(gen);
}
shznet_sessionid shznet_global_s::get_new_sessionid()
{
    //UPDATE: instead of incremental sessionids, generate random sessionid and keep them alive for each device
    auto rnd = getRandom64();
    if (rnd == 0) rnd++;
    return rnd;

    /*
    static shznet_sessionid _id;
    _id++;
    while (_id == -1 || _id == 0)
        _id++;
    return _id;
    */
}
shznet_ticketid shznet_global_s::get_new_ticketid()
{
    static shznet_ticketid _id;
    _id++;
    while (_id == -1 || _id == 0)
        _id++;
    return _id;
}
#endif

#define XXH_INLINE_ALL
#include "xxhash.h"

uint32_t shznet_hash(char* data, size_t size)
{
    XXH32_hash_t hash = XXH32(data, size, size);

    /*uint32_t hash = size;

    uint32_t blks = size / sizeof(uint32_t);
    uint32_t rest = size - blks * sizeof(uint32_t);

    uint32_t* a = (uint32_t*)data;

    for (uint32_t i = 0; i < blks; i++)
        hash += a[i];

    uint32_t rest_start = blks * sizeof(uint32_t);

    for (uint32_t i = rest_start; i < size; i++)
        hash += (uint32_t)data[i];
*/
    return hash;
}

uint32_t shznet_hash(const char* str)
{
    return shznet_hash((char*)str, strlen(str));
}

uint32_t shznet_hash(std::string& str)
{
    return shznet_hash((char*)str.c_str(), str.length());
}


#ifdef _WIN32

#pragma comment(lib, "winmm.lib")

#include <Windows.h>
#include <timeapi.h>


void GenericOSUDPSocket::start_high_resolution_timer()
{
    m_win_interrupt = CreateEvent(NULL, FALSE, FALSE, NULL);

    m_win_timer = CreateWaitableTimerEx(NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);

    int64_t duration_us = 1000;

    LARGE_INTEGER liDueTime;
    // Convert from microseconds to 100 of ns, and negative for relative time.
    liDueTime.QuadPart = -(duration_us * 10);

    if (!SetWaitableTimer(m_win_timer, &liDueTime, 1, NULL, NULL, 0)) {
        printf("CRITICAL ERROR: ");
        printf("SetWaitableTimer failed: errno=%d\n", GetLastError());
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void GenericOSUDPSocket::stop_high_resolution_timer()
{
    CloseHandle(m_win_timer);
    CloseHandle(m_win_interrupt);
}

void GenericOSUDPSocket::high_resolution_wait(uint32_t microseconds)
{
    //MICROSECONDS PARAM IS OBSOLETE !!! just sleep 1 ms always !!!
    HANDLE wait_handles[2];
    wait_handles[0] = m_win_interrupt;
    wait_handles[1] = m_win_timer;

    DWORD ret = WaitForMultipleObjects(2, wait_handles, FALSE, INFINITE);
    //me->m_sendsignal.notify_one();
}

#elif __linux__
void GenericOSUDPSocket::start_high_resolution_timer()
{
   
}

void GenericOSUDPSocket::stop_high_resolution_timer()
{
   
}

void GenericOSUDPSocket::high_resolution_wait(uint32_t microseconds)
{
    struct timespec ts;
    ts.tv_sec = microseconds / 1000000;
    ts.tv_nsec = (microseconds % 1000000) * 1000;
    nanosleep(&ts, NULL);
    //std::this_thread::sleep_for(std::chrono::microseconds(microseconds));
    //me->m_sendsignal.notify_one();
}
#endif