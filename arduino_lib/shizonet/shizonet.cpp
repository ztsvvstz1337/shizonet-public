
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
#ifdef __XTENSA__
    //check here if we have free SRAM, try to allocate stuff there first
    if (psramInit() && ((ESP.getFreeHeap()+size) < 1024 * 150))
        return ps_malloc(size);
#endif
    return malloc(size);
}

shznet_ip shznet_broadcast_ip = shznet_ip(255, 255, 255, 255, ART_NET_PORT);
shznet_mac shznet_broadcast_mac = shznet_mac((byte*)"\xFF\xFF\xFF\xFF\xFF\xFF");

#if defined(ARDUINO) && !defined(__XTENSA__)
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
        base->handle_response_add(shznet_base_impl::response_wait(tid, get_mac(), fetch_cmd->callback, 1000 * 10));

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

shznet_sessionid shznet_global_s::get_new_sessionid()
{
    static shznet_sessionid _id;
    _id++;
    while (_id == -1 || _id == 0)
        _id++;
    return _id;
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