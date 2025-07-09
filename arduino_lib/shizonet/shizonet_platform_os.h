
/*
 * Copyright (c) 2018–Now Erik Mackrodt. All rights reserved.
 *
 * This file is part of Shizotech™ software, developed and maintained by Erik Mackrodt.
 *
 * For inquiries, please visit: https://shizotech.com
 */

#pragma once

#ifndef SHZNET_OS_SOCKET_H_
#define SHZNET_OS_SOCKET_H_

#ifndef ARDUINO
#include <memory>
#include <string.h>     /* Commonly used string-handling functions */
#include <string>
#include <utility>
#include <vector>

typedef unsigned char byte;

#ifdef _WIN32 || _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <Windows.h>
    #include <WinSock2.h>
    #include <Ws2tcpip.h>
    #include <Iphlpapi.h>
    #include <Assert.h>
    
    #pragma comment(lib, "iphlpapi.lib")
    typedef in_addr in_addr_t;
    #pragma comment(lib,"ws2_32.lib") // Winsock Library
#elif __linux__
    #include <unistd.h>     /* Prototypes for many system calls */
    #include <stdio.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/ioctl.h>
    #include <fcntl.h>      /* Non blocking socket */

    #include <netinet/in.h> 
    #include <string.h> 

    #define SOCKET int
    #define SOCKET_ERROR (SOCKET)(-1)
    #define NO_ERROR 0
    typedef unsigned char byte;
#endif

#ifdef __COBALT__
#include <asm/ioctl.h>
#include <rtdm/rtdm.h>
//#include <rtnet.h>
#define RTIOC_TYPE_NETWORK      RTDM_CLASS_NETWORK
#define RTNET_RTIOC_TIMEOUT     _IOW(RTIOC_TYPE_NETWORK,  0x11, int64_t)
#endif

#include <cstddef>
#include <memory>
#include <type_traits>
#include <utility>

#ifdef __ANDROID__
#include "ifaddrs2.h"
#include <string>
#include <sstream>
/*namespace std
{
    template <typename T>
    std::string to_string(T value)
    {
        std::ostringstream os;
        os << value;
        return os.str();
    }
}*/
#elif defined(__linux__)
#include <ifaddrs.h>
#endif

#pragma pack(push, 1)
    struct IPAddress
    {
        byte ip[4];
        IPAddress(byte a, byte b, byte c, byte d)
        {
            ip[0] = a;
            ip[1] = b;
            ip[2] = c;
            ip[3] = d;
        }
        IPAddress(in_addr_t adr)
        {
            ip[0] = ((byte*)&adr)[0];
            ip[1] = ((byte*)&adr)[1];
            ip[2] = ((byte*)&adr)[2];
            ip[3] = ((byte*)&adr)[3];
        }
#ifdef _WIN32
        IPAddress(unsigned int adr)
        {
            memcpy(&ip[0], &adr, sizeof(unsigned int));
        }
#endif
        IPAddress() {}
        ~IPAddress() {}

        bool operator ==(const IPAddress& b) const
        {
            return b.ip[0] == ip[0] && b.ip[1] == ip[1] && b.ip[2] == ip[2] && b.ip[3] == ip[3];
        }

        bool operator < (const IPAddress& rhs) const {
            return false;
        };
        bool operator > (const IPAddress& rhs) const {
            return false;
        };

        std::string getStr() {
            return std::string(std::to_string((int)ip[0]) + "."
                + std::to_string((int)ip[1]) + "."
                + std::to_string((int)ip[2]) + "."
                + std::to_string((int)ip[3]));
        }
    };
    struct macinfo
    {
        byte mac[6] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
        macinfo(byte* _mac = 0) {
            if (_mac)
                memcpy(mac, _mac, 6);
        }

        std::string str()
        {
            char tmp[24];
            snprintf(tmp, sizeof(tmp), "%02X:%02X:%02X:%02X:%02X:%02X",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return tmp;
        }

        bool operator ==(const macinfo& b) const
        {
            return memcmp(mac, b.mac, 6) == 0;
        }
        bool operator !=(const macinfo& b) const
        {
            return memcmp(mac, b.mac, 6) != 0;
        }
        bool operator < (const macinfo& b) const {
            unsigned long long rt1 = 0;
            unsigned long long rt2 = 0;
            memcpy(&rt1, mac, 6);
            memcpy(&rt2, b.mac, 6);
            return rt1 < rt2;
        }
        bool operator > (const macinfo& b) const {
            unsigned long long rt1 = 0;
            unsigned long long rt2 = 0;
            memcpy(&rt1, mac, 6);
            memcpy(&rt2, b.mac, 6);
            return rt1 > rt2;
        }
        bool operator <= (const macinfo& b) const {
            unsigned long long rt1 = 0;
            unsigned long long rt2 = 0;
            memcpy(&rt1, mac, 6);
            memcpy(&rt2, b.mac, 6);
            return rt1 <= rt2;
        }
        bool operator >= (const macinfo& b) const {
            unsigned long long rt1 = 0;
            unsigned long long rt2 = 0;
            memcpy(&rt1, mac, 6);
            memcpy(&rt2, b.mac, 6);
            return rt1 >= rt2;
        }
    };
    struct ipinfo
    {
        IPAddress adr;
        int port = 0;
        macinfo mac;
        ipinfo() {}
        ipinfo(std::string strip, int port) : port(port) {
            // store this IP address in sa:
#ifdef _WIN32
            InetPton(AF_INET, strip.c_str(), &adr);
#else        
            inet_pton(AF_INET, strip.c_str(), &adr);
#endif  

        }
        ipinfo(const ipinfo& a)
        {
            adr = a.adr;
            port = a.port;
            mac = a.mac;
        }

        bool operator ==(const ipinfo& b) const
        {
            return mac == b.mac; //just check mac, manually update IP and port accordingly
        }
        bool operator !=(const ipinfo& b) const
        {
            return mac != b.mac; //just check mac, manually update IP and port accordingly
        }
        bool operator < (const ipinfo& b) const {
            return mac < b.mac; //just check mac, manually update IP and port accordingly
        };
        bool operator > (const ipinfo& b) const {
            return mac > b.mac; //just check mac, manually update IP and port accordingly
        };
        bool operator <= (const ipinfo& b) const {
            return mac <= b.mac; //just check mac, manually update IP and port accordingly
        };
        bool operator >= (const ipinfo& b) const {
            return mac >= b.mac; //just check mac, manually update IP and port accordingly
        };
    };
#pragma pack(pop)

    class IOSocket
    {
    protected:

        std::vector<char> buffer_receiver;

#ifdef _WIN32
        WSADATA wsaData;
#endif

        SOCKET socket_;
        struct sockaddr_in local_, si_recv;


    public:

        std::string mIPStr = "";
        IPAddress mIP;
        unsigned short mPort = 0;

        typedef std::unique_ptr<IOSocket> Ptr;

        virtual void sock_init() = 0;

        virtual ~IOSocket() {
#ifdef _WIN32
            closesocket(socket_);
#elif __linux__
            close(socket_);
#endif
        }

        void sock_close()
        {
#ifdef _WIN32
            closesocket(socket_);
#elif __linux__
            close(socket_);
#endif
        }

        /**
         * Bind the socket for incoming data
         * @param address Local address
         * @param port Local port
         */
        bool sock_bind(const char* address, uint16_t port)
        {
            /* zero out structure */
            mPort = port;
            memset((char*)(&this->local_), 0, sizeof(this->local_));

            /* initialize address to bind */
            char* IP = address == 0 ? (char*)"127.0.0.1" : (char*)address;
#ifndef _WIN32
            char addressBuffer[INET_ADDRSTRLEN];
            if (address == 0)
            {
                struct ifaddrs* ifAddrStruct = NULL;
                struct ifaddrs* ifa = NULL;
                void* tmpAddrPtr = NULL;

                getifaddrs(&ifAddrStruct);

                for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
                    if (!ifa->ifa_addr) {
                        continue;
                    }
                    if (ifa->ifa_addr->sa_family == AF_INET) { // check it is IP4
                        // is a valid IP4 Address
                        tmpAddrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
                        if (((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr == 16777343)
                        {
                            printf("skip localhost...\n");
                            continue;
                        }
                        inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
                        IP = addressBuffer;
                        printf("taking IP %s : %u\n", addressBuffer, ((struct sockaddr_in*)ifa->ifa_addr)->sin_port);
                        //break;
                    }
                    else if (ifa->ifa_addr->sa_family == AF_INET6) { // check it is IP6
                        // is a valid IP6 Address
                        tmpAddrPtr = &((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr;
                        char addressBuffer[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
                        printf("%s IP Address %s\n", ifa->ifa_name, addressBuffer);
                    }
                }
                if (ifAddrStruct != NULL) freeifaddrs(ifAddrStruct);

            }
#endif
            this->local_.sin_family = AF_INET;
            this->local_.sin_port = htons(port);
            //this->local_.sin_addr.s_addr = IP == 0 ? INADDR_ANY : inet_addr(IP);
            this->local_.sin_addr.s_addr = INADDR_ANY;
            this->mIPStr = IP ? IP : "127.0.0.1";
            this->mIP = IPAddress(inet_addr(IP));

            printf("bound to %s:%i\n", IP, (int)port);

            /* bind socket to address and port */
            if (::bind(this->socket_, (struct sockaddr*)(&this->local_), sizeof(this->local_)) != NO_ERROR) {
#ifdef _WIN32
                closesocket(socket_);

#elif __linux__

                close(this->socket_);
#endif
                printf("bind failed with error: %i\n", errno);
                // throw std::runtime_error("bind() failed");
                return false;
            }
            else
            {
                int broadcast = 1;

#if defined(__linux__) || defined(__unix__) || defined(__APPLE__)
                // Ensure the socket is in blocking mode (Linux/Unix)
                int flags = fcntl(this->socket_, F_GETFL, 0); // Get the current socket flags
                if (flags == -1) {
                    perror("Error getting socket flags");
                }
                else {
                    flags &= ~O_NONBLOCK; // Clear the non-blocking flag
                    if (fcntl(this->socket_, F_SETFL, flags) == -1) {
                        perror("Error setting socket to blocking mode");
            }
        }
#else
                // Ensure the socket is in blocking mode (Windows)
                u_long noBlock = 0; // 0 means blocking mode
                if (ioctlsocket(this->socket_, FIONBIO, &noBlock) != 0) {
                    perror("Error setting socket to blocking mode");
                }
#endif
                struct timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = 100000;
                if (setsockopt(this->socket_, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
                    perror("error setting recv timeout");
                }

#ifdef _WIN32
                if (setsockopt(this->socket_, SOL_SOCKET, SO_BROADCAST, (const char*)&broadcast, sizeof(broadcast)) != 0)
#else
                if (setsockopt(this->socket_, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) != 0)
#endif
                {
                    perror("setsockopt error");
                }
            }
            set_send_buf(1024 * 100);
            set_recv_buf(1024 * 1024 * 20);
            return true;
        }
        bool sock_bind_noclose(const char* address, uint16_t port)
        {
            /* zero out structure */
            mPort = port;
            memset((char*)(&this->local_), 0, sizeof(this->local_));

            /* initialize address to bind */
            char* IP = address == 0 ? (char*)"127.0.0.1" : (char*)address;
#ifndef _WIN32
            char addressBuffer[INET_ADDRSTRLEN];
            if (address == 0)
            {
                struct ifaddrs* ifAddrStruct = NULL;
                struct ifaddrs* ifa = NULL;
                void* tmpAddrPtr = NULL;

                getifaddrs(&ifAddrStruct);

                for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
                    if (!ifa->ifa_addr) {
                        continue;
                    }
                    if (ifa->ifa_addr->sa_family == AF_INET) { // check it is IP4
                        // is a valid IP4 Address
                        tmpAddrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
                        if (((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr == 16777343)
                        {
                            printf("skip localhost...\n");
                            continue;
                        }
                        inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
                        IP = addressBuffer;
                        printf("taking IP %s : %u\n", addressBuffer, ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr);
                        //break;
                    }
                    else if (ifa->ifa_addr->sa_family == AF_INET6) { // check it is IP6
                        // is a valid IP6 Address
                        tmpAddrPtr = &((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr;
                        char addressBuffer[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
                        printf("%s IP Address %s\n", ifa->ifa_name, addressBuffer);
                    }
                }
                if (ifAddrStruct != NULL) freeifaddrs(ifAddrStruct);

            }
#endif
            this->local_.sin_family = AF_INET;
            this->local_.sin_port = htons(port);
            //this->local_.sin_addr.s_addr = IP == 0 ? INADDR_ANY : inet_addr(IP);
            this->local_.sin_addr.s_addr = INADDR_ANY;
            this->mIPStr = IP ? IP : "127.0.0.1";
            this->mIP = IPAddress(inet_addr(IP));
            printf("bound to %s:%i\n", IP, (int)port);

            /* bind socket to address and port */
            if (::bind(this->socket_, (struct sockaddr*)(&this->local_), sizeof(this->local_)) != NO_ERROR) {
                printf("bind failed with error: %i\n", errno);
                // throw std::runtime_error("bind() failed");
                return false;
            }
            else
            {
#if __linux__
                //int opt = 1;
                //ioctl(this->socket_, FIONBIO, &opt); /* Non-blocking */
                // 
                // NON BLOCKING SOCKETS ARE NO LONGER NEEDED FOR SHIZONET !!!
                // 
                //int flags = fcntl(this->socket_, F_GETFL, 0);
                //fcntl(this->socket_, F_SETFL, flags | O_NONBLOCK); /* Non-blocking */
#else
                //make socket BLOCKING
                u_long noBlock = 0;
                ioctlsocket(this->socket_, FIONBIO, &noBlock);
#endif
                struct timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = 100000;
                if (setsockopt(this->socket_, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
                    perror("error setting recv timeout");
                }
                

                int broadcast = 1;
#ifdef _WIN32
                if (setsockopt(this->socket_, SOL_SOCKET, SO_BROADCAST, (const char*)&broadcast, sizeof(broadcast)) != 0)
#else
                if (setsockopt(this->socket_, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) != 0)
#endif
                {
                    perror("setsockopt error");
                }
            }
            set_send_buf(1024 * 100);
            set_recv_buf(1024 * 1024 * 20);

            return true;
        }

        /**
         * Connect to the destination socket
         * @param address Destination address
         * @param port Destination port
         */
        void sock_connect(const char* address, uint16_t port) {
            struct sockaddr_in  remote_;
            memset((char*)&remote_, 0, sizeof(remote_));
            remote_.sin_family = AF_INET;
            remote_.sin_port = port;
            remote_.sin_addr.s_addr = inet_addr(address);

            mPort = port;

            if (connect(socket_, (struct sockaddr*)(&remote_), sizeof(remote_)) < 0) {
#ifdef _WIN32
                closesocket(socket_);
#elif __linux__
                close(socket_);
#endif
                printf("sock_connect: failed!\n");
            }
        }

        /**
         * Send bytes to connected socket
         * @param tx structure to be sent
         * @param size number of bytes to copy into tx
         */

         /**
          * Receive bytes to connected socket
          * @param rx structure to be filled
          * @param size number of bytes to copy into rx
          */


        void set_recv_buf(int sendbuff)
        {
            socklen_t optlen = sizeof(int);

            if (setsockopt(this->socket_, SOL_SOCKET, SO_RCVBUF, (const char*)&sendbuff, sizeof(sendbuff)) == SOCKET_ERROR)
            {
                printf("error setsockopt()");

            }
            // Get buffer size
            auto res = getsockopt(this->socket_, SOL_SOCKET, SO_RCVBUF, (char*)&sendbuff, &optlen);

            if (res == -1)
                printf("error getsockopt()");

            printf("RECV BUF: %i\n\n", (int)sendbuff);

        }
        void set_send_buf(int sendbuff)
        {
            socklen_t optlen = sizeof(int);

            if (setsockopt(this->socket_, SOL_SOCKET, SO_SNDBUF, (const char*)&sendbuff, sizeof(sendbuff)) == SOCKET_ERROR)
            {
                printf("error setsockopt()");

            }

            printf("SEND BUF: %i\n\n", (int)sendbuff);
        }
    protected:

        IOSocket()
        {
        }

    };

    class UniversalUDP : public IOSocket
    {
    public:

#ifdef _WIN32
        /*char* getMAC() {
            PIP_ADAPTER_INFO AdapterInfo;
            DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
            char* mac_addr = (char*)malloc(18);

            AdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
            if (AdapterInfo == NULL) {
                printf("Error allocating memory needed to call GetAdaptersinfo\n");
                free(mac_addr);
                return NULL; // it is safe to call free(NULL)
            }

            // Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable
            if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
                free(AdapterInfo);
                AdapterInfo = (IP_ADAPTER_INFO*)malloc(dwBufLen);
                if (AdapterInfo == NULL) {
                    printf("Error allocating memory needed to call GetAdaptersinfo\n");
                    free(mac_addr);
                    return NULL;
                }
            }

            if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
                // Contains pointer to current adapter info
                PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
                do {
                    // technically should look at pAdapterInfo->AddressLength
                    //   and not assume it is 6.
                    sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
                        pAdapterInfo->Address[0], pAdapterInfo->Address[1],
                        pAdapterInfo->Address[2], pAdapterInfo->Address[3],
                        pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
                    printf("Address: %s, mac: %s\n", pAdapterInfo->IpAddressList.IpAddress.String, mac_addr);
                    // print them all, return the last one.
                    // return mac_addr;

                    printf("\n");
                    pAdapterInfo = pAdapterInfo->Next;
                } while (pAdapterInfo);
            }
            free(AdapterInfo);
            return mac_addr; // caller must free.
        }*/
        WSADATA wsaData;
        struct sockaddr_in si_recv;
#endif

        void sock_init() override
        {

#ifdef _WIN32
            /* Initialize Winsock */
            // consoleLog->iinfo("Initialising Winsock...");
            if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
            {
                WSACleanup();
                // exit(EXIT_FAILURE);
            }
#endif

            /*
            * create socket
            */
            if ((this->socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_ERROR)
            {
                perror("socket() udp");
                return;
            }
        }

        int sock_send(void* tx, const size_t size, ipinfo& iinfo) {

            if (*(uint32_t*)(&iinfo.adr.ip[0]) == 0)
                return 0;

            //DEBUG TESTS: drop random packets
            //if (rand() % 2 == 0)
            //    return size;

            struct sockaddr_in  remote_;
            memset((char*)&remote_, 0, sizeof(remote_));
            remote_.sin_family = AF_INET;
            remote_.sin_port = htons(iinfo.port);
            memcpy(&remote_.sin_addr.s_addr, iinfo.adr.ip, 4);
            /*#ifdef __linux__
            //int opt = 1;
            //ioctl(this->socket_, FIONBIO, &opt);
                    int flags = fcntl(this->socket_, F_GETFL, 0);
                    fcntl(this->socket_, F_SETFL, flags & ~O_NONBLOCK);
            #elif _WIN32
                    u_long iMode = 0;
                    ioctlsocket(socket_, FIONBIO, &iMode);
            #endif*/

            int bytes =
                sendto(this->socket_,                // Connected socket
                    (const char*) tx,    // Data buffer
                    size,           // Length of data
                    0, (sockaddr*)&remote_, sizeof(sockaddr_in));

#ifdef _WIN32
            if (bytes != size)
            {
                printf("sendto: failed! %i : %i %s\n", bytes, WSAGetLastError(), iinfo.adr.getStr().c_str());
            }
#endif
#ifdef __linux__
            if (bytes != size)
                printf("errno: %i\n", errno);
#endif

            return bytes;
        }


        u_long sock_peek(u_long size)
        {
            u_long bytes_available = 0;
#ifdef _WIN32
            ioctlsocket(this->socket_, FIONREAD, &bytes_available);
#else
            ioctl(this->socket_, FIONREAD, &bytes_available);
#endif


            return bytes_available > size ? size : bytes_available;
            /*sockaddr_in addr;
            socklen_t ssize = sizeof(sockaddr_in);
            return
                recvfrom(this->socket_,           // Bound socket
                    this->buffer_receiver_.get(), // Data buffer
                    size,         // Length of data
                    MSG_PEEK, (struct sockaddr*) & addr, &ssize);*/
        }

        int sock_receive(void* rx, size_t size, ipinfo& iinfo, ipinfo& local_ip) {
            memset(iinfo.mac.mac, 0, 6);
            memset(iinfo.adr.ip, 0, 4);
            iinfo.port = 0;

#ifdef _WIN32
            int si_len = sizeof(si_recv);
#elif __linux__
            socklen_t si_len = sizeof(this->si_recv);
#endif

            /* If there is nothing in the buffer, EAGAIN will be raised. It might happen */
            sockaddr_in addr;
            socklen_t ssize = sizeof(sockaddr_in);
            int bytes =
                recvfrom(this->socket_,           // Bound socket
                    (char*)rx, // Data buffer
                    size,         // Length of data
                    0, (struct sockaddr*)&addr, &ssize);
            
            /*size_t bytes =
                recv(socket_,           // Bound socket
                    buffer_receiver_.get(), // Data buffer
                    size_receiver_,         // Length of data
                    0);*/

                    //        if (errno == EAGAIN)
                    //        {
                    //            ret_value = -1;
                    //        }
                    //        perror("errno: ");

            if (bytes <= 0)
                return bytes;

            //this approach doesnt work when binding to all interfaces
            //TODO: bind to all interfaces and open sockets on all of them
            //then use the specific interface to determine the correct IP
            //after some testing, resolume arena seems to accept IP == 0 in the artnet packet and
            //sets the correct IP anyways (so this is a low prio to do)
            /*
            sockaddr_in localAddr;
            int localAddrLen = sizeof(localAddr);
            if (getsockname(this->socket_, (sockaddr*)&localAddr, &localAddrLen) == 0) {
                
                local_ip.adr = IPAddress(localAddr.sin_addr.s_addr);
                local_ip.port = ntohs(localAddr.sin_port);

                char localAddrStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(localAddr.sin_addr), localAddrStr, INET_ADDRSTRLEN);

                printf("received packet on %s : %i\n", localAddrStr, bytes);
            }
            else {
                printf("failed to get local address!\n");
            }
            */

            iinfo.adr = IPAddress(addr.sin_addr.s_addr);
            iinfo.port = ntohs(addr.sin_port);

            return bytes;
        }

        int sock_receive_flush(int size) {
            ipinfo iinfo;
            memset(iinfo.mac.mac, 0, 6);
            memset(iinfo.adr.ip, 0, 4);

#ifdef _WIN32
            int si_len = sizeof(si_recv);
#elif __linux__
            socklen_t si_len = sizeof(this->si_recv);
#endif

            /* If there is nothing in the buffer, EAGAIN will be raised. It might happen */
            sockaddr_in addr;
            socklen_t ssize = sizeof(sockaddr_in);
            size_t bytes =
                recvfrom(this->socket_,           // Bound socket
                    0, // Data buffer
                    size,         // Length of data
                    0, (struct sockaddr*)&addr, &ssize);
            /*size_t bytes =
                recv(socket_,           // Bound socket
                    buffer_receiver_.get(), // Data buffer
                    size_receiver_,         // Length of data
                    0);*/

                    //        if (errno == EAGAIN)
                    //        {
                    //            ret_value = -1;
                    //        }
                    //        perror("errno: ")

            iinfo.adr = IPAddress(addr.sin_addr.s_addr);
            iinfo.port = ntohs(addr.sin_port);

            return 0;
        }
    };
#endif
#endif // _UDP_SOCKET_H_
