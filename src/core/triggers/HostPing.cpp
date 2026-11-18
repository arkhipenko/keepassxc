/*
 *  Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "HostPing.h"

#include <QByteArray>
#include <QElapsedTimer>

#if defined(Q_OS_WIN)
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
// clang-format on
#elif defined(Q_OS_UNIX)
#include <cerrno>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace
{
    // KeePass sends 32 bytes of 'a' (KeePass/Ecas/EcasDefaultConditionProvider.cs)
    const QByteArray Payload(32, 'a');
} // namespace

#if defined(Q_OS_WIN)

namespace HostPing
{
    bool ping(const QString& host, int timeoutMs)
    {
        if (host.isEmpty() || timeoutMs <= 0) {
            return false;
        }

        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return false;
        }

        addrinfo hints = {};
        hints.ai_family = AF_UNSPEC;
        addrinfo* result = nullptr;
        const QByteArray hostName = host.toUtf8();
        bool reachable = false;
        if (getaddrinfo(hostName.constData(), nullptr, &hints, &result) == 0 && result) {
            // Room for one reply, its payload, an ICMP error and the IO status block
            QByteArray replyBuffer(sizeof(ICMPV6_ECHO_REPLY) + sizeof(ICMP_ECHO_REPLY) + Payload.size() + 8 + 64, '\0');
            auto* request = const_cast<char*>(Payload.constData());

            if (result->ai_family == AF_INET) {
                HANDLE icmp = IcmpCreateFile();
                if (icmp != INVALID_HANDLE_VALUE) {
                    const auto* address = reinterpret_cast<const sockaddr_in*>(result->ai_addr);
                    IP_OPTION_INFORMATION options = {};
                    options.Ttl = 64;
                    options.Flags = IP_FLAG_DF; // Do not fragment, as KeePass
                    const DWORD count = IcmpSendEcho(icmp,
                                                     address->sin_addr.S_un.S_addr,
                                                     request,
                                                     static_cast<WORD>(Payload.size()),
                                                     &options,
                                                     replyBuffer.data(),
                                                     static_cast<DWORD>(replyBuffer.size()),
                                                     static_cast<DWORD>(timeoutMs));
                    if (count > 0) {
                        const auto* reply = reinterpret_cast<const ICMP_ECHO_REPLY*>(replyBuffer.constData());
                        reachable = (reply->Status == IP_SUCCESS);
                    }
                    IcmpCloseHandle(icmp);
                }
            } else if (result->ai_family == AF_INET6) {
                HANDLE icmp = Icmp6CreateFile();
                if (icmp != INVALID_HANDLE_VALUE) {
                    sockaddr_in6 source = {};
                    source.sin6_family = AF_INET6;
                    auto* destination = reinterpret_cast<sockaddr_in6*>(result->ai_addr);
                    IP_OPTION_INFORMATION options = {};
                    options.Ttl = 64;
                    const DWORD count = Icmp6SendEcho2(icmp,
                                                       nullptr,
                                                       nullptr,
                                                       nullptr,
                                                       &source,
                                                       destination,
                                                       request,
                                                       static_cast<WORD>(Payload.size()),
                                                       &options,
                                                       replyBuffer.data(),
                                                       static_cast<DWORD>(replyBuffer.size()),
                                                       static_cast<DWORD>(timeoutMs));
                    if (count > 0) {
                        const auto* reply = reinterpret_cast<const ICMPV6_ECHO_REPLY*>(replyBuffer.constData());
                        reachable = (reply->Status == IP_SUCCESS);
                    }
                    IcmpCloseHandle(icmp);
                }
            }
        }
        if (result) {
            freeaddrinfo(result);
        }
        WSACleanup();
        return reachable;
    }
} // namespace HostPing

#elif defined(Q_OS_UNIX)

namespace
{
    constexpr quint8 IcmpEchoRequest = 8;
    constexpr quint8 IcmpEchoReply = 0;
    constexpr quint8 Icmp6EchoRequest = 128;
    constexpr quint8 Icmp6EchoReply = 129;

    bool pingAddress(const addrinfo* address, int timeoutMs)
    {
        const bool v6 = (address->ai_family == AF_INET6);
        // An unprivileged ICMP socket. The kernel sets the identifier and the checksum.
        const int protocol = v6 ? static_cast<int>(IPPROTO_ICMPV6) : static_cast<int>(IPPROTO_ICMP);
        const int fd = socket(address->ai_family, SOCK_DGRAM, protocol);
        if (fd < 0) {
            return false;
        }

        constexpr quint16 sequence = 1;
        QByteArray packet(8, '\0');
        packet[0] = static_cast<char>(v6 ? Icmp6EchoRequest : IcmpEchoRequest);
        packet[6] = static_cast<char>(sequence >> 8);
        packet[7] = static_cast<char>(sequence & 0xFF);
        packet.append(Payload);

        bool reachable = false;
        if (sendto(fd, packet.constData(), static_cast<size_t>(packet.size()), 0, address->ai_addr, address->ai_addrlen)
            == packet.size()) {
            QElapsedTimer timer;
            timer.start();
            char buffer[1500];
            while (!reachable) {
                const qint64 remaining = timeoutMs - timer.elapsed();
                if (remaining <= 0) {
                    break;
                }
                pollfd pfd = {fd, POLLIN, 0};
                const int ready = poll(&pfd, 1, static_cast<int>(remaining));
                if (ready < 0 && errno == EINTR) {
                    continue;
                }
                if (ready <= 0) {
                    break;
                }
                const ssize_t size = recv(fd, buffer, sizeof(buffer), 0);
                if (size < 8) {
                    continue;
                }
                // A datagram ICMP socket delivers the ICMP message without the IP header
                const auto type = static_cast<quint8>(buffer[0]);
                const quint16 replySequence =
                    static_cast<quint16>((static_cast<quint8>(buffer[6]) << 8) | static_cast<quint8>(buffer[7]));
                if (type == (v6 ? Icmp6EchoReply : IcmpEchoReply) && replySequence == sequence) {
                    reachable = true;
                }
            }
        }
        close(fd);
        return reachable;
    }
} // namespace

namespace HostPing
{
    bool ping(const QString& host, int timeoutMs)
    {
        if (host.isEmpty() || timeoutMs <= 0) {
            return false;
        }

        addrinfo hints = {};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        addrinfo* result = nullptr;
        const QByteArray hostName = host.toUtf8();
        if (getaddrinfo(hostName.constData(), nullptr, &hints, &result) != 0 || !result) {
            return false;
        }

        // The first address is used, as a ping program does
        const bool reachable = pingAddress(result, timeoutMs);
        freeaddrinfo(result);
        return reachable;
    }
} // namespace HostPing

#else

namespace HostPing
{
    bool ping(const QString& host, int timeoutMs)
    {
        Q_UNUSED(host);
        Q_UNUSED(timeoutMs);
        return false;
    }
} // namespace HostPing

#endif
