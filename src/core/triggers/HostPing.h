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

#ifndef KEEPASSXC_HOSTPING_H
#define KEEPASSXC_HOSTPING_H

#include <QString>

/**
 * ICMP echo ("ping") for the trigger condition "Remote host is reachable".
 *
 * - Linux and macOS: an unprivileged ICMP socket. On Linux the kernel allows it when the
 *   group of the user is in net.ipv4.ping_group_range.
 * - Windows: IcmpSendEcho and Icmp6SendEcho2.
 *
 * The call blocks for up to the timeout.
 */
namespace HostPing
{
    // True when the host answers within the timeout. A name that cannot be
    // resolved, or any other error, gives false.
    bool ping(const QString& host, int timeoutMs);
} // namespace HostPing

#endif // KEEPASSXC_HOSTPING_H
