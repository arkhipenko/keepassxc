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

#ifndef KEEPASSXC_KEEPASS1CSVEXPORTER_H
#define KEEPASSXC_KEEPASS1CSVEXPORTER_H

#include <QByteArray>
#include <QString>

class Group;

/**
 * CSV in the format of KeePass 1.x ("KeePass CSV (1.x)" in KeePass 2.x,
 * KeePass/DataExchange/Formats/KeePassCsv1.cs):
 * - The header line is "Account","Login Name","Password","Web Site","Comments".
 * - Each entry is one line with title, user name, password, URL and notes, each in double quotes.
 * - A backslash becomes \\ and a double quote becomes \".
 * - Lines end with CR LF. The text is UTF-8 without a byte order mark.
 * - The entries of a group come before the entries of its child groups.
 */
class KeePass1CsvExporter
{
public:
    static QByteArray exportGroup(const Group* group);
    static bool exportGroup(const QString& filePath, const Group* group, QString* error);
};

#endif // KEEPASSXC_KEEPASS1CSVEXPORTER_H
