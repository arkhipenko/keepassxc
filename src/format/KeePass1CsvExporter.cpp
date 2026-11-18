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

#include "KeePass1CsvExporter.h"

#include "core/Entry.h"
#include "core/Group.h"

#include <QSaveFile>

namespace
{
    QString escape(const QString& text)
    {
        QString result = text;
        result.replace("\\", "\\\\");
        result.replace("\"", "\\\"");
        return result;
    }

    void writeGroup(QString& out, const Group* group)
    {
        for (const auto* entry : group->entries()) {
            out += "\"" + escape(entry->title()) + "\",\"" + escape(entry->username()) + "\",\""
                   + escape(entry->password()) + "\",\"" + escape(entry->url()) + "\",\"" + escape(entry->notes())
                   + "\"\r\n";
        }
        for (const auto* child : group->children()) {
            writeGroup(out, child);
        }
    }
} // namespace

QByteArray KeePass1CsvExporter::exportGroup(const Group* group)
{
    QString out = "\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\r\n";
    if (group) {
        writeGroup(out, group);
    }
    return out.toUtf8();
}

bool KeePass1CsvExporter::exportGroup(const QString& filePath, const Group* group, QString* error)
{
    QSaveFile file(filePath);
    const QByteArray data = exportGroup(group);
    if (!file.open(QIODevice::WriteOnly) || file.write(data) != data.size() || !file.commit()) {
        if (error) {
            *error = file.errorString();
        }
        return false;
    }
    return true;
}
