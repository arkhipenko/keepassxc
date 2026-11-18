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

#include "TriggerUtil.h"

#include "Trigger.h"
#include "TriggerTypes.h"

#include <QCoreApplication>
#include <QRegularExpression>

namespace TriggerUtil
{
    QString paramString(const QStringList& params, int index, const QString& defaultValue)
    {
        if (index < 0 || index >= params.size()) {
            return defaultValue;
        }
        return params.at(index);
    }

    bool stringToBool(const QString& text, bool* ok)
    {
        const QString str = text.trimmed();
        if (ok) {
            *ok = true;
        }
        for (const auto* value : {"true", "yes", "enabled", "checked"}) {
            if (str.compare(QLatin1String(value), Qt::CaseInsensitive) == 0) {
                return true;
            }
        }
        for (const auto* value : {"false", "no", "disabled", "unchecked"}) {
            if (str.compare(QLatin1String(value), Qt::CaseInsensitive) == 0) {
                return false;
            }
        }
        if (str == "1") {
            return true;
        }
        if (ok) {
            *ok = (str == "0");
        }
        return false;
    }

    QString boolToString(bool value)
    {
        return value ? QStringLiteral("True") : QStringLiteral("False");
    }

    bool paramBool(const QStringList& params, int index)
    {
        return stringToBool(paramString(params, index));
    }

    quint32 paramUInt(const QStringList& params, int index, quint32 defaultValue)
    {
        bool ok = false;
        const quint32 value = paramString(params, index).trimmed().toUInt(&ok);
        return ok ? value : defaultValue;
    }

    quint32 paramEnum(const QStringList& params, int index, quint32 defaultValue, const TriggerParameter& info)
    {
        const QString str = paramString(params, index);
        if (str.isEmpty()) {
            return defaultValue;
        }
        bool ok = false;
        const quint32 id = str.trimmed().toUInt(&ok);
        if (!ok || !info.hasEnumId(id)) {
            return defaultValue;
        }
        return id;
    }

    QString stripPathQuotes(const QString& path)
    {
        const QString trimmed = path.trimmed();
        const auto length = trimmed.length();
        if (length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
            const QString inner = trimmed.mid(1, length - 2);
            if (!inner.contains('"')) {
                return inner;
            }
        }
        return path; // Untrimmed, as KeePass
    }

    QStringList splitPaths(const QString& paths)
    {
        if (paths.isEmpty()) {
            return {};
        }

        // Unquoted paths that contain spaces are supported, so unquoted text is not split at spaces
        const QStringList parts = paths.split('"');
        if (parts.size() == 1) {
            return parts;
        }
        if ((parts.size() % 2) == 0) {
            // Odd number of quotes
            return {paths};
        }

        QStringList result;
        for (int i = 0; i < parts.size(); ++i) {
            QString part = parts.at(i);
            if ((i % 2) == 0) {
                part = part.trimmed(); // Text outside the quotes
            }
            if (!part.isEmpty()) {
                result << part;
            }
        }
        return result;
    }

    bool compareStrings(const QString& value, const QString& filter, quint32 compareType)
    {
        switch (compareType) {
        case TriggerEnums::CompareEquals:
            return value.compare(filter, Qt::CaseInsensitive) == 0;
        case TriggerEnums::CompareContains:
            return value.contains(filter, Qt::CaseInsensitive);
        case TriggerEnums::CompareStartsWith:
            return value.startsWith(filter, Qt::CaseInsensitive);
        case TriggerEnums::CompareEndsWith:
            return value.endsWith(filter, Qt::CaseInsensitive);
        case TriggerEnums::CompareRegEx: {
            const QRegularExpression regex(filter, QRegularExpression::CaseInsensitiveOption);
            if (!regex.isValid()) {
                return false;
            }
            return regex.match(value).hasMatch();
        }
        default:
            return false;
        }
    }

    QString parametersToString(const TriggerObject& object, const TriggerTypeInfo* info, bool isCondition)
    {
        QStringList parts;
        if (isCondition && object.negate) {
            parts << QCoreApplication::translate("TriggerTypes", "Not");
        }

        const bool infoValid = info && object.parameters.size() <= info->parameters.size();
        for (int i = 0; i < object.parameters.size(); ++i) {
            const QString& param = object.parameters.at(i);
            QString text = param;
            if (infoValid) {
                const auto& paramInfo = info->parameters.at(i);
                switch (paramInfo.type) {
                case TriggerValueType::Bool:
                    text = stringToBool(param) ? QCoreApplication::translate("TriggerTypes", "Yes")
                                               : QCoreApplication::translate("TriggerTypes", "No");
                    break;
                case TriggerValueType::EnumStrings: {
                    bool ok = false;
                    const quint32 id = param.trimmed().toUInt(&ok);
                    text = ok ? paramInfo.enumName(id) : QString();
                    break;
                }
                case TriggerValueType::Int64: {
                    bool ok = false;
                    const qint64 value = param.trimmed().toLongLong(&ok);
                    text = ok ? QString::number(value) : QString();
                    break;
                }
                case TriggerValueType::UInt64: {
                    bool ok = false;
                    const quint64 value = param.trimmed().toULongLong(&ok);
                    text = ok ? QString::number(value) : QString();
                    break;
                }
                default:
                    break;
                }
            }

            text = text.trimmed();
            if (!text.isEmpty()) {
                parts << text;
            }
        }

        return parts.join(", ");
    }
} // namespace TriggerUtil
