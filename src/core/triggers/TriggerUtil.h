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

#ifndef KEEPASSXC_TRIGGERUTIL_H
#define KEEPASSXC_TRIGGERUTIL_H

#include <QStringList>

struct TriggerObject;
struct TriggerParameter;
struct TriggerTypeInfo;

/**
 * Parameter helpers of the trigger system. They copy KeePass/Ecas/EcasUtil.cs and
 * StrUtil.StringToBoolEx (KeePassLib/Utility/StrUtil.cs).
 */
namespace TriggerUtil
{
    // Parameter at the index, or the default when the list is shorter
    QString paramString(const QStringList& params, int index, const QString& defaultValue = {});

    // Accepts true/false, yes/no, enabled/disabled, checked/unchecked (ignoring case) and 1/0.
    // Sets ok to false for any other text; the result is then false.
    bool stringToBool(const QString& text, bool* ok = nullptr);
    // KeePass writes a Bool parameter as "True" or "False"
    QString boolToString(bool value);

    bool paramBool(const QStringList& params, int index);
    quint32 paramUInt(const QStringList& params, int index, quint32 defaultValue = 0);
    // The value must be a decimal id that the enumeration contains, otherwise the default is returned
    quint32 paramEnum(const QStringList& params, int index, quint32 defaultValue, const TriggerParameter& info);

    // A path in one pair of double quotes loses the quotes (KeePass: EcasUtil.GetParamPath)
    QString stripPathQuotes(const QString& path);
    // Several paths, each one in double quotes. A single unquoted path may contain spaces
    // (KeePass: EcasUtil.GetParamPaths).
    QStringList splitPaths(const QString& paths);

    // String comparison of the trigger system. It always ignores case.
    // An invalid regular expression gives false (KeePass: EcasUtil.CompareStrings).
    bool compareStrings(const QString& value, const QString& filter, quint32 compareType);

    // Short text of the parameters for the trigger editor lists (KeePass: EcasUtil.ParametersToString)
    QString parametersToString(const TriggerObject& object, const TriggerTypeInfo* info, bool isCondition);
} // namespace TriggerUtil

#endif // KEEPASSXC_TRIGGERUTIL_H
