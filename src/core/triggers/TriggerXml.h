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

#ifndef KEEPASSXC_TRIGGERXML_H
#define KEEPASSXC_TRIGGERXML_H

#include "Trigger.h"

#include <QByteArray>
#include <QCoreApplication>

/**
 * Trigger XML in the format of KeePass 2.x (the XML serialization of KeePass/Ecas/EcasTriggerSystem.cs
 * and EcasTriggerContainer).
 *
 * - <TriggerSystem> holds the global switch <Enabled> and the list <Triggers>. KeePass writes it
 *   under /Configuration/Application/TriggerSystem of its configuration file.
 * - <TriggerCollection> holds only <Triggers>. KeePass uses it for "Copy triggers" and "Paste triggers".
 *
 * Elements that have their default value are not written, as KeePass does. Unknown elements are ignored.
 */
class TriggerXml
{
    Q_DECLARE_TR_FUNCTIONS(TriggerXml)

public:
    static QByteArray writeTriggerSystem(const TriggerCollection& collection);
    static bool readTriggerSystem(const QByteArray& xml, TriggerCollection* collection, QString* error = nullptr);

    static QByteArray writeTriggerCollection(const QList<Trigger>& triggers);
    static bool readTriggerCollection(const QByteArray& xml, QList<Trigger>* triggers, QString* error = nullptr);
};

#endif // KEEPASSXC_TRIGGERXML_H
