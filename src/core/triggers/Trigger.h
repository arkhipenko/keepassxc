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

#ifndef KEEPASSXC_TRIGGER_H
#define KEEPASSXC_TRIGGER_H

#include <QList>
#include <QStringList>
#include <QUuid>

/**
 * Data model of the trigger system. It copies the model of KeePass 2.x
 * (KeePass/Ecas/EcasTrigger.cs, EcasEvent.cs, EcasCondition.cs, EcasAction.cs).
 *
 * A trigger has a list of events (combined with OR), a list of conditions
 * (combined with AND) and a list of actions (run in list order).
 */

// One event, condition or action of a trigger.
struct TriggerObject
{
    // KeePass type UUID of the event, condition or action
    QUuid type;
    // Every parameter is stored as a string, in the order of the type definition
    QStringList parameters;
    // Conditions only: the result of the condition is inverted
    bool negate = false;

    // Run time state of a "Time - Periodic" event: the next due time in
    // milliseconds since the epoch (UTC), or -1 when the timer is not armed.
    // It is not stored.
    qint64 runAtMs = -1;

    bool operator==(const TriggerObject& other) const;
    bool operator!=(const TriggerObject& other) const;
};

class Trigger
{
public:
    Trigger();
    explicit Trigger(const QUuid& uuid);

    QUuid uuid;
    QString name;
    QString comments;
    bool enabled = true;
    bool initiallyOn = true;
    bool turnOffAfterAction = false;
    QList<TriggerObject> events;
    QList<TriggerObject> conditions;
    QList<TriggerObject> actions;

    // Run time state. It is set from initiallyOn when the triggers load.
    bool on = true;

    void setToInitialState();

    // Compares the stored data. The run time state is ignored.
    bool operator==(const Trigger& other) const;
    bool operator!=(const Trigger& other) const;
};

// The complete trigger configuration ("TriggerSystem" in KeePass).
class TriggerCollection
{
public:
    // Global switch "Enable trigger system"
    bool enabled = true;
    QList<Trigger> triggers;

    void setToInitialState();

    // True when a trigger, or the type of an event, condition or action, has this UUID
    // (KeePass: EcasTriggerSystem.FindObjectByUuid)
    bool containsUuid(const QUuid& uuid) const;

    // Adds pasted triggers. A trigger receives a new UUID when its UUID already exists.
    void addPasted(const QList<Trigger>& pasted);

    bool operator==(const TriggerCollection& other) const;
    bool operator!=(const TriggerCollection& other) const;
};

#endif // KEEPASSXC_TRIGGER_H
