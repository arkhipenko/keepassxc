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

#include "Trigger.h"

bool TriggerObject::operator==(const TriggerObject& other) const
{
    return type == other.type && parameters == other.parameters && negate == other.negate;
}

bool TriggerObject::operator!=(const TriggerObject& other) const
{
    return !(*this == other);
}

Trigger::Trigger()
    : uuid(QUuid::createUuid())
{
}

Trigger::Trigger(const QUuid& uuid)
    : uuid(uuid)
{
}

void Trigger::setToInitialState()
{
    on = initiallyOn;
}

bool Trigger::operator==(const Trigger& other) const
{
    return uuid == other.uuid && name == other.name && comments == other.comments && enabled == other.enabled
           && initiallyOn == other.initiallyOn && turnOffAfterAction == other.turnOffAfterAction
           && events == other.events && conditions == other.conditions && actions == other.actions;
}

bool Trigger::operator!=(const Trigger& other) const
{
    return !(*this == other);
}

void TriggerCollection::setToInitialState()
{
    for (auto& trigger : triggers) {
        trigger.setToInitialState();
    }
}

bool TriggerCollection::containsUuid(const QUuid& uuid) const
{
    for (const auto& trigger : triggers) {
        if (trigger.uuid == uuid) {
            return true;
        }
        for (const auto* list : {&trigger.events, &trigger.conditions, &trigger.actions}) {
            for (const auto& object : *list) {
                if (object.type == uuid) {
                    return true;
                }
            }
        }
    }
    return false;
}

void TriggerCollection::addPasted(const QList<Trigger>& pasted)
{
    for (auto trigger : pasted) {
        if (containsUuid(trigger.uuid)) {
            trigger.uuid = QUuid::createUuid();
        }
        triggers.append(trigger);
    }
}

bool TriggerCollection::operator==(const TriggerCollection& other) const
{
    return enabled == other.enabled && triggers == other.triggers;
}

bool TriggerCollection::operator!=(const TriggerCollection& other) const
{
    return !(*this == other);
}
