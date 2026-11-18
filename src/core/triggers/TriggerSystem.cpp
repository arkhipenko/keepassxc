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

#include "TriggerSystem.h"

#include "HostPing.h"
#include "TriggerTypes.h"
#include "TriggerUtil.h"
#include "core/Clock.h"
#include "core/Database.h"
#include "core/Global.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QHash>
#include <QProcessEnvironment>
#include <QThread>

#include <limits>

TriggerSystem* TriggerSystem::m_instance = nullptr;

namespace
{
    qint64 nowMs()
    {
        return Clock::currentMilliSecondsSinceEpoch();
    }

    // Arms the timer of a "Time - Periodic" event. Returns false when the interval is 0.
    // KeePass subtracts 0.45 s, so that a 1 s main timer does not skip a tick
    // (KeePass/Ecas/EcasEvent.cs, RestartTimer).
    bool restartTimer(TriggerObject& event)
    {
        const quint32 seconds = TriggerUtil::paramUInt(event.parameters, 0);
        if (seconds == 0) {
            return false;
        }
        event.runAtMs = nowMs() + static_cast<qint64>(seconds) * 1000 - 450;
        return true;
    }
} // namespace

TriggerSystem::TriggerSystem(QObject* parent)
    : QObject(parent)
{
}

TriggerSystem* TriggerSystem::instance()
{
    if (!m_instance) {
        m_instance = new TriggerSystem(qApp);
    }
    return m_instance;
}

void TriggerSystem::setHost(TriggerHost* host)
{
    m_host = host;
}

TriggerHost* TriggerSystem::host() const
{
    return m_host;
}

bool TriggerSystem::isLoaded() const
{
    return !m_collection.isNull();
}

void TriggerSystem::load(const TriggerCollection& collection)
{
    m_collection.reset(new TriggerCollection(collection));
    m_collection->setToInitialState();
    emit triggersLoaded();
    emit triggersChanged();
}

void TriggerSystem::replace(const TriggerCollection& collection)
{
    // KeePass edits a copy that carries the on/off state, so the state of each trigger is kept
    QHash<QUuid, bool> states;
    if (m_collection) {
        for (const auto& trigger : asConst(m_collection->triggers)) {
            states.insert(trigger.uuid, trigger.on);
        }
    }

    auto updated = QSharedPointer<TriggerCollection>::create(collection);
    for (auto& trigger : updated->triggers) {
        trigger.on = states.value(trigger.uuid, trigger.initiallyOn);
    }
    // An event that runs keeps its own reference to the old list
    m_collection = updated;
    emit triggersChanged();
}

void TriggerSystem::unload()
{
    m_collection.reset();
    emit triggersChanged();
}

TriggerCollection TriggerSystem::collection() const
{
    return m_collection ? *m_collection : TriggerCollection();
}

void TriggerSystem::raiseEvent(const QUuid& eventType, const TriggerEventProperties& properties)
{
    // Keep a reference, so that a replace from an action does not destroy the list that runs
    QSharedPointer<TriggerCollection> collection = m_collection;
    if (!collection || !collection->enabled) {
        return;
    }

    // The list must not share its data with a copy: an action writes the on/off state through references
    collection->triggers.detach();

    // One error handler covers all triggers of one event (KeePass: EcasTriggerSystem.RaiseEventObj)
    for (int i = 0; i < collection->triggers.size(); ++i) {
        QString error;
        if (!runIfMatching(collection->triggers[i], *collection, eventType, properties, &error)) {
            if (m_host) {
                m_host->showExecutionError(error);
            } else {
                qWarning("Trigger execution failed: %s", qPrintable(error));
            }
            return;
        }
    }
}

bool TriggerSystem::runIfMatching(Trigger& trigger,
                                  TriggerCollection& collection,
                                  const QUuid& eventType,
                                  const TriggerEventProperties& properties,
                                  QString* error)
{
    if (!trigger.enabled || !trigger.on) {
        return true;
    }

    TriggerContext context;
    context.collection = &collection;
    context.trigger = &trigger;
    context.eventType = eventType;
    context.properties = &properties;

    bool eventMatches = false;
    for (auto& event : trigger.events) {
        if (event.type != eventType) {
            continue;
        }
        if (this->eventMatches(event, context)) {
            eventMatches = true;
            break;
        }
    }
    if (!eventMatches) {
        return true;
    }

    // Conditions are combined with AND and stop at the first false one
    for (const auto& condition : asConst(trigger.conditions)) {
        QString conditionError;
        const bool result = evaluateCondition(condition, context, &conditionError);
        if (!conditionError.isEmpty()) {
            *error = conditionError;
            return false;
        }
        if (!result) {
            return true;
        }
    }

    // The action list is copied, so that an action that changes the trigger does not change the loop
    const auto actions = trigger.actions;
    for (const auto& action : actions) {
        if (context.cancel) {
            break;
        }
        if (!executeAction(action, context, error)) {
            return false;
        }
    }

    if (trigger.turnOffAfterAction) {
        trigger.on = false;
    }
    return true;
}

bool TriggerSystem::eventMatches(const TriggerObject& event, const TriggerContext& context)
{
    if (event.type != context.eventType) {
        return false;
    }
    const auto* info = TriggerTypes::findEvent(event.type);
    if (!info) {
        // An unknown event type is never raised, so it never matches
        return false;
    }
    const auto& props = *context.properties;

    if (event.type == TriggerIds::OpenedDatabaseFile || event.type == TriggerIds::SavingDatabaseFile
        || event.type == TriggerIds::SavedDatabaseFile || event.type == TriggerIds::SynchronizingDatabaseFile
        || event.type == TriggerIds::SynchronizedDatabaseFile || event.type == TriggerIds::ClosingDatabaseFilePre
        || event.type == TriggerIds::ClosingDatabaseFilePost) {
        // KeePass: EcasDefaultEventProvider.IsMatchIocDbEvent
        const quint32 compareType =
            TriggerUtil::paramEnum(event.parameters, 0, TriggerEnums::CompareEquals, info->parameters.at(0));
        const QString filter = compiledPath(event, 1);
        if (filter.isEmpty()) {
            return true;
        }
        QString filePath = props.filePath;
        if (filePath.isEmpty() && props.database) {
            filePath = props.database->filePath();
        }
        if (filePath.isEmpty()) {
            return false;
        }
        return TriggerUtil::compareStrings(QDir::toNativeSeparators(filePath), filter, compareType);
    }

    if (event.type == TriggerIds::CopiedEntryInfo) {
        // KeePass: EcasDefaultEventProvider.IsMatchTextEvent
        const quint32 compareType =
            TriggerUtil::paramEnum(event.parameters, 0, TriggerEnums::CompareEquals, info->parameters.at(0));
        const QString filter = compiledParam(event, 1);
        if (filter.isEmpty()) {
            return true;
        }
        return TriggerUtil::compareStrings(props.text, filter, compareType);
    }

    if (event.type == TriggerIds::CustomTbButtonClicked) {
        // KeePass: EcasDefaultEventProvider.IsMatchIdEvent
        const QString idFilter = compiledParam(event, 0);
        if (idFilter.isEmpty()) {
            return true;
        }
        if (props.commandId.isEmpty()) {
            return false;
        }
        return idFilter.compare(props.commandId, Qt::CaseInsensitive) == 0;
    }

    if (event.type == TriggerIds::TimePeriodic) {
        // KeePass: EcasDefaultEventProvider.IsMatchTimePeriodicEvent. The first check only arms the timer.
        auto& periodic = const_cast<TriggerObject&>(event);
        bool restart = true;
        bool run = false;
        if (periodic.runAtMs >= 0) {
            if (nowMs() >= periodic.runAtMs) {
                run = true;
            } else {
                restart = false;
            }
        }
        if (restart && !restartTimer(periodic)) {
            return false;
        }
        return run;
    }

    // The application events have no parameters
    return true;
}

bool TriggerSystem::evaluateCondition(const TriggerObject& condition, TriggerContext& context, QString* error)
{
    const auto* info = TriggerTypes::findCondition(condition.type);
    if (!info) {
        if (error) {
            *error = tr("The trigger condition type is unknown.") + "\n\n"
                     + QString::fromLatin1(condition.type.toRfc4122().toBase64());
        }
        return false;
    }

    bool result = false;
    if (condition.type == TriggerIds::EnvironmentVariable) {
        const QString name = compiledParam(condition, 0);
        const quint32 compareType =
            TriggerUtil::paramEnum(condition.parameters, 1, TriggerEnums::CompareEquals, info->parameters.at(1));
        const QString value = compiledParam(condition, 2);
        const auto environment = QProcessEnvironment::systemEnvironment();
        if (!name.isEmpty() && environment.contains(name)) {
            result = TriggerUtil::compareStrings(environment.value(name), value, compareType);
        }
    } else if (condition.type == TriggerIds::String) {
        const QString text = compiledParam(condition, 0);
        const quint32 compareType =
            TriggerUtil::paramEnum(condition.parameters, 1, TriggerEnums::CompareEquals, info->parameters.at(1));
        const QString value = compiledParam(condition, 2);
        result = TriggerUtil::compareStrings(text, value, compareType);
    } else if (condition.type == TriggerIds::FileExists) {
        const QString filePath = compiledPath(condition, 0);
        // An empty path gives true, as in KeePass. Only local files are supported.
        result = filePath.isEmpty() || QFileInfo::exists(filePath);
    } else if (condition.type == TriggerIds::RemoteHostReachable) {
        const QString hostName = compiledParam(condition, 0);
        result = hostName.isEmpty() || hostReachable(hostName);
    } else if (condition.type == TriggerIds::DatabaseHasUnsavedChanges) {
        const quint32 selection = TriggerUtil::paramUInt(condition.parameters, 0, 0);
        QSharedPointer<Database> db;
        if (selection == TriggerEnums::DatabaseActive) {
            db = m_host ? m_host->activeDatabase() : QSharedPointer<Database>();
        } else if (selection == TriggerEnums::DatabaseTriggering) {
            db = context.properties->database;
        }
        result = db && db->isInitialized() && db->isModified();
    }

    // The negation is applied after the evaluation (KeePass: EcasPool.EvaluateCondition)
    return condition.negate ? !result : result;
}

bool TriggerSystem::hostReachable(const QString& hostName)
{
    // Two attempts, as KeePass: 250 ms, then 1250 ms
    for (const int timeout : {250, 1250}) {
        if (HostPing::ping(hostName, timeout)) {
            return true;
        }
    }
    return false;
}

bool TriggerSystem::executeAction(const TriggerObject& action, TriggerContext& context, QString* error)
{
    const auto* info = TriggerTypes::findAction(action.type);
    if (!info) {
        if (error) {
            *error = tr("The trigger action type is unknown.") + "\n\n"
                     + QString::fromLatin1(action.type.toRfc4122().toBase64());
        }
        return false;
    }

    if (action.type == TriggerIds::ChangeTriggerState) {
        // KeePass: EcasDefaultActionProvider.ChangeTriggerOnOff
        const QString name = compiledParam(action, 0);
        const quint32 state = TriggerUtil::paramUInt(action.parameters, 1);
        Trigger* target = nullptr;
        if (name.isEmpty()) {
            target = context.trigger;
        } else {
            for (auto& trigger : context.collection->triggers) {
                if (trigger.name == name) {
                    target = &trigger;
                    break;
                }
            }
        }
        if (!target) {
            if (error) {
                *error = tr("The object with the specified name could not be found.") + "\n\n"
                         + tr("Trigger name: %1.").arg(name);
            }
            return false;
        }
        if (state == TriggerEnums::TriggerOn) {
            target->on = true;
        } else if (state == TriggerEnums::TriggerOff) {
            target->on = false;
        } else if (state == TriggerEnums::TriggerToggle) {
            target->on = !target->on;
        }
        return true;
    }

    if (action.type == TriggerIds::Wait) {
        // Blocks the user interface thread, as KeePass does
        const quint32 milliseconds = TriggerUtil::paramUInt(action.parameters, 0);
        if (milliseconds != 0 && milliseconds <= static_cast<quint32>(std::numeric_limits<int>::max())) {
            QThread::msleep(milliseconds);
        }
        return true;
    }

    if (!m_host) {
        // Without the application, the other actions do nothing
        return true;
    }
    return m_host->executeAction(action, context, error);
}

void TriggerSystem::raiseEntryDataCopied(const QString& text)
{
    TriggerEventProperties properties;
    properties.text = text;
    raiseEvent(TriggerIds::CopiedEntryInfo, properties);
}

void TriggerSystem::raisePeriodicEvent()
{
    raiseEvent(TriggerIds::TimePeriodic);
}

void TriggerSystem::notifyUserActivity()
{
    if (!m_collection) {
        return;
    }
    for (auto& trigger : m_collection->triggers) {
        for (auto& event : trigger.events) {
            if (event.type == TriggerIds::TimePeriodic && TriggerUtil::paramBool(event.parameters, 1)) {
                restartTimer(event);
            }
        }
    }
}

bool TriggerSystem::usesObsoleteEvent() const
{
    if (!m_collection) {
        return false;
    }
    for (const auto& trigger : asConst(m_collection->triggers)) {
        for (const auto& event : trigger.events) {
            if (event.type == TriggerIds::UpdatedUIState) {
                return true;
            }
        }
    }
    return false;
}

QString TriggerSystem::compiledParam(const TriggerObject& object, int index, bool forCommandLine)
{
    const QString text = TriggerUtil::paramString(object.parameters, index);
    if (text.isEmpty() || !m_host) {
        return text;
    }
    return m_host->compilePlaceholders(text, forCommandLine);
}

QString TriggerSystem::compiledPath(const TriggerObject& object, int index)
{
    return TriggerUtil::stripPathQuotes(compiledParam(object, index));
}

QStringList TriggerSystem::compiledPaths(const TriggerObject& object, int index)
{
    return TriggerUtil::splitPaths(compiledParam(object, index));
}
