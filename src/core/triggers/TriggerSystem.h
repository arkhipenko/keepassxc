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

#ifndef KEEPASSXC_TRIGGERSYSTEM_H
#define KEEPASSXC_TRIGGERSYSTEM_H

#include "Trigger.h"

#include <QObject>
#include <QPointer>
#include <QSharedPointer>

class Database;
struct TriggerParameter;

// Data that comes with a raised event (KeePass: EcasPropertyDictionary)
struct TriggerEventProperties
{
    // The database that raised the event
    QSharedPointer<Database> database;
    // The file path of the event. When it is empty, the file path of the database is used.
    // "Saving database file" of a Save As sets the target path here.
    QString filePath;
    // "Copied entry data to clipboard": the copied value
    QString text;
    // "Custom toolbar button clicked": the button ID
    QString commandId;
};

// The state of one trigger run (KeePass: EcasContext)
struct TriggerContext
{
    TriggerCollection* collection = nullptr;
    Trigger* trigger = nullptr;
    QUuid eventType;
    const TriggerEventProperties* properties = nullptr;
    // Set by "Show message box" to abort the actions of the current trigger
    bool cancel = false;
};

/**
 * Interface to the application, implemented by the user interface.
 * The trigger system calls it for placeholders and for the actions that need the application.
 */
class TriggerHost
{
public:
    virtual ~TriggerHost() = default;

    // Compiles the placeholders of a parameter: all placeholders except the ones that change state.
    // The context is the selected entry and the active database.
    virtual QString compilePlaceholders(const QString& text, bool forCommandLine) = 0;
    virtual QSharedPointer<Database> activeDatabase() = 0;
    // Executes an action. Returns false and sets the error text when the action fails.
    virtual bool executeAction(const TriggerObject& action, TriggerContext& context, QString* error) = 0;
    // Shows "Trigger execution failed" with the error text
    virtual void showExecutionError(const QString& error) = 0;
};

/**
 * The trigger system. It copies the execution model of KeePass 2.x
 * (KeePass/Ecas/EcasTriggerSystem.cs, EcasTrigger.cs, EcasPool.cs):
 *
 * 1. An event is raised synchronously. Nothing runs while the global switch is off.
 * 2. The triggers are checked in list order. A trigger runs when it is enabled and on,
 *    one of its events matches, and all its conditions are true.
 * 3. Before each action, the trigger stops if a message box action asked to abort.
 * 4. After the actions, "Turn off after executing actions" sets the trigger off.
 * 5. One error ends the processing of the event: the error is shown and the remaining
 *    triggers of that event are skipped.
 * 6. Actions may raise further events. There is no guard against loops.
 *
 * Nothing runs until the triggers are loaded.
 */
class TriggerSystem : public QObject
{
    Q_OBJECT

public:
    static TriggerSystem* instance();

    void setHost(TriggerHost* host);
    TriggerHost* host() const;

    bool isLoaded() const;
    // Loads the triggers and sets each one to its initial state
    void load(const TriggerCollection& collection);
    // Replaces the triggers after an edit. The on/off state of a trigger that stays is kept.
    void replace(const TriggerCollection& collection);
    void unload();

    // A copy of the loaded triggers, with their current on/off state
    TriggerCollection collection() const;

    void raiseEvent(const QUuid& eventType, const TriggerEventProperties& properties = {});
    // "Copied entry data to clipboard" with the copied value
    void raiseEntryDataCopied(const QString& text);
    // Called every second by the application, while the main window is shown and no dialog is open
    void raisePeriodicEvent();
    // Restarts the periodic timers that have "Restart timer on KeePassXC activity" set
    void notifyUserActivity();

    // True when a trigger uses the obsolete event "User interface state updated"
    bool usesObsoleteEvent() const;

    // Evaluation helpers, public for tests
    bool eventMatches(const TriggerObject& event, const TriggerContext& context);
    bool evaluateCondition(const TriggerObject& condition, TriggerContext& context, QString* error);
    bool executeAction(const TriggerObject& action, TriggerContext& context, QString* error);

    // Parameter helpers that compile placeholders through the host
    QString compiledParam(const TriggerObject& object, int index, bool forCommandLine = false);
    QString compiledPath(const TriggerObject& object, int index);
    QStringList compiledPaths(const TriggerObject& object, int index);

signals:
    void triggersLoaded();
    void triggersChanged();

private:
    explicit TriggerSystem(QObject* parent = nullptr);

    bool runIfMatching(Trigger& trigger,
                       TriggerCollection& collection,
                       const QUuid& eventType,
                       const TriggerEventProperties& properties,
                       QString* error);
    bool hostReachable(const QString& host);

    static TriggerSystem* m_instance;
    TriggerHost* m_host = nullptr;
    QSharedPointer<TriggerCollection> m_collection;
};

inline TriggerSystem* triggerSystem()
{
    return TriggerSystem::instance();
}

#endif // KEEPASSXC_TRIGGERSYSTEM_H
