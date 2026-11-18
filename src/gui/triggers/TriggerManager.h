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

#ifndef KEEPASSXC_TRIGGERMANAGER_H
#define KEEPASSXC_TRIGGERMANAGER_H

#include "core/triggers/TriggerStore.h"
#include "core/triggers/TriggerSystem.h"

#include <QObject>
#include <QPointer>
#include <QTimer>

class DatabaseTabWidget;
class DatabaseWidget;
class QAction;
class QToolBar;
class QToolButton;

/**
 * Connects the trigger system to the application:
 *
 * - Loads the triggers from the sealed trigger file at the first unlock of a database that holds
 *   the trigger key, and raises the application start events then.
 * - Runs the periodic event every second and reports user activity.
 * - Executes the actions that need the application, and resolves placeholders.
 * - Opens the Triggers dialog (Tools > Triggers) with the edit flow of the sealed file.
 * - Copies the trigger key to another database (Tools > Copy Trigger Key to Active Database).
 */
class TriggerManager : public QObject, public TriggerHost
{
    Q_OBJECT

public:
    TriggerManager(QWidget* mainWindow, DatabaseTabWidget* tabWidget, QToolBar* toolBar, QAction* toolBarAnchor);
    ~TriggerManager() override;

    // The trigger file. Tests can set another path.
    QString triggerFilePath() const;
    void setTriggerFilePath(const QString& path);

    // TriggerHost
    QString compilePlaceholders(const QString& text, bool forCommandLine) override;
    QSharedPointer<Database> activeDatabase() override;
    bool executeAction(const TriggerObject& action, TriggerContext& context, QString* error) override;
    void showExecutionError(const QString& error) override;

    bool canCopyTriggerKey() const;
    // Unloads the triggers and resets the state of this run (start events, messages, toolbar buttons)
    void reset();
    // Custom toolbar buttons added by triggers, for tests
    QList<QToolButton*> customToolBarButtons() const;

public slots:
    void databaseUnlocked(DatabaseWidget* dbWidget);
    void editTriggers();
    void copyTriggerKeyToActiveDatabase();
    void applicationExit();

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

private slots:
    void periodicTick();
    void customButtonClicked();

private:
    struct KeyHolder
    {
        QPointer<DatabaseWidget> dbWidget;
        TriggerKey key;
    };

    QList<DatabaseWidget*> unlockedDatabaseWidgets() const;
    DatabaseWidget* activeUnlockedDatabaseWidget() const;
    // The unlocked database whose trigger key opens the trigger file
    bool findKeyHolder(KeyHolder* holder, TriggerCollection* collection) const;
    bool saveDatabaseWithKey(DatabaseWidget* dbWidget, const TriggerKey& key);
    void startTriggers();

    bool executeCommand(const QString& command,
                        const QString& arguments,
                        bool wait,
                        quint32 windowStyle,
                        const QString& verb,
                        QString* error);
    bool openUrlOrCommand(const QString& text, QString* error);
    bool showMessageBox(const TriggerObject& action, TriggerContext& context, QString* error);
    void addToolBarButton(const QString& id, const QString& name, const QString& description);
    void removeToolBarButton(const QString& id);

    QPointer<QWidget> m_mainWindow;
    QPointer<DatabaseTabWidget> m_tabWidget;
    QPointer<QToolBar> m_toolBar;
    QPointer<QAction> m_toolBarAnchor;
    QString m_triggerFilePath;

    QTimer m_periodicTimer;
    bool m_startEventsRaised = false;
    bool m_verifyWarningShown = false;
    bool m_mismatchInfoShown = false;
    bool m_inPeriodicEvent = false;

    QPointer<QAction> m_customSeparator;
    QList<QPair<QString, QPointer<QAction>>> m_customButtons;
};

#endif // KEEPASSXC_TRIGGERMANAGER_H
