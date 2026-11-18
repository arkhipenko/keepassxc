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

#ifndef KEEPASSXC_TRIGGERSDIALOG_H
#define KEEPASSXC_TRIGGERSDIALOG_H

#include "core/triggers/Trigger.h"

#include <QDialog>

#include <functional>

class QAction;
class QCheckBox;
class QPushButton;
class QTreeWidget;

/**
 * The Triggers dialog (Tools > Triggers), as KeePass/Forms/EcasTriggersForm.cs.
 * It edits a copy of the triggers. OK calls the save function; when it fails, the dialog stays open
 * and nothing is applied.
 */
class TriggersDialog : public QDialog
{
    Q_OBJECT

public:
    using SaveFunction = std::function<bool(const TriggerCollection& collection, QString* error)>;

    TriggersDialog(QWidget* parent, const TriggerCollection& collection, SaveFunction save);

    TriggerCollection collection() const;

public slots:
    void accept() override;

private slots:
    void addTrigger();
    void editTrigger();
    void deleteTriggers();
    void moveUp();
    void moveDown();
    void copyAllTriggers();
    void copySelectedTriggers();
    void pasteTriggers();
    void updateControls();

private:
    void updateList(const QList<int>& selectedRows = {});
    QList<int> selectedRows() const;
    void copyTriggers(const QList<Trigger>& triggers);

    TriggerCollection m_collection;
    SaveFunction m_save;
    QCheckBox* m_enableTriggers;
    QTreeWidget* m_list;
    QPushButton* m_add;
    QPushButton* m_edit;
    QPushButton* m_delete;
    QPushButton* m_moveUp;
    QPushButton* m_moveDown;
    QPushButton* m_tools;
    QAction* m_copyAll;
    QAction* m_copySelected;
    QAction* m_paste;
};

#endif // KEEPASSXC_TRIGGERSDIALOG_H
