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

#ifndef KEEPASSXC_TRIGGEREDITDIALOGS_H
#define KEEPASSXC_TRIGGEREDITDIALOGS_H

#include "core/triggers/Trigger.h"
#include "core/triggers/TriggerTypes.h"

#include <QDialog>

class QCheckBox;
class QComboBox;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QTabWidget;
class QTableWidget;
class QTreeWidget;

/**
 * Editor of one event, condition or action (KeePass: EcasEventForm, EcasConditionForm, EcasActionForm).
 * Each parameter gets an editor for its type: text, check box or list.
 */
class TriggerObjectDialog : public QDialog
{
    Q_OBJECT

public:
    TriggerObjectDialog(QWidget* parent, TriggerObjectKind kind, const TriggerObject& object, bool editing);

    TriggerObject object() const;

private slots:
    void typeChanged(int index);

private:
    void buildParameterEditors(const TriggerTypeInfo& info, const QStringList& values);
    QString parameterValue(int row) const;

    TriggerObjectKind m_kind;
    TriggerObject m_object;
    QComboBox* m_typeCombo;
    QTableWidget* m_parameters;
    QCheckBox* m_negate = nullptr;
};

/**
 * Editor of one trigger with the pages Properties, Events, Conditions and Actions
 * (KeePass: EcasTriggerForm). It edits a copy of the trigger.
 */
class EditTriggerDialog : public QDialog
{
    Q_OBJECT

public:
    EditTriggerDialog(QWidget* parent, const Trigger& trigger, bool editing);

    Trigger trigger() const;

private:
    struct ObjectPage
    {
        TriggerObjectKind kind;
        QList<TriggerObject>* objects;
        QTreeWidget* list;
        QPushButton* edit;
        QPushButton* remove;
        QPushButton* moveUp;
        QPushButton* moveDown;
    };

    QWidget* createObjectPage(ObjectPage& page, const QString& column);
    void updateList(ObjectPage& page, const QList<int>& selectedRows = {});
    void updateButtons();
    void addObject(ObjectPage& page);
    void editObject(ObjectPage& page);
    void removeObjects(ObjectPage& page);
    void moveObjects(ObjectPage& page, bool up);
    QList<int> selectedRows(const ObjectPage& page) const;

    Trigger m_trigger;
    QTabWidget* m_tabs;
    QLineEdit* m_name;
    QPlainTextEdit* m_comments;
    QCheckBox* m_enabled;
    QCheckBox* m_initiallyOn;
    QCheckBox* m_turnOff;
    QPushButton* m_back;
    QPushButton* m_next;
    ObjectPage m_events;
    ObjectPage m_conditions;
    ObjectPage m_actions;
};

#endif // KEEPASSXC_TRIGGEREDITDIALOGS_H
