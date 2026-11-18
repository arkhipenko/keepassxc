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

#include "TriggerEditDialogs.h"

#include "core/Global.h"
#include "core/triggers/TriggerUtil.h"
#include "gui/Icons.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpressionValidator>
#include <QTabWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>

namespace
{
    QString kindTitle(TriggerObjectKind kind, bool editing)
    {
        switch (kind) {
        case TriggerObjectKind::Event:
            return editing ? QObject::tr("Edit Event") : QObject::tr("Add Event");
        case TriggerObjectKind::Condition:
            return editing ? QObject::tr("Edit Condition") : QObject::tr("Add Condition");
        case TriggerObjectKind::Action:
            break;
        }
        return editing ? QObject::tr("Edit Action") : QObject::tr("Add Action");
    }
} // namespace

TriggerObjectDialog::TriggerObjectDialog(QWidget* parent,
                                         TriggerObjectKind kind,
                                         const TriggerObject& object,
                                         bool editing)
    : QDialog(parent)
    , m_kind(kind)
    , m_object(object)
{
    setWindowTitle(kindTitle(kind, editing));
    setObjectName("triggerObjectDialog");
    resize(560, 420);

    auto* layout = new QVBoxLayout(this);
    auto* typeRow = new QHBoxLayout();
    typeRow->addWidget(new QLabel(tr("Type:"), this));
    m_typeCombo = new QComboBox(this);
    m_typeCombo->setObjectName("typeComboBox");
    m_typeCombo->setMaxVisibleItems(20);
    for (const auto& info : TriggerTypes::types(kind)) {
        m_typeCombo->addItem(icons()->icon(info.icon), info.name, info.uuid);
    }
    typeRow->addWidget(m_typeCombo, 1);
    layout->addLayout(typeRow);

    m_parameters = new QTableWidget(this);
    m_parameters->setObjectName("parameterTable");
    m_parameters->setColumnCount(2);
    m_parameters->setHorizontalHeaderLabels({tr("Parameter"), tr("Value")});
    m_parameters->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_parameters->horizontalHeader()->setStretchLastSection(true);
    m_parameters->verticalHeader()->setVisible(false);
    m_parameters->setSelectionMode(QAbstractItemView::NoSelection);
    layout->addWidget(m_parameters, 1);

    if (kind == TriggerObjectKind::Condition) {
        m_negate = new QCheckBox(tr("Not (invert the result of the condition)"), this);
        m_negate->setObjectName("negateCheckBox");
        m_negate->setChecked(object.negate);
        layout->addWidget(m_negate);
    }

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    // A new or unknown type selects the first type of the list (KeePass)
    int index = m_typeCombo->findData(object.type);
    if (index < 0) {
        index = 0;
    }
    m_typeCombo->setCurrentIndex(index);
    typeChanged(index);
    connect(m_typeCombo, qOverload<int>(&QComboBox::currentIndexChanged), this, &TriggerObjectDialog::typeChanged);
}

void TriggerObjectDialog::typeChanged(int index)
{
    const QUuid uuid = m_typeCombo->itemData(index).toUuid();
    const auto* info = TriggerTypes::find(m_kind, uuid);
    if (!info) {
        return;
    }
    // The values of the object are used only when the type is the type of the object
    buildParameterEditors(*info, uuid == m_object.type ? m_object.parameters : QStringList());
}

void TriggerObjectDialog::buildParameterEditors(const TriggerTypeInfo& info, const QStringList& values)
{
    m_parameters->clearContents();
    m_parameters->setRowCount(info.parameters.size());
    for (int row = 0; row < info.parameters.size(); ++row) {
        const auto& param = info.parameters.at(row);
        const QString value = values.value(row);

        auto* nameItem = new QTableWidgetItem(param.name);
        nameItem->setFlags(Qt::ItemIsEnabled);
        m_parameters->setItem(row, 0, nameItem);

        QWidget* editor = nullptr;
        switch (param.type) {
        case TriggerValueType::Bool: {
            auto* checkBox = new QCheckBox(m_parameters);
            checkBox->setChecked(TriggerUtil::stringToBool(value));
            editor = checkBox;
            break;
        }
        case TriggerValueType::EnumStrings: {
            auto* combo = new QComboBox(m_parameters);
            int selected = 0;
            for (int i = 0; i < param.enumItems.size(); ++i) {
                combo->addItem(param.enumItems.at(i).name, param.enumItems.at(i).id);
                if (QString::number(param.enumItems.at(i).id) == value) {
                    selected = i;
                }
            }
            combo->setCurrentIndex(selected);
            editor = combo;
            break;
        }
        case TriggerValueType::Int64:
        case TriggerValueType::UInt64: {
            auto* line = new QLineEdit(m_parameters);
            const bool isSigned = (param.type == TriggerValueType::Int64);
            line->setValidator(
                new QRegularExpressionValidator(QRegularExpression(isSigned ? "-?[0-9]{0,19}" : "[0-9]{0,20}"), line));
            bool ok = false;
            if (isSigned) {
                const qint64 number = value.trimmed().toLongLong(&ok);
                line->setText(ok ? QString::number(number) : QString());
            } else {
                const quint64 number = value.trimmed().toULongLong(&ok);
                line->setText(ok ? QString::number(number) : QString());
            }
            editor = line;
            break;
        }
        default: {
            auto* line = new QLineEdit(m_parameters);
            line->setText(value);
            editor = line;
            break;
        }
        }
        editor->setObjectName(QString("parameter%1").arg(row));
        m_parameters->setCellWidget(row, 1, editor);
    }
    m_parameters->resizeRowsToContents();
}

QString TriggerObjectDialog::parameterValue(int row) const
{
    auto* widget = m_parameters->cellWidget(row, 1);
    if (auto* checkBox = qobject_cast<QCheckBox*>(widget)) {
        // KeePass stores a check box value as "True" or "False"
        return TriggerUtil::boolToString(checkBox->isChecked());
    }
    if (auto* combo = qobject_cast<QComboBox*>(widget)) {
        return QString::number(combo->currentData().toUInt());
    }
    if (auto* line = qobject_cast<QLineEdit*>(widget)) {
        return line->text();
    }
    return {};
}

TriggerObject TriggerObjectDialog::object() const
{
    TriggerObject result = m_object;
    result.type = m_typeCombo->currentData().toUuid();
    result.parameters.clear();
    for (int row = 0; row < m_parameters->rowCount(); ++row) {
        result.parameters << parameterValue(row);
    }
    if (m_negate) {
        result.negate = m_negate->isChecked();
    }
    result.runAtMs = -1;
    return result;
}

EditTriggerDialog::EditTriggerDialog(QWidget* parent, const Trigger& trigger, bool editing)
    : QDialog(parent)
    , m_trigger(trigger)
{
    setWindowTitle(editing ? tr("Edit Trigger") : tr("Add Trigger"));
    setObjectName("editTriggerDialog");
    resize(640, 480);

    // KeePass removes the objects of unknown types from the lists of the editor
    for (auto* list : {&m_trigger.events, &m_trigger.conditions, &m_trigger.actions}) {
        const auto kind = (list == &m_trigger.events)       ? TriggerObjectKind::Event
                          : (list == &m_trigger.conditions) ? TriggerObjectKind::Condition
                                                            : TriggerObjectKind::Action;
        list->erase(
            std::remove_if(list->begin(),
                           list->end(),
                           [kind](const TriggerObject& object) { return !TriggerTypes::find(kind, object.type); }),
            list->end());
    }

    auto* layout = new QVBoxLayout(this);
    auto* description = new QLabel(
        editing ? tr("Modify an existing workflow automation.") : tr("Create a new workflow automation."), this);
    layout->addWidget(description);

    m_tabs = new QTabWidget(this);
    m_tabs->setObjectName("triggerTabs");
    layout->addWidget(m_tabs, 1);

    // Properties
    auto* properties = new QWidget(m_tabs);
    auto* form = new QFormLayout(properties);
    m_name = new QLineEdit(m_trigger.name, properties);
    m_name->setObjectName("triggerName");
    form->addRow(tr("Name:"), m_name);
    m_comments = new QPlainTextEdit(m_trigger.comments, properties);
    m_comments->setObjectName("triggerComments");
    form->addRow(tr("Comments:"), m_comments);
    m_enabled = new QCheckBox(tr("Enabled"), properties);
    m_enabled->setObjectName("triggerEnabled");
    m_enabled->setChecked(m_trigger.enabled);
    form->addRow(m_enabled);
    m_initiallyOn = new QCheckBox(tr("Initially on"), properties);
    m_initiallyOn->setObjectName("triggerInitiallyOn");
    m_initiallyOn->setChecked(m_trigger.initiallyOn);
    form->addRow(m_initiallyOn);
    m_turnOff = new QCheckBox(tr("Turn off after executing actions"), properties);
    m_turnOff->setObjectName("triggerTurnOff");
    m_turnOff->setChecked(m_trigger.turnOffAfterAction);
    form->addRow(m_turnOff);
    m_tabs->addTab(properties, tr("Properties"));

    m_events = {TriggerObjectKind::Event, &m_trigger.events, nullptr, nullptr, nullptr, nullptr, nullptr};
    m_conditions = {TriggerObjectKind::Condition, &m_trigger.conditions, nullptr, nullptr, nullptr, nullptr, nullptr};
    m_actions = {TriggerObjectKind::Action, &m_trigger.actions, nullptr, nullptr, nullptr, nullptr, nullptr};
    m_tabs->addTab(createObjectPage(m_events, tr("Event")), tr("Events"));
    m_tabs->addTab(createObjectPage(m_conditions, tr("Condition")), tr("Conditions"));
    m_tabs->addTab(createObjectPage(m_actions, tr("Action")), tr("Actions"));

    auto* bottom = new QHBoxLayout();
    m_back = new QPushButton(tr("< Back"), this);
    m_next = new QPushButton(tr("Next >"), this);
    bottom->addWidget(m_back);
    bottom->addWidget(m_next);
    bottom->addStretch(1);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    bottom->addWidget(buttons);
    layout->addLayout(bottom);

    connect(m_back, &QPushButton::clicked, this, [this] { m_tabs->setCurrentIndex(m_tabs->currentIndex() - 1); });
    connect(m_next, &QPushButton::clicked, this, [this] { m_tabs->setCurrentIndex(m_tabs->currentIndex() + 1); });
    connect(m_tabs, &QTabWidget::currentChanged, this, &EditTriggerDialog::updateButtons);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    updateList(m_events);
    updateList(m_conditions);
    updateList(m_actions);
    updateButtons();
    m_name->setFocus();
}

QWidget* EditTriggerDialog::createObjectPage(ObjectPage& page, const QString& column)
{
    auto* widget = new QWidget(m_tabs);
    auto* layout = new QHBoxLayout(widget);
    page.list = new QTreeWidget(widget);
    page.list->setObjectName(column.toLower() + "List");
    page.list->setRootIsDecorated(false);
    page.list->setColumnCount(2);
    page.list->setHeaderLabels({column, tr("Parameters")});
    page.list->setSelectionMode(QAbstractItemView::ExtendedSelection);
    layout->addWidget(page.list, 1);

    auto* buttons = new QVBoxLayout();
    auto* add = new QPushButton(tr("Add…"), widget);
    add->setObjectName(column.toLower() + "AddButton");
    page.edit = new QPushButton(tr("Edit…"), widget);
    page.edit->setObjectName(column.toLower() + "EditButton");
    page.remove = new QPushButton(tr("Delete"), widget);
    page.remove->setObjectName(column.toLower() + "DeleteButton");
    page.moveUp = new QPushButton(icons()->icon("move-up"), {}, widget);
    page.moveUp->setToolTip(tr("Move up"));
    page.moveDown = new QPushButton(icons()->icon("move-down"), {}, widget);
    page.moveDown->setToolTip(tr("Move down"));
    for (auto* button : {add, page.edit, page.remove, page.moveUp, page.moveDown}) {
        buttons->addWidget(button);
    }
    buttons->addStretch(1);
    layout->addLayout(buttons);

    ObjectPage* p = &page;
    connect(add, &QPushButton::clicked, this, [this, p] { addObject(*p); });
    connect(page.edit, &QPushButton::clicked, this, [this, p] { editObject(*p); });
    connect(page.remove, &QPushButton::clicked, this, [this, p] { removeObjects(*p); });
    connect(page.moveUp, &QPushButton::clicked, this, [this, p] { moveObjects(*p, true); });
    connect(page.moveDown, &QPushButton::clicked, this, [this, p] { moveObjects(*p, false); });
    connect(page.list, &QTreeWidget::itemSelectionChanged, this, &EditTriggerDialog::updateButtons);
    connect(page.list, &QTreeWidget::itemActivated, this, [this, p] { editObject(*p); });
    return widget;
}

void EditTriggerDialog::updateList(ObjectPage& page, const QList<int>& selected)
{
    page.list->clear();
    const bool isCondition = (page.kind == TriggerObjectKind::Condition);
    for (const auto& object : asConst(*page.objects)) {
        const auto* info = TriggerTypes::find(page.kind, object.type);
        auto* item = new QTreeWidgetItem(page.list);
        item->setText(0, info ? info->name : QString());
        item->setText(1, TriggerUtil::parametersToString(object, info, isCondition));
        if (info) {
            item->setIcon(0, icons()->icon(info->icon));
        }
    }
    for (int row : selected) {
        if (auto* item = page.list->topLevelItem(row)) {
            item->setSelected(true);
        }
    }
    page.list->resizeColumnToContents(0);
    updateButtons();
}

QList<int> EditTriggerDialog::selectedRows(const ObjectPage& page) const
{
    QList<int> rows;
    for (auto* item : page.list->selectedItems()) {
        rows << page.list->indexOfTopLevelItem(item);
    }
    std::sort(rows.begin(), rows.end());
    return rows;
}

void EditTriggerDialog::updateButtons()
{
    const int tab = m_tabs->currentIndex();
    m_back->setEnabled(tab > 0);
    m_next->setEnabled(tab < m_tabs->count() - 1);
    for (auto* page : {&m_events, &m_conditions, &m_actions}) {
        if (!page->list) {
            continue;
        }
        const int selected = page->list->selectedItems().size();
        page->edit->setEnabled(selected == 1);
        page->remove->setEnabled(selected > 0);
        page->moveUp->setEnabled(selected > 0);
        page->moveDown->setEnabled(selected > 0);
    }
}

void EditTriggerDialog::addObject(ObjectPage& page)
{
    TriggerObject object;
    // A new event is "Application started and ready", as in KeePass
    if (page.kind == TriggerObjectKind::Event) {
        object.type = TriggerIds::AppLoadPost;
    }
    TriggerObjectDialog dialog(this, page.kind, object, false);
    if (dialog.exec() == QDialog::Accepted) {
        page.objects->append(dialog.object());
        updateList(page, {static_cast<int>(page.objects->size()) - 1});
    }
}

void EditTriggerDialog::editObject(ObjectPage& page)
{
    const auto rows = selectedRows(page);
    if (rows.size() != 1) {
        return;
    }
    const int row = rows.first();
    TriggerObjectDialog dialog(this, page.kind, page.objects->at(row), true);
    if (dialog.exec() == QDialog::Accepted) {
        (*page.objects)[row] = dialog.object();
        updateList(page, {row});
    }
}

void EditTriggerDialog::removeObjects(ObjectPage& page)
{
    const auto rows = selectedRows(page);
    for (int i = rows.size() - 1; i >= 0; --i) {
        page.objects->removeAt(rows.at(i));
    }
    updateList(page);
}

void EditTriggerDialog::moveObjects(ObjectPage& page, bool up)
{
    // Each selected object moves one position, as KeePass (UIUtil.MoveSelectedItemsInternalOne)
    auto rows = selectedRows(page);
    if (rows.isEmpty()) {
        return;
    }
    if (up) {
        if (rows.first() == 0) {
            return;
        }
        for (int& row : rows) {
            page.objects->swapItemsAt(row, row - 1);
            --row;
        }
    } else {
        if (rows.last() >= page.objects->size() - 1) {
            return;
        }
        for (int i = rows.size() - 1; i >= 0; --i) {
            page.objects->swapItemsAt(rows[i], rows[i] + 1);
            ++rows[i];
        }
    }
    updateList(page, rows);
}

Trigger EditTriggerDialog::trigger() const
{
    Trigger result = m_trigger;
    result.name = m_name->text();
    result.comments = m_comments->toPlainText();
    result.enabled = m_enabled->isChecked();
    result.initiallyOn = m_initiallyOn->isChecked();
    result.turnOffAfterAction = m_turnOff->isChecked();
    return result;
}
