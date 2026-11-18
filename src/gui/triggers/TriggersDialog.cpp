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

#include "TriggersDialog.h"

#include "TriggerEditDialogs.h"
#include "core/Global.h"
#include "core/triggers/TriggerXml.h"
#include "gui/Icons.h"
#include "gui/MessageBox.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMenu>
#include <QPushButton>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>

TriggersDialog::TriggersDialog(QWidget* parent, const TriggerCollection& collection, SaveFunction save)
    : QDialog(parent)
    , m_collection(collection)
    , m_save(std::move(save))
{
    setWindowTitle(tr("Triggers"));
    setObjectName("triggersDialog");
    resize(620, 440);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(new QLabel(tr("Automate workflows using the trigger system."), this));

    m_enableTriggers = new QCheckBox(tr("Enable trigger system"), this);
    m_enableTriggers->setObjectName("enableTriggersCheckBox");
    m_enableTriggers->setChecked(m_collection.enabled);
    layout->addWidget(m_enableTriggers);

    auto* center = new QHBoxLayout();
    m_list = new QTreeWidget(this);
    m_list->setObjectName("triggerList");
    m_list->setRootIsDecorated(false);
    m_list->setColumnCount(2);
    m_list->setHeaderLabels({tr("Name"), tr("Status")});
    m_list->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_list->header()->setStretchLastSection(true);
    center->addWidget(m_list, 1);

    auto* buttons = new QVBoxLayout();
    m_add = new QPushButton(tr("Add…"), this);
    m_add->setObjectName("addTriggerButton");
    m_edit = new QPushButton(tr("Edit…"), this);
    m_edit->setObjectName("editTriggerButton");
    m_delete = new QPushButton(tr("Delete"), this);
    m_delete->setObjectName("deleteTriggerButton");
    m_moveUp = new QPushButton(icons()->icon("move-up"), {}, this);
    m_moveUp->setObjectName("moveUpButton");
    m_moveUp->setToolTip(tr("Move up"));
    m_moveDown = new QPushButton(icons()->icon("move-down"), {}, this);
    m_moveDown->setObjectName("moveDownButton");
    m_moveDown->setToolTip(tr("Move down"));
    for (auto* button : {m_add, m_edit, m_delete, m_moveUp, m_moveDown}) {
        buttons->addWidget(button);
    }
    buttons->addStretch(1);
    center->addLayout(buttons);
    layout->addLayout(center, 1);

    auto* bottom = new QHBoxLayout();
    m_tools = new QPushButton(tr("Tools"), this);
    m_tools->setObjectName("toolsButton");
    auto* toolsMenu = new QMenu(m_tools);
    m_copyAll = toolsMenu->addAction(tr("Copy Triggers to Clipboard"));
    m_copyAll->setObjectName("copyTriggersAction");
    m_copySelected = toolsMenu->addAction(tr("Copy Selected Triggers to Clipboard"));
    m_copySelected->setObjectName("copySelectedTriggersAction");
    m_paste = toolsMenu->addAction(tr("Paste Triggers from Clipboard"));
    m_paste->setObjectName("pasteTriggersAction");
    m_tools->setMenu(toolsMenu);
    bottom->addWidget(m_tools);
    bottom->addStretch(1);
    auto* dialogButtons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    dialogButtons->setObjectName("dialogButtons");
    bottom->addWidget(dialogButtons);
    layout->addLayout(bottom);

    connect(dialogButtons, &QDialogButtonBox::accepted, this, &TriggersDialog::accept);
    connect(dialogButtons, &QDialogButtonBox::rejected, this, &TriggersDialog::reject);
    connect(m_add, &QPushButton::clicked, this, &TriggersDialog::addTrigger);
    connect(m_edit, &QPushButton::clicked, this, &TriggersDialog::editTrigger);
    connect(m_delete, &QPushButton::clicked, this, &TriggersDialog::deleteTriggers);
    connect(m_moveUp, &QPushButton::clicked, this, &TriggersDialog::moveUp);
    connect(m_moveDown, &QPushButton::clicked, this, &TriggersDialog::moveDown);
    connect(m_copyAll, &QAction::triggered, this, &TriggersDialog::copyAllTriggers);
    connect(m_copySelected, &QAction::triggered, this, &TriggersDialog::copySelectedTriggers);
    connect(m_paste, &QAction::triggered, this, &TriggersDialog::pasteTriggers);
    connect(m_list, &QTreeWidget::itemSelectionChanged, this, &TriggersDialog::updateControls);
    connect(m_list, &QTreeWidget::itemActivated, this, &TriggersDialog::editTrigger);
    connect(m_enableTriggers, &QCheckBox::toggled, this, &TriggersDialog::updateControls);

    updateList();
}

TriggerCollection TriggersDialog::collection() const
{
    TriggerCollection result = m_collection;
    result.enabled = m_enableTriggers->isChecked();
    return result;
}

void TriggersDialog::accept()
{
    QString error;
    if (m_save && !m_save(collection(), &error)) {
        MessageBox::critical(this, tr("Triggers"), tr("The triggers could not be saved: %1").arg(error));
        return;
    }
    QDialog::accept();
}

void TriggersDialog::updateList(const QList<int>& selected)
{
    m_list->clear();
    for (const auto& trigger : asConst(m_collection.triggers)) {
        auto* item = new QTreeWidgetItem(m_list);
        item->setText(0, trigger.name);
        QString status = tr("Disabled");
        if (trigger.enabled) {
            status = tr("Enabled") + " / " + (trigger.on ? tr("On") : tr("Off")) + " / "
                     + (trigger.initiallyOn ? tr("Initially on") : tr("Initially off"));
        }
        item->setText(1, status);
        item->setIcon(0, icons()->icon(trigger.enabled ? "dialog-ok" : "dialog-close"));
    }
    for (int row : selected) {
        if (auto* item = m_list->topLevelItem(row)) {
            item->setSelected(true);
        }
    }
    m_list->resizeColumnToContents(0);
    updateControls();
}

QList<int> TriggersDialog::selectedRows() const
{
    QList<int> rows;
    for (auto* item : m_list->selectedItems()) {
        rows << m_list->indexOfTopLevelItem(item);
    }
    std::sort(rows.begin(), rows.end());
    return rows;
}

void TriggersDialog::updateControls()
{
    // The checkbox "Enable trigger system" disables the other controls when cleared (as KeePass)
    const bool enabled = m_enableTriggers->isChecked();
    const int selected = m_list->selectedItems().size();
    m_list->setEnabled(enabled);
    m_add->setEnabled(enabled);
    m_edit->setEnabled(enabled && selected == 1);
    m_delete->setEnabled(enabled && selected >= 1);
    const bool move = enabled && m_list->topLevelItemCount() >= 2 && selected >= 1;
    m_moveUp->setEnabled(move);
    m_moveDown->setEnabled(move);
    m_copyAll->setEnabled(enabled);
    m_copySelected->setEnabled(enabled);
    m_paste->setEnabled(enabled);
}

void TriggersDialog::addTrigger()
{
    Trigger trigger;
    EditTriggerDialog dialog(this, trigger, false);
    if (dialog.exec() == QDialog::Accepted) {
        Trigger added = dialog.trigger();
        added.setToInitialState();
        m_collection.triggers.append(added);
        updateList();
    }
}

void TriggersDialog::editTrigger()
{
    const auto rows = selectedRows();
    if (rows.size() != 1) {
        return;
    }
    const int row = rows.first();
    EditTriggerDialog dialog(this, m_collection.triggers.at(row), true);
    if (dialog.exec() == QDialog::Accepted) {
        m_collection.triggers[row] = dialog.trigger();
        updateList({row});
    }
}

void TriggersDialog::deleteTriggers()
{
    const auto rows = selectedRows();
    for (int i = rows.size() - 1; i >= 0; --i) {
        m_collection.triggers.removeAt(rows.at(i));
    }
    updateList();
}

void TriggersDialog::moveUp()
{
    auto rows = selectedRows();
    if (rows.isEmpty() || rows.first() == 0) {
        return;
    }
    for (int& row : rows) {
        m_collection.triggers.swapItemsAt(row, row - 1);
        --row;
    }
    updateList(rows);
}

void TriggersDialog::moveDown()
{
    auto rows = selectedRows();
    if (rows.isEmpty() || rows.last() >= m_collection.triggers.size() - 1) {
        return;
    }
    for (int i = rows.size() - 1; i >= 0; --i) {
        m_collection.triggers.swapItemsAt(rows[i], rows[i] + 1);
        ++rows[i];
    }
    updateList(rows);
}

void TriggersDialog::copyTriggers(const QList<Trigger>& triggers)
{
    // The clipboard holds KeePass trigger XML (<TriggerCollection>), so triggers move to and from KeePass.
    // An empty selection clears the clipboard, as KeePass.
    if (triggers.isEmpty()) {
        QApplication::clipboard()->clear();
        return;
    }
    QApplication::clipboard()->setText(QString::fromUtf8(TriggerXml::writeTriggerCollection(triggers)));
}

void TriggersDialog::copyAllTriggers()
{
    copyTriggers(m_collection.triggers);
}

void TriggersDialog::copySelectedTriggers()
{
    QList<Trigger> triggers;
    for (int row : selectedRows()) {
        triggers << m_collection.triggers.at(row);
    }
    copyTriggers(triggers);
}

void TriggersDialog::pasteTriggers()
{
    QList<Trigger> pasted;
    QString error;
    const QString text = QApplication::clipboard()->text();
    if (!TriggerXml::readTriggerCollection(text.toUtf8(), &pasted, &error)) {
        MessageBox::warning(this, tr("Paste Triggers"), tr("The clipboard does not hold triggers: %1").arg(error));
        return;
    }
    // A pasted trigger receives a new UUID when its UUID already exists
    m_collection.addPasted(pasted);
    updateList();
}
