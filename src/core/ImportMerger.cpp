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

#include "ImportMerger.h"

#include "core/Compare.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/Global.h"
#include "core/Group.h"
#include "core/Metadata.h"

#include <QHash>

#include <algorithm>
#include <map>

namespace
{
    // Compare options of KeePass for "same data": parent group, last access and history are ignored
    constexpr CompareItemOptions SameDataOptions = CompareItemIgnoreLocation | CompareItemIgnoreStatistics
                                                   | CompareItemIgnoreHistory | CompareItemIgnoreMilliseconds;

    // KeePass compares modification times without milliseconds (TimeUtil.Compare with bOnlySeconds)
    int compareTimes(const QDateTime& left, const QDateTime& right)
    {
        return compare(left, right, CompareItemIgnoreMilliseconds);
    }

    // KeePass: PwEntry.HasBackupOfData(peData, false, true)
    bool hasBackupOfData(const Entry* entry, const Entry* data)
    {
        for (const auto* item : entry->historyItems()) {
            if (item->equals(data, SameDataOptions)) {
                return true;
            }
        }
        return false;
    }

    // KeePass: PwEntry.CreateBackup. The history item has the UUID of the entry and no history.
    void createBackup(Entry* entry)
    {
        auto* backup = entry->clone(Entry::CloneNoFlags);
        entry->addHistoryItem(backup);
    }

    // KeePass: PwEntry.AssignProperties(source, onlyIfNewer, false, false). The UUID, the history
    // and the location (parent group and its change time) stay.
    void assignEntry(Entry* target, const Entry* source, bool onlyIfNewer)
    {
        if (onlyIfNewer
            && compareTimes(source->timeInfo().lastModificationTime(), target->timeInfo().lastModificationTime()) < 0) {
            return;
        }
        const QDateTime locationChanged = target->timeInfo().locationChanged();
        target->setUpdateTimeinfo(false);
        target->copyDataFrom(source);
        TimeInfo timeInfo = target->timeInfo();
        timeInfo.setLocationChanged(locationChanged);
        target->setTimeInfo(timeInfo);
        target->setUpdateTimeinfo(true);
    }

    // KeePass: PwGroup.AssignProperties(source, onlyIfNewer, false)
    void assignGroup(Group* target, const Group* source, bool onlyIfNewer)
    {
        if (onlyIfNewer
            && compareTimes(source->timeInfo().lastModificationTime(), target->timeInfo().lastModificationTime()) < 0) {
            return;
        }
        TimeInfo timeInfo = source->timeInfo();
        timeInfo.setLocationChanged(target->timeInfo().locationChanged());

        const bool updateTimeInfo = target->canUpdateTimeinfo();
        target->setUpdateTimeinfo(false);
        target->setName(source->name());
        target->setNotes(source->notes());
        if (!source->iconUuid().isNull()) {
            target->setIcon(source->iconUuid());
        } else {
            target->setIcon(source->iconNumber());
        }
        target->setTags(source->tags());
        target->setExpanded(source->isExpanded());
        target->setDefaultAutoTypeSequence(source->defaultAutoTypeSequence());
        target->setAutoTypeEnabled(source->autoTypeEnabled());
        target->setSearchingEnabled(source->searchingEnabled());
        target->customData()->copyDataFrom(source->customData());
        target->setTimeInfo(timeInfo);
        target->setUpdateTimeinfo(updateTimeInfo);
    }

    // Removes an object without a new deletion record; the record already exists
    template <typename T> void eraseKeepingRecords(Database* db, T* object)
    {
        const QList<DeletedObject> deletions = db->deletedObjects();
        delete object;
        db->setDeletedObjects(deletions);
    }
} // namespace

ImportMerger::ImportMerger(Database* source, Database* target, Method method)
    : m_source(source)
    , m_target(target)
    , m_method(method)
{
    Q_ASSERT(source && target);
}

void ImportMerger::merge()
{
    if (m_method == Method::CreateNewUuids) {
        createNewUuids(m_source->rootGroup());
    }

    mergeGroup(m_source->rootGroup());
    applyDeletions(m_target->rootGroup());
    mergeDatabaseProperties();
    mergeCustomIcons();
    m_target->markAsModified();
}

void ImportMerger::createNewUuids(Group* group)
{
    group->setUuid(QUuid::createUuid());
    for (auto* entry : group->entries()) {
        const QUuid uuid = QUuid::createUuid();
        entry->setUuid(uuid);
        for (auto* item : entry->historyItems()) {
            item->setUuid(uuid);
        }
    }
    for (auto* child : group->children()) {
        createNewUuids(child);
    }
}

Group* ImportMerger::targetContainer(const Group* sourceParent) const
{
    if (!sourceParent || sourceParent == m_source->rootGroup()) {
        return m_target->rootGroup();
    }
    auto* container = m_target->rootGroup()->findGroupByUuid(sourceParent->uuid());
    return container ? container : m_target->rootGroup();
}

// Pre-order: the group itself, its entries, then its child groups (KeePass: TraverseTree PreOrder)
void ImportMerger::mergeGroup(Group* sourceGroup)
{
    Group* targetGroup = m_target->rootGroup()->findGroupByUuid(sourceGroup->uuid());
    if (!targetGroup) {
        auto* container = targetContainer(sourceGroup->parentGroup());
        auto* newGroup = sourceGroup->clone(Entry::CloneNoFlags, Group::CloneNoFlags);
        const TimeInfo timeInfo = newGroup->timeInfo();
        const bool containerUpdate = container->canUpdateTimeinfo();
        container->setUpdateTimeinfo(false);
        newGroup->setUpdateTimeinfo(false);
        newGroup->setParent(container);
        newGroup->setTimeInfo(timeInfo);
        newGroup->setUpdateTimeinfo(true);
        container->setUpdateTimeinfo(containerUpdate);
    } else if (m_method == Method::OverwriteExisting) {
        assignGroup(targetGroup, sourceGroup, false);
    } else if (m_method == Method::OverwriteIfNewer) {
        assignGroup(targetGroup, sourceGroup, true);
    }

    for (auto* entry : sourceGroup->entries()) {
        mergeEntry(entry);
    }
    for (auto* child : sourceGroup->children()) {
        mergeGroup(child);
    }
}

void ImportMerger::mergeEntry(Entry* sourceEntry)
{
    Entry* targetEntry = m_target->rootGroup()->findEntryByUuid(sourceEntry->uuid());
    if (!targetEntry) {
        auto* container = targetContainer(sourceEntry->group());
        auto* newEntry = sourceEntry->clone(Entry::CloneIncludeHistory);
        const bool containerUpdate = container->canUpdateTimeinfo();
        container->setUpdateTimeinfo(false);
        newEntry->setUpdateTimeinfo(false);
        newEntry->setGroup(container);
        newEntry->setUpdateTimeinfo(true);
        container->setUpdateTimeinfo(containerUpdate);
        return;
    }

    // KeePass: back up the data that is replaced, and the source data that is older than the target
    const bool equal = targetEntry->equals(sourceEntry, SameDataOptions);
    const int sourceVsTarget =
        compareTimes(sourceEntry->timeInfo().lastModificationTime(), targetEntry->timeInfo().lastModificationTime());

    bool targetBackup = !equal;
    if (m_method != Method::OverwriteExisting) {
        targetBackup = targetBackup && sourceVsTarget > 0;
    }
    targetBackup = targetBackup && !hasBackupOfData(sourceEntry, targetEntry);
    if (targetBackup) {
        createBackup(targetEntry);
    }

    bool sourceBackup = !equal && m_method != Method::OverwriteExisting;
    sourceBackup = sourceBackup && sourceVsTarget < 0;
    sourceBackup = sourceBackup && !hasBackupOfData(targetEntry, sourceEntry);
    if (sourceBackup) {
        createBackup(sourceEntry);
    }

    if (m_method == Method::OverwriteExisting) {
        assignEntry(targetEntry, sourceEntry, false);
    } else if (m_method == Method::OverwriteIfNewer) {
        assignEntry(targetEntry, sourceEntry, true);
    }

    mergeEntryHistory(targetEntry, sourceEntry);
    targetEntry->truncateHistory();
}

// KeePass: PwDatabase.MergeEntryHistory. History items are merged by their modification time.
void ImportMerger::mergeEntryHistory(Entry* targetEntry, const Entry* sourceEntry)
{
    const auto& targetItems = targetEntry->historyItems();
    const auto& sourceItems = sourceEntry->historyItems();
    if (targetItems.size() == sourceItems.size()) {
        bool same = true;
        for (int i = 0; i < targetItems.size(); ++i) {
            if (targetItems.at(i)->timeInfo().lastModificationTime()
                != sourceItems.at(i)->timeInfo().lastModificationTime()) {
                same = false;
                break;
            }
        }
        if (same) {
            return;
        }
    }

    std::map<QDateTime, Entry*> items;
    for (const auto* item : targetItems) {
        auto& slot = items[item->timeInfo().lastModificationTime()];
        delete slot; // A later item with the same time replaces an earlier one
        slot = item->clone(Entry::CloneNoFlags);
    }
    for (const auto* item : sourceItems) {
        const QDateTime time = item->timeInfo().lastModificationTime();
        auto it = items.find(time);
        if (it == items.end()) {
            items[time] = item->clone(Entry::CloneNoFlags);
        } else if (m_method == Method::OverwriteExisting) {
            delete it->second;
            it->second = item->clone(Entry::CloneNoFlags);
        }
    }

    const QList<Entry*> oldItems = targetEntry->historyItems();
    targetEntry->removeHistoryItems(oldItems);
    for (auto& pair : items) {
        pair.second->setUuid(targetEntry->uuid());
        targetEntry->addHistoryItem(pair.second);
    }
}

// KeePass: PwDatabase.ApplyDeletions with the deletion records of the target only.
// Post-order: the child groups first. A group is deleted only when it is empty.
void ImportMerger::applyDeletions(Group* group)
{
    for (auto* child : group->children()) {
        applyDeletions(child);
    }

    QHash<QUuid, QDateTime> records;
    for (const auto& record : m_target->deletedObjects()) {
        records.insert(record.uuid, record.deletionTime);
    }
    if (records.isEmpty()) {
        return;
    }

    auto keepObject = [this](const QUuid& uuid) {
        // Prevent later deletion attempts of an object that stays (as KeePass)
        auto deletions = m_target->deletedObjects();
        deletions.erase(std::remove_if(deletions.begin(),
                                       deletions.end(),
                                       [&uuid](const DeletedObject& record) { return record.uuid == uuid; }),
                        deletions.end());
        m_target->setDeletedObjects(deletions);
    };

    const auto children = group->children();
    for (auto* child : children) {
        if (!records.contains(child->uuid())) {
            continue;
        }
        const bool remove = compareTimes(child->timeInfo().lastModificationTime(), records.value(child->uuid())) < 0
                            && child->children().isEmpty() && child->entries().isEmpty();
        if (remove) {
            eraseKeepingRecords(m_target, child);
        } else {
            keepObject(child->uuid());
        }
    }

    const auto entries = group->entries();
    for (auto* entry : entries) {
        if (!records.contains(entry->uuid())) {
            continue;
        }
        if (compareTimes(entry->timeInfo().lastModificationTime(), records.value(entry->uuid())) < 0) {
            eraseKeepingRecords(m_target, entry);
        } else {
            keepObject(entry->uuid());
        }
    }
}

// KeePass: PwDatabase.MergeInDbProperties. "Keep existing" changes nothing.
void ImportMerger::mergeDatabaseProperties()
{
    if (m_method == Method::KeepExisting) {
        return;
    }
    const bool force = (m_method == Method::OverwriteExisting);
    const auto* source = m_source->metadata();
    auto* target = m_target->metadata();

    if (force || source->settingsChanged() > target->settingsChanged()) {
        target->setColor(source->color());
    }
    if (force || source->nameChanged() > target->nameChanged()) {
        target->setName(source->name());
        target->setNameChanged(source->nameChanged());
    }
    if (force || source->descriptionChanged() > target->descriptionChanged()) {
        target->setDescription(source->description());
        target->setDescriptionChanged(source->descriptionChanged());
    }
    if (force || source->defaultUserNameChanged() > target->defaultUserNameChanged()) {
        target->setDefaultUserName(source->defaultUserName());
        target->setDefaultUserNameChanged(source->defaultUserNameChanged());
    }

    // The recycle bin: the preferred one, else the other one, when it exists in the target
    QUuid preferred = target->recycleBin() ? target->recycleBin()->uuid() : QUuid();
    QUuid alternative = source->recycleBin() ? source->recycleBin()->uuid() : QUuid();
    if (force || source->recycleBinChanged() > target->recycleBinChanged()) {
        std::swap(preferred, alternative);
        target->setRecycleBinEnabled(source->recycleBinEnabled());
        target->setRecycleBinChanged(source->recycleBinChanged());
    }
    Group* bin = m_target->rootGroup()->findGroupByUuid(preferred);
    if (!bin) {
        bin = m_target->rootGroup()->findGroupByUuid(alternative);
    }
    target->setRecycleBin(bin);
}

// KeePass: PwDatabase.MergeInCustomIcons. A missing icon is added; a newer icon replaces the target icon.
void ImportMerger::mergeCustomIcons()
{
    const auto* source = m_source->metadata();
    auto* target = m_target->metadata();
    for (const auto& uuid : source->customIconsOrder()) {
        const auto& icon = source->customIcon(uuid);
        if (!target->hasCustomIcon(uuid)) {
            target->addCustomIcon(uuid, icon);
            continue;
        }
        const auto& existing = target->customIcon(uuid);
        bool replace = false;
        if (existing.lastModified.isValid() && icon.lastModified.isValid()) {
            replace = existing.lastModified < icon.lastModified;
        } else if (!existing.lastModified.isValid() && icon.lastModified.isValid()) {
            replace = true;
        }
        if (replace) {
            target->removeCustomIcon(uuid);
            target->addCustomIcon(uuid, icon);
        }
    }
}
