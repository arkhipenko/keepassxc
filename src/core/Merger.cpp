/*
 *  Copyright (C) 2018 KeePassXC Team <team@keepassxc.org>
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

#include "Merger.h"

#include "core/Global.h"
#include "core/Metadata.h"
#include "core/Tools.h"

Merger::Change::Change(Type type, QString details)
    : m_type{type}
    , m_details{std::move(details)}
{
}

Merger::Change::Change(Type type, const Group& group, QString details)
    : m_type{type}
    , m_group{group.fullPath()}
    , m_uuid{group.uuid()}
    , m_details{std::move(details)}
{
}
Merger::Change::Change(Type type, const Entry& entry, QString details)
    : m_type{type}
    , m_title{entry.title()}
    , m_uuid{entry.uuid()}
    , m_details{std::move(details)}
{
    if (const auto* group = entry.group()) {
        m_group = group->fullPath();
    }
}
Merger::Change::Change(QString details)
    : m_details{std::move(details)}
{
}

bool Merger::Change::operator==(const Merger::Change& other) const
{
    return m_type == other.m_type && m_group == other.m_group && m_title == other.m_title && m_uuid == other.m_uuid
           && m_details == other.m_details;
}

bool Merger::Change::operator!=(const Merger::Change& other) const
{
    return !(*this == other);
}

Merger::Change::Type Merger::Change::type() const
{
    return m_type;
}
const QString& Merger::Change::title() const
{
    return m_title;
}
const QString& Merger::Change::group() const
{
    return m_group;
}
const QUuid& Merger::Change::uuid() const
{
    return m_uuid;
}
const QString& Merger::Change::details() const
{
    return m_details;
}

QString Merger::Change::typeString() const
{
    switch (m_type) {
    case Type::Added:
        return tr("Added");
    case Type::Modified:
        return tr("Modified");
    case Type::Moved:
        return tr("Moved");
    case Type::Deleted:
        return tr("Deleted");
    case Type::Metadata:
        return "Metadata";
    case Type::Unspecified:
        return "";
    default:
        return "?";
    }
}

QString Merger::Change::toString() const
{
    QString result;
    if (m_type != Type::Unspecified) {
        result += QString("%1: ").arg(typeString());
    }
    if (!m_group.isEmpty()) {
        result += QString("'%1'").arg(m_group);
    }
    if (!m_title.isEmpty()) {
        result += QString("/'%1'").arg(m_title);
    }
    if (!m_uuid.isNull()) {
        result += QString(" [%1]").arg(m_uuid.toString());
    }
    if (!m_details.isEmpty()) {
        result += QString(" (%1)").arg(m_details);
    }
    return result;
}

Merger::Merger(const Database* sourceDb, Database* targetDb)
    : m_mode(Group::Default)
{
    if (!sourceDb || !targetDb) {
        Q_ASSERT(sourceDb && targetDb);
        return;
    }

    m_context = MergeContext{
        sourceDb, targetDb, sourceDb->rootGroup(), targetDb->rootGroup(), sourceDb->rootGroup(), targetDb->rootGroup()};
}

Merger::Merger(const Group* sourceGroup, Group* targetGroup)
    : m_mode(Group::Default)
{
    if (!sourceGroup || !targetGroup) {
        Q_ASSERT(sourceGroup && targetGroup);
        return;
    }

    m_context = MergeContext{sourceGroup->database(),
                             targetGroup->database(),
                             sourceGroup->database()->rootGroup(),
                             targetGroup->database()->rootGroup(),
                             sourceGroup,
                             targetGroup};
}

void Merger::setForcedMergeMode(Group::MergeMode mode)
{
    m_mode = mode;
}

void Merger::resetForcedMergeMode()
{
    m_mode = Group::Default;
}

void Merger::setSkipDatabaseCustomData(bool state)
{
    m_skipCustomData = state;
}

void Merger::setKeePassRules(bool state)
{
    m_keepassRules = state;
}

Merger::ChangeList Merger::merge(bool dryRun)
{
    m_dryRun = dryRun;
    // Order of merge steps is important - it is possible that we
    // create some items before deleting them afterwards
    ChangeList changes;
    // KeePass also merges the properties of the root group when both root groups have the same UUID
    if (m_keepassRules && m_context.m_sourceGroup == m_context.m_sourceRootGroup
        && m_context.m_targetGroup == m_context.m_targetRootGroup
        && m_context.m_sourceRootGroup->uuid() == m_context.m_targetRootGroup->uuid()) {
        changes << resolveGroupConflict(m_context, m_context.m_sourceRootGroup, m_context.m_targetRootGroup);
    }
    changes << mergeGroup(m_context);
    changes << mergeDeletions(m_context);
    changes << mergeMetadata(m_context);

    // At this point we have a list of changes we may want to show the user
    if (!changes.isEmpty() && !dryRun) {
        m_context.m_targetDb->markAsModified();
    }
    m_dryRun = false;
    return changes;
}

Merger::ChangeList Merger::mergeGroup(const MergeContext& context)
{
    ChangeList changes;
    // merge entries
    const QList<Entry*> sourceEntries = context.m_sourceGroup->entries();
    for (Entry* sourceEntry : sourceEntries) {
        Entry* targetEntry = context.m_targetRootGroup->findEntryByUuid(sourceEntry->uuid());
        if (!targetEntry) {
            // This entry does not exist at all. Create it.
            changes << Change(Change::Type::Added, *sourceEntry);
            if (!m_dryRun) {
                targetEntry = sourceEntry->clone(Entry::CloneIncludeHistory);
                moveEntry(targetEntry, context.m_targetGroup);
            }
        } else {
            // Entry is already present in the database. Update it.
            const bool locationChanged =
                targetEntry->timeInfo().locationChanged() < sourceEntry->timeInfo().locationChanged();
            if (locationChanged && targetEntry->group() != context.m_targetGroup) {
                changes << Change(
                    Change::Type::Moved, *sourceEntry, tr("Previous location: %1").arg(targetEntry->group()->name()));
                if (!m_dryRun) {
                    moveEntry(targetEntry, context.m_targetGroup);
                }
            }
            changes << resolveEntryConflict(context, sourceEntry, targetEntry);
        }
    }

    // merge child groups recursively
    const QList<Group*> sourceChildGroups = context.m_sourceGroup->children();
    for (Group* sourceChildGroup : sourceChildGroups) {
        bool groupCreated = false;
        Group* targetChildGroup = context.m_targetRootGroup->findGroupByUuid(sourceChildGroup->uuid());
        if (!targetChildGroup) {
            changes << Change(
                Change::Type::Added,
                *sourceChildGroup,
                tr("Number of entries in group: %1").arg(QString::number(sourceChildGroup->entries().size())));
            // Create the target group, it will be cleaned up later if in dry run mode
            targetChildGroup = sourceChildGroup->clone(Entry::CloneNoFlags, Group::CloneNoFlags);
            groupCreated = true;
            if (!m_dryRun) {
                moveGroup(targetChildGroup, context.m_targetGroup);
                TimeInfo timeinfo = targetChildGroup->timeInfo();
                timeinfo.setLocationChanged(sourceChildGroup->timeInfo().locationChanged());
                targetChildGroup->setTimeInfo(timeinfo);
            }
        } else {
            bool locationChanged =
                targetChildGroup->timeInfo().locationChanged() < sourceChildGroup->timeInfo().locationChanged();
            if (locationChanged && targetChildGroup->parent() != context.m_targetGroup) {
                changes << Change(
                    Change::Type::Moved, *sourceChildGroup, tr("Previous location: %1").arg(targetChildGroup->name()));
                if (!m_dryRun) {
                    moveGroup(targetChildGroup, context.m_targetGroup);
                    TimeInfo timeinfo = targetChildGroup->timeInfo();
                    timeinfo.setLocationChanged(sourceChildGroup->timeInfo().locationChanged());
                    targetChildGroup->setTimeInfo(timeinfo);
                }
            }
            changes << resolveGroupConflict(context, sourceChildGroup, targetChildGroup);
        }
        MergeContext subcontext{context.m_sourceDb,
                                context.m_targetDb,
                                context.m_sourceRootGroup,
                                context.m_targetRootGroup,
                                sourceChildGroup,
                                targetChildGroup};
        changes << mergeGroup(subcontext);
        // Cleanup the temporary target group structure
        if (m_dryRun && groupCreated) {
            delete subcontext.m_targetGroup;
        }
    }
    return changes;
}

Merger::ChangeList
Merger::resolveGroupConflict(const MergeContext& context, const Group* sourceChildGroup, Group* targetChildGroup)
{
    if (m_keepassRules) {
        return resolveGroupConflictKeePass(context, sourceChildGroup, targetChildGroup);
    }

    ChangeList changes;

    const QDateTime timeExisting = targetChildGroup->timeInfo().lastModificationTime();
    const QDateTime timeOther = sourceChildGroup->timeInfo().lastModificationTime();

    // only if the other group is newer, update the existing one.
    if (timeExisting < timeOther) {
        QStringList modifications;
        auto updateIfNecessary = [&modifications, this](const auto& targetValue,
                                                        const auto& sourceValue,
                                                        auto&& updateFunction,
                                                        const QString& modification) {
            if (targetValue != sourceValue) {
                modifications << modification;
                if (!m_dryRun) {
                    updateFunction(sourceValue);
                }
                return true;
            }
            return false;
        };
        updateIfNecessary(
            targetChildGroup->name(),
            sourceChildGroup->name(),
            [&](auto&& newValue) { targetChildGroup->setName(newValue); },
            tr("Group name"));
        updateIfNecessary(
            targetChildGroup->notes(),
            sourceChildGroup->notes(),
            [&](auto&& newValue) { targetChildGroup->setNotes(newValue); },
            tr("Notes"));
        if (sourceChildGroup->iconNumber() == 0) {
            updateIfNecessary(
                targetChildGroup->iconUuid(),
                sourceChildGroup->iconUuid(),
                [&](auto&& newValue) { targetChildGroup->setIcon(newValue); },
                tr("Icon (UUID)"));
        } else {
            updateIfNecessary(
                targetChildGroup->iconNumber(),
                sourceChildGroup->iconNumber(),
                [&](auto&& newValue) { targetChildGroup->setIcon(newValue); },
                tr("Icon (Number)"));
        }
        updateIfNecessary(
            targetChildGroup->timeInfo().expiryTime(),
            sourceChildGroup->timeInfo().expiryTime(),
            [&](auto&& newValue) { targetChildGroup->setExpiryTime(newValue); },
            tr("Expiry time"));
        updateIfNecessary(
            timeExisting,
            timeOther,
            [&](auto&& newValue) {
                TimeInfo timeInfo = targetChildGroup->timeInfo();
                timeInfo.setLastModificationTime(newValue);
                targetChildGroup->setTimeInfo(timeInfo);
            },
            tr("Modification time"));
        changes << Change(Change::Type::Modified, *sourceChildGroup, modifications.join(", "));
    }
    return changes;
}

/**
 * KeePass rule (KeePassLib/PwGroup.cs, AssignProperties with bOnlyIfNewer): when the source group
 * is not older than the target group, all properties of the source group are copied. The location
 * (previous parent group and location changed time) is not copied.
 */
Merger::ChangeList
Merger::resolveGroupConflictKeePass(const MergeContext& context, const Group* sourceGroup, Group* targetGroup)
{
    ChangeList changes;
    const int comparison = compare(sourceGroup->timeInfo().lastModificationTime(),
                                   targetGroup->timeInfo().lastModificationTime(),
                                   CompareItemIgnoreMilliseconds);
    if (comparison < 0) {
        return changes;
    }

    TimeInfo newTimeInfo = sourceGroup->timeInfo();
    newTimeInfo.setLocationChanged(targetGroup->timeInfo().locationChanged());

    QStringList modifications;
    if (targetGroup->name() != sourceGroup->name()) {
        modifications << tr("Group name");
    }
    if (targetGroup->notes() != sourceGroup->notes()) {
        modifications << tr("Notes");
    }
    if (targetGroup->iconNumber() != sourceGroup->iconNumber() || targetGroup->iconUuid() != sourceGroup->iconUuid()) {
        modifications << tr("Icon");
    }
    if (targetGroup->tags() != sourceGroup->tags()) {
        modifications << tr("Tags");
    }
    if (targetGroup->defaultAutoTypeSequence() != sourceGroup->defaultAutoTypeSequence()
        || targetGroup->autoTypeEnabled() != sourceGroup->autoTypeEnabled()) {
        modifications << tr("Auto-Type");
    }
    if (targetGroup->searchingEnabled() != sourceGroup->searchingEnabled()) {
        modifications << tr("Searching");
    }
    if (*targetGroup->customData() != *sourceGroup->customData()) {
        modifications << tr("Custom data");
    }
    if (!targetGroup->timeInfo().equals(newTimeInfo, CompareItemIgnoreMilliseconds)) {
        modifications << tr("Times");
    }

    if (modifications.isEmpty()) {
        return changes;
    }

    changes << Change(Change::Type::Modified, *sourceGroup, modifications.join(", "));
    if (m_dryRun) {
        return changes;
    }

    const bool updateTimeInfo = targetGroup->canUpdateTimeinfo();
    targetGroup->setUpdateTimeinfo(false);
    targetGroup->setName(sourceGroup->name());
    targetGroup->setNotes(sourceGroup->notes());
    if (!sourceGroup->iconUuid().isNull()) {
        targetGroup->setIcon(sourceGroup->iconUuid());
    } else {
        targetGroup->setIcon(sourceGroup->iconNumber());
    }
    targetGroup->setTags(sourceGroup->tags());
    targetGroup->setDefaultAutoTypeSequence(sourceGroup->defaultAutoTypeSequence());
    targetGroup->setAutoTypeEnabled(sourceGroup->autoTypeEnabled());
    targetGroup->setSearchingEnabled(sourceGroup->searchingEnabled());
    targetGroup->customData()->copyDataFrom(sourceGroup->customData());
    if (const Entry* sourceTopEntry = sourceGroup->lastTopVisibleEntry()) {
        if (Entry* targetTopEntry = context.m_targetRootGroup->findEntryByUuid(sourceTopEntry->uuid())) {
            targetGroup->setLastTopVisibleEntry(targetTopEntry);
        }
    }
    targetGroup->setTimeInfo(newTimeInfo);
    targetGroup->setUpdateTimeinfo(updateTimeInfo);
    return changes;
}

void Merger::moveEntry(Entry* entry, Group* targetGroup)
{
    if (m_dryRun) {
        return;
    }

    Q_ASSERT(entry);
    Group* sourceGroup = entry->group();
    if (sourceGroup == targetGroup) {
        return;
    }
    const bool sourceGroupUpdateTimeInfo = sourceGroup ? sourceGroup->canUpdateTimeinfo() : false;
    if (sourceGroup) {
        sourceGroup->setUpdateTimeinfo(false);
    }
    const bool targetGroupUpdateTimeInfo = targetGroup ? targetGroup->canUpdateTimeinfo() : false;
    if (targetGroup) {
        targetGroup->setUpdateTimeinfo(false);
    }
    const bool entryUpdateTimeInfo = entry->canUpdateTimeinfo();
    entry->setUpdateTimeinfo(false);

    entry->setGroup(targetGroup);

    entry->setUpdateTimeinfo(entryUpdateTimeInfo);
    if (targetGroup) {
        targetGroup->setUpdateTimeinfo(targetGroupUpdateTimeInfo);
    }
    if (sourceGroup) {
        sourceGroup->setUpdateTimeinfo(sourceGroupUpdateTimeInfo);
    }
}

void Merger::moveGroup(Group* group, Group* targetGroup)
{
    if (m_dryRun) {
        return;
    }

    Q_ASSERT(group);
    Group* sourceGroup = group->parentGroup();
    if (sourceGroup == targetGroup) {
        return;
    }
    const bool sourceGroupUpdateTimeInfo = sourceGroup ? sourceGroup->canUpdateTimeinfo() : false;
    if (sourceGroup) {
        sourceGroup->setUpdateTimeinfo(false);
    }
    const bool targetGroupUpdateTimeInfo = targetGroup ? targetGroup->canUpdateTimeinfo() : false;
    if (targetGroup) {
        targetGroup->setUpdateTimeinfo(false);
    }
    const bool groupUpdateTimeInfo = group->canUpdateTimeinfo();
    group->setUpdateTimeinfo(false);

    group->setParent(targetGroup);

    group->setUpdateTimeinfo(groupUpdateTimeInfo);
    if (targetGroup) {
        targetGroup->setUpdateTimeinfo(targetGroupUpdateTimeInfo);
    }
    if (sourceGroup) {
        sourceGroup->setUpdateTimeinfo(sourceGroupUpdateTimeInfo);
    }
}

void Merger::eraseEntry(Entry* entry)
{
    if (m_dryRun) {
        return;
    }

    Database* database = entry->database();
    // most simple method to remove an item from DeletedObjects :(
    const QList<DeletedObject> deletions = database->deletedObjects();
    Group* parentGroup = entry->group();
    const bool groupUpdateTimeInfo = parentGroup ? parentGroup->canUpdateTimeinfo() : false;
    if (parentGroup) {
        parentGroup->setUpdateTimeinfo(false);
    }
    delete entry;
    if (parentGroup) {
        parentGroup->setUpdateTimeinfo(groupUpdateTimeInfo);
    }
    database->setDeletedObjects(deletions);
}

void Merger::eraseGroup(Group* group)
{
    if (m_dryRun) {
        return;
    }

    Database* database = group->database();
    // most simple method to remove an item from DeletedObjects :(
    const QList<DeletedObject> deletions = database->deletedObjects();
    Group* parentGroup = group->parentGroup();
    const bool groupUpdateTimeInfo = parentGroup ? parentGroup->canUpdateTimeinfo() : false;
    if (parentGroup) {
        parentGroup->setUpdateTimeinfo(false);
    }
    delete group;
    if (parentGroup) {
        parentGroup->setUpdateTimeinfo(groupUpdateTimeInfo);
    }
    database->setDeletedObjects(deletions);
}

Merger::ChangeList Merger::resolveEntryConflict_MergeHistories(const MergeContext& context,
                                                               const Entry* sourceEntry,
                                                               Entry* targetEntry,
                                                               Group::MergeMode mergeMethod)
{
    Q_UNUSED(context);

    ChangeList changes;
    const int comparison = compare(targetEntry->timeInfo().lastModificationTime(),
                                   sourceEntry->timeInfo().lastModificationTime(),
                                   CompareItemIgnoreMilliseconds);
    auto differences = targetEntry->calculateDifference(sourceEntry);
    differences += "History";
    const int maxItems = targetEntry->database()->metadata()->historyMaxItems();
    if (comparison < 0) {
        Group* currentGroup = targetEntry->group();
        Entry* clonedEntry = sourceEntry->clone(Entry::CloneIncludeHistory);
        qDebug("Merge %s/%s with alien on top under %s",
               qPrintable(targetEntry->title()),
               qPrintable(sourceEntry->title()),
               qPrintable(currentGroup->name()));
        changes << Change(Change::Type::Modified,
                          *targetEntry,
                          tr("%1 (Add local modifications to new entry)").arg(differences.join(", ")));
        mergeHistory(targetEntry, clonedEntry, mergeMethod, maxItems);
        eraseEntry(targetEntry);
        moveEntry(clonedEntry, currentGroup);
    } else {
        qDebug("Merge %s/%s with local on top/under %s",
               qPrintable(targetEntry->title()),
               qPrintable(sourceEntry->title()),
               qPrintable(targetEntry->group()->name()));
        const bool changed = mergeHistory(sourceEntry, targetEntry, mergeMethod, maxItems);
        if (changed) {
            changes << Change(Change::Type::Modified,
                              *targetEntry,
                              tr("%1 (Add new modifications to existing entry)").arg(differences.join(", ")));
        }
    }
    return changes;
}

Merger::ChangeList
Merger::resolveEntryConflict(const MergeContext& context, const Entry* sourceEntry, Entry* targetEntry)
{
    // We need to cut off the milliseconds since the persistent format only supports times down to seconds
    // so when we import data from a remote source, it may represent the (or even some msec newer) data
    // which may be discarded due to higher runtime precision
    Group::MergeMode mergeMode = m_mode;
    if (mergeMode == Group::Default && context.m_targetGroup) {
        mergeMode = context.m_targetGroup->mergeMode();
    }
    return resolveEntryConflict_MergeHistories(context, sourceEntry, targetEntry, mergeMode);
}

bool Merger::mergeHistory(const Entry* sourceEntry,
                          Entry* targetEntry,
                          Group::MergeMode mergeMethod,
                          const int maxItems)
{
    Q_UNUSED(mergeMethod);
    const auto targetHistoryItems = targetEntry->historyItems();
    const auto sourceHistoryItems = sourceEntry->historyItems();
    const int comparison = compare(sourceEntry->timeInfo().lastModificationTime(),
                                   targetEntry->timeInfo().lastModificationTime(),
                                   CompareItemIgnoreMilliseconds);
    const bool preferLocal = comparison < 0;
    const bool preferRemote = comparison > 0;

    QMap<QDateTime, Entry*> merged;
    for (Entry* historyItem : targetHistoryItems) {
        const QDateTime modificationTime = Clock::serialized(historyItem->timeInfo().lastModificationTime());
        if (merged.contains(modificationTime)
            && !merged[modificationTime]->equals(historyItem, CompareItemIgnoreMilliseconds)) {
            qWarning("Inconsistent history entry of %s[%s] at %s contains conflicting changes - conflict resolution "
                     "may lose data!",
                     qPrintable(sourceEntry->title()),
                     qPrintable(sourceEntry->uuidToHex()),
                     qPrintable(modificationTime.toString("yyyy-MM-dd HH-mm-ss-zzz")));
        }
        merged[modificationTime] = historyItem->clone(Entry::CloneNoFlags);
    }
    for (Entry* historyItem : sourceHistoryItems) {
        // Items with same modification-time changes will be regarded as same (like KeePass2)
        const QDateTime modificationTime = Clock::serialized(historyItem->timeInfo().lastModificationTime());
        if (merged.contains(modificationTime)
            && !merged[modificationTime]->equals(historyItem, CompareItemIgnoreMilliseconds)) {
            qWarning("History entry of %s[%s] at %s contains conflicting changes - conflict resolution may lose data!",
                     qPrintable(sourceEntry->title()),
                     qPrintable(sourceEntry->uuidToHex()),
                     qPrintable(modificationTime.toString("yyyy-MM-dd HH-mm-ss-zzz")));
        }
        if (preferRemote && merged.contains(modificationTime)) {
            // forcefully apply the remote history item
            delete merged.take(modificationTime);
        }
        if (!merged.contains(modificationTime)) {
            merged[modificationTime] = historyItem->clone(Entry::CloneNoFlags);
        }
    }

    const QDateTime targetModificationTime = Clock::serialized(targetEntry->timeInfo().lastModificationTime());
    const QDateTime sourceModificationTime = Clock::serialized(sourceEntry->timeInfo().lastModificationTime());
    if (targetModificationTime == sourceModificationTime
        && !targetEntry->equals(sourceEntry,
                                CompareItemIgnoreMilliseconds | CompareItemIgnoreHistory | CompareItemIgnoreLocation)) {
        qWarning("Entry of %s[%s] contains conflicting changes - conflict resolution may lose data!",
                 qPrintable(sourceEntry->title()),
                 qPrintable(sourceEntry->uuidToHex()));
    }

    if (targetModificationTime < sourceModificationTime) {
        if (preferLocal && merged.contains(targetModificationTime)) {
            // forcefully apply the local history item
            delete merged.take(targetModificationTime);
        }
        if (!merged.contains(targetModificationTime)) {
            merged[targetModificationTime] = targetEntry->clone(Entry::CloneNoFlags);
        }
    } else if (targetModificationTime > sourceModificationTime) {
        if (preferRemote && !merged.contains(sourceModificationTime)) {
            // forcefully apply the remote history item
            delete merged.take(sourceModificationTime);
        }
        if (!merged.contains(sourceModificationTime)) {
            merged[sourceModificationTime] = sourceEntry->clone(Entry::CloneNoFlags);
        }
    }

    bool changed = false;
    const auto updatedHistoryItems = merged.values();
    for (int i = 0; i < maxItems; ++i) {
        const Entry* oldEntry = targetHistoryItems.value(targetHistoryItems.count() - i);
        const Entry* newEntry = updatedHistoryItems.value(updatedHistoryItems.count() - i);
        if (!oldEntry && !newEntry) {
            continue;
        }
        if (oldEntry && newEntry && oldEntry->equals(newEntry, CompareItemIgnoreMilliseconds)) {
            continue;
        }
        changed = true;
        break;
    }
    if (!changed) {
        qDeleteAll(updatedHistoryItems);
        return false;
    }
    if (!m_dryRun) {
        // We need to prevent any modification to the database since every change should be tracked either
        // in a clone history item or in the Entry itself
        const TimeInfo timeInfo = targetEntry->timeInfo();
        const bool blockedSignals = targetEntry->blockSignals(true);
        bool updateTimeInfo = targetEntry->canUpdateTimeinfo();
        targetEntry->setUpdateTimeinfo(false);
        targetEntry->removeHistoryItems(targetHistoryItems);
        for (Entry* historyItem : merged) {
            Q_ASSERT(!historyItem->parent());
            targetEntry->addHistoryItem(historyItem);
        }
        targetEntry->truncateHistory();
        targetEntry->blockSignals(blockedSignals);
        targetEntry->setUpdateTimeinfo(updateTimeInfo);
        Q_ASSERT(timeInfo == targetEntry->timeInfo());
        Q_UNUSED(timeInfo);
    }
    return true;
}

Merger::ChangeList Merger::mergeDeletions(const MergeContext& context)
{
    ChangeList changes;
    Group::MergeMode mergeMode = m_mode == Group::Default ? context.m_targetGroup->mergeMode() : m_mode;
    if (mergeMode != Group::Synchronize) {
        // no deletions are applied for any other strategy!
        return changes;
    }

    const auto targetDeletions = context.m_targetDb->deletedObjects();
    const auto sourceDeletions = context.m_sourceDb->deletedObjects();

    QList<DeletedObject> deletions;
    QMap<QUuid, DeletedObject> mergedDeletions;
    QList<Entry*> entries;
    QList<Group*> groups;
    // Deleted objects that are not entries or groups of the target (for example custom icons)
    QList<QUuid> otherObjects;

    for (const auto& object : (targetDeletions + sourceDeletions)) {
        if (!mergedDeletions.contains(object.uuid)) {
            mergedDeletions[object.uuid] = object;
            auto* entry = context.m_targetRootGroup->findEntryByUuid(object.uuid);
            if (entry) {
                entries << entry;
                continue;
            }
            auto* group = context.m_targetRootGroup->findGroupByUuid(object.uuid);
            if (group) {
                groups << group;
                continue;
            }
            if (m_keepassRules) {
                otherObjects << object.uuid;
            } else {
                deletions << object;
            }
            continue;
        }
        if (m_keepassRules) {
            // KeePass keeps the latest deletion time (KeePassLib/PwDatabase.cs, MergeInDeletionInfo)
            if (mergedDeletions[object.uuid].deletionTime < object.deletionTime) {
                mergedDeletions[object.uuid] = object;
            }
        } else if (mergedDeletions[object.uuid].deletionTime > object.deletionTime) {
            mergedDeletions[object.uuid] = object;
        }
    }
    for (const auto& uuid : otherObjects) {
        deletions << mergedDeletions[uuid];
    }

    while (!entries.isEmpty()) {
        auto* entry = entries.takeFirst();
        const auto& object = mergedDeletions[entry->uuid()];
        if (!canApplyDeletion(entry->timeInfo().lastModificationTime(), object.deletionTime)) {
            // keep deleted entry since it was changed after deletion date
            continue;
        }
        deletions << object;
        if (entry->group()) {
            changes << Change(Change::Type::Deleted, *entry, tr("Explicit deletion"));
        } else {
            changes << Change(Change::Type::Deleted, *entry, tr("Implicit deletion (e.g. removal of parent group)"));
        }
        if (!m_dryRun) {
            eraseEntry(entry);
        }
    }

    while (!groups.isEmpty()) {
        auto* group = groups.takeFirst();
        if (Tools::asSet(group->children()).intersects(Tools::asSet(groups))) {
            // we need to finish all children before we are able to determine if the group can be removed
            groups << group;
            continue;
        }
        const auto& object = mergedDeletions[group->uuid()];
        if (!canApplyDeletion(group->timeInfo().lastModificationTime(), object.deletionTime)) {
            // keep deleted group since it was changed after deletion date
            continue;
        }
        if (!group->entriesRecursive(false).isEmpty() || !group->groupsRecursive(false).isEmpty()) {
            // keep deleted group since it contains undeleted content
            continue;
        }
        deletions << object;
        if (group->parentGroup()) {
            changes << Change(Change::Type::Deleted, *group, tr("Explicit deletion"));
        } else {
            changes << Change(Change::Type::Deleted, *group, tr("Implicit deletion (e.g. removal of parent group)"));
        }
        if (!m_dryRun) {
            eraseGroup(group);
        }
    }
    // Put every deletion to the earliest date of deletion
    if (deletions != context.m_targetDb->deletedObjects()) {
        changes << Change(Change::Type::Metadata, tr("Changed deleted objects"));
        if (!m_dryRun) {
            context.m_targetDb->setDeletedObjects(deletions);
        }
    }

    return changes;
}

/**
 * An object is deleted only when it was not modified after its deletion time.
 * KeePass deletes an object only when its modification time is earlier than the deletion time
 * (KeePassLib/PwDatabase.cs, ApplyDeletions).
 */
bool Merger::canApplyDeletion(const QDateTime& lastModification, const QDateTime& deletionTime) const
{
    if (m_keepassRules) {
        return compare(lastModification, deletionTime, CompareItemIgnoreMilliseconds) < 0;
    }
    return lastModification <= deletionTime;
}

Merger::ChangeList Merger::mergeMetadata(const MergeContext& context)
{
    if (m_keepassRules) {
        return mergeMetadataKeePass(context);
    }

    // TODO HNH: missing handling of recycle bin, names, templates for groups and entries,
    //           public data (entries of newer dict override keys of older dict - ignoring
    //           their own age - it is enough if one entry of the whole dict is newer) => possible lost update
    ChangeList changes;
    auto* sourceMetadata = context.m_sourceDb->metadata();
    auto* targetMetadata = context.m_targetDb->metadata();

    for (const auto& iconUuid : sourceMetadata->customIconsOrder()) {
        if (!targetMetadata->hasCustomIcon(iconUuid)) {
            changes << Change(Change::Type::Metadata,
                              tr("Adding new icon %1").arg(QString::fromLatin1(iconUuid.toRfc4122().toHex())));
            if (!m_dryRun) {
                targetMetadata->addCustomIcon(iconUuid, sourceMetadata->customIcon(iconUuid));
            }
        }
    }

    // Some merges shouldn't modify the database custom data
    if (m_skipCustomData) {
        return changes;
    }

    // Merge Custom Data if source is newer
    const auto targetCustomDataModificationTime = targetMetadata->customData()->lastModified();
    const auto sourceCustomDataModificationTime = sourceMetadata->customData()->lastModified();
    if (!targetMetadata->customData()->contains(CustomData::LastModified)
        || (targetCustomDataModificationTime.isValid() && sourceCustomDataModificationTime.isValid()
            && targetCustomDataModificationTime < sourceCustomDataModificationTime)) {
        const auto sourceCustomDataKeys = sourceMetadata->customData()->keys();
        const auto targetCustomDataKeys = targetMetadata->customData()->keys();

        // Check missing keys from source. Remove those from target
        for (const auto& key : targetCustomDataKeys) {
            // Do not remove protected custom data
            if (!sourceMetadata->customData()->contains(key) && !sourceMetadata->customData()->isProtected(key)) {
                auto value = targetMetadata->customData()->value(key);
                changes << Change(Change::Type::Metadata, tr("Removed custom data %1 [%2]").arg(key, value));
                if (!m_dryRun) {
                    targetMetadata->customData()->remove(key);
                }
            }
        }

        // Transfer new/existing keys
        for (const auto& key : sourceCustomDataKeys) {
            // Don't merge auto-generated keys
            if (sourceMetadata->customData()->isAutoGenerated(key)) {
                continue;
            }

            auto sourceValue = sourceMetadata->customData()->value(key);
            auto targetValue = targetMetadata->customData()->value(key);
            // Merge only if the values are not the same.
            if (sourceValue != targetValue) {
                changes << Change(Change::Type::Metadata, tr("Adding custom data %1 [%2]").arg(key, sourceValue));
                if (!m_dryRun) {
                    targetMetadata->customData()->set(key, sourceValue);
                }
            }
        }
    }

    return changes;
}

/**
 * KeePass rules for database properties (KeePassLib/PwDatabase.cs, MergeInDbProperties and
 * MergeInCustomIcons). Each property is taken from the side that changed it last.
 */
Merger::ChangeList Merger::mergeMetadataKeePass(const MergeContext& context)
{
    ChangeList changes;
    auto* sourceMetadata = context.m_sourceDb->metadata();
    auto* targetMetadata = context.m_targetDb->metadata();

    // Change times are copied explicitly, so the setters must not set them to the current time
    targetMetadata->setUpdateDatetime(false);

    const bool sourceSettingsNewer = sourceMetadata->settingsChanged() > targetMetadata->settingsChanged();
    if (sourceSettingsNewer) {
        if (targetMetadata->color() != sourceMetadata->color()) {
            changes << Change(Change::Type::Metadata, tr("Database color"));
        }
        if (!m_dryRun) {
            targetMetadata->setColor(sourceMetadata->color());
            targetMetadata->setSettingsChanged(sourceMetadata->settingsChanged());
        }
    }

    if (sourceMetadata->nameChanged() > targetMetadata->nameChanged()) {
        if (targetMetadata->name() != sourceMetadata->name()) {
            changes << Change(Change::Type::Metadata, tr("Database name"));
        }
        if (!m_dryRun) {
            targetMetadata->setName(sourceMetadata->name());
            targetMetadata->setNameChanged(sourceMetadata->nameChanged());
        }
    }

    if (sourceMetadata->descriptionChanged() > targetMetadata->descriptionChanged()) {
        if (targetMetadata->description() != sourceMetadata->description()) {
            changes << Change(Change::Type::Metadata, tr("Database description"));
        }
        if (!m_dryRun) {
            targetMetadata->setDescription(sourceMetadata->description());
            targetMetadata->setDescriptionChanged(sourceMetadata->descriptionChanged());
        }
    }

    if (sourceMetadata->defaultUserNameChanged() > targetMetadata->defaultUserNameChanged()) {
        if (targetMetadata->defaultUserName() != sourceMetadata->defaultUserName()) {
            changes << Change(Change::Type::Metadata, tr("Default username"));
        }
        if (!m_dryRun) {
            targetMetadata->setDefaultUserName(sourceMetadata->defaultUserName());
            targetMetadata->setDefaultUserNameChanged(sourceMetadata->defaultUserNameChanged());
        }
    }

    // Recycle bin: prefer the group of the side that changed it last, if that group exists
    auto uuidOf = [](const Group* group) { return group ? group->uuid() : QUuid(); };
    QUuid preferredBin = uuidOf(targetMetadata->recycleBin());
    QUuid alternativeBin = uuidOf(sourceMetadata->recycleBin());
    bool recycleBinEnabled = targetMetadata->recycleBinEnabled();
    QDateTime recycleBinChanged = targetMetadata->recycleBinChanged();
    if (sourceMetadata->recycleBinChanged() > targetMetadata->recycleBinChanged()) {
        preferredBin = uuidOf(sourceMetadata->recycleBin());
        alternativeBin = uuidOf(targetMetadata->recycleBin());
        recycleBinEnabled = sourceMetadata->recycleBinEnabled();
        recycleBinChanged = sourceMetadata->recycleBinChanged();
    }
    Group* newBin = preferredBin.isNull() ? nullptr : context.m_targetRootGroup->findGroupByUuid(preferredBin);
    if (!newBin && !alternativeBin.isNull()) {
        newBin = context.m_targetRootGroup->findGroupByUuid(alternativeBin);
    }
    if (newBin != targetMetadata->recycleBin() || recycleBinEnabled != targetMetadata->recycleBinEnabled()) {
        changes << Change(Change::Type::Metadata, tr("Recycle bin"));
    }
    if (!m_dryRun) {
        targetMetadata->setRecycleBin(newBin);
        targetMetadata->setRecycleBinEnabled(recycleBinEnabled);
        if (recycleBinChanged != targetMetadata->recycleBinChanged()) {
            targetMetadata->setRecycleBinChanged(recycleBinChanged);
        }
    }

    // Entry templates group: same rule as the recycle bin
    QUuid preferredTemplates = uuidOf(targetMetadata->entryTemplatesGroup());
    QUuid alternativeTemplates = uuidOf(sourceMetadata->entryTemplatesGroup());
    QDateTime templatesChanged = targetMetadata->entryTemplatesGroupChanged();
    if (sourceMetadata->entryTemplatesGroupChanged() > targetMetadata->entryTemplatesGroupChanged()) {
        preferredTemplates = uuidOf(sourceMetadata->entryTemplatesGroup());
        alternativeTemplates = uuidOf(targetMetadata->entryTemplatesGroup());
        templatesChanged = sourceMetadata->entryTemplatesGroupChanged();
    }
    Group* newTemplates =
        preferredTemplates.isNull() ? nullptr : context.m_targetRootGroup->findGroupByUuid(preferredTemplates);
    if (!newTemplates && !alternativeTemplates.isNull()) {
        newTemplates = context.m_targetRootGroup->findGroupByUuid(alternativeTemplates);
    }
    if (newTemplates != targetMetadata->entryTemplatesGroup()) {
        changes << Change(Change::Type::Metadata, tr("Entry templates group"));
    }
    if (!m_dryRun) {
        targetMetadata->setEntryTemplatesGroup(newTemplates);
        if (templatesChanged != targetMetadata->entryTemplatesGroupChanged()) {
            targetMetadata->setEntryTemplatesGroupChanged(templatesChanged);
        }
    }

    targetMetadata->setUpdateDatetime(true);

    if (!m_skipCustomData) {
        changes << mergeCustomDataKeePass(context, sourceSettingsNewer);
    }
    changes << mergePublicCustomDataKeePass(context, sourceSettingsNewer);
    changes << mergeCustomIconsKeePass(context);
    return changes;
}

/**
 * KeePass rule for database custom data: each key is merged on its own, by its modification time.
 * Keys are never removed. KeePassXC bookkeeping keys (last modified, random slug) are not merged.
 */
Merger::ChangeList Merger::mergeCustomDataKeePass(const MergeContext& context, bool sourceSettingsNewer)
{
    ChangeList changes;
    const auto* sourceData = context.m_sourceDb->metadata()->customData();
    auto* targetData = context.m_targetDb->metadata()->customData();

    for (const auto& key : sourceData->keys()) {
        if (sourceData->isAutoGenerated(key)) {
            continue;
        }
        const auto& sourceItem = sourceData->item(key);
        const bool targetHasKey = targetData->contains(key);
        const QDateTime targetTime = targetHasKey ? targetData->lastModified(key) : QDateTime();
        const QDateTime sourceTime = sourceItem.lastModified;

        bool take = false;
        if (targetTime.isValid() && sourceTime.isValid()) {
            take = sourceTime > targetTime;
        } else if (targetTime.isValid()) {
            take = false; // Assume that the target is newer
        } else if (sourceTime.isValid()) {
            take = true;
        } else {
            take = sourceSettingsNewer || !targetHasKey;
        }

        if (!take || (targetHasKey && targetData->value(key) == sourceItem.value)) {
            continue;
        }
        changes << Change(Change::Type::Metadata, tr("Adding custom data %1 [%2]").arg(key, sourceItem.value));
        if (!m_dryRun) {
            targetData->set(key, sourceItem);
        }
    }
    return changes;
}

/**
 * KeePass rule for public custom data (KDBX 4 header): when the source settings are newer, the
 * source values replace the target values. Otherwise only keys that the target does not have are
 * added. The UUID that KeePassXC keeps there for quick unlock always stays the one of the target.
 */
Merger::ChangeList Merger::mergePublicCustomDataKeePass(const MergeContext& context, bool sourceSettingsNewer)
{
    static const QString publicUuidKey = QStringLiteral("KPXC_PUBLIC_UUID");

    ChangeList changes;
    const QVariantMap& sourceData = context.m_sourceDb->publicCustomData();
    const QVariantMap& targetData = context.m_targetDb->publicCustomData();

    QVariantMap merged = targetData;
    for (auto it = sourceData.constBegin(); it != sourceData.constEnd(); ++it) {
        if (it.key() == publicUuidKey) {
            continue;
        }
        if (sourceSettingsNewer || !merged.contains(it.key())) {
            merged.insert(it.key(), it.value());
        }
    }

    if (merged != targetData) {
        changes << Change(Change::Type::Metadata, tr("Public custom data"));
        if (!m_dryRun) {
            context.m_targetDb->setPublicCustomData(merged);
        }
    }
    return changes;
}

/**
 * KeePass rule for custom icons (KeePassLib/PwDatabase.cs, MergeInCustomIcons):
 * - a missing icon is added;
 * - an existing icon is replaced when the source icon was modified later;
 * - an icon with a deletion record is removed, unless it was modified after the deletion.
 *   References to a removed icon are cleared.
 */
Merger::ChangeList Merger::mergeCustomIconsKeePass(const MergeContext& context)
{
    ChangeList changes;
    const auto* sourceMetadata = context.m_sourceDb->metadata();
    auto* targetMetadata = context.m_targetDb->metadata();

    for (const auto& iconUuid : sourceMetadata->customIconsOrder()) {
        const auto& sourceIcon = sourceMetadata->customIcon(iconUuid);
        const QString iconId = QString::fromLatin1(iconUuid.toRfc4122().toHex());
        if (!targetMetadata->hasCustomIcon(iconUuid)) {
            changes << Change(Change::Type::Metadata, tr("Adding new icon %1").arg(iconId));
            if (!m_dryRun) {
                targetMetadata->addCustomIcon(iconUuid, sourceIcon);
            }
            continue;
        }

        const auto& targetIcon = targetMetadata->customIcon(iconUuid);
        const QDateTime targetTime = targetIcon.lastModified;
        const QDateTime sourceTime = sourceIcon.lastModified;
        bool take = false;
        if (targetTime.isValid() && sourceTime.isValid()) {
            take = targetTime < sourceTime;
        } else if (targetTime.isValid()) {
            take = false;
        } else {
            take = sourceTime.isValid();
        }
        if (!take) {
            continue;
        }
        changes << Change(Change::Type::Metadata, tr("Updating icon %1").arg(iconId));
        if (!m_dryRun) {
            targetMetadata->updateCustomIcon(iconUuid, sourceIcon);
        }
    }

    // Apply deletion records to custom icons
    QList<DeletedObject> deletions = context.m_targetDb->deletedObjects();
    QList<QUuid> removedIcons;
    for (int i = deletions.size() - 1; i >= 0; --i) {
        const auto& object = deletions.at(i);
        if (!targetMetadata->hasCustomIcon(object.uuid)) {
            continue;
        }
        const QDateTime iconTime = targetMetadata->customIcon(object.uuid).lastModified;
        if (iconTime.isValid() && iconTime > object.deletionTime) {
            // The icon was modified after its deletion: keep it and drop the deletion record
            changes << Change(Change::Type::Metadata, tr("Changed deleted objects"));
            deletions.removeAt(i);
        } else {
            changes << Change(Change::Type::Deleted,
                              tr("Removing icon %1").arg(QString::fromLatin1(object.uuid.toRfc4122().toHex())));
            removedIcons << object.uuid;
        }
    }

    if (m_dryRun || (removedIcons.isEmpty() && deletions == context.m_targetDb->deletedObjects())) {
        return changes;
    }

    for (const auto& iconUuid : removedIcons) {
        targetMetadata->removeCustomIcon(iconUuid);
    }

    // Clear references to removed icons without changing modification times, as KeePass does
    if (!removedIcons.isEmpty()) {
        const QSet<QUuid> removed = Tools::asSet(removedIcons);
        auto clearEntryIcon = [&removed](Entry* entry) {
            if (removed.contains(entry->iconUuid())) {
                const bool updateTimeInfo = entry->canUpdateTimeinfo();
                entry->setUpdateTimeinfo(false);
                entry->setIcon(entry->iconNumber());
                entry->setUpdateTimeinfo(updateTimeInfo);
            }
        };
        for (Group* group : context.m_targetRootGroup->groupsRecursive(true)) {
            if (removed.contains(group->iconUuid())) {
                const bool updateTimeInfo = group->canUpdateTimeinfo();
                group->setUpdateTimeinfo(false);
                group->setIcon(group->iconNumber());
                group->setUpdateTimeinfo(updateTimeInfo);
            }
            for (Entry* entry : group->entries()) {
                clearEntryIcon(entry);
                for (Entry* historyItem : entry->historyItems()) {
                    clearEntryIcon(historyItem);
                }
            }
        }
    }

    // removeCustomIcon adds new deletion records, so restore the merged list
    context.m_targetDb->setDeletedObjects(deletions);
    return changes;
}
