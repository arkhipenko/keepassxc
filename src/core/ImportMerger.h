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

#ifndef KEEPASSXC_IMPORTMERGER_H
#define KEEPASSXC_IMPORTMERGER_H

class Database;
class Entry;
class Group;

/**
 * The import merge methods of KeePass 2.x (KeePassLib/PwDatabase.cs, MergeIn), other than
 * "Synchronize". The synchronization merge is done by Merger with the KeePass rules.
 *
 * - Create new IDs: every group and entry of the source receives a new UUID, so everything is added.
 * - Keep existing: objects that exist in the target are not changed.
 * - Overwrite existing: objects that exist in the target receive the data of the source.
 * - Overwrite if newer: objects that exist in the target receive the data of the source when the
 *   source is not older. This is the synchronization merge without moves, reordering and the
 *   deletion records of the source.
 *
 * In all methods a new object is added to the group of the target with the UUID of its source group,
 * or to the root group. As in KeePass, the root group of the source is added as a group of the target
 * root group when the two root groups have different UUIDs, while the content of the source root group
 * goes to the target root group. The deletion records of the target are applied afterwards, so an
 * object that was deleted in the target and not changed since then is removed again.
 *
 * Difference from KeePass: a new object is added at the end of its group. KeePass places it next to
 * its neighbours of the source.
 *
 * The source database is changed: it receives new UUIDs (Create new IDs) and history items.
 */
class ImportMerger
{
public:
    enum class Method
    {
        CreateNewUuids,
        KeepExisting,
        OverwriteExisting,
        OverwriteIfNewer
    };

    ImportMerger(Database* source, Database* target, Method method);

    void merge();

private:
    void createNewUuids(Group* group);
    void mergeGroup(Group* sourceGroup);
    void mergeEntry(Entry* sourceEntry);
    void mergeEntryHistory(Entry* targetEntry, const Entry* sourceEntry);
    void applyDeletions(Group* group);
    void mergeDatabaseProperties();
    void mergeCustomIcons();
    Group* targetContainer(const Group* sourceParent) const;

    Database* m_source;
    Database* m_target;
    Method m_method;
};

#endif // KEEPASSXC_IMPORTMERGER_H
