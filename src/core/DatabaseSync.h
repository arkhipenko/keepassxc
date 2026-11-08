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

#ifndef KEEPASSXC_DATABASESYNC_H
#define KEEPASSXC_DATABASESYNC_H

#include "core/Database.h"
#include "core/Merger.h"

/**
 * Building blocks of the database synchronization, as KeePass 2.x "File > Synchronize" does it:
 * 1. Open each other file with the key of the open database (a different key is refused).
 * 2. Merge it into the open database in Synchronize mode with the KeePass merge rules.
 * 3. Save the open database (done by the caller through its normal save path).
 * 4. Copy the saved file over each other file.
 */
namespace DatabaseSync
{
    enum class MergeStatus
    {
        Merged,
        // The file could not be read, or it is not a database file
        FileError,
        // The file was read, but it did not open with the key of the open database
        OpenError,
    };

    /**
     * Open the database file at filePath with the key of target and merge it into target.
     * The merge uses Synchronize mode (deletions are applied) and the KeePass merge rules.
     *
     * @param changes receives the merge change list, can be null
     */
    MergeStatus
    mergeFile(Database* target, const QString& filePath, QString* error, Merger::ChangeList* changes = nullptr);

    /**
     * Copy the file sourcePath over the file targetPath. The write uses the given save action,
     * as a normal database save does.
     */
    bool copyFile(const QString& sourcePath, const QString& targetPath, Database::SaveAction action, QString* error);

    /**
     * True when both paths name the same file. The comparison ignores case on Windows and macOS.
     */
    bool isSameFile(const QString& first, const QString& second);
} // namespace DatabaseSync

#endif // KEEPASSXC_DATABASESYNC_H
