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

#include "DatabaseSync.h"

#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QTemporaryFile>

namespace DatabaseSync
{
    MergeStatus mergeFile(Database* target, const QString& filePath, QString* error, Merger::ChangeList* changes)
    {
        Q_ASSERT(target);

        QFileInfo info(filePath);
        if (!info.exists() || !info.isFile()) {
            if (error) {
                *error = QCoreApplication::translate("DatabaseSync", "File %1 does not exist.").arg(filePath);
            }
            return MergeStatus::FileError;
        }
        if (!info.isReadable()) {
            if (error) {
                *error = QCoreApplication::translate("DatabaseSync", "Unable to open file %1.").arg(filePath);
            }
            return MergeStatus::FileError;
        }

        auto otherDb = QSharedPointer<Database>::create();
        QString openError;
        if (!otherDb->open(filePath, target->key(), &openError)) {
            if (error) {
                *error = openError;
            }
            return MergeStatus::OpenError;
        }

        Merger merger(otherDb.data(), target);
        merger.setForcedMergeMode(Group::Synchronize);
        merger.setKeePassRules(true);
        auto changeList = merger.merge();
        if (changes) {
            *changes = changeList;
        }
        return MergeStatus::Merged;
    }

    bool copyFile(const QString& sourcePath, const QString& targetPath, Database::SaveAction action, QString* error)
    {
        QFile source(sourcePath);
        if (!source.open(QIODevice::ReadOnly)) {
            if (error) {
                *error = source.errorString();
            }
            return false;
        }
        const QByteArray data = source.readAll();
        source.close();

        QFileInfo targetInfo(targetPath);
        const QString realTargetPath =
            targetInfo.exists() ? targetInfo.canonicalFilePath() : targetInfo.absoluteFilePath();
        const auto createTime = targetInfo.exists() ? targetInfo.birthTime() : QDateTime::currentDateTime();

        switch (action) {
        case Database::Atomic: {
            QSaveFile saveFile(realTargetPath);
            if (saveFile.open(QIODevice::WriteOnly) && saveFile.write(data) == data.size()) {
                saveFile.setFileTime(createTime, QFile::FileBirthTime);
                if (saveFile.commit()) {
                    return true;
                }
            }
            if (error) {
                *error = saveFile.errorString();
            }
            return false;
        }
        case Database::TempFile: {
            QTemporaryFile tempFile;
            if (tempFile.open() && tempFile.write(data) == data.size()) {
                tempFile.close();
                const auto permissions = QFile::permissions(realTargetPath);
                QFile::remove(realTargetPath);
                // Use the QFile rename, as Database::performSave does, so that a move across file systems works
                if (tempFile.QFile::rename(realTargetPath)) {
                    tempFile.setAutoRemove(false);
                    QFile::setPermissions(realTargetPath, permissions);
                    tempFile.setFileTime(createTime, QFile::FileBirthTime);
                    return true;
                }
                // The original file is gone. Keep the temporary file, so that no data is lost.
                tempFile.setAutoRemove(false);
                if (error) {
                    *error = QCoreApplication::translate("DatabaseSync", "%1\nThe synchronized data is in %2")
                                 .arg(tempFile.errorString(), tempFile.fileName());
                }
                return false;
            }
            if (error) {
                *error = tempFile.errorString();
            }
            return false;
        }
        case Database::DirectWrite: {
            QFile targetFile(realTargetPath);
            if (targetFile.open(QIODevice::WriteOnly | QIODevice::Truncate) && targetFile.write(data) == data.size()) {
                targetFile.close();
                return true;
            }
            if (error) {
                *error = targetFile.errorString();
            }
            return false;
        }
        }

        return false;
    }

    bool isSameFile(const QString& first, const QString& second)
    {
        const QFileInfo firstInfo(first);
        const QFileInfo secondInfo(second);
        const QString firstPath = firstInfo.exists() ? firstInfo.canonicalFilePath() : firstInfo.absoluteFilePath();
        const QString secondPath = secondInfo.exists() ? secondInfo.canonicalFilePath() : secondInfo.absoluteFilePath();
#if defined(Q_OS_WIN) || defined(Q_OS_MACOS)
        return firstPath.compare(secondPath, Qt::CaseInsensitive) == 0;
#else
        return firstPath == secondPath;
#endif
    }
} // namespace DatabaseSync
