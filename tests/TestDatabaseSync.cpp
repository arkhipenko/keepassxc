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

#include "TestDatabaseSync.h"

#include <QFile>
#include <QTest>

#include "config-keepassx-tests.h"
#include "core/Clock.h"
#include "core/DatabaseSync.h"
#include "core/Group.h"
#include "crypto/Crypto.h"
#include "keys/PasswordKey.h"

QTEST_GUILESS_MAIN(TestDatabaseSync)

namespace
{
    const QString BaseDatabase = QStringLiteral(KEEPASSX_TEST_DATA_DIR).append("/NewDatabase.kdbx");

    QSharedPointer<CompositeKey> passwordKey(const QString& password)
    {
        auto key = QSharedPointer<CompositeKey>::create();
        key->addKey(QSharedPointer<PasswordKey>::create(password));
        return key;
    }

    QSharedPointer<Database> openDatabase(const QString& filePath, const QString& password = "a")
    {
        auto db = QSharedPointer<Database>::create();
        if (!db->open(filePath, passwordKey(password))) {
            return {};
        }
        return db;
    }

    Entry* addEntry(Database* db, const QString& title)
    {
        auto* entry = new Entry();
        entry->setUuid(QUuid::createUuid());
        entry->setTitle(title);
        entry->setGroup(db->rootGroup());
        // A deletion applies only to an object modified before the deletion time (KeePass rule),
        // so the entries get a modification time in the past
        entry->setUpdateTimeinfo(false);
        TimeInfo timeInfo = entry->timeInfo();
        timeInfo.setLastModificationTime(Clock::datetimeUtc(2020, 1, 1, 0, 0, 0));
        entry->setTimeInfo(timeInfo);
        entry->setUpdateTimeinfo(true);
        return entry;
    }

    QByteArray fileData(const QString& filePath)
    {
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly)) {
            return {};
        }
        return file.readAll();
    }
} // namespace

void TestDatabaseSync::initTestCase()
{
    QVERIFY(Crypto::init());
    QLocale::setDefault(QLocale::c());
}

void TestDatabaseSync::init()
{
    // Two files that come from the same database, so they share the object UUIDs
    m_dir.reset(new QTemporaryDir());
    QVERIFY(m_dir->isValid());
    m_fileA = m_dir->filePath("a.kdbx");
    m_fileB = m_dir->filePath("b.kdbx");

    auto db = openDatabase(BaseDatabase);
    QVERIFY(db);
    addEntry(db.data(), "shared");
    addEntry(db.data(), "to be deleted");
    QString error;
    QVERIFY2(db->saveAs(m_fileA, Database::Atomic, {}, &error), qPrintable(error));
    QVERIFY(QFile::copy(m_fileA, m_fileB));
}

/**
 * A file with the same key merges into the open database in Synchronize mode: entries added in the
 * file arrive, and an entry deleted in the file is deleted in the open database.
 */
void TestDatabaseSync::testMergeFileSameKey()
{
    auto other = openDatabase(m_fileB);
    QVERIFY(other);
    addEntry(other.data(), "added in other");
    delete other->rootGroup()->findEntryByPath("to be deleted");
    QVERIFY(other->save());

    auto target = openDatabase(m_fileA);
    QVERIFY(target);
    addEntry(target.data(), "added in target");

    QString error;
    Merger::ChangeList changes;
    const auto status = DatabaseSync::mergeFile(target.data(), m_fileB, &error, &changes);
    QCOMPARE(status, DatabaseSync::MergeStatus::Merged);
    QVERIFY(!changes.isEmpty());

    QVERIFY(target->rootGroup()->findEntryByPath("shared"));
    QVERIFY(target->rootGroup()->findEntryByPath("added in other"));
    QVERIFY(target->rootGroup()->findEntryByPath("added in target"));
    QVERIFY(!target->rootGroup()->findEntryByPath("to be deleted"));
}

/**
 * A file that does not open with the key of the open database is refused, and the open database
 * does not change.
 */
void TestDatabaseSync::testMergeFileDifferentKey()
{
    auto other = openDatabase(m_fileB);
    QVERIFY(other);
    other->setKey(passwordKey("different"));
    addEntry(other.data(), "added in other");
    QVERIFY(other->save());

    auto target = openDatabase(m_fileA);
    QVERIFY(target);
    const int entriesBefore = target->rootGroup()->entriesRecursive().size();

    QString error;
    const auto status = DatabaseSync::mergeFile(target.data(), m_fileB, &error);
    QCOMPARE(status, DatabaseSync::MergeStatus::OpenError);
    QVERIFY(!error.isEmpty());
    QCOMPARE(target->rootGroup()->entriesRecursive().size(), entriesBefore);
    QVERIFY(!target->rootGroup()->findEntryByPath("added in other"));
}

void TestDatabaseSync::testMergeFileMissing()
{
    auto target = openDatabase(m_fileA);
    QVERIFY(target);

    QString error;
    const auto status = DatabaseSync::mergeFile(target.data(), m_dir->filePath("missing.kdbx"), &error);
    QCOMPARE(status, DatabaseSync::MergeStatus::FileError);
    QVERIFY(!error.isEmpty());
}

void TestDatabaseSync::testCopyFile_data()
{
    QTest::addColumn<int>("action");
    QTest::newRow("Atomic") << static_cast<int>(Database::Atomic);
    QTest::newRow("TempFile") << static_cast<int>(Database::TempFile);
    QTest::newRow("DirectWrite") << static_cast<int>(Database::DirectWrite);
}

/**
 * The copy makes the other file byte-identical to the saved file, with each save mode.
 */
void TestDatabaseSync::testCopyFile()
{
    QFETCH(int, action);

    auto db = openDatabase(m_fileA);
    QVERIFY(db);
    addEntry(db.data(), "only in a");
    QVERIFY(db->save());
    QVERIFY(fileData(m_fileA) != fileData(m_fileB));

    QString error;
    QVERIFY2(DatabaseSync::copyFile(m_fileA, m_fileB, static_cast<Database::SaveAction>(action), &error),
             qPrintable(error));
    QCOMPARE(fileData(m_fileB), fileData(m_fileA));

    // The copy opens with the same key and holds the same data
    auto copy = openDatabase(m_fileB);
    QVERIFY(copy);
    QVERIFY(copy->rootGroup()->findEntryByPath("only in a"));
}

void TestDatabaseSync::testIsSameFile()
{
    QVERIFY(DatabaseSync::isSameFile(m_fileA, m_fileA));
    QVERIFY(DatabaseSync::isSameFile(m_fileA, m_dir->path() + "/./a.kdbx"));
    QVERIFY(!DatabaseSync::isSameFile(m_fileA, m_fileB));
}
