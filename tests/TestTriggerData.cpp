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

#include "core/Database.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "core/ImportMerger.h"
#include "core/Metadata.h"
#include "crypto/Crypto.h"
#include "format/KeePass1CsvExporter.h"
#include "gui/triggers/TriggerDataExchange.h"
#include "keys/FileKey.h"
#include "keys/PasswordKey.h"
#include "mock/MockClock.h"

#include <QTemporaryDir>
#include <QTest>

class TestTriggerData : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void init();
    void cleanup();

    void testCreateNewUuids();
    void testKeepExisting();
    void testOverwriteExisting();
    void testOverwriteIfNewer();
    void testTargetDeletionsApply();
    void testSameRootUuid();
    void testKeePass1Csv();
    void testFilteredDatabase();
    void testMatchesMasterKey();

private:
    MockClock* m_clock = nullptr;
};

QTEST_GUILESS_MAIN(TestTriggerData)

namespace
{
    QSharedPointer<Database> newDatabase(const QString& rootName = "Root")
    {
        auto db = QSharedPointer<Database>::create();
        auto key = QSharedPointer<CompositeKey>::create();
        key->addKey(QSharedPointer<PasswordKey>::create("a"));
        db->setKey(key);
        db->rootGroup()->setName(rootName);
        return db;
    }

    Group* addGroup(Group* parent, const QString& name, const QUuid& uuid = QUuid::createUuid())
    {
        auto* group = new Group();
        group->setUuid(uuid);
        group->setName(name);
        group->setParent(parent);
        return group;
    }

    Entry*
    addEntry(Group* group, const QString& title, const QString& password, const QUuid& uuid = QUuid::createUuid())
    {
        auto* entry = new Entry();
        entry->setUuid(uuid);
        entry->setTitle(title);
        entry->setPassword(password);
        entry->setGroup(group);
        return entry;
    }

    // A copy of the entry in another database, with the same UUID
    Entry* copyEntry(const Entry* entry, Group* group)
    {
        auto* copy = entry->clone(Entry::CloneIncludeHistory);
        copy->setGroup(group);
        return copy;
    }

    void setPassword(Entry* entry, const QString& password)
    {
        entry->beginUpdate();
        entry->setPassword(password);
        entry->endUpdate();
    }
} // namespace

void TestTriggerData::initTestCase()
{
    QVERIFY(Crypto::init());
}

void TestTriggerData::init()
{
    m_clock = new MockClock(2026, 1, 1, 12, 0, 0);
    MockClock::setup(m_clock);
}

void TestTriggerData::cleanup()
{
    MockClock::teardown();
    m_clock = nullptr;
}

void TestTriggerData::testCreateNewUuids()
{
    auto target = newDatabase("Target");
    auto source = newDatabase("Source");
    auto* existing = addEntry(target->rootGroup(), "Same", "target");
    auto* group = addGroup(source->rootGroup(), "Internet");
    addEntry(group, "Mail", "pw");
    copyEntry(existing, source->rootGroup());

    ImportMerger(source.data(), target.data(), ImportMerger::Method::CreateNewUuids).merge();

    // Everything is added with new UUIDs: two entries "Same" now
    const auto entries = target->rootGroup()->entriesRecursive();
    QCOMPARE(entries.size(), 3);
    int same = 0;
    for (const auto* entry : entries) {
        if (entry->title() == "Same") {
            ++same;
        }
    }
    QCOMPARE(same, 2);
    QCOMPARE(existing->password(), QString("target"));
    // The child group goes to the target root group. The source root group is added as an empty group.
    QVERIFY(target->rootGroup()->findGroupByPath("Internet"));
    QVERIFY(target->rootGroup()->findGroupByPath("Source"));
    QVERIFY(target->rootGroup()->findGroupByPath("Source")->entries().isEmpty());
    QVERIFY(target->isModified());
}

void TestTriggerData::testKeepExisting()
{
    auto target = newDatabase();
    auto source = newDatabase();
    auto* entry = addEntry(target->rootGroup(), "Entry", "old");
    auto* copy = copyEntry(entry, source->rootGroup());
    m_clock->advanceMinute(1);
    setPassword(copy, "new");
    addEntry(source->rootGroup(), "Added", "x");

    ImportMerger(source.data(), target.data(), ImportMerger::Method::KeepExisting).merge();

    // The data of the target stays. As in KeePass, the current data of the target gets a backup in the
    // history (the source is newer), and the history of the source is merged in; the current data of the
    // source is not kept.
    QCOMPARE(entry->password(), QString("old"));
    QVERIFY(!entry->historyItems().isEmpty());
    for (const auto* item : entry->historyItems()) {
        QCOMPARE(item->password(), QString("old"));
    }
    QVERIFY(target->rootGroup()->findEntryByPath("Added"));
}

void TestTriggerData::testOverwriteExisting()
{
    auto target = newDatabase();
    auto source = newDatabase();
    auto* entry = addEntry(target->rootGroup(), "Entry", "target");
    auto* copy = copyEntry(entry, source->rootGroup());
    setPassword(copy, "source");
    m_clock->advanceMinute(1);
    // The target is newer, but overwrite does not check times
    setPassword(entry, "newer target");
    auto* sub = addGroup(target->rootGroup(), "Sub");
    auto* subCopy = addGroup(source->rootGroup(), "Renamed", sub->uuid());
    Q_UNUSED(subCopy);

    ImportMerger(source.data(), target.data(), ImportMerger::Method::OverwriteExisting).merge();

    QCOMPARE(entry->password(), QString("source"));
    QCOMPARE(sub->name(), QString("Renamed"));
    // The replaced data is kept in the history
    bool inHistory = false;
    for (const auto* item : entry->historyItems()) {
        inHistory |= (item->password() == "newer target");
    }
    QVERIFY(inHistory);
}

void TestTriggerData::testOverwriteIfNewer()
{
    auto target = newDatabase();
    auto source = newDatabase();
    auto* older = addEntry(target->rootGroup(), "Older in target", "target");
    auto* newer = addEntry(target->rootGroup(), "Newer in target", "target");
    auto* olderCopy = copyEntry(older, source->rootGroup());
    auto* newerCopy = copyEntry(newer, source->rootGroup());
    m_clock->advanceMinute(1);
    setPassword(olderCopy, "source");
    setPassword(newer, "target 2");
    m_clock->advanceMinute(1);
    Q_UNUSED(newerCopy);

    // A moved entry in the source is not moved in the target
    auto* folder = addGroup(source->rootGroup(), "Folder");
    olderCopy->setGroup(folder);

    ImportMerger(source.data(), target.data(), ImportMerger::Method::OverwriteIfNewer).merge();

    QCOMPARE(older->password(), QString("source"));
    QCOMPARE(newer->password(), QString("target 2"));
    QCOMPARE(older->group(), target->rootGroup());
    QVERIFY(target->rootGroup()->findGroupByPath("Folder"));
}

void TestTriggerData::testTargetDeletionsApply()
{
    auto target = newDatabase();
    auto source = newDatabase();
    auto* entry = addEntry(source->rootGroup(), "Deleted in target", "x");
    const QUuid uuid = entry->uuid();
    // The target deleted this entry after its last change, so the import removes it again
    m_clock->advanceMinute(1);
    target->addDeletedObject(uuid);
    m_clock->advanceMinute(1);

    ImportMerger(source.data(), target.data(), ImportMerger::Method::KeepExisting).merge();
    QVERIFY(!target->rootGroup()->findEntryByUuid(uuid));
    QVERIFY(target->containsDeletedObject(uuid));

    // The deletion records of the source are not applied
    auto target2 = newDatabase();
    auto source2 = newDatabase();
    auto* kept = addEntry(target2->rootGroup(), "Kept", "x");
    m_clock->advanceMinute(1);
    source2->addDeletedObject(kept->uuid());
    ImportMerger(source2.data(), target2.data(), ImportMerger::Method::OverwriteIfNewer).merge();
    QVERIFY(target2->rootGroup()->findEntryByUuid(kept->uuid()));
}

void TestTriggerData::testSameRootUuid()
{
    auto target = newDatabase("Target");
    auto source = newDatabase("Source");
    source->rootGroup()->setUuid(target->rootGroup()->uuid());
    m_clock->advanceMinute(1);
    source->rootGroup()->setNotes("Notes");

    ImportMerger(source.data(), target.data(), ImportMerger::Method::OverwriteIfNewer).merge();
    // With the same UUID, the root group is merged and no group is added
    QCOMPARE(target->rootGroup()->name(), QString("Source"));
    QVERIFY(target->rootGroup()->children().isEmpty());
}

void TestTriggerData::testKeePass1Csv()
{
    auto db = newDatabase();
    auto* first = addEntry(db->rootGroup(), "Title \"quoted\"", "pa\\ss");
    first->setUsername("user");
    first->setUrl("https://example.com");
    first->setNotes("Line 1\nLine 2");
    auto* group = addGroup(db->rootGroup(), "Sub");
    addEntry(group, "Second", "two");

    const QByteArray csv = KeePass1CsvExporter::exportGroup(db->rootGroup());
    const QByteArray expected =
        "\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\r\n"
        "\"Title \\\"quoted\\\"\",\"user\",\"pa\\\\ss\",\"https://example.com\",\"Line 1\nLine 2\"\r\n"
        "\"Second\",\"\",\"two\",\"\",\"\"\r\n";
    QCOMPARE(csv, expected);

    QTemporaryDir dir;
    QString error;
    QVERIFY(KeePass1CsvExporter::exportGroup(dir.filePath("out.csv"), db->rootGroup(), &error));
    QFile file(dir.filePath("out.csv"));
    QVERIFY(file.open(QIODevice::ReadOnly));
    QCOMPARE(file.readAll(), expected);
}

void TestTriggerData::testFilteredDatabase()
{
    auto db = newDatabase();
    auto* internet = addGroup(db->rootGroup(), "Internet");
    internet->setTags("web");
    auto* mail = addGroup(internet, "Mail");
    auto* tagged = addEntry(mail, "Tagged", "x");
    tagged->setTags("work");
    addEntry(mail, "Untagged", "y");
    addEntry(db->rootGroup(), "Root entry", "z");

    // Group filter: the first character separates the names
    auto filtered = TriggerDataExchange::filteredDatabase(db, "/Internet/Mail", {});
    QVERIFY(filtered);
    QCOMPARE(filtered->rootGroup()->name(), QString("Mail"));
    QCOMPARE(filtered->rootGroup()->entriesRecursive().size(), 2);
    QCOMPARE(filtered->rootGroup()->findEntryByPath("Tagged")->uuid(), tagged->uuid());

    // Tag filter, with the tags of the groups inherited
    filtered = TriggerDataExchange::filteredDatabase(db, "\\Internet", "work");
    QCOMPARE(filtered->rootGroup()->entriesRecursive().size(), 1);
    filtered = TriggerDataExchange::filteredDatabase(db, {}, "web");
    QCOMPARE(filtered->rootGroup()->entriesRecursive().size(), 2);

    // A group that is not found gives an empty export
    filtered = TriggerDataExchange::filteredDatabase(db, "/Nothing", {});
    QVERIFY(filtered->rootGroup()->entriesRecursive().isEmpty());

    // The source database is not changed
    QCOMPARE(db->rootGroup()->entriesRecursive().size(), 3);

    // The copy uses the key of the database
    QByteArray xml;
    QVERIFY(filtered->extract(xml));
    QVERIFY(filtered->key() == db->key());
}

void TestTriggerData::testMatchesMasterKey()
{
    auto db = newDatabase();
    QVERIFY(TriggerDataExchange::matchesMasterKey(db, "a", {}));
    QVERIFY(!TriggerDataExchange::matchesMasterKey(db, "b", {}));
    QVERIFY(!TriggerDataExchange::matchesMasterKey(db, "a", "/nonexistent/key"));

    // Password and key file
    QTemporaryDir dir;
    const QString keyPath = dir.filePath("key.keyx");
    QVERIFY(FileKey::create(keyPath));
    auto fileKey = QSharedPointer<FileKey>::create();
    QVERIFY(fileKey->load(keyPath));
    auto key = QSharedPointer<CompositeKey>::create();
    key->addKey(QSharedPointer<PasswordKey>::create("a"));
    key->addKey(fileKey);
    db->setKey(key);
    QVERIFY(TriggerDataExchange::matchesMasterKey(db, "a", keyPath));
    QVERIFY(!TriggerDataExchange::matchesMasterKey(db, "a", {}));
    QVERIFY(!TriggerDataExchange::matchesMasterKey(db, "", keyPath));
}

#include "TestTriggerData.moc"
