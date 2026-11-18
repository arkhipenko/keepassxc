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

#include "TestTriggers.h"

#include "config-keepassx-tests.h"
#include "core/CustomData.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "core/Merger.h"
#include "core/Metadata.h"
#include "core/triggers/TriggerPlaceholders.h"
#include "core/triggers/TriggerStore.h"
#include "core/triggers/TriggerSystem.h"
#include "core/triggers/TriggerTypes.h"
#include "core/triggers/TriggerUtil.h"
#include "core/triggers/TriggerXml.h"
#include "crypto/Crypto.h"
#include "keys/PasswordKey.h"
#include "mock/MockClock.h"

#include <QFile>
#include <QTemporaryDir>
#include <QTest>

QTEST_GUILESS_MAIN(TestTriggers)

namespace
{
    // Test host: records the actions it executes. An action with the first parameter
    // "abort" asks to abort, "fail" fails.
    class MockHost : public TriggerHost
    {
    public:
        QSharedPointer<Database> active;
        QStringList executed;
        QStringList errors;

        QString compilePlaceholders(const QString& text, bool forCommandLine) override
        {
            Q_UNUSED(forCommandLine);
            return text;
        }

        QSharedPointer<Database> activeDatabase() override
        {
            return active;
        }

        bool executeAction(const TriggerObject& action, TriggerContext& context, QString* error) override
        {
            const QString param = action.parameters.value(0);
            executed << context.trigger->name + ":" + param;
            if (param == "abort") {
                context.cancel = true;
            } else if (param == "fail") {
                *error = "failed";
                return false;
            }
            return true;
        }

        void showExecutionError(const QString& error) override
        {
            errors << error;
        }
    };

    MockHost* g_host = nullptr;

    TriggerObject object(const QUuid& type, const QStringList& parameters = {}, bool negate = false)
    {
        TriggerObject result;
        result.type = type;
        result.parameters = parameters;
        result.negate = negate;
        return result;
    }

    // An action that the mock host records
    TriggerObject hostAction(const QString& marker)
    {
        return object(TriggerIds::ShowMessageBox, {marker});
    }

    Trigger makeTrigger(const QString& name,
                        const QList<TriggerObject>& events,
                        const QList<TriggerObject>& conditions,
                        const QList<TriggerObject>& actions)
    {
        Trigger trigger;
        trigger.name = name;
        trigger.events = events;
        trigger.conditions = conditions;
        trigger.actions = actions;
        return trigger;
    }

    TriggerObject appStarted()
    {
        return object(TriggerIds::AppLoadPost);
    }

    TriggerObject stringCondition(const QString& value, quint32 compare, const QString& filter, bool negate = false)
    {
        return object(TriggerIds::String, {value, QString::number(compare), filter}, negate);
    }

    QSharedPointer<Database> newDatabase()
    {
        auto db = QSharedPointer<Database>::create();
        auto key = QSharedPointer<CompositeKey>::create();
        key->addKey(QSharedPointer<PasswordKey>::create("a"));
        db->setKey(key);
        return db;
    }
} // namespace

void TestTriggers::initTestCase()
{
    QVERIFY(Crypto::init());
    g_host = new MockHost();
    triggerSystem()->setHost(g_host);
}

void TestTriggers::cleanup()
{
    triggerSystem()->unload();
    g_host->executed.clear();
    g_host->errors.clear();
    g_host->active.reset();
    MockClock::teardown();
}

void TestTriggers::testTypeUuids()
{
    // The base64 type UUIDs of KeePass 2.61.1
    const QList<QPair<QUuid, QString>> expected = {
        {TriggerIds::AppInitPost, "1M7NtUuYT/KmqeJVJh7I6A=="},
        {TriggerIds::AppLoadPost, "2PMe6cxpSBuJxfzi6ktqlw=="},
        {TriggerIds::AppExit, "goq3q7EcTr+AOTY/kXGXeA=="},
        {TriggerIds::OpenedDatabaseFile, "5f8TBoW4QYm5BvaeKztApw=="},
        {TriggerIds::SavingDatabaseFile, "lcGm/XJ8QMei+VsPoJljHA=="},
        {TriggerIds::SavedDatabaseFile, "s6j9/ngTSmqcXdW6hDqbjg=="},
        {TriggerIds::SynchronizingDatabaseFile, "Bn4npyCwR3GPFGjVAVx2ag=="},
        {TriggerIds::SynchronizedDatabaseFile, "taHg1aL2RLOKoYTGhsKpYA=="},
        {TriggerIds::ClosingDatabaseFilePre, "jOremqgXSRmjL/QeOx3sSQ=="},
        {TriggerIds::ClosingDatabaseFilePost, "lPpw5bE/QSamTgZP2MNslQ=="},
        {TriggerIds::CopiedEntryInfo, "P35exipUTFiVRIX78m9W3A=="},
        {TriggerIds::TimePeriodic, "bES7XfGLTA2IzmXm6a0pig=="},
        {TriggerIds::CustomTbButtonClicked, "R0dZkpenQ6K5aB8fwvebkg=="},
        {TriggerIds::UpdatedUIState, "jRLUmvLLT/eo78/arGJomQ=="},
        {TriggerIds::EnvironmentVariable, "nxHQvezpRTulRSYf96T/Hw=="},
        {TriggerIds::String, "uQ/4B3M4T+q7LrwL6juYww=="},
        {TriggerIds::FileExists, "y0qeNFaMTJWtZ00coQQZvA=="},
        {TriggerIds::RemoteHostReachable, "KiKDqJ0TQeiZh4usIY2B9A=="},
        {TriggerIds::DatabaseHasUnsavedChanges, "08r67ygqRkqZkNhl/OAW7Q=="},
        {TriggerIds::ExecuteCommandLine, "2uX4OwcwTBOe7y66y27kxw=="},
        {TriggerIds::ChangeTriggerState, "tkamn96US7mbrjykfswQ6g=="},
        {TriggerIds::OpenDatabaseFile, "/UFV1XmPRPqrifL4cO+UuA=="},
        {TriggerIds::SaveDatabase, "9VdhS/hMQV2pE3o5zRDwvQ=="},
        {TriggerIds::SynchronizeDatabase, "Iq135Bd4Tu2ZtFcdArOtTQ=="},
        {TriggerIds::ImportIntoDatabase, "gOZ/TnLxQEWRdh8sI9jsvg=="},
        {TriggerIds::ExportDatabase, "D5prW87VRr65NO2xP5RIIg=="},
        {TriggerIds::CloseDatabase, "W79FnVS/Sb2X+yzuX5kKZw=="},
        {TriggerIds::ActivateDatabaseTab, "P7gzLdYWToeZBWTbFkzWJg=="},
        {TriggerIds::Wait, "Oz0+MeSzQqa6zNXAO6ypaQ=="},
        {TriggerIds::ShowMessageBox, "CfePcyTsT+yItiXVMPQ0bg=="},
        {TriggerIds::PerformGlobalAutoType, "QGmlNlcbR5Kps3NlMODPww=="},
        {TriggerIds::PerformSelectedAutoType, "MXCPrWSTQ/WU7sgaI24yTQ=="},
        {TriggerIds::ShowEntriesByTag, "Qug3gXPTTuyBSJ47NqyDhA=="},
        {TriggerIds::AddToolbarButton, "lYGPRZlmSYirPoboGpZoNg=="},
        {TriggerIds::RemoveToolbarButton, "1m1BomyyRLqkSApB+glIeQ=="},
    };
    QCOMPARE(expected.size(), 35);
    for (const auto& pair : expected) {
        QCOMPARE(QString::fromLatin1(pair.first.toRfc4122().toBase64()), pair.second);
    }

    // Every listed type is known, except the obsolete event
    QCOMPARE(TriggerTypes::events().size(), 13);
    QCOMPARE(TriggerTypes::conditions().size(), 5);
    QCOMPARE(TriggerTypes::actions().size(), 16);
    QVERIFY(!TriggerTypes::findEvent(TriggerIds::UpdatedUIState));
    QVERIFY(TriggerTypes::findAction(TriggerIds::Wait));
}

void TestTriggers::testStringToBool()
{
    bool ok = false;
    for (const auto& text : {"True", "true", " TRUE ", "yes", "Enabled", "checked", "1"}) {
        QVERIFY2(TriggerUtil::stringToBool(text, &ok), text);
        QVERIFY(ok);
    }
    for (const auto& text : {"False", "no", "disabled", "Unchecked", "0"}) {
        QVERIFY2(!TriggerUtil::stringToBool(text, &ok), text);
        QVERIFY(ok);
    }
    QVERIFY(!TriggerUtil::stringToBool("maybe", &ok));
    QVERIFY(!ok);
    QVERIFY(!TriggerUtil::stringToBool("", &ok));
    QVERIFY(!ok);
    QCOMPARE(TriggerUtil::boolToString(true), QString("True"));
    QCOMPARE(TriggerUtil::boolToString(false), QString("False"));
}

void TestTriggers::testParamHelpers()
{
    const QStringList params = {"text", " 42 ", "abc", "3", "9"};
    QCOMPARE(TriggerUtil::paramString(params, 0), QString("text"));
    QCOMPARE(TriggerUtil::paramString(params, 7, "default"), QString("default"));
    QCOMPARE(TriggerUtil::paramUInt(params, 1), 42u);
    QCOMPARE(TriggerUtil::paramUInt(params, 2, 5), 5u);
    QCOMPARE(TriggerUtil::paramUInt(params, 9, 6), 6u);

    const auto& compare = TriggerTypes::findCondition(TriggerIds::String)->parameters.at(1);
    QCOMPARE(TriggerUtil::paramEnum(params, 3, 0, compare), 3u);
    // 9 is not in the enumeration
    QCOMPARE(TriggerUtil::paramEnum(params, 4, 1, compare), 1u);

    QCOMPARE(TriggerUtil::stripPathQuotes(" \"/tmp/a b.kdbx\" "), QString("/tmp/a b.kdbx"));
    QCOMPARE(TriggerUtil::stripPathQuotes("/tmp/a b.kdbx"), QString("/tmp/a b.kdbx"));
    QCOMPARE(TriggerUtil::stripPathQuotes("\"a\"b\""), QString("\"a\"b\""));
}

void TestTriggers::testSplitPaths_data()
{
    QTest::addColumn<QString>("input");
    QTest::addColumn<QStringList>("expected");
    QTest::newRow("empty") << QString() << QStringList();
    QTest::newRow("unquoted with spaces") << QString("/tmp/my file.kdbx") << QStringList{"/tmp/my file.kdbx"};
    QTest::newRow("two quoted") << QString("\"/tmp/a.kdbx\" \"/tmp/b c.kdbx\"")
                                << QStringList{"/tmp/a.kdbx", "/tmp/b c.kdbx"};
    QTest::newRow("odd quotes") << QString("\"/tmp/a.kdbx") << QStringList{"\"/tmp/a.kdbx"};
    QTest::newRow("mixed") << QString(" /tmp/x.kdbx \"/tmp/y.kdbx\"") << QStringList{"/tmp/x.kdbx", "/tmp/y.kdbx"};
}

void TestTriggers::testSplitPaths()
{
    QFETCH(QString, input);
    QFETCH(QStringList, expected);
    QCOMPARE(TriggerUtil::splitPaths(input), expected);
}

void TestTriggers::testCompareStrings()
{
    using namespace TriggerEnums;
    QVERIFY(TriggerUtil::compareStrings("Database.KDBX", "database.kdbx", CompareEquals));
    QVERIFY(!TriggerUtil::compareStrings("Database.kdbx", "database", CompareEquals));
    QVERIFY(TriggerUtil::compareStrings("/home/x/Database.kdbx", "DATABASE", CompareContains));
    QVERIFY(TriggerUtil::compareStrings("/home/x/Database.kdbx", "/HOME", CompareStartsWith));
    QVERIFY(TriggerUtil::compareStrings("/home/x/Database.kdbx", ".KDBX", CompareEndsWith));
    QVERIFY(TriggerUtil::compareStrings("/home/x/Database.kdbx", "^/home/.*\\.KDBX$", CompareRegEx));
    // An invalid regular expression gives false
    QVERIFY(!TriggerUtil::compareStrings("abc", "(", CompareRegEx));
    QVERIFY(!TriggerUtil::compareStrings("abc", "abc", 99));
}

void TestTriggers::testParametersToString()
{
    const auto* info = TriggerTypes::findCondition(TriggerIds::String);
    const auto condition = stringCondition("abc", TriggerEnums::CompareContains, "b", true);
    QCOMPARE(TriggerUtil::parametersToString(condition, info, true), QString("Not, abc, Contains, b"));

    const auto* execInfo = TriggerTypes::findAction(TriggerIds::ExecuteCommandLine);
    const auto action = object(TriggerIds::ExecuteCommandLine, {"cmd", "", "True", "1", ""});
    QCOMPARE(TriggerUtil::parametersToString(action, execInfo, false), QString("cmd, Yes, Hidden"));
}

void TestTriggers::testReadKeePassXml()
{
    // Trigger XML in the format of the .NET XML serializer of KeePass (default values are not written)
    QFile file(QStringLiteral(KEEPASSX_TEST_DATA_DIR).append("/KeePassTriggerCollection.xml"));
    QVERIFY(file.open(QIODevice::ReadOnly));
    QList<Trigger> triggers;
    QString error;
    QVERIFY2(TriggerXml::readTriggerCollection(file.readAll(), &triggers, &error), qPrintable(error));
    QCOMPARE(triggers.size(), 2);

    const auto& first = triggers.at(0);
    QCOMPARE(QString::fromLatin1(first.uuid.toRfc4122().toBase64()), QString("q2Ez9WQkS1yYc6sZ5f6x8A=="));
    QCOMPARE(first.name, QString("Export after save"));
    QCOMPARE(first.comments, QString("Exports the database after each save."));
    QVERIFY(first.enabled);
    QVERIFY(first.initiallyOn);
    QVERIFY(first.turnOffAfterAction);
    QCOMPARE(first.events.size(), 1);
    QCOMPARE(first.events.at(0).type, TriggerIds::SavedDatabaseFile);
    QCOMPARE(first.events.at(0).parameters, QStringList({"1", "Passwords.kdbx"}));
    QCOMPARE(first.conditions.size(), 1);
    QCOMPARE(first.conditions.at(0).type, TriggerIds::String);
    QVERIFY(first.conditions.at(0).negate);
    QCOMPARE(first.conditions.at(0).parameters, QStringList({"%USERNAME%", "0", "alice"}));
    QCOMPARE(first.actions.size(), 1);
    QCOMPARE(first.actions.at(0).type, TriggerIds::ExportDatabase);
    QCOMPARE(first.actions.at(0).parameters, QStringList({"{DB_DIR}\\Export.xml", "KeePass XML (2.x)", "", ""}));

    const auto& second = triggers.at(1);
    QCOMPARE(second.name, QString("Disabled trigger"));
    QVERIFY(!second.enabled);
    QVERIFY(!second.initiallyOn);
    QVERIFY(!second.on);
    QVERIFY(second.events.isEmpty());
}

void TestTriggers::testXmlRoundTrip()
{
    Trigger trigger = makeTrigger("Round trip <&> \"quoted\"",
                                  {object(TriggerIds::OpenedDatabaseFile, {"4", ".*\\.kdbx$"})},
                                  {stringCondition("a", 0, "", true)},
                                  {object(TriggerIds::Wait, {"10"}), hostAction("x")});
    trigger.comments = "Line 1\nLine 2";
    trigger.enabled = false;
    trigger.initiallyOn = false;
    trigger.turnOffAfterAction = true;
    Trigger plain = makeTrigger("Defaults", {}, {}, {});

    const QByteArray xml = TriggerXml::writeTriggerCollection({trigger, plain});
    // Default values are not written
    QVERIFY(xml.contains("<TriggerCollection"));
    QVERIFY(!xml.contains("<Enabled>true</Enabled>"));

    QList<Trigger> read;
    QString error;
    QVERIFY2(TriggerXml::readTriggerCollection(xml, &read, &error), qPrintable(error));
    QCOMPARE(read.size(), 2);
    QVERIFY(read.at(0) == trigger);
    QVERIFY(read.at(1) == plain);
}

void TestTriggers::testTriggerSystemXml()
{
    TriggerCollection collection;
    collection.enabled = false;
    collection.triggers << makeTrigger("One", {appStarted()}, {}, {hostAction("a")});

    const QByteArray xml = TriggerXml::writeTriggerSystem(collection);
    QVERIFY(xml.contains("<TriggerSystem"));
    QVERIFY(xml.contains("<Enabled>false</Enabled>"));

    TriggerCollection read;
    QVERIFY(TriggerXml::readTriggerSystem(xml, &read));
    QVERIFY(read == collection);

    // The root element must match
    QList<Trigger> triggers;
    QVERIFY(!TriggerXml::readTriggerCollection(xml, &triggers));
}

void TestTriggers::testInvalidXml()
{
    QList<Trigger> triggers;
    QString error;
    QVERIFY(!TriggerXml::readTriggerCollection("not xml", &triggers, &error));
    QVERIFY(!error.isEmpty());
    QVERIFY(!TriggerXml::readTriggerCollection(
        "<TriggerCollection><Triggers><Trigger><Guid>abc</Guid></Trigger></Triggers></TriggerCollection>",
        &triggers,
        &error));
    QVERIFY(!TriggerXml::readTriggerCollection(
        "<TriggerCollection><Triggers><Trigger><Enabled>perhaps</Enabled></Trigger></Triggers></TriggerCollection>",
        &triggers,
        &error));
    // Unknown elements are ignored
    QVERIFY(TriggerXml::readTriggerCollection(
        "<TriggerCollection><Other/><Triggers><Trigger><X>1</X></Trigger></Triggers></TriggerCollection>",
        &triggers,
        &error));
    QCOMPARE(triggers.size(), 1);
}

void TestTriggers::testPasteNewUuid()
{
    TriggerCollection collection;
    const Trigger existing = makeTrigger("Existing", {}, {}, {});
    collection.triggers << existing;

    Trigger same = existing;
    same.name = "Pasted copy";
    const Trigger other = makeTrigger("Other", {}, {}, {});
    collection.addPasted({same, other});

    QCOMPARE(collection.triggers.size(), 3);
    QVERIFY(collection.triggers.at(1).uuid != existing.uuid);
    QCOMPARE(collection.triggers.at(1).name, QString("Pasted copy"));
    QCOMPARE(collection.triggers.at(2).uuid, other.uuid);
}

void TestTriggers::testTriggerKeyValue()
{
    // The worked example of the design
    const TriggerKey key(QByteArray::fromHex("9A3B5C7D112233445566778899AABBCC"),
                         QByteArray::fromHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"));
    QVERIFY(key.isValid());
    QCOMPARE(key.toCustomDataValue(), QString("mjtcfREiM0RVZneImaq7zAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"));
    QVERIFY(TriggerKey::fromCustomDataValue(key.toCustomDataValue()) == key);
    QVERIFY(!TriggerKey::fromCustomDataValue("short").isValid());

    const auto generated = TriggerKey::generate();
    QVERIFY(generated.isValid());
    QVERIFY(generated != TriggerKey::generate());

    // Header layout with a fixed nonce
    const QByteArray sealed =
        TriggerFile::seal(key, "<TriggerSystem />", QByteArray::fromHex("A1A2A3A4A5A6A7A8A9AAABAC"));
    QCOMPARE(sealed.left(TriggerFile::HeaderSize).toHex().toUpper(),
             QByteArray("4B58545201000000"
                        "9A3B5C7D112233445566778899AABBCC"
                        "A1A2A3A4A5A6A7A8A9AAABAC"));
    QCOMPARE(sealed.size(), TriggerFile::HeaderSize + 17 + TriggerFile::TagSize);
}

void TestTriggers::testTriggerKeyInDatabase()
{
    auto db = newDatabase();
    QVERIFY(!TriggerKey::fromDatabase(db.data()).isValid());
    QVERIFY(db->metadata()->customData()->isProtected(CustomData::TriggerKey));

    const auto key = TriggerKey::generate();
    db->markAsClean();
    key.storeInDatabase(db.data());
    QVERIFY(db->isModified());
    QVERIFY(TriggerKey::fromDatabase(db.data()) == key);

    TriggerKey::removeFromDatabase(db.data());
    QVERIFY(!TriggerKey::fromDatabase(db.data()).isValid());
}

void TestTriggers::testTriggerFileRoundTrip()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString path = dir.filePath("sub/keepassxc_triggers.dat");
    const auto key = TriggerKey::generate();

    TriggerCollection collection;
    collection.triggers << makeTrigger(
        "Saved", {appStarted()}, {}, {object(TriggerIds::OpenDatabaseFile, {"/tmp/x.kdbx", "", "", "secret"})});
    QString error;
    QVERIFY2(TriggerFile::write(path, key, collection, &error), qPrintable(error));
    QCOMPARE(TriggerFile::readKeyId(path), key.id());

#ifndef Q_OS_WIN
    QCOMPARE(QFile::permissions(path) & (QFileDevice::ReadGroup | QFileDevice::ReadOther), QFileDevice::Permissions());
#endif

    // The file does not contain the parameters in clear text
    QFile file(path);
    QVERIFY(file.open(QIODevice::ReadOnly));
    const QByteArray content = file.readAll();
    file.close();
    QVERIFY(!content.contains("secret"));
    QVERIFY(!content.contains("TriggerSystem"));

    TriggerCollection read;
    QCOMPARE(TriggerFile::read(path, key, &read, &error), TriggerFile::Status::Ok);
    QVERIFY(read == collection);

    // Each write uses a new nonce
    QVERIFY(TriggerFile::write(path, key, collection, &error));
    QVERIFY(file.open(QIODevice::ReadOnly));
    QVERIFY(file.readAll() != content);
}

void TestTriggers::testTriggerFileTamper()
{
    QTemporaryDir dir;
    const QString path = dir.filePath("keepassxc_triggers.dat");
    const auto key = TriggerKey::generate();
    TriggerCollection collection;
    collection.triggers << makeTrigger("T", {appStarted()}, {}, {hostAction("a")});
    QVERIFY(TriggerFile::write(path, key, collection, nullptr));

    QFile file(path);
    QVERIFY(file.open(QIODevice::ReadOnly));
    const QByteArray original = file.readAll();
    file.close();

    // One changed byte in the reserved header bytes, the nonce, the ciphertext and the tag
    const QList<qsizetype> positions = {5, 30, TriggerFile::HeaderSize + 3, original.size() - 1};
    for (const auto position : positions) {
        QByteArray changed = original;
        changed[position] = static_cast<char>(changed.at(position) ^ 0x01);
        QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
        file.write(changed);
        file.close();
        TriggerCollection read;
        QCOMPARE(TriggerFile::read(path, key, &read, nullptr), TriggerFile::Status::VerifyFailed);
    }

    // A changed key id byte gives a mismatch, a truncated file fails
    QByteArray changedId = original;
    changedId[8] = static_cast<char>(changedId.at(8) ^ 0x01);
    QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    file.write(changedId);
    file.close();
    TriggerCollection read;
    QCOMPARE(TriggerFile::read(path, key, &read, nullptr), TriggerFile::Status::KeyMismatch);

    QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    file.write(original.left(20));
    file.close();
    QCOMPARE(TriggerFile::read(path, key, &read, nullptr), TriggerFile::Status::VerifyFailed);
    QVERIFY(TriggerFile::readKeyId(path).isEmpty());
}

void TestTriggers::testTriggerFileKeyMismatch()
{
    QTemporaryDir dir;
    const QString path = dir.filePath("keepassxc_triggers.dat");
    QVERIFY(TriggerFile::write(path, TriggerKey::generate(), TriggerCollection(), nullptr));
    TriggerCollection read;
    QCOMPARE(TriggerFile::read(path, TriggerKey::generate(), &read, nullptr), TriggerFile::Status::KeyMismatch);

    // Same key id, other key: the tag check fails
    const auto key = TriggerKey::generate();
    QVERIFY(TriggerFile::write(path, key, TriggerCollection(), nullptr));
    const TriggerKey forged(key.id(), TriggerKey::generate().key());
    QCOMPARE(TriggerFile::read(path, forged, &read, nullptr), TriggerFile::Status::VerifyFailed);
}

void TestTriggers::testTriggerFileMissing()
{
    QTemporaryDir dir;
    TriggerCollection read;
    QCOMPARE(TriggerFile::read(dir.filePath("none.dat"), TriggerKey::generate(), &read, nullptr),
             TriggerFile::Status::NotFound);
    QVERIFY(TriggerFile::readKeyId(dir.filePath("none.dat")).isEmpty());
}

void TestTriggers::testTriggerKeySurvivesMerge()
{
    auto* clock = new MockClock(2026, 1, 1, 12, 0, 0);
    MockClock::setup(clock);

    const auto key = TriggerKey::generate();

    // Synchronization (KeePass rules) in both directions
    for (const bool keyInSource : {true, false}) {
        auto source = newDatabase();
        auto target = newDatabase();
        key.storeInDatabase(keyInSource ? source.data() : target.data());
        clock->advanceMinute(1);
        // The side without the key changes its custom data later
        (keyInSource ? target : source)->metadata()->customData()->set("Other", "value");
        clock->advanceMinute(1);

        Merger merger(source.data(), target.data());
        merger.setForcedMergeMode(Group::Synchronize);
        merger.setKeePassRules(true);
        merger.merge();
        QVERIFY2(TriggerKey::fromDatabase(target.data()) == key, keyInSource ? "source to target" : "kept in target");
    }

    // Default merge: the newer custom data of the source does not remove the protected key of the target
    auto source = newDatabase();
    auto target = newDatabase();
    key.storeInDatabase(target.data());
    clock->advanceMinute(1);
    source->metadata()->customData()->set("Other", "value");
    clock->advanceMinute(1);
    Merger merger(source.data(), target.data());
    merger.merge();
    QVERIFY(TriggerKey::fromDatabase(target.data()) == key);

    // Default merge: the key reaches a target that has no custom data
    auto empty = newDatabase();
    Merger toEmpty(target.data(), empty.data());
    toEmpty.merge();
    QVERIFY(TriggerKey::fromDatabase(empty.data()) == key);
}

void TestTriggers::testNotLoaded()
{
    QVERIFY(!triggerSystem()->isLoaded());
    triggerSystem()->raiseEvent(TriggerIds::AppLoadPost);
    QVERIFY(g_host->executed.isEmpty());
}

void TestTriggers::testGlobalSwitch()
{
    TriggerCollection collection;
    collection.enabled = false;
    collection.triggers << makeTrigger("T", {appStarted()}, {}, {hostAction("a")});
    triggerSystem()->load(collection);
    triggerSystem()->raiseEvent(TriggerIds::AppLoadPost);
    QVERIFY(g_host->executed.isEmpty());
}

void TestTriggers::testOrderAndMatching()
{
    TriggerCollection collection;
    // Events are combined with OR
    collection.triggers << makeTrigger(
        "First", {object(TriggerIds::AppExit), appStarted()}, {}, {hostAction("1"), hostAction("2")});
    collection.triggers << makeTrigger("Other event", {object(TriggerIds::AppExit)}, {}, {hostAction("x")});
    auto disabled = makeTrigger("Disabled", {appStarted()}, {}, {hostAction("x")});
    disabled.enabled = false;
    collection.triggers << disabled;
    auto off = makeTrigger("Off", {appStarted()}, {}, {hostAction("x")});
    off.initiallyOn = false;
    collection.triggers << off;
    collection.triggers << makeTrigger("Last", {appStarted()}, {}, {hostAction("3")});
    triggerSystem()->load(collection);

    triggerSystem()->raiseEvent(TriggerIds::AppLoadPost);
    QCOMPARE(g_host->executed, QStringList({"First:1", "First:2", "Last:3"}));
}

void TestTriggers::testConditionsAndNegate()
{
    using namespace TriggerEnums;
    TriggerCollection collection;
    collection.triggers << makeTrigger(
        "All true",
        {appStarted()},
        {stringCondition("abc", CompareEquals, "ABC"), stringCondition("abc", CompareContains, "x", true)},
        {hostAction("run")});
    collection.triggers << makeTrigger(
        "One false",
        {appStarted()},
        {stringCondition("abc", CompareEquals, "ABC"), stringCondition("abc", CompareContains, "b", true)},
        {hostAction("run")});
    triggerSystem()->load(collection);
    triggerSystem()->raiseEvent(TriggerIds::AppLoadPost);
    QCOMPARE(g_host->executed, QStringList({"All true:run"}));
}

void TestTriggers::testAbort()
{
    TriggerCollection collection;
    auto trigger = makeTrigger("T", {appStarted()}, {}, {hostAction("1"), hostAction("abort"), hostAction("3")});
    trigger.turnOffAfterAction = true;
    collection.triggers << trigger;
    collection.triggers << makeTrigger("Next", {appStarted()}, {}, {hostAction("4")});
    triggerSystem()->load(collection);

    triggerSystem()->raiseEvent(TriggerIds::AppLoadPost);
    // The abort ends the actions of this trigger only. The trigger is still turned off.
    QCOMPARE(g_host->executed, QStringList({"T:1", "T:abort", "Next:4"}));
    QVERIFY(!triggerSystem()->collection().triggers.at(0).on);
}

void TestTriggers::testTurnOffAfterAction()
{
    TriggerCollection collection;
    auto trigger = makeTrigger("T", {appStarted()}, {}, {hostAction("1")});
    trigger.turnOffAfterAction = true;
    collection.triggers << trigger;
    auto failing = makeTrigger("Failing condition", {appStarted()}, {stringCondition("a", 0, "b")}, {});
    failing.turnOffAfterAction = true;
    collection.triggers << failing;
    triggerSystem()->load(collection);

    triggerSystem()->raiseEvent(TriggerIds::AppLoadPost);
    triggerSystem()->raiseEvent(TriggerIds::AppLoadPost);
    QCOMPARE(g_host->executed, QStringList({"T:1"}));
    QVERIFY(!triggerSystem()->collection().triggers.at(0).on);
    // A trigger whose conditions fail is not turned off
    QVERIFY(triggerSystem()->collection().triggers.at(1).on);
}

void TestTriggers::testErrorSkipsRemainingTriggers()
{
    TriggerCollection collection;
    auto failing = makeTrigger("Failing", {appStarted()}, {}, {hostAction("fail"), hostAction("after")});
    failing.turnOffAfterAction = true;
    collection.triggers << failing;
    collection.triggers << makeTrigger("Next", {appStarted()}, {}, {hostAction("x")});
    triggerSystem()->load(collection);

    triggerSystem()->raiseEvent(TriggerIds::AppLoadPost);
    QCOMPARE(g_host->executed, QStringList({"Failing:fail"}));
    QCOMPARE(g_host->errors, QStringList({"failed"}));
    // No turn off after an error
    QVERIFY(triggerSystem()->collection().triggers.at(0).on);

    // The next event runs again
    triggerSystem()->raiseEvent(TriggerIds::AppLoadPost);
    QCOMPARE(g_host->errors.size(), 2);
}

void TestTriggers::testUnknownTypes()
{
    const QUuid unknown = QUuid::createUuid();
    TriggerCollection collection;
    // An unknown event type never matches
    collection.triggers << makeTrigger("Unknown event", {object(unknown)}, {}, {hostAction("x")});
    triggerSystem()->load(collection);
    triggerSystem()->raiseEvent(TriggerIds::AppLoadPost);
    triggerSystem()->raiseEvent(unknown);
    QVERIFY(g_host->executed.isEmpty());
    QVERIFY(g_host->errors.isEmpty());

    // An unknown condition or action type is an error
    collection.triggers.clear();
    collection.triggers << makeTrigger("Unknown condition", {appStarted()}, {object(unknown)}, {hostAction("x")});
    triggerSystem()->load(collection);
    triggerSystem()->raiseEvent(TriggerIds::AppLoadPost);
    QCOMPARE(g_host->errors.size(), 1);
    QVERIFY(g_host->errors.at(0).contains("condition type is unknown"));

    collection.triggers.clear();
    collection.triggers << makeTrigger("Unknown action", {appStarted()}, {}, {object(unknown)});
    triggerSystem()->load(collection);
    triggerSystem()->raiseEvent(TriggerIds::AppLoadPost);
    QCOMPARE(g_host->errors.size(), 2);
    QVERIFY(g_host->errors.at(1).contains("action type is unknown"));
    QVERIFY(g_host->executed.isEmpty());

    // The obsolete event is reported
    collection.triggers.clear();
    collection.triggers << makeTrigger("Obsolete", {object(TriggerIds::UpdatedUIState)}, {}, {});
    triggerSystem()->load(collection);
    QVERIFY(triggerSystem()->usesObsoleteEvent());
}

void TestTriggers::testChangeTriggerState()
{
    using namespace TriggerEnums;
    TriggerCollection collection;
    auto target = makeTrigger("Target", {object(TriggerIds::AppExit)}, {}, {hostAction("t")});
    target.initiallyOn = false;
    collection.triggers << target;
    collection.triggers << makeTrigger("Switcher",
                                       {appStarted()},
                                       {},
                                       {object(TriggerIds::ChangeTriggerState, {"Target", QString::number(TriggerOn)}),
                                        object(TriggerIds::ChangeTriggerState, {"", QString::number(TriggerOff)})});
    collection.triggers << makeTrigger(
        "Missing", {object(TriggerIds::AppExit)}, {}, {object(TriggerIds::ChangeTriggerState, {"Nobody", "2"})});
    triggerSystem()->load(collection);

    QVERIFY(!triggerSystem()->collection().triggers.at(0).on);
    triggerSystem()->raiseEvent(TriggerIds::AppLoadPost);
    QVERIFY(triggerSystem()->collection().triggers.at(0).on);
    // An empty name means the current trigger
    QVERIFY(!triggerSystem()->collection().triggers.at(1).on);

    // A name that is not found is an error
    triggerSystem()->raiseEvent(TriggerIds::AppExit);
    QCOMPARE(g_host->executed, QStringList({"Target:t"}));
    QCOMPARE(g_host->errors.size(), 1);
    QVERIFY(g_host->errors.at(0).contains("Nobody"));
}

void TestTriggers::testEventFilters()
{
    using namespace TriggerEnums;
    auto db = newDatabase();
    db->setFilePath("/tmp/Folder/Passwords.kdbx");

    TriggerCollection collection;
    collection.triggers << makeTrigger(
        "Ends",
        {object(TriggerIds::SavedDatabaseFile, {QString::number(CompareEndsWith), "passwords.KDBX"})},
        {},
        {hostAction("ends")});
    collection.triggers << makeTrigger(
        "Quoted",
        {object(TriggerIds::SavedDatabaseFile, {QString::number(CompareContains), "\"Folder\""})},
        {},
        {hostAction("quoted")});
    collection.triggers << makeTrigger(
        "Other",
        {object(TriggerIds::SavedDatabaseFile, {QString::number(CompareEquals), "/tmp/other.kdbx"})},
        {},
        {hostAction("other")});
    collection.triggers << makeTrigger(
        "Empty filter", {object(TriggerIds::SavedDatabaseFile, {"0", ""})}, {}, {hostAction("any")});
    collection.triggers << makeTrigger(
        "Text",
        {object(TriggerIds::CopiedEntryInfo, {QString::number(CompareStartsWith), "sec"})},
        {},
        {hostAction("text")});
    collection.triggers << makeTrigger(
        "Button", {object(TriggerIds::CustomTbButtonClicked, {"MyButton"})}, {}, {hostAction("button")});
    triggerSystem()->load(collection);

    TriggerEventProperties props;
    props.database = db;
    triggerSystem()->raiseEvent(TriggerIds::SavedDatabaseFile, props);
    QCOMPARE(g_host->executed, QStringList({"Ends:ends", "Quoted:quoted", "Empty filter:any"}));

    // The file path of the event overrides the path of the database (Save As)
    g_host->executed.clear();
    props.filePath = "/tmp/other.kdbx";
    triggerSystem()->raiseEvent(TriggerIds::SavedDatabaseFile, props);
    QCOMPARE(g_host->executed, QStringList({"Other:other", "Empty filter:any"}));

    // A database without a path matches only an empty filter
    g_host->executed.clear();
    TriggerEventProperties noPath;
    noPath.database = newDatabase();
    triggerSystem()->raiseEvent(TriggerIds::SavedDatabaseFile, noPath);
    QCOMPARE(g_host->executed, QStringList({"Empty filter:any"}));

    g_host->executed.clear();
    TriggerEventProperties text;
    text.text = "Secret value";
    triggerSystem()->raiseEvent(TriggerIds::CopiedEntryInfo, text);
    text.text = "other";
    triggerSystem()->raiseEvent(TriggerIds::CopiedEntryInfo, text);
    QCOMPARE(g_host->executed, QStringList({"Text:text"}));

    g_host->executed.clear();
    TriggerEventProperties button;
    button.commandId = "mybutton";
    triggerSystem()->raiseEvent(TriggerIds::CustomTbButtonClicked, button);
    button.commandId = "other";
    triggerSystem()->raiseEvent(TriggerIds::CustomTbButtonClicked, button);
    QCOMPARE(g_host->executed, QStringList({"Button:button"}));
}

void TestTriggers::testPeriodicEvent()
{
    auto* clock = new MockClock(2026, 1, 1, 12, 0, 0);
    MockClock::setup(clock);

    TriggerCollection collection;
    collection.triggers << makeTrigger(
        "Every 2 s", {object(TriggerIds::TimePeriodic, {"2", "False"})}, {}, {hostAction("tick")});
    collection.triggers << makeTrigger(
        "Never", {object(TriggerIds::TimePeriodic, {"0", "False"})}, {}, {hostAction("never")});
    collection.triggers << makeTrigger(
        "Restart", {object(TriggerIds::TimePeriodic, {"2", "True"})}, {}, {hostAction("restart")});
    triggerSystem()->load(collection);

    // The first check only arms the timer
    triggerSystem()->raisePeriodicEvent();
    QVERIFY(g_host->executed.isEmpty());
    clock->advanceSecond(1);
    triggerSystem()->raisePeriodicEvent();
    QVERIFY(g_host->executed.isEmpty());

    // User activity restarts the timer of "Restart"
    triggerSystem()->notifyUserActivity();
    clock->advanceSecond(1);
    triggerSystem()->raisePeriodicEvent();
    QCOMPARE(g_host->executed, QStringList({"Every 2 s:tick"}));

    clock->advanceSecond(1);
    triggerSystem()->raisePeriodicEvent();
    QCOMPARE(g_host->executed, QStringList({"Every 2 s:tick", "Restart:restart"}));

    clock->advanceSecond(1);
    triggerSystem()->raisePeriodicEvent();
    QCOMPARE(g_host->executed, QStringList({"Every 2 s:tick", "Restart:restart", "Every 2 s:tick"}));
}

void TestTriggers::testReplaceKeepsState()
{
    using namespace TriggerEnums;
    TriggerCollection collection;
    auto kept = makeTrigger("Kept", {object(TriggerIds::AppExit)}, {}, {});
    kept.initiallyOn = false;
    collection.triggers << kept;
    collection.triggers << makeTrigger(
        "Switcher", {appStarted()}, {}, {object(TriggerIds::ChangeTriggerState, {"Kept", QString::number(TriggerOn)})});
    triggerSystem()->load(collection);
    QVERIFY(!triggerSystem()->collection().triggers.at(0).on);

    // A trigger turns "Kept" on
    triggerSystem()->raiseEvent(TriggerIds::AppLoadPost);
    QVERIFY(triggerSystem()->collection().triggers.at(0).on);

    // The edited list keeps the state of a trigger that stays. A new trigger starts in its initial state.
    TriggerCollection edited = collection;
    edited.triggers[0].name = "Kept and renamed";
    auto added = makeTrigger("Added", {appStarted()}, {}, {});
    added.initiallyOn = false;
    edited.triggers << added;
    triggerSystem()->replace(edited);
    QCOMPARE(triggerSystem()->collection().triggers.at(0).name, QString("Kept and renamed"));
    QVERIFY(triggerSystem()->collection().triggers.at(0).on);
    QVERIFY(!triggerSystem()->collection().triggers.at(2).on);
}

void TestTriggers::testConditions()
{
    using namespace TriggerEnums;
    QTemporaryDir dir;
    const QString existing = dir.filePath("exists.txt");
    QFile file(existing);
    QVERIFY(file.open(QIODevice::WriteOnly));
    file.close();

    qputenv("KPXC_TRIGGER_TEST", "Value123");

    auto active = newDatabase();
    auto triggering = newDatabase();
    active->markAsModified();
    triggering->markAsClean();
    g_host->active = active;

    TriggerEventProperties props;
    props.database = triggering;
    Trigger trigger;
    TriggerCollection collection;
    TriggerContext context;
    context.collection = &collection;
    context.trigger = &trigger;
    context.properties = &props;

    auto eval = [&](const TriggerObject& condition) {
        QString error;
        const bool result = triggerSystem()->evaluateCondition(condition, context, &error);
        Q_ASSERT(error.isEmpty());
        return result;
    };

    QVERIFY(
        eval(object(TriggerIds::EnvironmentVariable, {"KPXC_TRIGGER_TEST", QString::number(CompareEndsWith), "123"})));
    QVERIFY(!eval(object(TriggerIds::EnvironmentVariable, {"KPXC_TRIGGER_TEST", "0", "other"})));
    // A missing variable gives false, also when negated it is the negation of false
    QVERIFY(!eval(object(TriggerIds::EnvironmentVariable, {"KPXC_TRIGGER_MISSING", "0", ""})));
    QVERIFY(eval(object(TriggerIds::EnvironmentVariable, {"KPXC_TRIGGER_MISSING", "0", ""}, true)));

    QVERIFY(eval(object(TriggerIds::FileExists, {existing})));
    QVERIFY(eval(object(TriggerIds::FileExists, {"\"" + existing + "\""})));
    QVERIFY(!eval(object(TriggerIds::FileExists, {dir.filePath("missing.txt")})));
    QVERIFY(eval(object(TriggerIds::FileExists, {""})));

    // An empty host gives true
    QVERIFY(eval(object(TriggerIds::RemoteHostReachable, {""})));
    QVERIFY(!eval(object(TriggerIds::RemoteHostReachable, {"host.invalid"})));

    QVERIFY(eval(object(TriggerIds::DatabaseHasUnsavedChanges, {QString::number(DatabaseActive)})));
    QVERIFY(!eval(object(TriggerIds::DatabaseHasUnsavedChanges, {QString::number(DatabaseTriggering)})));
    g_host->active.reset();
    QVERIFY(!eval(object(TriggerIds::DatabaseHasUnsavedChanges, {QString::number(DatabaseActive)})));
}

void TestTriggers::testPlaceholdersWithoutEntry()
{
    auto db = newDatabase();
    db->setFilePath("/tmp/Folder/My Passwords.kdbx");

    TriggerPlaceholders::Context context;
    context.database = db.data();
    QCOMPARE(TriggerPlaceholders::compile("{DB_PATH}|{db_dir}|{DB_NAME}|{DB_BASENAME}|{DB_EXT}|{DOCDIR}", context),
             QDir::toNativeSeparators("/tmp/Folder/My Passwords.kdbx|/tmp/Folder|My Passwords.kdbx|My Passwords|kdbx|"
                                      "/tmp/Folder"));
    QCOMPARE(TriggerPlaceholders::compile("{ENV_DIRSEP}", context), QString(QDir::separator()));
    QCOMPARE(TriggerPlaceholders::compile("{APPDIR}", context),
             QDir::toNativeSeparators(QCoreApplication::applicationDirPath()));

    qputenv("KPXC_TRIGGER_TEST", "EnvValue");
    QCOMPARE(TriggerPlaceholders::compile("a%KPXC_TRIGGER_TEST%b %kpxc_trigger_test%", context),
             QString("aEnvValueb EnvValue"));

    // Entry placeholders stay without an entry, date placeholders and transformations work
    QCOMPARE(TriggerPlaceholders::compile("{TITLE}{PASSWORD}", context), QString("{TITLE}{PASSWORD}"));
    QCOMPARE(TriggerPlaceholders::compile("{DT_YEAR}", context), QString::number(QDate::currentDate().year()));
    QCOMPARE(TriggerPlaceholders::compile("{T-CONV:/Text/Upper/}", context), QString("TEXT"));

    // References search the database
    auto* entry = new Entry();
    entry->setUuid(QUuid::createUuid());
    entry->setTitle("Mail");
    entry->setPassword("pass{word}");
    entry->setGroup(db->rootGroup());
    QCOMPARE(TriggerPlaceholders::compile("x{REF:P@T:Mail}y", context), QString("xpass{word}y"));
    QCOMPARE(TriggerPlaceholders::compile("{REF:P@T:Nothing}", context), QString());

    // Command line encoding of inserted values only
    context.forCommandLine = true;
#ifdef Q_OS_WIN
    QCOMPARE(TriggerPlaceholders::compile("\"{REF:T@T:Mail}\"", context), QString("\"Mail\""));
#else
    entry->setTitle("Ma\"il");
    QCOMPARE(TriggerPlaceholders::compile("\"{REF:T@T:Ma\"il}\"", context), QString("\"Ma\\\"il\""));
#endif
}

void TestTriggers::testPlaceholdersWithEntry()
{
    auto db = newDatabase();
    auto* group = new Group();
    group->setUuid(QUuid::createUuid());
    group->setName("Internet");
    group->setNotes("Group notes");
    group->setParent(db->rootGroup());
    auto* sub = new Group();
    sub->setUuid(QUuid::createUuid());
    sub->setName("Mail");
    sub->setParent(group);

    auto* entry = new Entry();
    entry->setUuid(QUuid::createUuid());
    entry->setTitle("Title");
    entry->setUsername("user");
    entry->setPassword("secret");
    entry->setGroup(sub);

    TriggerPlaceholders::Context context;
    context.entry = entry;
    context.database = db.data();
    context.selectedGroup = group;
    QCOMPARE(TriggerPlaceholders::compile("{TITLE}:{USERNAME}:{PASSWORD}:{S:Title}", context),
             QString("Title:user:secret:Title"));
    QCOMPARE(TriggerPlaceholders::compile("{GROUP}|{GROUP_PATH}|{GROUPPATH}", context),
             QString("Mail|Internet.Mail|Internet.Mail"));
    QCOMPARE(TriggerPlaceholders::compile("{GROUP_SEL}|{GROUP_SEL_PATH}|{GROUP_SEL_NOTES}", context),
             QString("Internet|Internet|Group notes"));
    QCOMPARE(TriggerPlaceholders::compile("{UNKNOWN}", context), QString("{UNKNOWN}"));
}

void TestTriggers::testPlaceholderComments()
{
    TriggerPlaceholders::Context context;
    QCOMPARE(TriggerPlaceholders::removeComments("a{C:comment}b{c:with {nested}}c"), QString("abc"));
    QCOMPARE(TriggerPlaceholders::compile("x{C:note}y", context), QString("xy"));
    // Malformed comments stay
    QCOMPARE(TriggerPlaceholders::removeComments("a{C:open"), QString("a{C:open"));
}

void TestTriggers::testPlaceholderClipboard()
{
    QString clipboard = "Clip";
    TriggerPlaceholders::Context context;
    context.clipboardText = [&] { return clipboard; };
    context.setClipboardText = [&](const QString& text) { clipboard = text; };

    QCOMPARE(TriggerPlaceholders::compile("[{CLIPBOARD}]", context), QString("[Clip]"));
    // The set placeholder is removed, its text is compiled first
    QCOMPARE(TriggerPlaceholders::compile("a{CLIPBOARD-SET:/x{C:c}y/}b", context), QString("ab"));
    QCOMPARE(clipboard, QString("xy"));
    QCOMPARE(TriggerPlaceholders::compile("{CLIPBOARD-SET:/new/}{CLIPBOARD}", context), QString("new"));
}

void TestTriggers::testPlaceholderCommand()
{
    TriggerPlaceholders::Context context;
    QStringList asked;
    bool allow = false;
    context.confirmCommand = [&](const QString& program, const QString& arguments) {
        asked << program + "|" + arguments;
        return allow;
    };

    // Not confirmed: the placeholder is removed and nothing runs
    QCOMPARE(TriggerPlaceholders::compile("a{CMD:/echo hello/m=c,o=1/}b", context), QString("ab"));
    QCOMPARE(asked, QStringList({"echo|hello"}));

#ifndef Q_OS_WIN
    allow = true;
    QCOMPARE(TriggerPlaceholders::compile("a{CMD:/echo hello world/m=c,o=1/}b", context), QString("ahello worldb"));
    // Without o=1 the output is not inserted
    QCOMPARE(TriggerPlaceholders::compile("a{CMD:/echo hello/m=c,o=0/}b", context), QString("ab"));
#endif
    // A malformed placeholder drops the rest of the text, as in KeePass
    QCOMPARE(TriggerPlaceholders::compile("a{CMD:/echo", context), QString("a"));
}

void TestTriggers::testCommandLineEncoding()
{
#ifdef Q_OS_WIN
    QCOMPARE(TriggerPlaceholders::encodeForCommandLine("a\"b"), QString("a\\\"b"));
    QCOMPARE(TriggerPlaceholders::encodeForCommandLine("a\\\"b"), QString("a\\\\\\\"b"));
    QCOMPARE(TriggerPlaceholders::encodeForCommandLine("a\\b\\"), QString("a\\b\\"));
#else
    QCOMPARE(TriggerPlaceholders::encodeForCommandLine("a\"b\\c"), QString("a\\\"b\\\\c"));
#endif
}
