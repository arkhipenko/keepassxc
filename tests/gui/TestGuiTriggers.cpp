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

#include "config-keepassx-tests.h"

#include "core/Config.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "core/triggers/TriggerStore.h"
#include "core/triggers/TriggerSystem.h"
#include "core/triggers/TriggerTypes.h"
#include "core/triggers/TriggerUtil.h"
#include "core/triggers/TriggerXml.h"
#include "crypto/Crypto.h"
#include "gui/Application.h"
#include "gui/DatabaseTabWidget.h"
#include "gui/DatabaseWidget.h"
#include "gui/FileDialog.h"
#include "gui/MainWindow.h"
#include "gui/MessageBox.h"
#include "gui/MessageWidget.h"
#include "gui/PasswordWidget.h"
#include "gui/triggers/TriggerEditDialogs.h"
#include "gui/triggers/TriggerManager.h"
#include "gui/triggers/TriggersDialog.h"
#include "keys/PasswordKey.h"
#include "util/TemporaryFile.h"

#include <QAction>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QTest>
#include <QTimer>
#include <QToolButton>
#include <QTreeWidget>

// Runs code when a modal dialog of the type is open. The check repeats, because a dialog can open
// after other event processing (for example a save).
#define TEST_MODAL(TYPE, TEST_CODE)                                                                                    \
    bool dialogFinished = false;                                                                                       \
    auto* modalTimer = new QTimer(this);                                                                               \
    QObject::connect(modalTimer, &QTimer::timeout, this, [&, modalTimer]() {                                           \
        auto* modal = qobject_cast<TYPE*>(QApplication::activeModalWidget());                                          \
        if (!modal) {                                                                                                  \
            return;                                                                                                    \
        }                                                                                                              \
        modalTimer->stop();                                                                                            \
        modalTimer->deleteLater();                                                                                     \
        TEST_CODE dialogFinished = true;                                                                               \
    });                                                                                                                \
    modalTimer->start(20)

class TestGuiTriggers : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void init();
    void cleanup();

    void testLoadAtUnlock();
    void testVerifyFailure();
    void testKeyMismatch();
    void testCreateKeyAndEditTriggers();
    void testReplaceTriggerFile();
    void testCopyTriggerKey();
    void testDialogCopyPaste();
    void testObjectEditor();
    void testDatabaseEvents();
    void testToolbarButtons();
    void testSynchronizeErrorOptions();
    void testActionExecuteCommand();
    void testActionSaveCloseActivate();
    void testActionOpenDatabase();
    void testActionImport();
    void testActionExport();
    void testActionMessageBoxAbort();
    void testActionShowEntriesByTag();

private:
    TriggerManager* manager() const;
    void unlock(DatabaseWidget* dbWidget, const QString& password = "a");
    void installTriggers(const QList<Trigger>& triggers, bool load = true);
    QStringList buttonNames() const;
    bool messageShown(const QString& text) const;
    void trigger(const QString& actionName);

    QScopedPointer<MainWindow> m_mainWindow;
    QPointer<DatabaseTabWidget> m_tabWidget;
    QPointer<DatabaseWidget> m_dbWidget;
    QSharedPointer<Database> m_db;
    TemporaryFile m_dbFile;
    QString m_dbFilePath;
    QScopedPointer<QTemporaryDir> m_dir;
    QString m_triggerFile;
};

namespace
{
    TriggerObject object(const QUuid& type, const QStringList& parameters = {})
    {
        TriggerObject result;
        result.type = type;
        result.parameters = parameters;
        return result;
    }

    // An action that adds a toolbar button: it shows that a trigger ran
    TriggerObject marker(const QString& name)
    {
        return object(TriggerIds::AddToolbarButton, {name, name, {}});
    }

    Trigger makeTrigger(const QString& name, const QUuid& event, const QList<TriggerObject>& actions)
    {
        Trigger trigger;
        trigger.name = name;
        trigger.events << object(event);
        trigger.actions = actions;
        return trigger;
    }
} // namespace

void TestGuiTriggers::initTestCase()
{
    QVERIFY(Crypto::init());
    const auto configFile = TemporaryFile::createTempConfigFile();
    Config::createConfigFromFile(configFile, configFile);
    QLocale::setDefault(QLocale::c());
    Application::bootstrap();

    m_mainWindow.reset(new MainWindow());
    m_tabWidget = m_mainWindow->findChild<DatabaseTabWidget*>("tabWidget");
    m_mainWindow->show();
    m_mainWindow->resize(1024, 768);
}

void TestGuiTriggers::init()
{
    config()->resetToDefaults();
    config()->set(Config::AutoSaveAfterEveryChange, false);
    config()->set(Config::AutoSaveOnExit, false);
    config()->set(Config::UpdateCheckMessageShown, true);
    config()->set(Config::Security_QuickUnlock, false);
    config()->set(Config::UseAtomicSaves, false);
    config()->set(Config::GUI_ShowExpiredEntriesOnDatabaseUnlock, false);

    m_dir.reset(new QTemporaryDir());
    QVERIFY(m_dir->isValid());
    m_triggerFile = m_dir->filePath("keepassxc_triggers.dat");
    manager()->reset();
    manager()->setTriggerFilePath(m_triggerFile);

    QVERIFY(m_dbFile.copyFromFile(QDir(KEEPASSX_TEST_DATA_DIR).absoluteFilePath("NewDatabase.kdbx")));
    m_dbFilePath = m_dbFile.fileName();

    m_mainWindow->activateWindow();
    QApplication::processEvents();
    fileDialog()->setNextFileName(m_dbFilePath);
    trigger("actionDatabaseOpen");
    m_dbWidget = m_tabWidget->currentDatabaseWidget();
    unlock(m_dbWidget);
    m_db = m_dbWidget->database();
}

void TestGuiTriggers::cleanup()
{
    manager()->reset();
    MessageBox::setNextAnswer(MessageBox::NoButton);
    while (m_tabWidget->count() > 0) {
        auto* dbWidget = m_tabWidget->databaseWidgetFromIndex(0);
        if (!dbWidget->isLocked()) {
            dbWidget->database()->markAsClean();
        }
        MessageBox::setNextAnswer(MessageBox::No);
        QVERIFY(m_tabWidget->closeDatabaseTab(0));
        QApplication::processEvents();
    }
    MessageBox::setNextAnswer(MessageBox::NoButton);
}

TriggerManager* TestGuiTriggers::manager() const
{
    return m_mainWindow->findChild<TriggerManager*>();
}

void TestGuiTriggers::trigger(const QString& actionName)
{
    auto* action = m_mainWindow->findChild<QAction*>(actionName);
    QVERIFY2(action, qPrintable(actionName));
    QVERIFY2(action->isEnabled(), qPrintable(actionName));
    action->trigger();
    QApplication::processEvents();
}

void TestGuiTriggers::unlock(DatabaseWidget* dbWidget, const QString& password)
{
    auto* openWidget = dbWidget->findChild<QWidget*>("databaseOpenWidget");
    QVERIFY(openWidget);
    auto* edit = openWidget->findChild<PasswordWidget*>("editPassword")->findChild<QLineEdit*>("passwordEdit");
    QVERIFY(edit);
    edit->setFocus();
    QTRY_VERIFY(edit->hasFocus());
    QTest::keyClicks(edit, password);
    QTest::keyClick(edit, Qt::Key_Enter);
    QTRY_VERIFY(!dbWidget->isLocked());
}

// Stores a trigger key in the open database, writes the trigger file and optionally loads it
void TestGuiTriggers::installTriggers(const QList<Trigger>& triggers, bool load)
{
    const auto key = TriggerKey::generate();
    key.storeInDatabase(m_db.data());
    QVERIFY(m_dbWidget->save());
    TriggerCollection collection;
    collection.triggers = triggers;
    QString error;
    QVERIFY2(TriggerFile::write(m_triggerFile, key, collection, &error), qPrintable(error));
    if (load) {
        manager()->databaseUnlocked(m_dbWidget);
        QVERIFY(triggerSystem()->isLoaded());
    }
}

bool TestGuiTriggers::messageShown(const QString& text) const
{
    for (auto* widget : m_dbWidget->findChildren<MessageWidget*>()) {
        if (widget->isVisible() && widget->text().contains(text)) {
            return true;
        }
    }
    return false;
}

QStringList TestGuiTriggers::buttonNames() const
{
    QStringList names;
    for (auto* button : manager()->customToolBarButtons()) {
        names << button->text();
    }
    return names;
}

void TestGuiTriggers::testLoadAtUnlock()
{
    installTriggers({makeTrigger("Init", TriggerIds::AppInitPost, {marker("init")}),
                     makeTrigger("Ready", TriggerIds::AppLoadPost, {marker("ready")}),
                     makeTrigger("Opened", TriggerIds::OpenedDatabaseFile, {marker("opened")})},
                    false);
    QVERIFY(!triggerSystem()->isLoaded());

    // Nothing is loaded before an unlock. The unlock of the database with the key loads the triggers.
    trigger("actionLockDatabase");
    QTRY_VERIFY(m_dbWidget->isLocked());
    QVERIFY(!triggerSystem()->isLoaded());
    unlock(m_dbWidget);
    QVERIFY(triggerSystem()->isLoaded());
    QCOMPARE(buttonNames(), QStringList({"init", "ready", "opened"}));

    // A later unlock raises only "Opened database file"
    trigger("actionLockDatabase");
    QTRY_VERIFY(m_dbWidget->isLocked());
    unlock(m_dbWidget);
    QCOMPARE(buttonNames(), QStringList({"init", "ready", "opened", "opened"}));
}

void TestGuiTriggers::testVerifyFailure()
{
    installTriggers({makeTrigger("Ready", TriggerIds::AppLoadPost, {marker("ready")})}, false);
    QFile file(m_triggerFile);
    QVERIFY(file.open(QIODevice::ReadWrite));
    QByteArray data = file.readAll();
    data[data.size() - 1] = static_cast<char>(data.at(data.size() - 1) ^ 0x01);
    file.seek(0);
    file.write(data);
    file.close();

    manager()->databaseUnlocked(m_dbWidget);
    QVERIFY(!triggerSystem()->isLoaded());
    QTRY_VERIFY(messageShown("cannot be verified"));
    QVERIFY(buttonNames().isEmpty());
}

void TestGuiTriggers::testKeyMismatch()
{
    TriggerKey::generate().storeInDatabase(m_db.data());
    QVERIFY(TriggerFile::write(m_triggerFile, TriggerKey::generate(), TriggerCollection(), nullptr));
    manager()->databaseUnlocked(m_dbWidget);
    QVERIFY(!triggerSystem()->isLoaded());
    QTRY_VERIFY(messageShown("another database"));
}

void TestGuiTriggers::testCreateKeyAndEditTriggers()
{
    QVERIFY(!QFile::exists(m_triggerFile));
    QVERIFY(!TriggerKey::fromDatabase(m_db.data()).isValid());

    // The pasted trigger comes from the clipboard in KeePass format
    const Trigger pasted = makeTrigger("Pasted", TriggerIds::CustomTbButtonClicked, {marker("clicked")});
    QApplication::clipboard()->setText(QString::fromUtf8(TriggerXml::writeTriggerCollection({pasted})));

    MessageBox::setNextAnswer(MessageBox::Yes);
    TEST_MODAL(TriggersDialog, {
        modal->findChild<QAction*>("pasteTriggersAction")->trigger();
        QCOMPARE(modal->findChild<QTreeWidget*>("triggerList")->topLevelItemCount(), 1);
        modal->accept();
    });
    trigger("actionTriggers");
    QTRY_VERIFY(dialogFinished);

    // The key was created and saved in the database, the file was written, the triggers are loaded
    const auto key = TriggerKey::fromDatabase(m_db.data());
    QVERIFY(key.isValid());
    QVERIFY(!m_db->isModified());
    TriggerCollection read;
    QCOMPARE(TriggerFile::read(m_triggerFile, key, &read, nullptr), TriggerFile::Status::Ok);
    QCOMPARE(read.triggers.size(), 1);
    QCOMPARE(read.triggers.at(0).name, QString("Pasted"));
    QVERIFY(triggerSystem()->isLoaded());
    QCOMPARE(triggerSystem()->collection().triggers.size(), 1);
}

void TestGuiTriggers::testReplaceTriggerFile()
{
    // A file with a key that no unlocked database holds
    const auto otherKey = TriggerKey::generate();
    TriggerCollection other;
    other.triggers << makeTrigger("Other", TriggerIds::AppLoadPost, {});
    QVERIFY(TriggerFile::write(m_triggerFile, otherKey, other, nullptr));

    // Cancel is the default and changes nothing
    MessageBox::setNextAnswer(MessageBox::Cancel);
    trigger("actionTriggers");
    QCOMPARE(TriggerFile::readKeyId(m_triggerFile), otherKey.id());
    QVERIFY(!TriggerKey::fromDatabase(m_db.data()).isValid());

    // Replace: the dialog starts with an empty list; OK writes the file with the key of this database
    MessageBox::setNextAnswer(MessageBox::Replace);
    TEST_MODAL(TriggersDialog, {
        QCOMPARE(modal->findChild<QTreeWidget*>("triggerList")->topLevelItemCount(), 0);
        modal->accept();
    });
    trigger("actionTriggers");
    QTRY_VERIFY(dialogFinished);
    const auto key = TriggerKey::fromDatabase(m_db.data());
    QVERIFY(key.isValid());
    QCOMPARE(TriggerFile::readKeyId(m_triggerFile), key.id());
}

void TestGuiTriggers::testCopyTriggerKey()
{
    installTriggers({}, false);
    const auto key = TriggerKey::fromDatabase(m_db.data());

    // A second database, opened in a second tab
    TemporaryFile secondFile;
    QVERIFY(secondFile.copyFromFile(QDir(KEEPASSX_TEST_DATA_DIR).absoluteFilePath("NewDatabase.kdbx")));
    m_tabWidget->addDatabaseTab(secondFile.fileName());
    auto* second = m_tabWidget->currentDatabaseWidget();
    QVERIFY(second != m_dbWidget);
    unlock(second);

    QVERIFY(manager()->canCopyTriggerKey());
    trigger("actionCopyTriggerKey");
    QVERIFY(TriggerKey::fromDatabase(second->database().data()) == key);
    QVERIFY(!second->database()->isModified());
    QVERIFY(!manager()->canCopyTriggerKey());
}

void TestGuiTriggers::testDialogCopyPaste()
{
    TriggerCollection collection;
    collection.triggers << makeTrigger("First", TriggerIds::AppLoadPost, {});
    collection.triggers << makeTrigger("Second", TriggerIds::AppExit, {});
    TriggersDialog dialog(m_mainWindow.data(), collection, nullptr);
    auto* list = dialog.findChild<QTreeWidget*>("triggerList");
    QCOMPARE(list->topLevelItemCount(), 2);
    QVERIFY(list->topLevelItem(0)->text(1).startsWith("Enabled / On / Initially on"));

    list->topLevelItem(1)->setSelected(true);
    dialog.findChild<QAction*>("copySelectedTriggersAction")->trigger();
    QList<Trigger> copied;
    QVERIFY(TriggerXml::readTriggerCollection(QApplication::clipboard()->text().toUtf8(), &copied));
    QCOMPARE(copied.size(), 1);
    QCOMPARE(copied.at(0).name, QString("Second"));

    // Pasting a trigger whose UUID exists gives it a new UUID
    dialog.findChild<QAction*>("pasteTriggersAction")->trigger();
    const auto result = dialog.collection();
    QCOMPARE(result.triggers.size(), 3);
    QCOMPARE(result.triggers.at(2).name, QString("Second"));
    QVERIFY(result.triggers.at(2).uuid != result.triggers.at(1).uuid);

    // Move up, delete
    list->clearSelection();
    list->topLevelItem(2)->setSelected(true);
    dialog.findChild<QPushButton*>("moveUpButton")->click();
    QCOMPARE(dialog.collection().triggers.at(1).uuid, result.triggers.at(2).uuid);
    dialog.findChild<QPushButton*>("deleteTriggerButton")->click();
    QCOMPARE(dialog.collection().triggers.size(), 2);

    // The global switch disables the other controls
    dialog.findChild<QCheckBox*>("enableTriggersCheckBox")->setChecked(false);
    QVERIFY(!dialog.findChild<QPushButton*>("addTriggerButton")->isEnabled());
    QVERIFY(!dialog.collection().enabled);
}

void TestGuiTriggers::testObjectEditor()
{
    TriggerObject action = object(TriggerIds::ExecuteCommandLine,
                                  {"cmd", "args", "True", QString::number(TriggerEnums::WindowHidden), ""});
    TriggerObjectDialog dialog(m_mainWindow.data(), TriggerObjectKind::Action, action, true);
    auto* table = dialog.findChild<QTableWidget*>("parameterTable");
    QCOMPARE(table->rowCount(), 5);
    QCOMPARE(dialog.object().parameters, action.parameters);

    auto* wait = qobject_cast<QCheckBox*>(table->cellWidget(2, 1));
    QVERIFY(wait);
    wait->setChecked(false);
    QCOMPARE(dialog.object().parameters.at(2), QString("False"));

    // Another type gives the editors of that type, with empty values
    auto* combo = dialog.findChild<QComboBox*>("typeComboBox");
    combo->setCurrentIndex(combo->findData(TriggerIds::Wait));
    QCOMPARE(table->rowCount(), 1);
    QCOMPARE(dialog.object().type, TriggerIds::Wait);
    QCOMPARE(dialog.object().parameters, QStringList({""}));

    // A condition has the "Not" check box
    TriggerObjectDialog conditionDialog(m_mainWindow.data(), TriggerObjectKind::Condition, TriggerObject(), false);
    auto* negate = conditionDialog.findChild<QCheckBox*>("negateCheckBox");
    QVERIFY(negate);
    negate->setChecked(true);
    QVERIFY(conditionDialog.object().negate);
    QCOMPARE(conditionDialog.object().type, TriggerTypes::conditions().first().uuid);
}

void TestGuiTriggers::testDatabaseEvents()
{
    installTriggers({makeTrigger("Saving", TriggerIds::SavingDatabaseFile, {marker("saving")}),
                     makeTrigger("Saved", TriggerIds::SavedDatabaseFile, {marker("saved")}),
                     makeTrigger("Copied", TriggerIds::CopiedEntryInfo, {marker("copied")}),
                     makeTrigger("Closing pre", TriggerIds::ClosingDatabaseFilePre, {marker("pre")}),
                     makeTrigger("Closing post", TriggerIds::ClosingDatabaseFilePost, {marker("post")})});
    QStringList expected;

    m_db->markAsModified();
    QVERIFY(m_dbWidget->save());
    expected << "saving" << "saved";
    QCOMPARE(buttonNames(), expected);

    m_dbWidget->setClipboardTextAndMinimize("secret");
    expected << "copied";
    QCOMPARE(buttonNames(), expected);

    // Lock: before and after the save decision
    trigger("actionLockDatabase");
    QTRY_VERIFY(m_dbWidget->isLocked());
    expected << "pre" << "post";
    QCOMPARE(buttonNames(), expected);
    unlock(m_dbWidget);
}

void TestGuiTriggers::testToolbarButtons()
{
    Trigger onClick = makeTrigger("Click", TriggerIds::CustomTbButtonClicked, {marker("was clicked")});
    onClick.events[0].parameters = QStringList{"MYBUTTON"};
    installTriggers(
        {makeTrigger("Add",
                     TriggerIds::AppExit,
                     {marker("first"), object(TriggerIds::AddToolbarButton, {"MyButton", "Press", "Tip"})}),
         makeTrigger("Remove", TriggerIds::AppInitPost, {object(TriggerIds::RemoveToolbarButton, {"mybutton"})}),
         onClick});

    triggerSystem()->raiseEvent(TriggerIds::AppExit);
    QCOMPARE(buttonNames(), QStringList({"first", "Press"}));
    auto* button = manager()->customToolBarButtons().at(1);
    QCOMPARE(button->toolTip(), QString("Tip"));

    // A click raises the event with the button ID; the ID compares ignoring case
    button->click();
    QCOMPARE(buttonNames(), QStringList({"first", "Press", "was clicked"}));

    triggerSystem()->raiseEvent(TriggerIds::AppInitPost);
    QCOMPARE(buttonNames(), QStringList({"first", "was clicked"}));
}

void TestGuiTriggers::testSynchronizeErrorOptions()
{
    const QString good = m_dir->filePath("good.kdbx");
    QVERIFY(QFile::copy(m_dbFilePath, good));
    const QString missing = m_dir->filePath("missing.kdbx");
    // Without options a failed file stops the synchronization: nothing is saved or copied
    auto* entry = new Entry();
    entry->setUuid(QUuid::createUuid());
    entry->setTitle("Added");
    entry->setGroup(m_db->rootGroup());
    QVERIFY(!m_dbWidget->synchronizeWithFiles({good, missing}));
    QVERIFY(m_db->isModified());
    QTRY_VERIFY(messageShown("Synchronization failed"));

    // Continue: the database is saved and copied over the file that merged. The result is still a failure.
    m_dbWidget->hideMessage();
    DatabaseWidget::SynchronizeOptions options;
    options.continueOnError = true;
    options.silent = true;
    QVERIFY(!m_dbWidget->synchronizeWithFiles({good, missing}, options));
    QVERIFY(!m_db->isModified());
    auto copy = QSharedPointer<Database>::create();
    auto key = QSharedPointer<CompositeKey>::create();
    key->addKey(QSharedPointer<PasswordKey>::create("a"));
    QVERIFY(copy->open(good, key));
    QVERIFY(copy->rootGroup()->findEntryByPath("Added"));
    // Silent: no error message
    QTest::qWait(100);
    QVERIFY(!messageShown("Synchronization failed"));
}

void TestGuiTriggers::testActionExecuteCommand()
{
#ifdef Q_OS_WIN
    QSKIP("The command of this test is for Unix");
#else
    const QString created = m_dir->filePath("created by trigger");
    installTriggers(
        {makeTrigger("Run",
                     TriggerIds::AppExit,
                     {object(TriggerIds::ExecuteCommandLine, {"touch", "\"" + created + "\"", "True", "0", ""})})});
    triggerSystem()->raiseEvent(TriggerIds::AppExit);
    QVERIFY(QFile::exists(created));

    // A program that is not found is an execution error
    installTriggers({makeTrigger(
        "Missing", TriggerIds::AppExit, {object(TriggerIds::ExecuteCommandLine, {"no-such-program-kpxc"})})});
    MessageBox::setNextAnswer(MessageBox::Ok);
    triggerSystem()->raiseEvent(TriggerIds::AppExit);
#endif
}

void TestGuiTriggers::testActionSaveCloseActivate()
{
    TemporaryFile secondFile;
    QVERIFY(secondFile.copyFromFile(QDir(KEEPASSX_TEST_DATA_DIR).absoluteFilePath("NewDatabase.kdbx")));
    // The start events are raised by the load, so these triggers use the toolbar button event
    Trigger activate =
        makeTrigger("Activate",
                    TriggerIds::CustomTbButtonClicked,
                    {object(TriggerIds::ActivateDatabaseTab, {QFileInfo(m_dbFilePath).fileName(), "0"})});
    activate.events[0].parameters = QStringList{"activate"};
    Trigger close = makeTrigger("Close", TriggerIds::CustomTbButtonClicked, {object(TriggerIds::CloseDatabase)});
    close.events[0].parameters = QStringList{"close"};
    installTriggers({makeTrigger("Save", TriggerIds::AppExit, {object(TriggerIds::SaveDatabase)}), activate, close});
    auto raiseButton = [](const QString& id) {
        TriggerEventProperties properties;
        properties.commandId = id;
        triggerSystem()->raiseEvent(TriggerIds::CustomTbButtonClicked, properties);
    };

    m_db->markAsModified();
    triggerSystem()->raiseEvent(TriggerIds::AppExit);
    QVERIFY(!m_db->isModified());

    m_tabWidget->addDatabaseTab(secondFile.fileName());
    QVERIFY(m_tabWidget->currentDatabaseWidget() != m_dbWidget);
    raiseButton("activate");
    QCOMPARE(m_tabWidget->currentDatabaseWidget(), m_dbWidget.data());

    // Close the second tab: activate it first
    m_tabWidget->setCurrentIndex(1);
    const int count = m_tabWidget->count();
    raiseButton("close");
    QCOMPARE(m_tabWidget->count(), count - 1);
    QCOMPARE(m_tabWidget->currentDatabaseWidget(), m_dbWidget.data());
}

void TestGuiTriggers::testActionOpenDatabase()
{
    TemporaryFile secondFile;
    QVERIFY(secondFile.copyFromFile(QDir(KEEPASSX_TEST_DATA_DIR).absoluteFilePath("NewDatabase.kdbx")));
    installTriggers(
        {makeTrigger("Open",
                     TriggerIds::AppExit,
                     {object(TriggerIds::OpenDatabaseFile, {secondFile.fileName(), "", "", "a", "", "False"})})});
    const int count = m_tabWidget->count();
    triggerSystem()->raiseEvent(TriggerIds::AppExit);
    QTRY_COMPARE(m_tabWidget->count(), count + 1);
    auto* opened = m_tabWidget->currentDatabaseWidget();
    QTRY_VERIFY(!opened->isLocked());
}

void TestGuiTriggers::testActionImport()
{
    // A KeePass XML file with one entry
    auto source = QSharedPointer<Database>::create();
    auto* entry = new Entry();
    entry->setUuid(QUuid::createUuid());
    entry->setTitle("Imported entry");
    entry->setGroup(source->rootGroup());
    QByteArray xml;
    QVERIFY(source->extract(xml));
    const QString xmlFile = m_dir->filePath("import.xml");
    QFile file(xmlFile);
    QVERIFY(file.open(QIODevice::WriteOnly));
    file.write(xml);
    file.close();

    installTriggers({makeTrigger(
        "Import",
        TriggerIds::AppExit,
        {object(
            TriggerIds::ImportIntoDatabase,
            {xmlFile, "keepass xml (2.x)", QString::number(TriggerEnums::MergeCreateNewUuids), "", "", "False"})})});
    triggerSystem()->raiseEvent(TriggerIds::AppExit);
    QVERIFY(m_db->rootGroup()->findEntryByPath("Imported entry"));
    QVERIFY(m_db->rootGroup()->findEntryByPath("Imported entry")->uuid() != entry->uuid());
    QVERIFY(m_db->isModified());

    // An unknown format is an execution error
    installTriggers({makeTrigger(
        "Unknown", TriggerIds::AppExit, {object(TriggerIds::ImportIntoDatabase, {xmlFile, "Some Format", "0"})})});
    MessageBox::setNextAnswer(MessageBox::Ok);
    triggerSystem()->raiseEvent(TriggerIds::AppExit);
}

void TestGuiTriggers::testActionExport()
{
    const QString csvFile = m_dir->filePath("export.csv");
    installTriggers({makeTrigger(
        "Export", TriggerIds::AppExit, {object(TriggerIds::ExportDatabase, {csvFile, "KeePass CSV (1.x)", "", ""})})});

    // The master key is asked again before the export
    TEST_MODAL(QDialog, {
        modal->findChild<QLineEdit*>("triggerKeyPassword")->setText("a");
        modal->accept();
    });
    triggerSystem()->raiseEvent(TriggerIds::AppExit);
    QTRY_VERIFY(dialogFinished);
    QFile file(csvFile);
    QVERIFY(file.open(QIODevice::ReadOnly));
    const QByteArray csv = file.readAll();
    QVERIFY(csv.startsWith("\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\r\n"));
    QVERIFY(csv.contains("\"Sample Entry\""));
}

void TestGuiTriggers::testActionMessageBoxAbort()
{
    using namespace TriggerEnums;
    installTriggers({makeTrigger("Ask",
                                 TriggerIds::AppExit,
                                 {object(TriggerIds::ShowMessageBox,
                                         {"Continue?",
                                          "Text",
                                          QString::number(IconQuestion),
                                          QString::number(ButtonsYesNo),
                                          "0",
                                          QString::number(MessageConditionCancelNo),
                                          QString::number(MessageActionAbort),
                                          ""}),
                                  marker("after")})});
    TEST_MODAL(QMessageBox, {
        QVERIFY(modal->informativeText().contains("Trigger: 'Ask'."));
        modal->button(QMessageBox::No)->click();
    });
    triggerSystem()->raiseEvent(TriggerIds::AppExit);
    QTRY_VERIFY(dialogFinished);
    // "No" aborted the remaining actions of the trigger
    QVERIFY(!buttonNames().contains("after"));
}

void TestGuiTriggers::testActionShowEntriesByTag()
{
    installTriggers({makeTrigger("Tag", TriggerIds::AppExit, {object(TriggerIds::ShowEntriesByTag, {"my tag"})})});
    triggerSystem()->raiseEvent(TriggerIds::AppExit);
    auto* searchEdit = m_mainWindow->findChild<QLineEdit*>("searchEdit");
    QVERIFY(searchEdit);
    QTRY_COMPARE(searchEdit->text(), QString("tag:\"my tag\""));
}

int main(int argc, char* argv[])
{
    Application app(argc, argv);
    app.setApplicationName("KeePassXC");
    app.setQuitOnLastWindowClosed(false);
    app.applyTheme();
    TestGuiTriggers tc;
    QTEST_SET_MAIN_SOURCE_PATH
    return QTest::qExec(&tc, argc, argv);
}

#include "TestGuiTriggers.moc"
