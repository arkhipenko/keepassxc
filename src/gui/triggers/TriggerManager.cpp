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

#include "TriggerManager.h"

#include "TriggerDataExchange.h"
#include "TriggersDialog.h"
#include "autotype/AutoType.h"
#include "core/Clock.h"
#include "core/CustomData.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "core/triggers/TriggerPlaceholders.h"
#include "core/triggers/TriggerTypes.h"
#include "core/triggers/TriggerUtil.h"
#include "gui/Clipboard.h"
#include "gui/DatabaseTabWidget.h"
#include "gui/DatabaseWidget.h"
#include "gui/MessageBox.h"

#include <QApplication>
#include <QClipboard>
#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QGuiApplication>
#include <QKeyEvent>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QToolBar>
#include <QToolButton>
#include <QUrl>

#ifdef Q_OS_WIN
// clang-format off
#include <windows.h>
#include <shellapi.h>
// clang-format on
#endif

namespace
{
    // A text that starts with a scheme of at least two letters is a URL (a drive letter is not)
    bool looksLikeUrl(const QString& text)
    {
        static const QRegularExpression scheme("^[A-Za-z][A-Za-z0-9+.-]+:");
        return scheme.match(text.trimmed()).hasMatch();
    }

    // Splits a command line into the program and the rest (KeePass: StrUtil.SplitCommandLine)
    void splitCommandLine(const QString& commandLine, QString* program, QString* arguments)
    {
        const QString command = commandLine.trimmed();
        program->clear();
        arguments->clear();
        if (command.startsWith('"')) {
            const int end = command.indexOf('"', 1);
            if (end < 0) {
                *program = command.mid(1);
                return;
            }
            *program = command.mid(1, end - 1);
            *arguments = command.mid(end + 1).trimmed();
            return;
        }
        const int end = command.indexOf(' ');
        if (end < 0) {
            *program = command;
            return;
        }
        *program = command.left(end);
        *arguments = command.mid(end + 1).trimmed();
    }
} // namespace

TriggerManager::TriggerManager(QWidget* mainWindow,
                               DatabaseTabWidget* tabWidget,
                               QToolBar* toolBar,
                               QAction* toolBarAnchor)
    : QObject(mainWindow)
    , m_mainWindow(mainWindow)
    , m_tabWidget(tabWidget)
    , m_toolBar(toolBar)
    , m_toolBarAnchor(toolBarAnchor)
    , m_triggerFilePath(TriggerFile::defaultPath())
{
    triggerSystem()->setHost(this);
    // Captures the start time for imports (see TriggerDataExchange::applicationStartTime)
    TriggerDataExchange::applicationStartTime();

    // KeePass checks the periodic event in its main timer, once per second
    m_periodicTimer.setInterval(1000);
    connect(&m_periodicTimer, &QTimer::timeout, this, &TriggerManager::periodicTick);

    qApp->installEventFilter(this);
}

TriggerManager::~TriggerManager()
{
    if (triggerSystem()->host() == this) {
        triggerSystem()->setHost(nullptr);
    }
}

QString TriggerManager::triggerFilePath() const
{
    return m_triggerFilePath;
}

void TriggerManager::setTriggerFilePath(const QString& path)
{
    m_triggerFilePath = path;
}

QList<DatabaseWidget*> TriggerManager::unlockedDatabaseWidgets() const
{
    QList<DatabaseWidget*> result;
    if (!m_tabWidget) {
        return result;
    }
    // The active database first
    auto* active = activeUnlockedDatabaseWidget();
    if (active) {
        result << active;
    }
    for (int i = 0; i < m_tabWidget->count(); ++i) {
        auto* dbWidget = m_tabWidget->databaseWidgetFromIndex(i);
        if (dbWidget && dbWidget != active && !dbWidget->isLocked()) {
            result << dbWidget;
        }
    }
    return result;
}

DatabaseWidget* TriggerManager::activeUnlockedDatabaseWidget() const
{
    if (!m_tabWidget) {
        return nullptr;
    }
    auto* dbWidget = m_tabWidget->currentDatabaseWidget();
    return (dbWidget && !dbWidget->isLocked()) ? dbWidget : nullptr;
}

QSharedPointer<Database> TriggerManager::activeDatabase()
{
    auto* dbWidget = activeUnlockedDatabaseWidget();
    return dbWidget ? dbWidget->database() : QSharedPointer<Database>();
}

/**
 * Load sequence: the triggers load at the first unlock of a database that holds the trigger key
 * of the trigger file. The application start events are raised at that moment.
 */
void TriggerManager::databaseUnlocked(DatabaseWidget* dbWidget)
{
    if (!dbWidget || dbWidget->isLocked()) {
        return;
    }

    TriggerEventProperties properties;
    properties.database = dbWidget->database();

    if (triggerSystem()->isLoaded()) {
        triggerSystem()->raiseEvent(TriggerIds::OpenedDatabaseFile, properties);
        return;
    }

    const auto key = TriggerKey::fromDatabase(dbWidget->database().data());
    const QString path = triggerFilePath();
    if (!key.isValid() || !QFileInfo::exists(path)) {
        return;
    }

    const QByteArray fileKeyId = TriggerFile::readKeyId(path);
    if (!fileKeyId.isEmpty() && fileKeyId != key.id()) {
        if (!m_mismatchInfoShown) {
            m_mismatchInfoShown = true;
            dbWidget->showMessage(tr("The trigger file uses the trigger key of another database."),
                                  MessageWidget::Information);
        }
        return;
    }

    TriggerCollection collection;
    QString error;
    if (TriggerFile::read(path, key, &collection, &error) != TriggerFile::Status::Ok) {
        if (!m_verifyWarningShown) {
            m_verifyWarningShown = true;
            dbWidget->showMessage(tr("The trigger file cannot be verified. No trigger runs."),
                                  MessageWidget::Warning,
                                  true,
                                  MessageWidget::DisableAutoHide);
        }
        return;
    }

    triggerSystem()->load(collection);
    startTriggers();
    if (!m_startEventsRaised) {
        m_startEventsRaised = true;
        triggerSystem()->raiseEvent(TriggerIds::AppInitPost);
        triggerSystem()->raiseEvent(TriggerIds::AppLoadPost);
    }
    triggerSystem()->raiseEvent(TriggerIds::OpenedDatabaseFile, properties);
}

void TriggerManager::startTriggers()
{
    m_periodicTimer.start();
    if (triggerSystem()->usesObsoleteEvent()) {
        // KeePass: EcasTriggerSystem.CheckTriggers
        MessageBox::warning(m_mainWindow,
                            tr("Triggers"),
                            tr("A trigger uses the event \"User interface state updated\". "
                               "This event is obsolete and is never raised."));
    }
}

void TriggerManager::reset()
{
    triggerSystem()->unload();
    m_periodicTimer.stop();
    m_startEventsRaised = false;
    m_verifyWarningShown = false;
    m_mismatchInfoShown = false;
    while (!m_customButtons.isEmpty()) {
        removeToolBarButton(m_customButtons.first().first);
    }
}

void TriggerManager::applicationExit()
{
    triggerSystem()->raiseEvent(TriggerIds::AppExit);
    m_periodicTimer.stop();
}

void TriggerManager::periodicTick()
{
    // Only while the main window is enabled and no dialog is open (KeePass: MainForm main timer)
    if (m_inPeriodicEvent || !m_mainWindow || !m_mainWindow->isEnabled() || QApplication::activeModalWidget()) {
        return;
    }
    m_inPeriodicEvent = true;
    triggerSystem()->raisePeriodicEvent();
    m_inPeriodicEvent = false;
}

bool TriggerManager::eventFilter(QObject* watched, QEvent* event)
{
    const auto type = event->type();
    if (type == QEvent::KeyPress || type == QEvent::MouseButtonPress || type == QEvent::Wheel) {
        triggerSystem()->notifyUserActivity();
    }
    return QObject::eventFilter(watched, event);
}

QString TriggerManager::compilePlaceholders(const QString& text, bool forCommandLine)
{
    TriggerPlaceholders::Context context;
    auto* dbWidget = activeUnlockedDatabaseWidget();
    if (dbWidget) {
        context.entry = dbWidget->currentSelectedEntry();
        context.database = dbWidget->database().data();
        context.selectedGroup = dbWidget->currentGroup();
    }
    context.forCommandLine = forCommandLine;
    context.clipboardText = [] { return QGuiApplication::clipboard()->text(); };
    context.setClipboardText = [](const QString& value) {
        clipboard()->setText(value);
        // KeePass copies {CLIPBOARD-SET:...} as entry data
        triggerSystem()->raiseEntryDataCopied(value);
    };
    context.confirmCommand = [this](const QString& program, const QString& arguments) {
        const auto answer = MessageBox::question(
            m_mainWindow,
            tr("Run Command"),
            tr("A trigger placeholder wants to run this command:\n\n%1 %2\n\nRun it?").arg(program, arguments),
            MessageBox::Yes | MessageBox::No,
            MessageBox::No);
        return answer == MessageBox::Yes;
    };
    return TriggerPlaceholders::compile(text, context);
}

void TriggerManager::showExecutionError(const QString& error)
{
    MessageBox::warning(m_mainWindow, tr("Trigger execution failed"), tr("Trigger execution failed.") + "\n\n" + error);
}

bool TriggerManager::executeAction(const TriggerObject& action, TriggerContext& context, QString* error)
{
    auto* system = triggerSystem();
    const auto& type = action.type;
    const auto& params = action.parameters;

    if (type == TriggerIds::ExecuteCommandLine) {
        // KeePass: EcasDefaultActionProvider.ExecuteShellCmd
        const QString command = TriggerUtil::stripPathQuotes(compilePlaceholders(params.value(0), false));
        if (command.isEmpty()) {
            return true;
        }
        const QString arguments = system->compiledParam(action, 1, true);
        const bool wait = TriggerUtil::paramBool(params, 2);
        const quint32 windowStyle = TriggerUtil::paramUInt(params, 3);
        const QString verb = system->compiledParam(action, 4);
        return executeCommand(command, arguments, wait, windowStyle, verb, error);
    }

    if (type == TriggerIds::OpenDatabaseFile) {
        const QString path = system->compiledPath(action, 0);
        if (path.isEmpty() || !m_tabWidget) {
            return true;
        }
        if (TriggerUtil::paramBool(params, 5)) {
            *error = tr("The Windows user account is not supported as a key part.");
            return false;
        }
        const QString password = system->compiledParam(action, 3);
        const QString keyFile = system->compiledPath(action, 4);
        // Without a key part, the unlock view is shown
        m_tabWidget->addDatabaseTab(path, false, password, keyFile);
        return true;
    }

    if (type == TriggerIds::SaveDatabase) {
        auto* dbWidget = activeUnlockedDatabaseWidget();
        if (dbWidget) {
            // Saves also when nothing changed. A database without a path gets Save As.
            dbWidget->save();
        }
        return true;
    }

    if (type == TriggerIds::SynchronizeDatabase) {
        auto* dbWidget = activeUnlockedDatabaseWidget();
        const QStringList paths = system->compiledPaths(action, 0);
        if (!dbWidget || paths.isEmpty()) {
            return true;
        }
        DatabaseWidget::SynchronizeOptions options;
        options.silent = TriggerUtil::paramBool(params, 3);
        options.continueOnError = TriggerUtil::paramBool(params, 4);
        dbWidget->synchronizeWithFiles(paths, options);
        return true;
    }

    if (type == TriggerIds::ImportIntoDatabase) {
        auto* dbWidget = activeUnlockedDatabaseWidget();
        if (!dbWidget) {
            return true;
        }
        if (TriggerUtil::paramBool(params, 5)) {
            *error = tr("The Windows user account is not supported as a key part.");
            return false;
        }
        TriggerDataExchange::ImportParameters parameters;
        parameters.filePath = system->compiledPath(action, 0);
        parameters.format = system->compiledParam(action, 1);
        parameters.method = TriggerUtil::paramUInt(params, 2);
        parameters.password = system->compiledParam(action, 3);
        parameters.keyFile = system->compiledPath(action, 4);
        return TriggerDataExchange::importIntoDatabase(m_mainWindow, dbWidget->database(), parameters, error);
    }

    if (type == TriggerIds::ExportDatabase) {
        auto* dbWidget = activeUnlockedDatabaseWidget();
        if (!dbWidget) {
            return true;
        }
        TriggerDataExchange::ExportParameters parameters;
        parameters.filePath = system->compiledPath(action, 0);
        parameters.format = system->compiledParam(action, 1);
        parameters.groupFilter = system->compiledParam(action, 2);
        parameters.tagFilter = system->compiledParam(action, 3);
        return TriggerDataExchange::exportDatabase(m_mainWindow, dbWidget->database(), parameters, error);
    }

    if (type == TriggerIds::CloseDatabase) {
        if (m_tabWidget && m_tabWidget->currentDatabaseWidget()) {
            m_tabWidget->closeCurrentDatabaseTab();
        }
        return true;
    }

    if (type == TriggerIds::ActivateDatabaseTab) {
        // KeePass: EcasDefaultActionProvider.ActivateDatabaseTab
        if (!m_tabWidget) {
            return true;
        }
        const QString name = system->compiledPath(action, 0);
        const quint32 filter = TriggerUtil::paramUInt(params, 1, 0);
        const auto triggering = context.properties->database;
        for (int i = 0; i < m_tabWidget->count(); ++i) {
            auto* dbWidget = m_tabWidget->databaseWidgetFromIndex(i);
            if (!dbWidget) {
                continue;
            }
            if (filter == TriggerEnums::FilterAll) {
                if (name.isEmpty()) {
                    continue; // A name is required in this case
                }
            } else if (filter == TriggerEnums::FilterTriggering) {
                if (!triggering || dbWidget->database() != triggering) {
                    continue;
                }
            } else {
                continue;
            }
            const QString path = QDir::toNativeSeparators(dbWidget->database()->filePath());
            if (name.isEmpty() || (!path.isEmpty() && path.contains(name, Qt::CaseInsensitive))) {
                m_tabWidget->setCurrentIndex(i);
                break;
            }
        }
        return true;
    }

    if (type == TriggerIds::ShowMessageBox) {
        return showMessageBox(action, context, error);
    }

    if (type == TriggerIds::PerformGlobalAutoType) {
        if (m_tabWidget) {
            m_tabWidget->performGlobalAutoType({});
        }
        return true;
    }

    if (type == TriggerIds::PerformSelectedAutoType) {
        // The sequence is not compiled here; the auto-type engine compiles it
        auto* dbWidget = activeUnlockedDatabaseWidget();
        auto* entry = dbWidget ? dbWidget->currentSelectedEntry() : nullptr;
        if (!entry) {
            return true;
        }
        const QString sequence = TriggerUtil::paramString(params, 0);
        if (sequence.isEmpty()) {
            autoType()->performAutoType(entry);
        } else {
            autoType()->performAutoTypeWithSequence(entry, sequence);
        }
        return true;
    }

    if (type == TriggerIds::ShowEntriesByTag) {
        const QString tag = system->compiledParam(action, 0);
        auto* dbWidget = activeUnlockedDatabaseWidget();
        if (!tag.isEmpty() && dbWidget) {
            QString escaped = tag;
            escaped.replace("\"", "\\\"");
            emit dbWidget->requestSearch(QString("tag:\"%1\"").arg(escaped));
        }
        return true;
    }

    if (type == TriggerIds::AddToolbarButton) {
        addToolBarButton(
            system->compiledParam(action, 0), system->compiledParam(action, 1), system->compiledParam(action, 2));
        return true;
    }

    if (type == TriggerIds::RemoveToolbarButton) {
        removeToolBarButton(system->compiledParam(action, 0));
        return true;
    }

    return true;
}

bool TriggerManager::executeCommand(const QString& command,
                                    const QString& arguments,
                                    bool wait,
                                    quint32 windowStyle,
                                    const QString& verb,
                                    QString* error)
{
#ifdef Q_OS_WIN
    // KeePass rule: shell execute, unless there is no verb, the window is normal or hidden,
    // and the command ends with .exe or .com (KeePass: EcasDefaultActionProvider.ExecuteShellCmd)
    bool shellExecute = true;
    if (verb.isEmpty() && windowStyle != TriggerEnums::WindowMinimized
        && windowStyle != TriggerEnums::WindowMaximized) {
        QString trimmed = command;
        while (!trimmed.isEmpty() && QString("\"' \t\r\n").contains(trimmed.back())) {
            trimmed.chop(1);
        }
        if (trimmed.endsWith(".exe", Qt::CaseInsensitive) || trimmed.endsWith(".com", Qt::CaseInsensitive)) {
            shellExecute = false;
        }
    }

    int showCommand = SW_SHOWNORMAL;
    if (windowStyle == TriggerEnums::WindowHidden) {
        showCommand = SW_HIDE;
    } else if (windowStyle == TriggerEnums::WindowMinimized) {
        showCommand = SW_SHOWMINIMIZED;
    } else if (windowStyle == TriggerEnums::WindowMaximized) {
        showCommand = SW_SHOWMAXIMIZED;
    }

    if (shellExecute) {
        const std::wstring file = command.toStdWString();
        const std::wstring params = arguments.toStdWString();
        const std::wstring operation = verb.toStdWString();
        SHELLEXECUTEINFOW info = {};
        info.cbSize = sizeof(info);
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
        info.lpVerb = verb.isEmpty() ? nullptr : operation.c_str();
        info.lpFile = file.c_str();
        info.lpParameters = arguments.isEmpty() ? nullptr : params.c_str();
        info.nShow = showCommand;
        if (!ShellExecuteExW(&info)) {
            *error = tr("The command cannot be started: %1").arg(command);
            return false;
        }
        if (info.hProcess) {
            if (wait) {
                WaitForSingleObject(info.hProcess, INFINITE);
            }
            CloseHandle(info.hProcess);
        }
        return true;
    }

    QProcess process;
    process.setProgram(command);
    process.setNativeArguments(arguments);
    process.setCreateProcessArgumentsModifier([showCommand](QProcess::CreateProcessArguments* args) {
        args->startupInfo->dwFlags |= STARTF_USESHOWWINDOW;
        args->startupInfo->wShowWindow = static_cast<WORD>(showCommand);
        if (showCommand == SW_HIDE) {
            args->flags |= CREATE_NO_WINDOW;
        }
    });
    if (!wait) {
        if (!process.startDetached()) {
            *error = tr("The command cannot be started: %1").arg(command);
            return false;
        }
        return true;
    }
    process.start();
    if (!process.waitForStarted(-1)) {
        *error = tr("The command cannot be started: %1").arg(command);
        return false;
    }
    process.waitForFinished(-1);
    return true;
#else
    // Verb and window style have no effect here
    Q_UNUSED(windowStyle);
    Q_UNUSED(verb);

    if (looksLikeUrl(command) && !command.startsWith("file:", Qt::CaseInsensitive)) {
        if (!QDesktopServices::openUrl(QUrl(command))) {
            *error = tr("The URL cannot be opened: %1").arg(command);
            return false;
        }
        return true;
    }

    QString localPath = command;
    if (command.startsWith("file:", Qt::CaseInsensitive)) {
        localPath = QUrl(command).toLocalFile();
    }
    const QFileInfo info(localPath);
    QString program;
    if (info.exists() && info.isFile() && info.isExecutable()) {
        program = info.absoluteFilePath();
    } else if (info.exists()) {
        // A document opens with the default application of the desktop
        if (!QDesktopServices::openUrl(QUrl::fromLocalFile(info.absoluteFilePath()))) {
            *error = tr("The file cannot be opened: %1").arg(command);
            return false;
        }
        return true;
    } else {
        program = QStandardPaths::findExecutable(command);
        if (program.isEmpty()) {
            *error = tr("The file was not found: %1").arg(command);
            return false;
        }
    }

    QProcess process;
    process.setProgram(program);
    process.setArguments(QProcess::splitCommand(arguments));
    if (!wait) {
        if (!process.startDetached()) {
            *error = tr("The command cannot be started: %1").arg(command);
            return false;
        }
        return true;
    }
    // Wait for exit blocks the user interface until the process ends, as in KeePass
    process.start();
    if (!process.waitForStarted(-1)) {
        *error = tr("The command cannot be started: %1").arg(command);
        return false;
    }
    process.closeWriteChannel();
    process.waitForFinished(-1);
    return true;
#endif
}

bool TriggerManager::openUrlOrCommand(const QString& text, QString* error)
{
    // KeePass: WinUtil.OpenUrl. A URL opens in the browser, other text runs as a command line.
    const QString trimmed = text.trimmed();
    if (trimmed.isEmpty()) {
        return true;
    }
    if (looksLikeUrl(trimmed) && !trimmed.startsWith("cmd://", Qt::CaseInsensitive)) {
        return executeCommand(trimmed, {}, false, TriggerEnums::WindowNormal, {}, error);
    }
    QString commandLine = trimmed;
    if (commandLine.startsWith("cmd://", Qt::CaseInsensitive)) {
        commandLine = commandLine.mid(6);
    }
    QString program;
    QString arguments;
    splitCommandLine(commandLine, &program, &arguments);
    return executeCommand(program, arguments, false, TriggerEnums::WindowNormal, {}, error);
}

bool TriggerManager::showMessageBox(const TriggerObject& action, TriggerContext& context, QString* error)
{
    // KeePass: EcasDefaultActionProvider.ShowMessageBox
    using namespace TriggerEnums;
    auto* system = triggerSystem();
    const QString mainInstruction = system->compiledParam(action, 0);
    const QString text = system->compiledParam(action, 1);
    const quint32 icon = TriggerUtil::paramUInt(action.parameters, 2, 0);
    const quint32 buttons = TriggerUtil::paramUInt(action.parameters, 3, 0);
    const quint32 defaultButton = TriggerUtil::paramUInt(action.parameters, 4, 0);

    QMessageBox box(m_mainWindow);
    box.setWindowTitle(QApplication::applicationName());
    QString informative = text;
    if (!mainInstruction.isEmpty()) {
        box.setText(QString("<b>%1</b>").arg(mainInstruction.toHtmlEscaped()));
        box.setTextFormat(Qt::RichText);
    } else {
        box.setText(text);
        informative.clear();
    }
    const QString triggerName = context.trigger ? context.trigger->name : QString();
    if (!triggerName.isEmpty()) {
        const QString footer = tr("Trigger: '%1'.").arg(triggerName);
        informative = informative.isEmpty() ? footer : informative + "\n\n" + footer;
    }
    box.setInformativeText(informative);

    switch (icon) {
    case IconInformation:
        box.setIcon(QMessageBox::Information);
        break;
    case IconQuestion:
        box.setIcon(QMessageBox::Question);
        break;
    case IconWarning:
        box.setIcon(QMessageBox::Warning);
        break;
    case IconError:
        box.setIcon(QMessageBox::Critical);
        break;
    default:
        box.setIcon(QMessageBox::NoIcon);
        break;
    }

    QList<QAbstractButton*> order;
    bool canCancel = false;
    QAbstractButton* yesButton = nullptr;
    QAbstractButton* noButton = nullptr;
    if (buttons == ButtonsOkCancel) {
        yesButton = box.addButton(QMessageBox::Ok);
        noButton = box.addButton(QMessageBox::Cancel);
        canCancel = true;
    } else if (buttons == ButtonsYesNo) {
        yesButton = box.addButton(QMessageBox::Yes);
        noButton = box.addButton(QMessageBox::No);
        canCancel = true;
    } else {
        yesButton = box.addButton(QMessageBox::Ok);
    }
    order << yesButton;
    if (noButton) {
        order << noButton;
        box.setEscapeButton(noButton);
    }
    if (defaultButton < static_cast<quint32>(order.size())) {
        box.setDefaultButton(qobject_cast<QPushButton*>(order.at(static_cast<int>(defaultButton))));
    }

    box.exec();
    const bool answeredYes = (box.clickedButton() == yesButton);
    const bool answeredNo = !answeredYes;

    const quint32 condition = TriggerUtil::paramUInt(action.parameters, 5, 0);
    const bool perform =
        (condition == MessageConditionOkYes && answeredYes) || (condition == MessageConditionCancelNo && answeredNo);
    if (!perform) {
        return true;
    }

    const quint32 followUp = TriggerUtil::paramUInt(action.parameters, 6, 0);
    if (followUp == MessageActionAbort) {
        if (canCancel) {
            context.cancel = true;
        }
    } else if (followUp == MessageActionCommand) {
        const QString parameters = system->compiledParam(action, 7);
        if (!parameters.isEmpty()) {
            return openUrlOrCommand(parameters, error);
        }
    }
    return true;
}

void TriggerManager::addToolBarButton(const QString& id, const QString& name, const QString& description)
{
    // KeePass: MainForm.AddCustomToolBarButton. ID and name are required; duplicates are not checked.
    if (id.isEmpty() || name.isEmpty() || !m_toolBar) {
        return;
    }
    if (m_customButtons.isEmpty()) {
        m_customSeparator = m_toolBar->insertSeparator(m_toolBarAnchor);
    }
    auto* button = new QToolButton(m_toolBar);
    button->setText(name);
    button->setToolButtonStyle(Qt::ToolButtonTextOnly);
    button->setAutoRaise(true);
    button->setProperty("triggerButtonId", id);
    if (!description.isEmpty()) {
        button->setToolTip(description);
    }
    connect(button, &QToolButton::clicked, this, &TriggerManager::customButtonClicked);
    QAction* action = m_toolBar->insertWidget(m_toolBarAnchor, button);
    m_customButtons.append({id, action});
}

void TriggerManager::removeToolBarButton(const QString& id)
{
    if (id.isEmpty() || !m_toolBar) {
        return;
    }
    for (int i = 0; i < m_customButtons.size(); ++i) {
        if (m_customButtons.at(i).first.compare(id, Qt::CaseInsensitive) == 0) {
            auto action = m_customButtons.at(i).second;
            m_customButtons.removeAt(i);
            if (action) {
                m_toolBar->removeAction(action);
                action->deleteLater();
            }
            break;
        }
    }
    if (m_customButtons.isEmpty() && m_customSeparator) {
        m_toolBar->removeAction(m_customSeparator);
        m_customSeparator->deleteLater();
    }
}

QList<QToolButton*> TriggerManager::customToolBarButtons() const
{
    QList<QToolButton*> buttons;
    if (!m_toolBar) {
        return buttons;
    }
    for (const auto& pair : m_customButtons) {
        if (pair.second) {
            if (auto* button = qobject_cast<QToolButton*>(m_toolBar->widgetForAction(pair.second))) {
                buttons << button;
            }
        }
    }
    return buttons;
}

void TriggerManager::customButtonClicked()
{
    auto* button = qobject_cast<QToolButton*>(sender());
    if (!button) {
        return;
    }
    TriggerEventProperties properties;
    properties.commandId = button->property("triggerButtonId").toString();
    properties.database = activeDatabase();
    triggerSystem()->raiseEvent(TriggerIds::CustomTbButtonClicked, properties);
}

bool TriggerManager::findKeyHolder(KeyHolder* holder, TriggerCollection* collection) const
{
    const QString path = triggerFilePath();
    const bool fileExists = QFileInfo::exists(path);
    const QByteArray fileKeyId = fileExists ? TriggerFile::readKeyId(path) : QByteArray();

    for (auto* dbWidget : unlockedDatabaseWidgets()) {
        const auto key = TriggerKey::fromDatabase(dbWidget->database().data());
        if (!key.isValid()) {
            continue;
        }
        if (!fileExists) {
            holder->dbWidget = dbWidget;
            holder->key = key;
            *collection = TriggerCollection();
            return true;
        }
        if (key.id() != fileKeyId) {
            continue;
        }
        TriggerCollection fileCollection;
        if (TriggerFile::read(path, key, &fileCollection, nullptr) == TriggerFile::Status::Ok) {
            holder->dbWidget = dbWidget;
            holder->key = key;
            *collection = fileCollection;
            return true;
        }
    }
    return false;
}

bool TriggerManager::saveDatabaseWithKey(DatabaseWidget* dbWidget, const TriggerKey& key)
{
    auto db = dbWidget->database();
    const QString previous = db->metadata()->customData()->value(CustomData::TriggerKey);
    key.storeInDatabase(db.data());
    if (dbWidget->save()) {
        return true;
    }
    // The key is not kept when the database cannot be saved
    if (previous.isEmpty()) {
        TriggerKey::removeFromDatabase(db.data());
    } else {
        db->metadata()->customData()->set(CustomData::TriggerKey, previous);
    }
    return false;
}

/**
 * Edit sequence of the sealed trigger file.
 */
void TriggerManager::editTriggers()
{
    KeyHolder holder;
    TriggerCollection collection;
    const bool fromFile = findKeyHolder(&holder, &collection);
    if (!fromFile) {
        auto* active = activeUnlockedDatabaseWidget();
        if (!active) {
            MessageBox::information(
                m_mainWindow, tr("Triggers"), tr("Unlock the database that holds the trigger key."));
            return;
        }
        const QString name = active->displayName();
        const auto existingKey = TriggerKey::fromDatabase(active->database().data());
        if (!QFileInfo::exists(triggerFilePath())) {
            const auto answer = MessageBox::question(
                m_mainWindow,
                tr("Triggers"),
                tr("Create a trigger key in database %1? The database is saved now, together with any unsaved changes.")
                    .arg(name),
                MessageBox::Yes | MessageBox::Cancel,
                MessageBox::Yes);
            if (answer != MessageBox::Yes) {
                return;
            }
        } else {
            const auto answer =
                MessageBox::question(m_mainWindow,
                                     tr("Triggers"),
                                     tr("No unlocked database opens the trigger file. Unlock the database that holds "
                                        "the trigger key, or replace the trigger file with an empty list protected by "
                                        "database %1. The current triggers are then lost.")
                                         .arg(name),
                                     MessageBox::Replace | MessageBox::Cancel,
                                     MessageBox::Cancel);
            if (answer != MessageBox::Replace) {
                return;
            }
        }
        const auto key = existingKey.isValid() ? existingKey : TriggerKey::generate();
        if (!existingKey.isValid() && !saveDatabaseWithKey(active, key)) {
            MessageBox::warning(
                m_mainWindow, tr("Triggers"), tr("The database could not be saved. No trigger key was created."));
            return;
        }
        holder.dbWidget = active;
        holder.key = key;
        collection = TriggerCollection();
    }

    // The dialog edits a copy of the loaded triggers with their current on/off state,
    // when the loaded triggers are the ones in the file
    if (fromFile && triggerSystem()->isLoaded()) {
        const auto loaded = triggerSystem()->collection();
        if (loaded == collection) {
            collection = loaded;
        }
    }

    const TriggerKey key = holder.key;
    const QString path = triggerFilePath();
    TriggersDialog dialog(m_mainWindow, collection, [key, path](const TriggerCollection& edited, QString* error) {
        return TriggerFile::write(path, key, edited, error);
    });
    if (dialog.exec() != QDialog::Accepted) {
        return;
    }

    if (triggerSystem()->isLoaded()) {
        triggerSystem()->replace(dialog.collection());
    } else {
        triggerSystem()->load(dialog.collection());
        startTriggers();
    }
}

bool TriggerManager::canCopyTriggerKey() const
{
    auto* active = activeUnlockedDatabaseWidget();
    const QString path = triggerFilePath();
    if (!active || !QFileInfo::exists(path)) {
        return false;
    }
    const QByteArray fileKeyId = TriggerFile::readKeyId(path);
    if (fileKeyId.isEmpty() || TriggerKey::fromDatabase(active->database().data()).id() == fileKeyId) {
        return false;
    }
    for (auto* dbWidget : unlockedDatabaseWidgets()) {
        if (TriggerKey::fromDatabase(dbWidget->database().data()).id() == fileKeyId) {
            return true;
        }
    }
    return false;
}

void TriggerManager::copyTriggerKeyToActiveDatabase()
{
    auto* active = activeUnlockedDatabaseWidget();
    KeyHolder holder;
    TriggerCollection collection;
    if (!active || !findKeyHolder(&holder, &collection) || !QFileInfo::exists(triggerFilePath())) {
        MessageBox::information(m_mainWindow,
                                tr("Copy Trigger Key"),
                                tr("Unlock the database that holds the trigger key and the database that "
                                   "receives it. Then select the database that receives it."));
        return;
    }
    if (TriggerKey::fromDatabase(active->database().data()) == holder.key) {
        return;
    }
    if (!saveDatabaseWithKey(active, holder.key)) {
        MessageBox::warning(m_mainWindow,
                            tr("Copy Trigger Key"),
                            tr("The database could not be saved. The trigger key was not copied."));
        return;
    }
    active->showMessage(tr("The trigger key was copied to this database."), MessageWidget::Positive);
}
