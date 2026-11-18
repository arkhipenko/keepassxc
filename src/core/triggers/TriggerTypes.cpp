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

#include "TriggerTypes.h"

namespace
{
    QUuid uuidFromHex(const char* hex)
    {
        return QUuid::fromRfc4122(QByteArray::fromHex(hex));
    }
} // namespace

namespace TriggerIds
{
    // Byte values from KeePass/Ecas/EcasDefaultEventProvider.cs
    const QUuid OpenedDatabaseFile = uuidFromHex("E5FF130685B84189B906F69E2B3B40A7");
    const QUuid SavingDatabaseFile = uuidFromHex("95C1A6FD727C40C7A2F95B0FA099631C");
    const QUuid SavedDatabaseFile = uuidFromHex("B3A8FDFE78134A6A9C5DD5BA843A9B8E");
    const QUuid SynchronizingDatabaseFile = uuidFromHex("067E27A720B047718F1468D5015C766A");
    const QUuid SynchronizedDatabaseFile = uuidFromHex("B5A1E0D5A2F644B38AA184C686C2A960");
    const QUuid ClosingDatabaseFilePre = uuidFromHex("8CEADE9AA8174919A32FF41E3B1DEC49");
    const QUuid ClosingDatabaseFilePost = uuidFromHex("94FA70E5B13F4126A64E064FD8C36C95");
    const QUuid CopiedEntryInfo = uuidFromHex("3F7E5EC62A544C58954485FBF26F56DC");
    const QUuid AppInitPost = uuidFromHex("D4CECDB54B984FF2A6A9E255261EC8E8");
    const QUuid AppLoadPost = uuidFromHex("D8F31EE9CC69481B89C5FCE2EA4B6A97");
    const QUuid AppExit = uuidFromHex("828AB7ABB11C4EBF8039363F91719778");
    const QUuid CustomTbButtonClicked = uuidFromHex("4747599297A743A2B9681F1FC2F79B92");
    const QUuid TimePeriodic = uuidFromHex("6C44BB5DF18B4C0D88CE65E6E9AD298A");
    const QUuid UpdatedUIState = uuidFromHex("8D12D49AF2CB4FF7A8EFCFDAAC626899");

    // Byte values from KeePass/Ecas/EcasDefaultConditionProvider.cs
    const QUuid EnvironmentVariable = uuidFromHex("9F11D0BDECE9453BA545261FF7A4FF1F");
    const QUuid String = uuidFromHex("B90FF80773384FEABB2EBC0BEA3B98C3");
    const QUuid FileExists = uuidFromHex("CB4A9E34568C4C95AD674D1CA10419BC");
    const QUuid RemoteHostReachable = uuidFromHex("2A2283A89D1341E899878BAC218D81F4");
    const QUuid DatabaseHasUnsavedChanges = uuidFromHex("D3CAFAEF282A464A9990D865FCE016ED");

    // Byte values from KeePass/Ecas/EcasDefaultActionProvider.cs
    const QUuid ExecuteCommandLine = uuidFromHex("DAE5F83B07304C139EEF2EBACB6EE4C7");
    const QUuid ChangeTriggerState = uuidFromHex("B646A69FDE944BB99BAE3CA47ECC10EA");
    const QUuid OpenDatabaseFile = uuidFromHex("FD4155D5798F44FAAB89F2F870EF94B8");
    const QUuid SaveDatabase = uuidFromHex("F557614BF84C415DA9137A39CD10F0BD");
    const QUuid SynchronizeDatabase = uuidFromHex("22AD77E417784EED99B4571D02B3AD4D");
    const QUuid ImportIntoDatabase = uuidFromHex("80E67F4E72F1404591761F2C23D8ECBE");
    const QUuid ExportDatabase = uuidFromHex("0F9A6B5BCED546BEB934EDB13F944822");
    const QUuid CloseDatabase = uuidFromHex("5BBF459D54BF49BD97FB2CEE5F990A67");
    const QUuid ActivateDatabaseTab = uuidFromHex("3FB8332DD6164E87990564DB164CD626");
    const QUuid Wait = uuidFromHex("3B3D3E31E4B342A6BACCD5C03BACA969");
    const QUuid ShowMessageBox = uuidFromHex("09F78F7324EC4FEC88B625D530F4346E");
    const QUuid PerformGlobalAutoType = uuidFromHex("4069A536571B4792A9B3736530E0CFC3");
    const QUuid PerformSelectedAutoType = uuidFromHex("31708FAD649343F594EEC81A236E324D");
    const QUuid ShowEntriesByTag = uuidFromHex("42E8378173D34EEC81489E3B36AC8384");
    const QUuid AddToolbarButton = uuidFromHex("95818F4599664988AB3E86E81A966836");
    const QUuid RemoveToolbarButton = uuidFromHex("D66D41A26CB244BAA4480A41FA094879");
} // namespace TriggerIds

QString TriggerParameter::enumName(quint32 id) const
{
    for (const auto& item : enumItems) {
        if (item.id == id) {
            return item.name;
        }
    }
    return {};
}

quint32 TriggerParameter::enumId(const QString& name, quint32 defaultId) const
{
    for (const auto& item : enumItems) {
        if (item.name == name) {
            return item.id;
        }
    }
    return defaultId;
}

bool TriggerParameter::hasEnumId(quint32 id) const
{
    for (const auto& item : enumItems) {
        if (item.id == id) {
            return true;
        }
    }
    return false;
}

QList<TriggerEnumItem> TriggerTypes::stringCompareItems()
{
    using namespace TriggerEnums;
    return {{CompareEquals, tr("Equals")},
            {CompareContains, tr("Contains")},
            {CompareStartsWith, tr("Starts with")},
            {CompareEndsWith, tr("Ends with")},
            {CompareRegEx, tr("Matches regular expression")}};
}

const QList<TriggerTypeInfo>& TriggerTypes::events()
{
    static const QList<TriggerTypeInfo> list = [] {
        using T = TriggerValueType;
        const QList<TriggerParameter> fileFilter = {
            {tr("File/URL") + " - " + tr("Comparison"), T::EnumStrings, stringCompareItems()},
            {tr("File/URL") + " - " + tr("Filter"), T::String, {}}};
        const QList<TriggerParameter> valueFilter = {
            {tr("Value") + " - " + tr("Comparison"), T::EnumStrings, stringCompareItems()},
            {tr("Value") + " - " + tr("Filter"), T::String, {}}};

        // The order is the order of KeePass. "User interface state updated" is obsolete and not listed.
        return QList<TriggerTypeInfo>{
            {TriggerIds::AppInitPost, tr("Application initialized"), "keepassxc-monochrome-dark", {}},
            {TriggerIds::AppLoadPost, tr("Application started and ready"), "keepassxc-monochrome-dark", {}},
            {TriggerIds::AppExit, tr("Application exit"), "application-exit", {}},
            {TriggerIds::OpenedDatabaseFile, tr("Opened database file"), "document-open", fileFilter},
            {TriggerIds::SavingDatabaseFile, tr("Saving database file"), "document-save", fileFilter},
            {TriggerIds::SavedDatabaseFile, tr("Saved database file"), "document-save", fileFilter},
            {TriggerIds::SynchronizingDatabaseFile, tr("Synchronizing database file"), "database-merge", fileFilter},
            {TriggerIds::SynchronizedDatabaseFile, tr("Synchronized database file"), "database-merge", fileFilter},
            {TriggerIds::ClosingDatabaseFilePre,
             tr("Closing database file") + " (" + tr("before saving") + ")",
             "document-close",
             fileFilter},
            {TriggerIds::ClosingDatabaseFilePost,
             tr("Closing database file") + " (" + tr("after saving") + ")",
             "document-close",
             fileFilter},
            {TriggerIds::CopiedEntryInfo, tr("Copied entry data to clipboard"), "clipboard-text", valueFilter},
            {TriggerIds::TimePeriodic,
             tr("Time") + " - " + tr("Periodic"),
             "totp",
             {{tr("Interval") + " [s]", T::UInt64, {}}, {tr("Restart timer on KeePassXC activity"), T::Bool, {}}}},
            {TriggerIds::CustomTbButtonClicked,
             tr("Custom toolbar button clicked"),
             "hammer-wrench",
             {{tr("ID"), T::String, {}}}},
        };
    }();
    return list;
}

const QList<TriggerTypeInfo>& TriggerTypes::conditions()
{
    static const QList<TriggerTypeInfo> list = [] {
        using T = TriggerValueType;
        return QList<TriggerTypeInfo>{
            {TriggerIds::EnvironmentVariable,
             tr("Environment variable"),
             "configure",
             {{tr("Name"), T::String, {}},
              {tr("Value") + " - " + tr("Comparison"), T::EnumStrings, stringCompareItems()},
              {tr("Value"), T::String, {}}}},
            {TriggerIds::String,
             tr("String"),
             "configure",
             {{tr("String"), T::String, {}},
              {tr("Value") + " - " + tr("Comparison"), T::EnumStrings, stringCompareItems()},
              {tr("Value"), T::String, {}}}},
            {TriggerIds::FileExists, tr("File exists"), "document-properties", {{tr("File/URL"), T::String, {}}}},
            {TriggerIds::RemoteHostReachable,
             tr("Remote host is reachable (ping)"),
             "web",
             {{tr("Host"), T::String, {}}}},
            {TriggerIds::DatabaseHasUnsavedChanges,
             tr("Database has unsaved changes"),
             "document-save",
             {{tr("Database"),
               T::EnumStrings,
               {{TriggerEnums::DatabaseActive, tr("Active")}, {TriggerEnums::DatabaseTriggering, tr("Triggering")}}}}},
        };
    }();
    return list;
}

const QList<TriggerTypeInfo>& TriggerTypes::actions()
{
    static const QList<TriggerTypeInfo> list = [] {
        using T = TriggerValueType;
        using namespace TriggerEnums;
        const QString ioConnection = tr("I/O Connection");
        return QList<TriggerTypeInfo>{
            {TriggerIds::ExecuteCommandLine,
             tr("Execute command line / URL"),
             "web",
             {{tr("File/URL"), T::String, {}},
              {tr("Arguments"), T::String, {}},
              {tr("Wait for exit"), T::Bool, {}},
              {tr("Window style"),
               T::EnumStrings,
               {{WindowNormal, tr("Normal")},
                {WindowHidden, tr("Hidden")},
                {WindowMinimized, tr("Minimized")},
                {WindowMaximized, tr("Maximized")}}},
              {tr("Verb"), T::String, {}}}},
            {TriggerIds::ChangeTriggerState,
             tr("Change trigger on/off state"),
             "configure",
             {{tr("Trigger name"), T::String, {}},
              {tr("New state"),
               T::EnumStrings,
               {{TriggerOn, tr("On")}, {TriggerOff, tr("Off")}, {TriggerToggle, tr("Toggle")}}}}},
            {TriggerIds::OpenDatabaseFile,
             tr("Open database file"),
             "document-open",
             {{tr("File/URL"), T::String, {}},
              {ioConnection + " - " + tr("User name"), T::String, {}},
              {ioConnection + " - " + tr("Password"), T::String, {}},
              {tr("Password"), T::String, {}},
              {tr("Key file"), T::String, {}},
              {tr("Windows user account"), T::Bool, {}}}},
            {TriggerIds::SaveDatabase, tr("Save active database"), "document-save", {}},
            {TriggerIds::SynchronizeDatabase,
             tr("Synchronize active database with a file/URL"),
             "database-merge",
             {{tr("File/URL"), T::String, {}},
              {ioConnection + " - " + tr("User name"), T::String, {}},
              {ioConnection + " - " + tr("Password"), T::String, {}},
              {tr("On error") + " - " + tr("Silent"), T::Bool, {}},
              {tr("On error") + " - " + tr("Continue"), T::Bool, {}}}},
            {TriggerIds::ImportIntoDatabase,
             tr("Import into active database"),
             "document-import",
             {{tr("File/URL"), T::String, {}},
              {tr("File format"), T::String, {}},
              {tr("Method"),
               T::EnumStrings,
               {{MergeNone, tr("Default")},
                {MergeCreateNewUuids, tr("Create new IDs")},
                {MergeKeepExisting, tr("Keep existing")},
                {MergeOverwriteExisting, tr("Overwrite existing")},
                {MergeOverwriteIfNewer, tr("Overwrite if newer")},
                {MergeSynchronize, tr("Overwrite if newer and apply deletions")}}},
              {tr("Password"), T::String, {}},
              {tr("Key file"), T::String, {}},
              {tr("Windows user account"), T::Bool, {}}}},
            {TriggerIds::ExportDatabase,
             tr("Export active database"),
             "document-export",
             {{tr("File/URL"), T::String, {}},
              {tr("File format"), T::String, {}},
              {tr("Filter") + " - " + tr("Group"), T::String, {}},
              {tr("Filter") + " - " + tr("Tag"), T::String, {}}}},
            {TriggerIds::CloseDatabase, tr("Close active database"), "document-close", {}},
            {TriggerIds::ActivateDatabaseTab,
             tr("Activate database (select tab)"),
             "database-change-key",
             {{tr("File/URL"), T::String, {}},
              {tr("Filter"), T::EnumStrings, {{FilterAll, tr("All")}, {FilterTriggering, tr("Triggering")}}}}},
            {TriggerIds::Wait, tr("Wait"), "totp", {{tr("Time span") + " [ms]", T::UInt64, {}}}},
            {TriggerIds::ShowMessageBox,
             tr("Show message box"),
             "help-about",
             {{tr("Main instruction"), T::String, {}},
              {tr("Text"), T::String, {}},
              {tr("Icon"),
               T::EnumStrings,
               {{IconNone, tr("None")},
                {IconInformation, "i"},
                {IconQuestion, "?"},
                {IconWarning, tr("Warning")},
                {IconError, tr("Error")}}},
              {tr("Buttons"),
               T::EnumStrings,
               {{ButtonsOk, tr("OK")},
                {ButtonsOkCancel, tr("OK") + "/" + tr("Cancel")},
                {ButtonsYesNo, tr("Yes") + "/" + tr("No")}}},
              {tr("Default button"), T::EnumStrings, {{0, tr("Button") + " 1"}, {1, tr("Button") + " 2"}}},
              {tr("Action") + " - " + tr("Condition"),
               T::EnumStrings,
               {{MessageConditionOkYes, tr("Button") + " " + tr("OK") + "/" + tr("Yes")},
                {MessageConditionCancelNo, tr("Button") + " " + tr("Cancel") + "/" + tr("No")}}},
              {tr("Action"),
               T::EnumStrings,
               {{MessageActionNone, tr("None")},
                {MessageActionAbort, tr("Abort current trigger execution")},
                {MessageActionCommand, tr("Execute command line / URL")}}},
              {tr("Action") + " - " + tr("Parameters"), T::String, {}}}},
            {TriggerIds::PerformGlobalAutoType, tr("Perform global auto-type"), "auto-type", {}},
            {TriggerIds::PerformSelectedAutoType,
             tr("Perform auto-type with selected entry"),
             "auto-type",
             {{tr("Sequence"), T::String, {}}}},
            {TriggerIds::ShowEntriesByTag, tr("Show entries by tag"), "tag-search", {{tr("Tag"), T::String, {}}}},
            {TriggerIds::AddToolbarButton,
             tr("Add custom toolbar button"),
             "hammer-wrench",
             {{tr("ID"), T::String, {}}, {tr("Name"), T::String, {}}, {tr("Description"), T::String, {}}}},
            {TriggerIds::RemoveToolbarButton,
             tr("Remove custom toolbar button"),
             "hammer-wrench",
             {{tr("ID"), T::String, {}}}},
        };
    }();
    return list;
}

const QList<TriggerTypeInfo>& TriggerTypes::types(TriggerObjectKind kind)
{
    switch (kind) {
    case TriggerObjectKind::Event:
        return events();
    case TriggerObjectKind::Condition:
        return conditions();
    case TriggerObjectKind::Action:
        break;
    }
    return actions();
}

const TriggerTypeInfo* TriggerTypes::find(TriggerObjectKind kind, const QUuid& uuid)
{
    for (const auto& info : types(kind)) {
        if (info.uuid == uuid) {
            return &info;
        }
    }
    return nullptr;
}

const TriggerTypeInfo* TriggerTypes::findEvent(const QUuid& uuid)
{
    return find(TriggerObjectKind::Event, uuid);
}

const TriggerTypeInfo* TriggerTypes::findCondition(const QUuid& uuid)
{
    return find(TriggerObjectKind::Condition, uuid);
}

const TriggerTypeInfo* TriggerTypes::findAction(const QUuid& uuid)
{
    return find(TriggerObjectKind::Action, uuid);
}
