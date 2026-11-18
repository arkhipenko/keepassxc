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

#ifndef KEEPASSXC_TRIGGERTYPES_H
#define KEEPASSXC_TRIGGERTYPES_H

#include <QCoreApplication>
#include <QList>
#include <QString>
#include <QUuid>

/**
 * The event, condition and action types of the trigger system.
 * The type UUIDs, the parameter lists and the enumeration values are the ones of
 * KeePass 2.x (KeePass/Ecas/EcasDefaultEventProvider.cs, EcasDefaultConditionProvider.cs,
 * EcasDefaultActionProvider.cs), so that trigger XML moves between KeePass and KeePassXC unchanged.
 */

enum class TriggerValueType
{
    None = 0,
    String = 1,
    Bool = 2,
    EnumStrings = 3,
    Int64 = 4,
    UInt64 = 5
};

enum class TriggerObjectKind
{
    Event,
    Condition,
    Action
};

struct TriggerEnumItem
{
    quint32 id;
    QString name;
};

struct TriggerParameter
{
    QString name;
    TriggerValueType type = TriggerValueType::String;
    QList<TriggerEnumItem> enumItems;

    // Name of the item with this id, or a null string
    QString enumName(quint32 id) const;
    // Id of the item with this name, or the default
    quint32 enumId(const QString& name, quint32 defaultId) const;
    bool hasEnumId(quint32 id) const;
};

struct TriggerTypeInfo
{
    QUuid uuid;
    QString name;
    // Name of the icon in the KeePassXC icon theme
    QString icon;
    QList<TriggerParameter> parameters;
};

namespace TriggerIds
{
    // Events
    extern const QUuid OpenedDatabaseFile;
    extern const QUuid SavingDatabaseFile;
    extern const QUuid SavedDatabaseFile;
    extern const QUuid SynchronizingDatabaseFile;
    extern const QUuid SynchronizedDatabaseFile;
    extern const QUuid ClosingDatabaseFilePre;
    extern const QUuid ClosingDatabaseFilePost;
    extern const QUuid CopiedEntryInfo;
    extern const QUuid AppInitPost;
    extern const QUuid AppLoadPost;
    extern const QUuid AppExit;
    extern const QUuid CustomTbButtonClicked;
    extern const QUuid TimePeriodic;
    // Obsolete in KeePass. It is never raised.
    extern const QUuid UpdatedUIState;

    // Conditions
    extern const QUuid EnvironmentVariable;
    extern const QUuid String;
    extern const QUuid FileExists;
    extern const QUuid RemoteHostReachable;
    extern const QUuid DatabaseHasUnsavedChanges;

    // Actions
    extern const QUuid ExecuteCommandLine;
    extern const QUuid ChangeTriggerState;
    extern const QUuid OpenDatabaseFile;
    extern const QUuid SaveDatabase;
    extern const QUuid SynchronizeDatabase;
    extern const QUuid ImportIntoDatabase;
    extern const QUuid ExportDatabase;
    extern const QUuid CloseDatabase;
    extern const QUuid ActivateDatabaseTab;
    extern const QUuid Wait;
    extern const QUuid ShowMessageBox;
    extern const QUuid PerformGlobalAutoType;
    extern const QUuid PerformSelectedAutoType;
    extern const QUuid ShowEntriesByTag;
    extern const QUuid AddToolbarButton;
    extern const QUuid RemoveToolbarButton;
} // namespace TriggerIds

namespace TriggerEnums
{
    // String comparison (KeePass/Ecas/EcasUtil.cs)
    constexpr quint32 CompareEquals = 0;
    constexpr quint32 CompareContains = 1;
    constexpr quint32 CompareStartsWith = 2;
    constexpr quint32 CompareEndsWith = 3;
    constexpr quint32 CompareRegEx = 4;

    // Window style of "Execute command line / URL"
    constexpr quint32 WindowNormal = 0;
    constexpr quint32 WindowHidden = 1;
    constexpr quint32 WindowMinimized = 2;
    constexpr quint32 WindowMaximized = 3;

    // New state of "Change trigger on/off state"
    constexpr quint32 TriggerOff = 0;
    constexpr quint32 TriggerOn = 1;
    constexpr quint32 TriggerToggle = 2;

    // Merge method of "Import into active database" (KeePassLib/PwEnums.cs, PwMergeMethod)
    constexpr quint32 MergeNone = 0;
    constexpr quint32 MergeOverwriteExisting = 1;
    constexpr quint32 MergeKeepExisting = 2;
    constexpr quint32 MergeOverwriteIfNewer = 3;
    constexpr quint32 MergeCreateNewUuids = 4;
    constexpr quint32 MergeSynchronize = 5;

    // "Show message box": icon (System.Windows.Forms.MessageBoxIcon values)
    constexpr quint32 IconNone = 0;
    constexpr quint32 IconError = 16;
    constexpr quint32 IconQuestion = 32;
    constexpr quint32 IconWarning = 48;
    constexpr quint32 IconInformation = 64;

    // "Show message box": buttons (System.Windows.Forms.MessageBoxButtons values)
    constexpr quint32 ButtonsOk = 0;
    constexpr quint32 ButtonsOkCancel = 1;
    constexpr quint32 ButtonsYesNo = 4;

    // "Show message box": action condition and action
    constexpr quint32 MessageConditionOkYes = 0;
    constexpr quint32 MessageConditionCancelNo = 1;
    constexpr quint32 MessageActionNone = 0;
    constexpr quint32 MessageActionAbort = 1;
    constexpr quint32 MessageActionCommand = 2;

    // "Database has unsaved changes" and "Activate database (select tab)"
    constexpr quint32 DatabaseActive = 0;
    constexpr quint32 DatabaseTriggering = 1;
    constexpr quint32 FilterAll = 0;
    constexpr quint32 FilterTriggering = 1;
} // namespace TriggerEnums

class TriggerTypes
{
    Q_DECLARE_TR_FUNCTIONS(TriggerTypes)

public:
    static const QList<TriggerTypeInfo>& events();
    static const QList<TriggerTypeInfo>& conditions();
    static const QList<TriggerTypeInfo>& actions();
    static const QList<TriggerTypeInfo>& types(TriggerObjectKind kind);

    // Returns nullptr for an unknown type
    static const TriggerTypeInfo* find(TriggerObjectKind kind, const QUuid& uuid);
    static const TriggerTypeInfo* findEvent(const QUuid& uuid);
    static const TriggerTypeInfo* findCondition(const QUuid& uuid);
    static const TriggerTypeInfo* findAction(const QUuid& uuid);

    // The string comparison enumeration, shared by several types
    static QList<TriggerEnumItem> stringCompareItems();
};

#endif // KEEPASSXC_TRIGGERTYPES_H
