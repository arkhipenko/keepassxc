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

#ifndef KEEPASSXC_TRIGGERDATAEXCHANGE_H
#define KEEPASSXC_TRIGGERDATAEXCHANGE_H

#include <QCoreApplication>
#include <QDateTime>
#include <QSharedPointer>
#include <QString>

class Database;
class QWidget;

/**
 * The trigger actions "Import into active database" and "Export active database"
 * (KeePass/Ecas/EcasDefaultActionProvider.cs, ImportIntoCurrentDatabase and ExportDatabaseFile).
 */
class TriggerDataExchange
{
    Q_DECLARE_TR_FUNCTIONS(TriggerDataExchange)

public:
    struct ImportParameters
    {
        QString filePath;
        // KeePass format name, for example "KeePass KDBX (2.x)"
        QString format;
        // KeePass merge method id (0 default, 1 overwrite, 2 keep, 3 overwrite if newer, 4 new ids, 5 synchronize)
        quint32 method = 0;
        QString password;
        QString keyFile;
    };

    struct ExportParameters
    {
        QString filePath;
        QString format;
        // The first character separates the group names, for example "/Internet/Mail"
        QString groupFilter;
        QString tagFilter;
    };

    // Returns false and sets the error text on a failure. A cancel by the user is no failure.
    static bool importIntoDatabase(QWidget* parent,
                                   const QSharedPointer<Database>& db,
                                   const ImportParameters& parameters,
                                   QString* error);
    static bool exportDatabase(QWidget* parent,
                               const QSharedPointer<Database>& db,
                               const ExportParameters& parameters,
                               QString* error);

    // The import formats of KeePass that KeePassXC reads, and the export formats it writes
    static QStringList importFormats();
    static QStringList exportFormats();

    // A copy of the database that holds only the group of the filter and the entries with the tag
    static QSharedPointer<Database>
    filteredDatabase(const QSharedPointer<Database>& db, const QString& groupFilter, const QString& tagFilter);

    // Asks for the current master key (password and key file) and checks it against the database key.
    // A hardware key of the database is not asked again.
    static bool confirmMasterKey(QWidget* parent, const QSharedPointer<Database>& db);
    // The time when the application started. KeePass gives the database properties of an imported
    // file without its own properties this time (PwDefs.DtDefaultNow).
    static QDateTime applicationStartTime();

    // Checks a password and a key file against the database key
    static bool matchesMasterKey(const QSharedPointer<Database>& db, const QString& password, const QString& keyFile);
};

#endif // KEEPASSXC_TRIGGERDATAEXCHANGE_H
