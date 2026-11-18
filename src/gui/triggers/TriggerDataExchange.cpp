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

#include "TriggerDataExchange.h"

#include "core/Clock.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "core/ImportMerger.h"
#include "core/Merger.h"
#include "core/Metadata.h"
#include "core/triggers/TriggerTypes.h"
#include "crypto/kdf/Kdf.h"
#include "format/BitwardenReader.h"
#include "format/HtmlExporter.h"
#include "format/KeePass1CsvExporter.h"
#include "format/KeePass1Reader.h"
#include "format/KeePass2Writer.h"
#include "format/OPUXReader.h"
#include "gui/FileDialog.h"
#include "gui/MessageBox.h"
#include "gui/csvImport/CsvImportWidget.h"
#include "keys/CompositeKey.h"
#include "keys/FileKey.h"
#include "keys/PasswordKey.h"

#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSet>
#include <QVBoxLayout>

namespace
{
    // KeePass format names (KeePass/DataExchange/Formats). The match ignores case, as KeePass.
    const QString FormatKdbx = QStringLiteral("KeePass KDBX (2.x)");
    const QString FormatXml = QStringLiteral("KeePass XML (2.x)");
    const QString FormatKdb = QStringLiteral("KeePass KDB (1.x)");
    const QString FormatBitwarden = QStringLiteral("Bitwarden JSON");
    const QString Format1Pux = QStringLiteral("1Password 1PUX");
    const QString FormatGenericCsv = QStringLiteral("Generic CSV Importer");
    const QString FormatCsvText = QStringLiteral("CSV/Text File");
    const QString FormatCsv1 = QStringLiteral("KeePass CSV (1.x)");
    const QString FormatHtml = QStringLiteral("Customizable HTML File");
    const QString FormatHtmlShort = QStringLiteral("Customizable HTML");

    bool sameFormat(const QString& name, const QString& format)
    {
        return name.trimmed().compare(format, Qt::CaseInsensitive) == 0;
    }

    // A dialog that asks for a password and a key file
    class KeyDialog : public QDialog
    {
    public:
        KeyDialog(QWidget* parent, const QString& title, const QString& text)
            : QDialog(parent)
        {
            setWindowTitle(title);
            auto* layout = new QVBoxLayout(this);
            auto* label = new QLabel(text, this);
            label->setWordWrap(true);
            layout->addWidget(label);

            auto* form = new QFormLayout();
            m_password = new QLineEdit(this);
            m_password->setEchoMode(QLineEdit::Password);
            m_password->setObjectName("triggerKeyPassword");
            form->addRow(TriggerDataExchange::tr("Password:"), m_password);

            auto* keyFileRow = new QHBoxLayout();
            m_keyFile = new QLineEdit(this);
            m_keyFile->setObjectName("triggerKeyFile");
            auto* browse = new QPushButton(TriggerDataExchange::tr("Browse…"), this);
            keyFileRow->addWidget(m_keyFile);
            keyFileRow->addWidget(browse);
            form->addRow(TriggerDataExchange::tr("Key file:"), keyFileRow);
            layout->addLayout(form);

            auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
            layout->addWidget(buttons);
            connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
            connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
            connect(browse, &QPushButton::clicked, this, [this] {
                const QString file = fileDialog()->getOpenFileName(this, TriggerDataExchange::tr("Select key file"));
                if (!file.isEmpty()) {
                    m_keyFile->setText(file);
                }
            });
            m_password->setFocus();
        }

        QString password() const
        {
            return m_password->text();
        }

        QString keyFile() const
        {
            return m_keyFile->text();
        }

    private:
        QLineEdit* m_password;
        QLineEdit* m_keyFile;
    };

    QSharedPointer<CompositeKey> buildKey(const QString& password, const QString& keyFile, QString* error)
    {
        auto key = QSharedPointer<CompositeKey>::create();
        if (!password.isEmpty() || keyFile.isEmpty()) {
            key->addKey(QSharedPointer<PasswordKey>::create(password));
        }
        if (!keyFile.isEmpty()) {
            auto fileKey = QSharedPointer<FileKey>::create();
            QString fileError;
            if (!fileKey->load(keyFile, &fileError)) {
                if (error) {
                    *error = TriggerDataExchange::tr("The key file %1 cannot be read: %2").arg(keyFile, fileError);
                }
                return {};
            }
            key->addKey(fileKey);
        }
        return key;
    }

    bool entryHasTag(const Entry* entry, const QString& tag)
    {
        if (entry->tagList().contains(tag)) {
            return true;
        }
        // Tags of the groups are inherited, as in KeePass
        for (auto* group = entry->group(); group; group = group->parentGroup()) {
            const auto groupTags = group->tags().split(QRegularExpression("[,;]"), Qt::SkipEmptyParts);
            for (const auto& groupTag : groupTags) {
                if (groupTag.trimmed() == tag) {
                    return true;
                }
            }
        }
        return false;
    }

    void removeEntries(Group* group, const QSet<QUuid>& keep)
    {
        const auto entries = group->entries();
        for (auto* entry : entries) {
            if (!keep.contains(entry->uuid())) {
                delete entry;
            }
        }
        for (auto* child : group->children()) {
            removeEntries(child, keep);
        }
    }

    // KeePass: PwGroup.FindCreateSubTree without creation. The names are compared exactly.
    const Group* findSubGroup(const Group* root, const QStringList& names)
    {
        const Group* current = root;
        for (const auto& name : names) {
            const Group* next = nullptr;
            for (const auto* child : current->children()) {
                if (child->name() == name) {
                    next = child;
                    break;
                }
            }
            if (!next) {
                return nullptr;
            }
            current = next;
        }
        return current;
    }

    QSharedPointer<Database> readSource(QWidget* parent,
                                        const QString& format,
                                        const TriggerDataExchange::ImportParameters& parameters,
                                        bool* canceled,
                                        QString* error)
    {
        QString password = parameters.password;
        QString keyFile = parameters.keyFile;
        const bool needsKey = sameFormat(format, FormatKdbx) || sameFormat(format, FormatKdb);
        if (needsKey && password.isEmpty() && keyFile.isEmpty()) {
            // KeePass asks for the key of the file when the parameters give none
            KeyDialog dialog(
                parent,
                TriggerDataExchange::tr("Import"),
                TriggerDataExchange::tr("Enter the key of %1.").arg(QDir::toNativeSeparators(parameters.filePath)));
            if (dialog.exec() != QDialog::Accepted) {
                *canceled = true;
                return {};
            }
            password = dialog.password();
            keyFile = dialog.keyFile();
        }

        if (sameFormat(format, FormatKdbx)) {
            const auto key = buildKey(password, keyFile, error);
            if (!key) {
                return {};
            }
            auto db = QSharedPointer<Database>::create();
            if (!db->open(parameters.filePath, key, error)) {
                return {};
            }
            return db;
        }
        if (sameFormat(format, FormatXml)) {
            auto db = QSharedPointer<Database>::create();
            if (!db->import(parameters.filePath, error)) {
                return {};
            }
            return db;
        }
        if (sameFormat(format, FormatKdb)) {
            KeePass1Reader reader;
            auto db = reader.readDatabase(parameters.filePath, password, keyFile);
            if (reader.hasError() || !db) {
                *error = reader.errorString();
                return {};
            }
            return db;
        }
        if (sameFormat(format, FormatBitwarden)) {
            BitwardenReader reader;
            auto db = reader.convert(parameters.filePath, password);
            if (reader.hasError() || !db) {
                *error = reader.errorString();
                return {};
            }
            return db;
        }
        if (sameFormat(format, Format1Pux)) {
            OPUXReader reader;
            auto db = reader.convert(parameters.filePath);
            if (reader.hasError() || !db) {
                *error = reader.errorString();
                return {};
            }
            return db;
        }

        // Generic CSV: the CSV import dialog lets the user assign the columns
        QDialog dialog(parent);
        dialog.setWindowTitle(TriggerDataExchange::tr("Import CSV file"));
        auto* layout = new QVBoxLayout(&dialog);
        auto* csvWidget = new CsvImportWidget(&dialog);
        layout->addWidget(csvWidget);
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
        layout->addWidget(buttons);
        QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        csvWidget->load(parameters.filePath);
        dialog.resize(800, 600);
        if (dialog.exec() != QDialog::Accepted) {
            *canceled = true;
            return {};
        }
        auto db = csvWidget->buildDatabase();
        if (!db) {
            *error = TriggerDataExchange::tr("The CSV file cannot be imported.");
        }
        return db;
    }
} // namespace

QDateTime TriggerDataExchange::applicationStartTime()
{
    static const QDateTime startTime = Clock::currentDateTimeUtc();
    return startTime;
}

QStringList TriggerDataExchange::importFormats()
{
    return {FormatKdbx, FormatXml, FormatKdb, FormatBitwarden, Format1Pux, FormatGenericCsv};
}

QStringList TriggerDataExchange::exportFormats()
{
    return {FormatKdbx, FormatXml, FormatCsv1, FormatHtml};
}

bool TriggerDataExchange::importIntoDatabase(QWidget* parent,
                                             const QSharedPointer<Database>& db,
                                             const ImportParameters& parameters,
                                             QString* error)
{
    if (!db || parameters.filePath.isEmpty() || parameters.format.isEmpty()) {
        return true;
    }

    QString format;
    for (const auto& known : importFormats() + QStringList{FormatCsvText}) {
        if (sameFormat(parameters.format, known)) {
            format = known;
            break;
        }
    }
    if (format.isEmpty()) {
        *error = tr("Unknown: %1").arg(parameters.format);
        return false;
    }
    if (!QFileInfo::exists(parameters.filePath)) {
        *error = tr("File %1 does not exist.").arg(QDir::toNativeSeparators(parameters.filePath));
        return false;
    }

    bool canceled = false;
    QString readError;
    auto source = readSource(parent, format, parameters, &canceled, &readError);
    if (canceled) {
        return true;
    }
    if (!source) {
        *error = QDir::toNativeSeparators(parameters.filePath) + "\n\n" + readError;
        return false;
    }

    if (format != FormatKdbx && format != FormatXml) {
        // KeePass imports these formats into a new database without a name and with the default
        // property times (PwDatabase.New). The merge then treats the properties as KeePass does.
        const QDateTime start = applicationStartTime();
        auto* metadata = source->metadata();
        metadata->setName({});
        metadata->setNameChanged(start);
        metadata->setDescription({});
        metadata->setDescriptionChanged(start);
        metadata->setDefaultUserName({});
        metadata->setDefaultUserNameChanged(start);
        metadata->setColor({});
        metadata->setSettingsChanged(start);
        metadata->setRecycleBinChanged(start);
        source->rootGroup()->setName({});
    }

    using namespace TriggerEnums;
    switch (parameters.method) {
    case MergeSynchronize: {
        Merger merger(source.data(), db.data());
        merger.setForcedMergeMode(Group::Synchronize);
        merger.setKeePassRules(true);
        merger.merge();
        db->markAsModified();
        break;
    }
    case MergeOverwriteExisting:
        ImportMerger(source.data(), db.data(), ImportMerger::Method::OverwriteExisting).merge();
        break;
    case MergeKeepExisting:
        ImportMerger(source.data(), db.data(), ImportMerger::Method::KeepExisting).merge();
        break;
    case MergeOverwriteIfNewer:
        ImportMerger(source.data(), db.data(), ImportMerger::Method::OverwriteIfNewer).merge();
        break;
    default:
        // "Default" and an unknown value mean "Create new IDs" (KeePass)
        ImportMerger(source.data(), db.data(), ImportMerger::Method::CreateNewUuids).merge();
        break;
    }
    return true;
}

QSharedPointer<Database> TriggerDataExchange::filteredDatabase(const QSharedPointer<Database>& db,
                                                               const QString& groupFilter,
                                                               const QString& tagFilter)
{
    const Group* group = db->rootGroup();
    Group* copy = nullptr;
    if (!groupFilter.isEmpty()) {
        const QChar separator = groupFilter.at(0);
        const QStringList names = groupFilter.mid(1).split(separator);
        group = findSubGroup(db->rootGroup(), names);
    }
    if (group) {
        copy = group->clone(Entry::CloneIncludeHistory, Group::CloneIncludeEntries);
    } else {
        // A group that is not found gives an empty export, as in KeePass
        copy = new Group();
        copy->setUuid(QUuid::createUuid());
        copy->setName(tr("Group"));
    }

    const QString tag = tagFilter.trimmed();
    if (!tag.isEmpty()) {
        // The entries are checked in the original tree, so that the tags of all parent groups count
        QSet<QUuid> keep;
        if (group) {
            for (const auto* entry : group->entriesRecursive()) {
                if (entryHasTag(entry, tag)) {
                    keep.insert(entry->uuid());
                }
            }
        }
        removeEntries(copy, keep);
    }

    auto result = QSharedPointer<Database>::create();
    result->setFormatVersion(db->formatVersion());
    result->setCipher(db->cipher());
    result->setCompressionAlgorithm(db->compressionAlgorithm());
    result->setKdf(db->kdf()->clone());
    result->metadata()->copyAttributesFrom(db->metadata());
    for (const auto& uuid : db->metadata()->customIconsOrder()) {
        result->metadata()->addCustomIcon(uuid, db->metadata()->customIcon(uuid));
    }
    delete result->setRootGroup(copy);
    if (!result->setKey(db->key(), false, false)) {
        return {};
    }
    return result;
}

bool TriggerDataExchange::matchesMasterKey(const QSharedPointer<Database>& db,
                                           const QString& password,
                                           const QString& keyFile)
{
    const auto dbKey = db ? db->key() : QSharedPointer<const CompositeKey>();
    if (!dbKey) {
        return false;
    }

    const auto dbPassword = dbKey->getKey(PasswordKey::UUID);
    if (dbPassword) {
        if (PasswordKey(password).rawKey() != dbPassword->rawKey()) {
            return false;
        }
    } else if (!password.isEmpty()) {
        return false;
    }

    const auto dbFileKey = dbKey->getKey(FileKey::UUID);
    if (dbFileKey) {
        FileKey fileKey;
        if (keyFile.isEmpty() || !fileKey.load(keyFile) || fileKey.rawKey() != dbFileKey->rawKey()) {
            return false;
        }
    } else if (!keyFile.isEmpty()) {
        return false;
    }
    return true;
}

bool TriggerDataExchange::confirmMasterKey(QWidget* parent, const QSharedPointer<Database>& db)
{
    KeyDialog dialog(parent,
                     tr("Export"),
                     tr("Enter the current master key of the database to export it. "
                        "The export writes the data without encryption."));
    if (dialog.exec() != QDialog::Accepted) {
        return false;
    }
    if (!matchesMasterKey(db, dialog.password(), dialog.keyFile())) {
        MessageBox::warning(parent, tr("Export"), tr("The master key is not correct. Nothing was exported."));
        return false;
    }
    return true;
}

bool TriggerDataExchange::exportDatabase(QWidget* parent,
                                         const QSharedPointer<Database>& db,
                                         const ExportParameters& parameters,
                                         QString* error)
{
    if (!db || parameters.format.isEmpty()) {
        return true;
    }

    QString format;
    for (const auto& known : exportFormats() + QStringList{FormatHtmlShort}) {
        if (sameFormat(parameters.format, known)) {
            format = (known == FormatHtmlShort) ? FormatHtml : known;
            break;
        }
    }
    if (format.isEmpty()) {
        // An unknown format returns without action, as in KeePass
        return true;
    }

    // The master key is asked again before every export (KeePass: ExportUtil.Export)
    if (!confirmMasterKey(parent, db)) {
        return true;
    }

    QString filePath = parameters.filePath;
    if (filePath.isEmpty()) {
        filePath = fileDialog()->getSaveFileName(parent, tr("Export"));
        if (filePath.isEmpty()) {
            return true;
        }
    }

    const auto exportDb = filteredDatabase(db, parameters.groupFilter, parameters.tagFilter);
    if (!exportDb) {
        *error = tr("The export database cannot be created.");
        return false;
    }

    QString writeError;
    bool ok = false;
    if (format == FormatKdbx) {
        KeePass2Writer writer;
        ok = writer.writeDatabase(filePath, exportDb.data());
        writeError = writer.errorString();
    } else if (format == FormatXml) {
        QByteArray xml;
        ok = exportDb->extract(xml, &writeError);
        if (ok) {
            QSaveFile file(filePath);
            ok = file.open(QIODevice::WriteOnly) && file.write(xml) == xml.size() && file.commit();
            writeError = file.errorString();
        }
    } else if (format == FormatCsv1) {
        ok = KeePass1CsvExporter::exportGroup(filePath, exportDb->rootGroup(), &writeError);
    } else {
        HtmlExporter exporter;
        ok = exporter.exportDatabase(filePath, exportDb);
        writeError = exporter.errorString();
    }

    if (!ok) {
        *error = tr("Writing the file %1 failed: %2").arg(QDir::toNativeSeparators(filePath), writeError);
    }
    return ok;
}
