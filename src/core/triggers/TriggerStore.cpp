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

#include "TriggerStore.h"

#include "TriggerXml.h"
#include "core/Config.h"
#include "core/CustomData.h"
#include "core/Database.h"
#include "core/Metadata.h"
#include "crypto/Random.h"
#include "crypto/SymmetricCipher.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>

namespace
{
    const QByteArray Magic = QByteArrayLiteral("KXTR");
    constexpr char FormatVersion = 1;

    QByteArray buildHeader(const QByteArray& keyId, const QByteArray& nonce)
    {
        QByteArray header;
        header.reserve(TriggerFile::HeaderSize);
        header.append(Magic);
        header.append(FormatVersion);
        header.append(QByteArray(3, '\0'));
        header.append(keyId);
        header.append(nonce);
        Q_ASSERT(header.size() == TriggerFile::HeaderSize);
        return header;
    }

    bool hasValidHeader(const QByteArray& data)
    {
        return data.size() >= TriggerFile::HeaderSize + TriggerFile::TagSize && data.startsWith(Magic)
               && data.at(4) == FormatVersion;
    }
} // namespace

TriggerKey::TriggerKey(const QByteArray& id, const QByteArray& key)
    : m_id(id)
    , m_key(key)
{
}

TriggerKey TriggerKey::generate()
{
    return {randomGen()->randomArray(IdSize), randomGen()->randomArray(KeySize)};
}

TriggerKey TriggerKey::fromDatabase(const Database* db)
{
    if (!db || !db->metadata()) {
        return {};
    }
    return fromCustomDataValue(db->metadata()->customData()->value(CustomData::TriggerKey));
}

bool TriggerKey::isValid() const
{
    return m_id.size() == IdSize && m_key.size() == KeySize;
}

const QByteArray& TriggerKey::id() const
{
    return m_id;
}

const QByteArray& TriggerKey::key() const
{
    return m_key;
}

void TriggerKey::storeInDatabase(Database* db) const
{
    Q_ASSERT(db && isValid());
    if (!db || !isValid()) {
        return;
    }
    db->metadata()->customData()->set(CustomData::TriggerKey, toCustomDataValue());
}

void TriggerKey::removeFromDatabase(Database* db)
{
    if (db && db->metadata()) {
        db->metadata()->customData()->remove(CustomData::TriggerKey);
    }
}

QString TriggerKey::toCustomDataValue() const
{
    return QString::fromLatin1((m_id + m_key).toBase64());
}

TriggerKey TriggerKey::fromCustomDataValue(const QString& value)
{
    const QByteArray bytes = QByteArray::fromBase64(value.trimmed().toLatin1());
    if (bytes.size() != IdSize + KeySize) {
        return {};
    }
    return {bytes.left(IdSize), bytes.mid(IdSize)};
}

bool TriggerKey::operator==(const TriggerKey& other) const
{
    return m_id == other.m_id && m_key == other.m_key;
}

bool TriggerKey::operator!=(const TriggerKey& other) const
{
    return !(*this == other);
}

QString TriggerFile::defaultPath()
{
    const QFileInfo settingsFile(config()->getFileName());
    return QDir::toNativeSeparators(settingsFile.absolutePath() + "/keepassxc_triggers.dat");
}

QByteArray TriggerFile::readKeyId(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }
    const QByteArray header = file.read(HeaderSize + TagSize);
    if (!hasValidHeader(header)) {
        return {};
    }
    return header.mid(8, TriggerKey::IdSize);
}

QByteArray TriggerFile::seal(const TriggerKey& key, const QByteArray& plaintext, const QByteArray& nonce)
{
    Q_ASSERT(key.isValid());
    const QByteArray usedNonce = nonce.isEmpty() ? randomGen()->randomArray(NonceSize) : nonce;
    Q_ASSERT(usedNonce.size() == NonceSize);
    const QByteArray header = buildHeader(key.id(), usedNonce);

    SymmetricCipher cipher;
    if (!cipher.init(SymmetricCipher::Aes256_GCM, SymmetricCipher::Encrypt, key.key(), usedNonce, header)) {
        return {};
    }
    // finish() of GCM appends the tag. Process all data in finish() so that an empty text also works.
    QByteArray data = plaintext;
    if (!cipher.finish(data)) {
        return {};
    }
    return header + data;
}

TriggerFile::Status TriggerFile::unseal(const TriggerKey& key, const QByteArray& data, QByteArray* plaintext)
{
    Q_ASSERT(plaintext);
    if (!hasValidHeader(data)) {
        return Status::VerifyFailed;
    }
    const QByteArray header = data.left(HeaderSize);
    if (header.mid(8, TriggerKey::IdSize) != key.id()) {
        return Status::KeyMismatch;
    }
    const QByteArray nonce = header.mid(8 + TriggerKey::IdSize, NonceSize);

    SymmetricCipher cipher;
    if (!cipher.init(SymmetricCipher::Aes256_GCM, SymmetricCipher::Decrypt, key.key(), nonce, header)) {
        return Status::VerifyFailed;
    }
    // finish() checks the tag at the end of the data and removes it
    QByteArray buffer = data.mid(HeaderSize);
    if (!cipher.finish(buffer)) {
        return Status::VerifyFailed;
    }
    *plaintext = buffer;
    return Status::Ok;
}

TriggerFile::Status
TriggerFile::read(const QString& path, const TriggerKey& key, TriggerCollection* collection, QString* error)
{
    Q_ASSERT(collection);
    QFile file(path);
    if (!file.exists()) {
        return Status::NotFound;
    }
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) {
            *error = file.errorString();
        }
        return Status::ReadError;
    }
    const QByteArray data = file.readAll();
    file.close();

    if (!key.isValid()) {
        return Status::KeyMismatch;
    }

    QByteArray xml;
    const auto status = unseal(key, data, &xml);
    if (status != Status::Ok) {
        return status;
    }

    QString xmlError;
    if (!TriggerXml::readTriggerSystem(xml, collection, &xmlError)) {
        if (error) {
            *error = xmlError;
        }
        return Status::VerifyFailed;
    }
    return Status::Ok;
}

bool TriggerFile::write(const QString& path, const TriggerKey& key, const TriggerCollection& collection, QString* error)
{
    if (!key.isValid()) {
        if (error) {
            *error = tr("The trigger key is not valid.");
        }
        return false;
    }

    const QByteArray data = seal(key, TriggerXml::writeTriggerSystem(collection));
    if (data.isEmpty()) {
        if (error) {
            *error = tr("The triggers could not be encrypted.");
        }
        return false;
    }

    const QFileInfo info(path);
    if (!QDir().mkpath(info.absolutePath())) {
        if (error) {
            *error = tr("The folder %1 could not be created.").arg(QDir::toNativeSeparators(info.absolutePath()));
        }
        return false;
    }

    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        if (error) {
            *error = file.errorString();
        }
        return false;
    }
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    if (file.write(data) != data.size() || !file.commit()) {
        if (error) {
            *error = file.errorString();
        }
        return false;
    }
#ifndef Q_OS_WIN
    // QSaveFile keeps the mode of an existing file. Make sure that only the owner can read it.
    QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
#endif
    return true;
}
