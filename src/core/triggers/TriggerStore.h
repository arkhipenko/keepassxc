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

#ifndef KEEPASSXC_TRIGGERSTORE_H
#define KEEPASSXC_TRIGGERSTORE_H

#include "Trigger.h"

#include <QByteArray>
#include <QCoreApplication>

class Database;

/**
 * The trigger key: a random key id (16 bytes) and a random AES-256 key (32 bytes).
 * It is stored in the database custom data, so only the master key gives access to it.
 * The key is a protected custom data item, so a merge never removes it, and a
 * synchronization carries it to the other database file.
 */
class TriggerKey
{
public:
    static constexpr int IdSize = 16;
    static constexpr int KeySize = 32;

    TriggerKey() = default;
    TriggerKey(const QByteArray& id, const QByteArray& key);

    static TriggerKey generate();
    // The key in the database custom data, or an invalid key
    static TriggerKey fromDatabase(const Database* db);

    bool isValid() const;
    const QByteArray& id() const;
    const QByteArray& key() const;

    // Stores the key in the database custom data. The database becomes modified.
    void storeInDatabase(Database* db) const;
    static void removeFromDatabase(Database* db);

    // Base64 text of the key id followed by the key
    QString toCustomDataValue() const;
    static TriggerKey fromCustomDataValue(const QString& value);

    bool operator==(const TriggerKey& other) const;
    bool operator!=(const TriggerKey& other) const;

private:
    QByteArray m_id;
    QByteArray m_key;
};

/**
 * The sealed trigger file.
 *
 * Layout (all values in the order written):
 *   magic      4 bytes   "KXTR"
 *   version    1 byte    1
 *   reserved   3 bytes   0
 *   key id    16 bytes   id of the trigger key
 *   nonce     12 bytes   AES-256-GCM nonce, new random value on every write
 *   ciphertext n bytes   the TriggerSystem XML (UTF-8), encrypted
 *   tag       16 bytes   GCM tag over the 36-byte header (associated data) and the ciphertext
 */
class TriggerFile
{
    Q_DECLARE_TR_FUNCTIONS(TriggerFile)

public:
    static constexpr int HeaderSize = 36;
    static constexpr int NonceSize = 12;
    static constexpr int TagSize = 16;

    enum class Status
    {
        Ok,
        // The file does not exist
        NotFound,
        // The file cannot be read
        ReadError,
        // The file uses the trigger key of another database
        KeyMismatch,
        // The file is not a trigger file, the tag check failed, or the XML is not valid
        VerifyFailed,
    };

    // keepassxc_triggers.dat in the folder of the application settings file
    static QString defaultPath();

    // Key id in the header of the file. Returns an empty array when the file is
    // missing or does not have a valid header.
    static QByteArray readKeyId(const QString& path);

    static Status read(const QString& path, const TriggerKey& key, TriggerCollection* collection, QString* error);
    static bool write(const QString& path, const TriggerKey& key, const TriggerCollection& collection, QString* error);

    // Encrypts and decrypts the file content. Exposed for tests.
    static QByteArray seal(const TriggerKey& key, const QByteArray& plaintext, const QByteArray& nonce = {});
    static Status unseal(const TriggerKey& key, const QByteArray& data, QByteArray* plaintext);
};

#endif // KEEPASSXC_TRIGGERSTORE_H
