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

#ifndef KEEPASSXC_TRIGGERPLACEHOLDERS_H
#define KEEPASSXC_TRIGGERPLACEHOLDERS_H

#include <QString>

#include <functional>

class Database;
class Entry;
class Group;

/**
 * Placeholder resolver for trigger parameters. The entry placeholders of KeePassXC
 * need an entry; trigger parameters also need placeholders without an entry.
 * The resolver follows the order of KeePass (KeePass/Util/Spr/SprEngine.cs, CompileInternal):
 *
 * 1. {C:...} comments are removed.
 * 2. {CMD:...} runs a command (after a confirmation) and inserts its output.
 * 3. {CLIPBOARD-SET:...} copies text to the clipboard, {CLIPBOARD} inserts the clipboard text.
 * 4. {GROUP}, {GROUP_PATH}, {GROUP_NOTES} of the entry group, and the {GROUP_SEL...} forms of the
 *    selected group.
 * 5. {APPDIR}, {ENV_DIRSEP}, {ENV_PROGRAMFILES_X86}, and with a database {DOCDIR}, {DB_PATH},
 *    {DB_DIR}, {DB_NAME}, {DB_BASENAME}, {DB_EXT}.
 * 6. Environment variables written as %NAME%.
 * 7. The entry placeholders of KeePassXC, when an entry is selected. Without an entry,
 *    {DT_...}, {T-CONV:...}, {T-REPLACE-RX:...} and {REF:...} (with a database) are resolved.
 *
 * Names are matched ignoring case, as in KeePass.
 */
class TriggerPlaceholders
{
public:
    struct Context
    {
        const Entry* entry = nullptr;
        const Database* database = nullptr;
        const Group* selectedGroup = nullptr;
        // Values that are inserted are encoded for a command line (quotes and backslashes)
        bool forCommandLine = false;

        std::function<QString()> clipboardText;
        std::function<void(const QString&)> setClipboardText;
        // Asks whether a {CMD:...} command may run
        std::function<bool(const QString& program, const QString& arguments)> confirmCommand;
    };

    static QString compile(const QString& text, const Context& context);

    // Encodes text as a command line argument value (KeePass: NativeLib.EncodeDataToArgs)
    static QString encodeForCommandLine(const QString& text);

    // Removes {C:...} comments
    static QString removeComments(const QString& text);

private:
    static QString compileInternal(const QString& text, const Context& context, int depth);
};

#endif // KEEPASSXC_TRIGGERPLACEHOLDERS_H
