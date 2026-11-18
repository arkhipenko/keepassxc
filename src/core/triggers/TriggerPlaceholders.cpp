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

#include "TriggerPlaceholders.h"

#include "core/Database.h"
#include "core/Entry.h"
#include "core/EntryPlaceholders.h"
#include "core/Group.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QHash>
#include <QProcess>
#include <QProcessEnvironment>

namespace
{
    constexpr int MaxDepth = 12;

    QString encodeValue(const QString& value, const TriggerPlaceholders::Context& context)
    {
        return context.forCommandLine ? TriggerPlaceholders::encodeForCommandLine(value) : value;
    }

    // Replaces each occurrence of the placeholder, ignoring case (KeePass: SprEngine.Fill)
    QString fill(const QString& text,
                 const QString& placeholder,
                 const QString& value,
                 const TriggerPlaceholders::Context& context)
    {
        if (!text.contains(placeholder, Qt::CaseInsensitive)) {
            return text;
        }
        QString result = text;
        result.replace(placeholder, encodeValue(value, context), Qt::CaseInsensitive);
        return result;
    }

    // Finds a placeholder with parameters, for example {CMD:/command/options/}, and removes it.
    // The first character after the colon separates the parameters
    // (KeePass: SprEngine.ParseAndRemovePlhWithParams).
    bool parseAndRemove(QString& text, const QString& prefix, int* start, QStringList* params)
    {
        const int index = text.indexOf(prefix, 0, Qt::CaseInsensitive);
        if (index < 0) {
            return false;
        }
        *start = index;
        params->clear();

        int p = index + prefix.length();
        bool valid = p < text.length();
        if (valid) {
            const QChar separator = text.at(p);
            while (true) {
                if (p + 1 >= text.length()) {
                    valid = false;
                    break;
                }
                if (text.at(p + 1) == '}') {
                    break;
                }
                const int q = text.indexOf(separator, p + 1);
                if (q < 0) {
                    valid = false;
                    break;
                }
                *params << text.mid(p + 1, q - p - 1);
                p = q;
            }
        }

        if (valid) {
            text.remove(index, (p + 1) - index + 1);
        } else {
            // Malformed placeholder: the rest of the text is dropped, as in KeePass
            params->clear();
            text.truncate(index);
        }
        return true;
    }

    QHash<QString, QString> splitOptions(const QString& options)
    {
        QHash<QString, QString> result;
        for (const auto& option : options.split(',', Qt::SkipEmptyParts)) {
            const auto pair = option.split('=');
            if (pair.size() != 2) {
                continue;
            }
            result.insert(pair.at(0).trimmed().toLower(), pair.at(1).trimmed());
        }
        return result;
    }

    // Splits a command line into the program and the rest (KeePass: StrUtil.SplitCommandLine)
    void splitCommandLine(const QString& commandLine, QString* program, QString* arguments)
    {
        const QString command = commandLine.trimmed();
        program->clear();
        arguments->clear();
        if (command.isEmpty()) {
            return;
        }
        int end;
        if (command.startsWith('"')) {
            end = command.indexOf('"', 1);
            if (end < 0) {
                *program = command.mid(1);
                return;
            }
            *program = command.mid(1, end - 1);
            ++end;
        } else {
            end = command.indexOf(' ');
            if (end < 0) {
                *program = command;
                return;
            }
            *program = command.left(end);
        }
        *arguments = command.mid(end).trimmed();
    }

    QString runCommands(const QString& text, const TriggerPlaceholders::Context& context)
    {
        QString result = text;
        int start = 0;
        QStringList params;
        while (parseAndRemove(result, "{CMD:", &start, &params)) {
            if (params.isEmpty()) {
                continue;
            }
            QString program;
            QString arguments;
            splitCommandLine(params.at(0), &program, &arguments);
            if (program.isEmpty()) {
                continue;
            }

            const auto options = splitOptions(params.size() >= 2 ? params.at(1) : QString());
            // m=s (shell, default) or m=c (create process); o=1 captures the output;
            // w=1 (default) waits for the end. Window style and verb have no effect here.
            const bool shellExecute = options.value("m", "s").compare("c", Qt::CaseInsensitive) != 0;
            const bool captureOutput = options.value("o", shellExecute ? "0" : "1") == "1";
            const bool wait = options.value("w", "1") == "1";

            if (!context.confirmCommand || !context.confirmCommand(program, arguments)) {
                continue;
            }

            QProcess process;
#ifdef Q_OS_WIN
            process.setProgram(program);
            process.setNativeArguments(arguments);
#else
            process.setProgram(program);
            process.setArguments(QProcess::splitCommand(arguments));
#endif
            if (!captureOutput && !wait) {
                process.startDetached();
                continue;
            }
            process.start();
            if (!process.waitForStarted(-1)) {
                continue;
            }
            process.closeWriteChannel();
            process.waitForFinished(-1);
            if (captureOutput) {
                QString output = QString::fromLocal8Bit(process.readAllStandardOutput());
                // Trailing new lines are removed, as a shell does with $(...)
                while (output.endsWith('\n') || output.endsWith('\r')) {
                    output.chop(1);
                }
                result.insert(start, encodeValue(output, context));
            }
        }
        return result;
    }

    // KeePass group path: the names from below the root group to the group, separated by dots
    QString groupPath(const Group* group)
    {
        QStringList names;
        for (auto current = group; current; current = current->parentGroup()) {
            if (!current->parentGroup() && current != group) {
                break; // The root group is not part of the path
            }
            names.prepend(current->name());
        }
        return names.join('.');
    }

    QString fillGroup(const QString& text,
                      const QString& prefix,
                      const Group* group,
                      const TriggerPlaceholders::Context& context)
    {
        QString result = text;
        result = fill(result, prefix + "}", group->name(), context);
        const QString path = groupPath(group);
        result = fill(result, prefix + "_PATH}", path, context);
        result = fill(result, prefix + "PATH}", path, context); // Obsolete form
        result = fill(result, prefix + "_NOTES}", group->notes(), context);
        return result;
    }

    QString referenceValue(const Database* db, const QString& placeholder)
    {
        const auto match = EntryPlaceholders::matchReference(placeholder);
        if (!match.hasMatch() || !db || !db->rootGroup()) {
            return placeholder;
        }
        const QString searchIn = match.captured(EntryAttributes::SearchInGroupName).toLower();
        const QString searchText = match.captured(EntryAttributes::SearchTextGroupName);
        const QString wanted = match.captured(EntryAttributes::WantedFieldGroupName).toLower();

        static const QHash<QString, EntryReferenceType> types = {{"t", EntryReferenceType::Title},
                                                                 {"u", EntryReferenceType::UserName},
                                                                 {"p", EntryReferenceType::Password},
                                                                 {"a", EntryReferenceType::Url},
                                                                 {"n", EntryReferenceType::Notes},
                                                                 {"i", EntryReferenceType::QUuid},
                                                                 {"o", EntryReferenceType::CustomAttributes}};
        const auto* found =
            const_cast<Group*>(db->rootGroup())->findEntryBySearchTerm(searchText, types.value(searchIn));
        if (!found) {
            return {};
        }
        // The found entry resolves the field itself, including its own placeholders
        static const QHash<QString, QString> fields = {{"t", "{TITLE}"},
                                                       {"u", "{USERNAME}"},
                                                       {"p", "{PASSWORD}"},
                                                       {"a", "{URL}"},
                                                       {"n", "{NOTES}"},
                                                       {"i", "{UUID}"}};
        return found->resolvePlaceholder(fields.value(wanted));
    }

    // Placeholders that KeePassXC resolves for an entry, or without an entry where possible
    QString fillEntryPlaceholders(const QString& text, const TriggerPlaceholders::Context& context)
    {
        QString result;
        auto matches = EntryPlaceholders::placeholderMatches(text);
        int end = 0;
        while (matches.hasNext()) {
            const auto match = matches.next();
            const QString placeholder = match.captured();
            result += QStringView{text}.mid(end, match.capturedStart() - end);
            end = match.capturedEnd();

            QString value = placeholder;
            if (context.entry) {
                value = context.entry->resolvePlaceholder(placeholder);
            } else {
                using T = EntryPlaceholders::PlaceholderType;
                const auto type = EntryPlaceholders::placeholderType(placeholder);
                switch (type) {
                case T::DateTimeSimple:
                case T::DateTimeYear:
                case T::DateTimeMonth:
                case T::DateTimeDay:
                case T::DateTimeHour:
                case T::DateTimeMinute:
                case T::DateTimeSecond:
                case T::DateTimeUtcSimple:
                case T::DateTimeUtcYear:
                case T::DateTimeUtcMonth:
                case T::DateTimeUtcDay:
                case T::DateTimeUtcHour:
                case T::DateTimeUtcMinute:
                case T::DateTimeUtcSecond:
                case T::Conversion:
                case T::Regex: {
                    // An entry without data and without a database resolves these placeholders
                    const Entry noEntry;
                    value = noEntry.resolvePlaceholder(placeholder);
                    break;
                }
                case T::Reference:
                    value = referenceValue(context.database, placeholder);
                    break;
                default:
                    break;
                }
            }

            result += (value == placeholder) ? placeholder : encodeValue(value, context);
        }
        result += QStringView{text}.mid(end);
        return result;
    }
} // namespace

QString TriggerPlaceholders::compile(const QString& text, const Context& context)
{
    return compileInternal(text, context, 0);
}

QString TriggerPlaceholders::compileInternal(const QString& text, const Context& context, int depth)
{
    if (depth >= MaxDepth) {
        return {};
    }
    if (text.isEmpty()) {
        return text;
    }

    QString str = removeComments(text);
    str = runCommands(str, context);

    // {CLIPBOARD-SET:/text/}: the text is compiled without command line encoding, then copied
    {
        int start = 0;
        QStringList params;
        Context plainContext = context;
        plainContext.forCommandLine = false;
        while (parseAndRemove(str, "{CLIPBOARD-SET:", &start, &params)) {
            if (params.isEmpty()) {
                continue;
            }
            const QString value = compileInternal(params.at(0), plainContext, depth + 1);
            if (context.setClipboardText) {
                context.setClipboardText(value);
            }
        }
    }

    if (str.contains("{CLIPBOARD}", Qt::CaseInsensitive)) {
        str = fill(str, "{CLIPBOARD}", context.clipboardText ? context.clipboardText() : QString(), context);
    }

    if (context.entry && context.entry->group()) {
        str = fillGroup(str, "{GROUP", context.entry->group(), context);
    }
    if (context.selectedGroup) {
        str = fillGroup(str, "{GROUP_SEL", context.selectedGroup, context);
    }

    str = fill(str, "{APPDIR}", QDir::toNativeSeparators(QCoreApplication::applicationDirPath()), context);
    str = fill(str, "{ENV_DIRSEP}", QDir::separator(), context);
    QString programFilesX86;
#ifdef Q_OS_WIN
    const auto environment = QProcessEnvironment::systemEnvironment();
    programFilesX86 = environment.value("ProgramFiles(x86)");
    if (programFilesX86.isEmpty()) {
        programFilesX86 = environment.value("ProgramFiles");
    }
#endif
    str = fill(str, "{ENV_PROGRAMFILES_X86}", programFilesX86, context);

    if (context.database) {
        const QString path = QDir::toNativeSeparators(context.database->filePath());
        const QFileInfo info(context.database->filePath());
        const QString dir = path.isEmpty() ? QString() : QDir::toNativeSeparators(info.absolutePath());
        str = fill(str, "{DOCDIR}", dir, context);
        str = fill(str, "{DB_PATH}", path, context);
        str = fill(str, "{DB_DIR}", dir, context);
        str = fill(str, "{DB_NAME}", info.fileName(), context);
        str = fill(str, "{DB_BASENAME}", info.completeBaseName(), context);
        str = fill(str, "{DB_EXT}", info.suffix(), context);
    }

    str = fillEntryPlaceholders(str, context);

    if (str.contains('%')) {
        const auto environment = QProcessEnvironment::systemEnvironment();
        for (const auto& key : environment.keys()) {
            if (!key.isEmpty()) {
                str = fill(str, "%" + key + "%", environment.value(key), context);
            }
        }
    }

    return str;
}

QString TriggerPlaceholders::removeComments(const QString& text)
{
    // KeePass: SprEngine.RemoveComments. Braces inside the comment are counted.
    QString str = text;
    int offset = 0;
    while (offset < str.length()) {
        const int start = str.indexOf("{C:", offset, Qt::CaseInsensitive);
        if (start < 0) {
            break;
        }
        int braces = 1;
        int end = start + 3;
        for (; end < str.length(); ++end) {
            const QChar ch = str.at(end);
            if (ch == '{') {
                ++braces;
            } else if (ch == '}' && --braces == 0) {
                str.remove(start, end - start + 1);
                break;
            }
        }
        if (braces != 0) {
            break; // Malformed input
        }
        offset = start;
    }
    return str;
}

QString TriggerPlaceholders::encodeForCommandLine(const QString& text)
{
#ifdef Q_OS_WIN
    // Rules of the Microsoft C/C++ start-up code (KeePass: NativeLib.EncodeDataToArgs)
    QString result;
    int i = 0;
    while (i < text.length()) {
        const QChar ch = text.at(i++);
        if (ch == '\\') {
            int backslashes = 1;
            while (i < text.length() && text.at(i) == '\\') {
                ++backslashes;
                ++i;
            }
            if (i == text.length()) {
                result += QString(backslashes, '\\');
            } else if (text.at(i) == '"') {
                result += QString(backslashes * 2 + 1, '\\');
                result += '"';
                ++i;
            } else {
                result += QString(backslashes, '\\');
            }
        } else if (ch == '"') {
            result += "\\\"";
        } else {
            result += ch;
        }
    }
    return result;
#else
    QString result = text;
    result.replace("\\", "\\\\");
    result.replace("\"", "\\\"");
    return result;
#endif
}
