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

#include "TriggerXml.h"

#include <QXmlStreamReader>
#include <QXmlStreamWriter>

namespace
{
    const QString XsiNamespace = QStringLiteral("http://www.w3.org/2001/XMLSchema-instance");
    const QString XsdNamespace = QStringLiteral("http://www.w3.org/2001/XMLSchema");

    QString uuidToBase64(const QUuid& uuid)
    {
        return QString::fromLatin1(uuid.toRfc4122().toBase64());
    }

    // Serialization of a xs:boolean value, as the .NET XML serializer writes it
    QString xmlBool(bool value)
    {
        return value ? QStringLiteral("true") : QStringLiteral("false");
    }

    void writeObject(QXmlStreamWriter& writer, const QString& tag, const TriggerObject& object, bool isCondition)
    {
        writer.writeStartElement(tag);
        writer.writeTextElement("TypeGuid", uuidToBase64(object.type));
        writer.writeStartElement("Parameters");
        for (const auto& param : object.parameters) {
            writer.writeTextElement("Parameter", param);
        }
        writer.writeEndElement();
        if (isCondition && object.negate) {
            writer.writeTextElement("Negate", xmlBool(true));
        }
        writer.writeEndElement();
    }

    void writeObjectList(QXmlStreamWriter& writer,
                         const QString& listTag,
                         const QString& itemTag,
                         const QList<TriggerObject>& objects,
                         bool isCondition)
    {
        writer.writeStartElement(listTag);
        for (const auto& object : objects) {
            writeObject(writer, itemTag, object, isCondition);
        }
        writer.writeEndElement();
    }

    void writeTrigger(QXmlStreamWriter& writer, const Trigger& trigger)
    {
        writer.writeStartElement("Trigger");
        writer.writeTextElement("Guid", uuidToBase64(trigger.uuid));
        if (!trigger.name.isEmpty()) {
            writer.writeTextElement("Name", trigger.name);
        }
        if (!trigger.comments.isEmpty()) {
            writer.writeTextElement("Comments", trigger.comments);
        }
        if (!trigger.enabled) {
            writer.writeTextElement("Enabled", xmlBool(false));
        }
        if (!trigger.initiallyOn) {
            writer.writeTextElement("InitiallyOn", xmlBool(false));
        }
        if (trigger.turnOffAfterAction) {
            writer.writeTextElement("TurnOffAfterAction", xmlBool(true));
        }
        writeObjectList(writer, "Events", "Event", trigger.events, false);
        writeObjectList(writer, "Conditions", "Condition", trigger.conditions, true);
        writeObjectList(writer, "Actions", "Action", trigger.actions, false);
        writer.writeEndElement();
    }

    void writeTriggers(QXmlStreamWriter& writer, const QList<Trigger>& triggers)
    {
        writer.writeStartElement("Triggers");
        for (const auto& trigger : triggers) {
            writeTrigger(writer, trigger);
        }
        writer.writeEndElement();
    }

    void startDocument(QXmlStreamWriter& writer, const QString& rootTag)
    {
        writer.setAutoFormatting(true);
        writer.setAutoFormattingIndent(-1); // One tab, as KeePass
        writer.writeStartDocument();
        writer.writeStartElement(rootTag);
        writer.writeNamespace(XsiNamespace, "xsi");
        writer.writeNamespace(XsdNamespace, "xsd");
    }

    class Reader
    {
        Q_DECLARE_TR_FUNCTIONS(TriggerXml)

    public:
        explicit Reader(const QByteArray& xml)
            : m_xml(xml)
        {
        }

        // Reads the root element and calls the handler for each of its children
        template <typename Handler> bool readRoot(const QString& rootTag, Handler handler)
        {
            if (!m_xml.readNextStartElement()) {
                raiseError(tr("The text is not trigger XML."));
                return false;
            }
            if (m_xml.name() != rootTag) {
                raiseError(
                    tr("The root element is \"%1\", but \"%2\" was expected.").arg(m_xml.name().toString(), rootTag));
                return false;
            }
            while (!m_xml.hasError() && m_xml.readNextStartElement()) {
                handler();
            }
            return !m_xml.hasError() && m_error.isEmpty();
        }

        QList<Trigger> readTriggers()
        {
            QList<Trigger> triggers;
            while (!m_xml.hasError() && m_xml.readNextStartElement()) {
                if (m_xml.name() == QLatin1String("Trigger")) {
                    triggers << readTrigger();
                } else {
                    m_xml.skipCurrentElement();
                }
            }
            return triggers;
        }

        bool readBoolValue()
        {
            // xs:boolean accepts true, false, 1 and 0
            const QString text = m_xml.readElementText().trimmed();
            if (text == "true" || text == "1") {
                return true;
            }
            if (text != "false" && text != "0") {
                raiseError(tr("\"%1\" is not a valid boolean value.").arg(text));
            }
            return false;
        }

        QString errorString() const
        {
            if (!m_error.isEmpty()) {
                return m_error;
            }
            return tr("XML error in line %1: %2").arg(m_xml.lineNumber()).arg(m_xml.errorString());
        }

        void skip()
        {
            m_xml.skipCurrentElement();
        }

        QStringView name() const
        {
            return m_xml.name();
        }

    private:
        void raiseError(const QString& error)
        {
            if (m_error.isEmpty()) {
                m_error = error;
            }
            m_xml.raiseError(error);
        }

        QUuid readUuid()
        {
            const QString text = m_xml.readElementText().trimmed();
            const QByteArray bytes = QByteArray::fromBase64(text.toLatin1());
            if (bytes.size() != 16) {
                raiseError(tr("\"%1\" is not a valid UUID.").arg(text));
                return {};
            }
            return QUuid::fromRfc4122(bytes);
        }

        TriggerObject readObject()
        {
            TriggerObject object;
            while (!m_xml.hasError() && m_xml.readNextStartElement()) {
                if (m_xml.name() == QLatin1String("TypeGuid")) {
                    object.type = readUuid();
                } else if (m_xml.name() == QLatin1String("Parameters")) {
                    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
                        if (m_xml.name() == QLatin1String("Parameter")) {
                            object.parameters << m_xml.readElementText();
                        } else {
                            m_xml.skipCurrentElement();
                        }
                    }
                } else if (m_xml.name() == QLatin1String("Negate")) {
                    object.negate = readBoolValue();
                } else {
                    m_xml.skipCurrentElement();
                }
            }
            return object;
        }

        QList<TriggerObject> readObjectList(const QString& itemTag)
        {
            QList<TriggerObject> objects;
            while (!m_xml.hasError() && m_xml.readNextStartElement()) {
                if (m_xml.name() == itemTag) {
                    objects << readObject();
                } else {
                    m_xml.skipCurrentElement();
                }
            }
            return objects;
        }

        Trigger readTrigger()
        {
            // A trigger without <Guid> has the zero UUID, as in KeePass
            Trigger trigger{QUuid()};
            while (!m_xml.hasError() && m_xml.readNextStartElement()) {
                const auto name = m_xml.name();
                if (name == QLatin1String("Guid")) {
                    trigger.uuid = readUuid();
                } else if (name == QLatin1String("Name")) {
                    trigger.name = m_xml.readElementText();
                } else if (name == QLatin1String("Comments")) {
                    trigger.comments = m_xml.readElementText();
                } else if (name == QLatin1String("Enabled")) {
                    trigger.enabled = readBoolValue();
                } else if (name == QLatin1String("InitiallyOn")) {
                    trigger.initiallyOn = readBoolValue();
                } else if (name == QLatin1String("TurnOffAfterAction")) {
                    trigger.turnOffAfterAction = readBoolValue();
                } else if (name == QLatin1String("Events")) {
                    trigger.events = readObjectList("Event");
                } else if (name == QLatin1String("Conditions")) {
                    trigger.conditions = readObjectList("Condition");
                } else if (name == QLatin1String("Actions")) {
                    trigger.actions = readObjectList("Action");
                } else {
                    m_xml.skipCurrentElement();
                }
            }
            trigger.setToInitialState();
            return trigger;
        }

        QXmlStreamReader m_xml;
        QString m_error;
    };
} // namespace

QByteArray TriggerXml::writeTriggerSystem(const TriggerCollection& collection)
{
    QByteArray xml;
    QXmlStreamWriter writer(&xml);
    startDocument(writer, "TriggerSystem");
    if (!collection.enabled) {
        writer.writeTextElement("Enabled", xmlBool(false));
    }
    writeTriggers(writer, collection.triggers);
    writer.writeEndElement();
    writer.writeEndDocument();
    return xml;
}

bool TriggerXml::readTriggerSystem(const QByteArray& xml, TriggerCollection* collection, QString* error)
{
    Q_ASSERT(collection);
    TriggerCollection result;
    Reader reader(xml);
    const bool ok = reader.readRoot("TriggerSystem", [&] {
        if (reader.name() == QLatin1String("Enabled")) {
            result.enabled = reader.readBoolValue();
        } else if (reader.name() == QLatin1String("Triggers")) {
            result.triggers << reader.readTriggers();
        } else {
            reader.skip();
        }
    });
    if (!ok) {
        if (error) {
            *error = reader.errorString();
        }
        return false;
    }
    *collection = result;
    return true;
}

QByteArray TriggerXml::writeTriggerCollection(const QList<Trigger>& triggers)
{
    QByteArray xml;
    QXmlStreamWriter writer(&xml);
    startDocument(writer, "TriggerCollection");
    writeTriggers(writer, triggers);
    writer.writeEndElement();
    writer.writeEndDocument();
    return xml;
}

bool TriggerXml::readTriggerCollection(const QByteArray& xml, QList<Trigger>* triggers, QString* error)
{
    Q_ASSERT(triggers);
    QList<Trigger> result;
    Reader reader(xml);
    const bool ok = reader.readRoot("TriggerCollection", [&] {
        if (reader.name() == QLatin1String("Triggers")) {
            result << reader.readTriggers();
        } else {
            reader.skip();
        }
    });
    if (!ok) {
        if (error) {
            *error = reader.errorString();
        }
        return false;
    }
    *triggers = result;
    return true;
}
