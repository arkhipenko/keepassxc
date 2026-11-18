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

#ifndef KEEPASSXC_TESTTRIGGERS_H
#define KEEPASSXC_TESTTRIGGERS_H

#include <QObject>

class TestTriggers : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanup();

    // Types and parameters
    void testTypeUuids();
    void testStringToBool();
    void testParamHelpers();
    void testSplitPaths_data();
    void testSplitPaths();
    void testCompareStrings();
    void testParametersToString();

    // XML
    void testReadKeePassXml();
    void testXmlRoundTrip();
    void testTriggerSystemXml();
    void testInvalidXml();
    void testPasteNewUuid();

    // Sealed file and trigger key
    void testTriggerKeyValue();
    void testTriggerKeyInDatabase();
    void testTriggerFileRoundTrip();
    void testTriggerFileTamper();
    void testTriggerFileKeyMismatch();
    void testTriggerFileMissing();
    void testTriggerKeySurvivesMerge();

    // Execution model
    void testNotLoaded();
    void testGlobalSwitch();
    void testOrderAndMatching();
    void testConditionsAndNegate();
    void testAbort();
    void testTurnOffAfterAction();
    void testErrorSkipsRemainingTriggers();
    void testUnknownTypes();
    void testChangeTriggerState();
    void testEventFilters();
    void testPeriodicEvent();
    void testReplaceKeepsState();
    void testConditions();

    // Placeholders
    void testPlaceholdersWithoutEntry();
    void testPlaceholdersWithEntry();
    void testPlaceholderComments();
    void testPlaceholderClipboard();
    void testPlaceholderCommand();
    void testCommandLineEncoding();
};

#endif // KEEPASSXC_TESTTRIGGERS_H
