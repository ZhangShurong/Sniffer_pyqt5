import QtQuick 2.0
import QtQml 2.2
import QtTest 1.1
import SortFilterProxyModel 0.2
import SortFilterProxyModel.Test 0.2

Item {
    ListModel {
        id: listModel
        ListElement { test: "first" }
        ListElement { test: "second" }
        ListElement { test: "third" }
        ListElement { test: "fourth" }
    }

    property list<QtObject> sorters: [
        QtObject {
          property string tag: "no sorter"
          property bool notASorter: true
          property var expectedValues: ["first", "second", "third", "fourth"]
        },
        IndexSorter {
            property string tag: "Dummy IndexSorter"
            property var expectedValues: ["first", "second", "third", "fourth"]
        },
        ReverseIndexSorter {
            property string tag: "Dummy ReverseIndexSorter"
            property var expectedValues: ["fourth", "third", "second", "first"]
        },
        IndexSorter {
            property string tag: "Disabled dummy IndexSorter"
            enabled: false
            property var expectedValues: ["first", "second", "third", "fourth"]
        },
        ReverseIndexSorter {
            property string tag: "Disabled dummy ReverseIndexSorter"
            enabled: false
            property var expectedValues: ["first", "second", "third", "fourth"]
        },
        IndexSorter {
            property string tag: "Descending dummy IndexSorter"
            ascendingOrder: false
            property var expectedValues: ["fourth", "third", "second", "first"]
        },
        ReverseIndexSorter {
            property string tag: "Descending dummy ReverseIndexSorter"
            ascendingOrder: false
            property var expectedValues: ["first", "second", "third", "fourth"]
        },
        IndexSorter {
            property string tag: "Disabled descending dummy IndexSorter"
            enabled: false
            ascendingOrder: false
            property var expectedValues: ["first", "second", "third", "fourth"]
        },
        ReverseIndexSorter {
            property string tag: "Disabled descending dummy ReverseIndexSorter"
            enabled: false
            ascendingOrder: false
            property var expectedValues: ["first", "second", "third", "fourth"]
        }
    ]
    ReverseIndexSorter {
        id: reverseIndexSorter
    }
    SortFilterProxyModel {
        id: testModel
        sourceModel: listModel
    }

    TestCase {
        name: "SortersTests"

        function test_indexOrder_data() {
            return sorters;
        }

        function test_indexOrder(sorter) {
            testModel.sorters = sorter;
            verifyModelValues(testModel, sorter.expectedValues);
        }

        function test_enablingSorter() {
            reverseIndexSorter.enabled = false;
            testModel.sorters = reverseIndexSorter;
            var expectedValuesBeforeEnabling = ["first", "second", "third", "fourth"];
            var expectedValuesAfterEnabling = ["fourth", "third", "second", "first"];
            verifyModelValues(testModel, expectedValuesBeforeEnabling);
            reverseIndexSorter.enabled = true;
            verifyModelValues(testModel, expectedValuesAfterEnabling);
        }

        function test_disablingSorter() {
            reverseIndexSorter.enabled = true;
            testModel.sorters = reverseIndexSorter;
            var expectedValuesBeforeDisabling = ["fourth", "third", "second", "first"];
            var expectedValuesAfterDisabling = ["first", "second", "third", "fourth"];
            verifyModelValues(testModel, expectedValuesBeforeDisabling);
            reverseIndexSorter.enabled = false;
            verifyModelValues(testModel, expectedValuesAfterDisabling);
        }

        function verifyModelValues(model, expectedValues) {
            verify(model.count === expectedValues.length,
                   "Expected count " + expectedValues.length + ", actual count: " + model.count);
            for (var i = 0; i < model.count; i++)
            {
                var modelValue = model.data(model.index(i, 0));
                verify(modelValue === expectedValues[i],
                       "Expected testModel value " + expectedValues[i] + ", actual: " + modelValue);
            }
        }
    }
}
