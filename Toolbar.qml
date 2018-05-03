import QtQuick 2.0
import QtQuick.Controls 1.4
import QtQuick.Layouts 1.3



RowLayout {

    spacing: 10
    anchors.left: parent.left
    anchors.right: parent.right

    ColumnLayout {
        id: interfaceLayout
        Layout.alignment: Qt.AlignBottom
        spacing: 2

        Label {
            id: interfaceLabel
            text: qsTr("Interface")
        }

        ComboBox {
            id: interfaceComboBox
            Layout.fillWidth: true
            //model: ["First", "Second", "Third"]
            model: interfaces.interfaceList()
            onActivated:{
                console.log(index)
                interfaces.selected(index)
            }
        }
    }

    ColumnLayout {
        id: filterLayout
        Layout.alignment: Qt.AlignBottom
        spacing: 2

        Label {
            id: filterLabel
            text: qsTr("Filter Profile")
        }

        ComboBox {
            id: filterComboBox
            Layout.fillWidth: true
            model: sniffer.filterList()
            onActivated:{
                console.log(index)
                sniffer.selectFilter(index)
            }
        }
    }

    ColumnLayout {
        id: columnLayout


        Label {
            id: ipLabel
            text: qsTr("Target IP")
        }

        TextField {
            id: ipText
            Layout.fillWidth: true
            placeholderText: qsTr("Target IP")

        }
    }

    Button {
        id: start
        text: qsTr("Start")
        Layout.alignment: Qt.AlignBottom
        onClicked:{
            sniffer.start_sniff()
        }
    }

    Button {
        id: pause
        text: qsTr("Pause")
        Layout.alignment: Qt.AlignBottom
        onClicked:{
            sniffer.stop_sniff()
        }
    }

    Button {
        id: clear
        text: qsTr("Clear")
        Layout.alignment: Qt.AlignBottom
    }

    Button {
        id: save
        text: qsTr("Save")
        Layout.alignment: Qt.AlignBottom
    }

}


