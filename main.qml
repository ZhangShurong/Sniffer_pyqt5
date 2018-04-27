import QtQuick 2.9
import QtQuick.Window 2.2
import QtQuick.Layouts 1.3
Window {
    id: window
    minimumWidth: 1000
    minimumHeight: 700
    title: qsTr("MySniffer")
    visible: true

    ColumnLayout {
        id: columnLayout
        anchors.fill: parent
        anchors.margins: 10
        spacing: 10

        Toolbar {
            id: toolbar
            Layout.fillHeight: true
            Layout.fillWidth: true
        }

        PacketTable {
            id: packetTable
            Layout.minimumHeight: 300
            Layout.fillWidth: true
        }

        PacketTree {
            id: packetTree
            Layout.minimumHeight: 80
            Layout.fillWidth: true
        }

        HexTree{
            id: hexTree
            Layout.minimumHeight: 80
            Layout.fillWidth: true
        }
        
        
    }


}
