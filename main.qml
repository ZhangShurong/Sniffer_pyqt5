import QtQuick 2.9
import QtQuick.Window 2.2
import QtQuick.Layouts 1.3
import QtQuick.Controls 1.4
//import Material 0.2
ApplicationWindow {
    id: window
    minimumWidth: 1000
    minimumHeight: 700
    title: qsTr("MySniffer")
    visible: true

    ColumnLayout {
        id: columnLayout
        anchors.fill: parent
        anchors.margins: 10
        spacing: 2

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
            anchors.bottom : count_label.top
            anchors.top : packetTree.bottom
            Layout.minimumHeight: 80
            Layout.fillWidth: true
        }

        Label {
        anchors.bottom : parent.bottom
        id: count_label
            text: ""
        }
     Connections {
    target: sniffer
    onUpdateCount: {
    //['total', 'ipv4', 'ipv6', 'tcp', 'udp', 'arp', 'http', 'icmp'])
        count_label.text = "Total: " + total +
                            "; ipv4: " + ipv4 +
                            "; ipv6: " + ipv6 +
                            "; tcp: " + tcp +
                            "; udp: " + udp +
                            "; arp: " + arp +
                            "; http: " + http +
                            "; icmp: " + icmp
    }
    }
Item { Layout.fillHeight: true }    // <-- filler here
    }
}
