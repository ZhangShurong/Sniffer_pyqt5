import QtQuick 2.4
import QtQuick.Controls 1.3
import QQSFPM 0.2

TableView {
    id: packed_table
    currentRow: -2

    TableViewColumn{
        id: number_column
        role: "number"
        title: "No."
        width: 60
        horizontalAlignment: Text.AlignHCenter
    }

    TableViewColumn{
        id: time_column
        role: "time"
        title: "Time"
        width: 80
        horizontalAlignment: Text.AlignHCenter

    }

    TableViewColumn{
        id: sourceip_column
        role: "sourceip"
        title: "Source"
        width: 150
        horizontalAlignment: Text.AlignHCenter
    }

    TableViewColumn{
        id: destip_column
        role: "destip"
        title: "Destination"
        width: 150
        horizontalAlignment: Text.AlignHCenter
    }

    TableViewColumn{
        id: protocol_column
        role: "procotol"
        title: "Protocol"
        width: 100
        horizontalAlignment: Text.AlignHCenter
    }

    TableViewColumn{
        id: lenth_column
        role: "lenth"
        title: "Lenth"
        width: 80
        horizontalAlignment: Text.AlignHCenter
    }

    TableViewColumn{
        id: info_column
        role: "info"
        title: "Information"
        width: parent.width - 620
        horizontalAlignment: Text.AlignHCenter
    }
    ListModel {
        id: libraryModel
    }
    model: packetProxyModel
    SortFilterProxyModel {
        id: packetProxyModel
        sourceModel: libraryModel
        filters: RegExpFilter {
            roleName:"procotol"
            pattern:""
            caseSensitivity:Qt.CaseInsensitive
        }
    }
    onClicked:{
        console.log(packetProxyModel.get(row).number)
        sniffer.selectPacket(packetProxyModel.get(row).number - 1)
    }
    Connections {
    target: sniffer
    onNewPacketCatched: {
        libraryModel.append({
                "number" : number, 
                "time" : time, 
                "sourceip": sourceip,
                "destip": destip,
                "procotol" : procotol,
                "lenth": lenth,
                "info": info
        })
    }
    property  list<RegExpFilter> filters_test: [
    RegExpFilter {
            id:filter
            roleName:"procotol"
            pattern:""
            caseSensitivity:Qt.CaseInsensitive
    }
    ]
    onFilterSelected: {
        filters_test[0].pattern = pattern
        packetProxyModel.filters = filters_test
    }
  }
}

