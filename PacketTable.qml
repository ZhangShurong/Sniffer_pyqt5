import QtQuick 2.4
import QtQuick.Controls 1.3
TableView {
    currentRow: -2

    TableViewColumn{
        id: number_column
       // role: number
        title: "No."
        width: 60
        horizontalAlignment: Text.AlignHCenter
    }

    TableViewColumn{
        id: time_column
      //  role: time
        title: "Time"
        width: 80
        horizontalAlignment: Text.AlignHCenter

    }

    TableViewColumn{
        id: sourceip_column
       // role: sourceip
        title: "Source"
        width: 150
        horizontalAlignment: Text.AlignHCenter
    }

    TableViewColumn{
        id: destip_column
       // role: destip
        title: "Destination"
        width: 150
        horizontalAlignment: Text.AlignHCenter
    }

    TableViewColumn{
        id: protocol_column
       // role: procotol
        title: "Protocol"
        width: 100
        horizontalAlignment: Text.AlignHCenter
    }

    TableViewColumn{
        id: lenth_column
       // role: lenth
        title: "Lenth"
        width: 80
        horizontalAlignment: Text.AlignHCenter
    }

    TableViewColumn{
        id: info_column
       // role: info
        title: "Information"
        width: parent.width - 620
        horizontalAlignment: Text.AlignHCenter
    }

}

