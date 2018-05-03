import QtQuick 2.4
import QtQuick.Controls 1.4
TreeView {
    highlightOnFocus: true
    id: treeview
    model: packetItemModel  
    TableViewColumn {  
        role: "content"  
        title: "Content"  
    }
    Connections {
        target: packetItemModel
        onDataChanged: {
            console.log("QML got data changed signal, row:", topLeft.row, "item:", topLeft.data, "roles:", roles)
            //model.reset()
        }
        onLayoutChanged: {
            console.log("QML got layout changed signal")
        }
    }
}
