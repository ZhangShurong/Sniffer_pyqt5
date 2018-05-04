import QtQuick 2.0
import QtQuick.Controls 1.4
Rectangle {
id: background;
border {
            width: 1;
        }
TextArea {
    id: hexText
    anchors.fill: parent;
    font.family: "Consolas"
    Connections {
    target: sniffer
    onHexChanged: {
        hexText.text = hex
        console.log(hex)
    }
  }
}
}