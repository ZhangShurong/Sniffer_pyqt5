import QtQuick 2.0
import QtQuick.Controls 1.4

TextEdit {
    id: hexText
    Connections {
    target: sniffer
    onHexChanged: {
        hexText.text = hex
        console.log(hex)
    }
  }
}
