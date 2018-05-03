from PyQt5.QtCore import QAbstractItemModel, QFile, QIODevice, QModelIndex, Qt
from PyQt5.QtWidgets import QApplication, QTreeView
from scapy.all import *


class TreeItem(object):
    def __init__(self, data, parent=None):
        self.parentItem = parent
        self.itemData = data
        self.childItems = []

    def appendChild(self, item):
        self.childItems.append(item)

    def child(self, row):
        return self.childItems[row]

    def childCount(self):
        return len(self.childItems)

    def columnCount(self):
        return len(self.itemData)

    def data(self, column):
        try:
            return self.itemData[column]
        except IndexError:
            return None

    def parent(self):
        return self.parentItem

    def row(self):
        if self.parentItem:
            return self.parentItem.childItems.index(self)
        return 0

    def clearChildren(self):
        if self.childCount() <= 0:
            return
        self.childItems.clear()


class TreeModel(QAbstractItemModel):
    rootItem = None
    def __init__(self, parent=None):
        super(TreeModel, self).__init__(parent)
        self.rootItem = TreeItem(["content"])
        #self.EtherNet_item = TreeItem(["Ethernet II"], self.rootItem)
        #self.rootItem.appendChild(self.EtherNet_item)

    def setPacket(self, packet):
        if packet is None:
            return
        self.rootItem.clearChildren()
        EtherNet_item = TreeItem(["Ethernet II"], self.rootItem)
        index_root = QModelIndex()
        index_Ethernet = self.index(0, 0, index_root)
        #-----EtherNet start----------

        src = packet.getlayer(Ether).src
        dst = packet.getlayer(Ether).dst
        eth_type = str(packet.getlayer(Ether).type)
        if int(packet.getlayer(Ether).type) == 34525:#IPv6
            eth_type = "IPv6(0x86DD)"
        elif int(packet.getlayer(Ether).type) == 2048:#IPv4
            eth_type = "IPv4(0x0800)"
        elif int(packet.getlayer(Ether).type) == 2054:#ARP
            eth_type = "ARP(0x0800)"

        src_item = TreeItem(["Source: " + src], EtherNet_item)
        dst_item = TreeItem(["Destination: " + dst], EtherNet_item)
        type_item = TreeItem(["Type: " + eth_type], EtherNet_item)
        EtherNet_item.appendChild(src_item)
        EtherNet_item.appendChild(dst_item)
        EtherNet_item.appendChild(type_item)
        EtherNet_item.itemData = ["Ethernet II, " + "Src: " + src +", Dst: " + dst]
        self.rootItem.appendChild(EtherNet_item)

        index_start = self.index(0, 0, index_Ethernet)
        index_end = self.index(2, 0, index_Ethernet)

        self.modelReset.emit()
        self.dataChanged.emit(index_Ethernet, index_Ethernet)
        self.dataChanged.emit(index_start, index_end)
        #-----EtherNet end----------

        if int(packet.getlayer(Ether).type) == 34525:
            proto = 'IPv6'
            src = str(packet.getlayer(IPv6).src)
            dst = str(packet.getlayer(IPv6).dst)
            info = str(packet.summary())
            
        elif int(packet.getlayer(Ether).type) == 2048:
            src = str(packet.getlayer(IP).src)
            dst = str(packet.getlayer(IP).dst)
            info = str(packet.summary())
            ipv4_item = TreeItem(["Internet Protocal Version 4, Src:" + src + 
                            ", Dst: " + dst], self.rootItem)
            src_item = TreeItem(["Source: "+src], ipv4_item)
            dst_item = TreeItem(["Destination: "+dst], ipv4_item)
            version_item = TreeItem(["0100 .... = Version 4"], ipv4_item)
            ipv4_item.appendChild(version_item)
            ipv4_item.appendChild(src_item)
            ipv4_item.appendChild(dst_item)
            self.rootItem.appendChild(ipv4_item)

            index_root = QModelIndex()
            index_Ethernet = self.index(0, 0, index_root)
            index_ipv4 = self.index(1, 0, index_root)

            index_start = self.index(0, 0, index_ipv4)
            index_end = self.index(2, 0, index_ipv4)

            self.dataChanged.emit(index_Ethernet, index_ipv4)
            self.dataChanged.emit(index_root, index_root)
            self.dataChanged.emit(index_start, index_end)

            header_len = packet.getlayer(IP).len
            print("___________-")
            print(header_len)
            print("___________-")
            print(info)

            if int(packet.getlayer(IP).proto) == 6:
                proto = 'TCP'
            elif int(packet.getlayer(IP).proto) == 17:
                proto = 'UDP'
            elif int(packet.getlayer(IP).proto) == 1:
                proto = 'ICMP'
            

        elif int(packet.getlayer(Ether).type) == 2054:
            proto = 'ARP'
            src = str(packet.getlayer(ARP).psrc)
            dst = str(packet.getlayer(ARP).pdst)
            info = str(packet.summary())
        self.modelReset.emit()
        

    def columnCount(self, parent):
        if parent.isValid():
            return parent.internalPointer().columnCount()
        else:
            return self.rootItem.columnCount()

    def roleNames(self):
        roles = {
                Qt.UserRole + 1: b"content",
            }
        return roles

    def data(self, index, role):
        if not index.isValid():
            return None

        # if role != Qt.DisplayRole:
        #     return None

        item = index.internalPointer()
        return item.data(index.column())

    def flags(self, index):
        if not index.isValid():
            return Qt.NoItemFlags

        return Qt.ItemIsEnabled | Qt.ItemIsSelectable

    def headerData(self, section, orientation, role):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.rootItem.data(section)

        return None

    def index(self, row, column, parent):
        if not self.hasIndex(row, column, parent):
            return QModelIndex()

        if not parent.isValid():
            parentItem = self.rootItem
        else:
            parentItem = parent.internalPointer()

        childItem = parentItem.child(row)
        if childItem:
            return self.createIndex(row, column, childItem)
        else:
            return QModelIndex()

    def parent(self, index):
        if not index.isValid():
            return QModelIndex()

        childItem = index.internalPointer()
        parentItem = childItem.parent()

        if parentItem == self.rootItem:
            return QModelIndex()

        return self.createIndex(parentItem.row(), 0, parentItem)

    def rowCount(self, parent):
        if parent.column() > 0:
            return 0

        if not parent.isValid():
            parentItem = self.rootItem
        else:
            parentItem = parent.internalPointer()

        return parentItem.childCount()

