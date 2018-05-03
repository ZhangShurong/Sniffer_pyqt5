from PyQt5.QtCore import QAbstractItemModel, QFile, QIODevice, QModelIndex, Qt
from PyQt5.QtWidgets import QApplication, QTreeView
from scapy.all import *
import HTTPParser
'''
###[ IP ]### 
 version   = 4
 ihl       = 5
 tos       = 0x50
 len       = 52
 id        = 30803
 flags     = 
 frag      = 0
 ttl       = 47
 proto     = tcp
 chksum    = 0x64c4
 src       = 203.208.50.90
 dst       = 10.11.166.39
###[ TCP ]### 
        sport     = 63163
        dport     = www_http
        seq       = 2838763121
        ack       = 2507956993
        dataofs   = 5
        reserved  = 0
        flags     = FA
        window    = 255
        chksum    = 0x828c
        urgptr    = 0
        options   = []

###[ UDP ]### 
        sport     = 54817
        dport     = ssdp
        len       = 137
        chksum    = 0x3553
###[ ARP ]### 
     hwtype    = 0x1
     ptype     = 0x800
     hwlen     = 6
     plen      = 4
     op        = who-has
     hwsrc     = 84:ef:18:c2:83:e6
     psrc      = 0.0.0.0
     hwdst     = 00:00:00:00:00:00
     pdst      = 10.11.166.249
###[ ICMP ]### 
        type      = echo-request
        code      = 0
        chksum    = 0x8d1f
        id        = 0x4f38
        seq       = 0x2

'''

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

    def setPacket(self, packet):
        if packet is None:
            return
        self.rootItem.clearChildren()

        src = packet.getlayer(Ether).src
        dst = packet.getlayer(Ether).dst
        eth_type = str(packet.getlayer(Ether).type)
        if int(packet.getlayer(Ether).type) == 34525:#IPv6
            eth_type = "IPv6(0x86DD)"
        elif int(packet.getlayer(Ether).type) == 2048:#IPv4
            eth_type = "IPv4(0x0800)"
        elif int(packet.getlayer(Ether).type) == 2054:#ARP
            eth_type = "ARP(0x0800)"

        EtherNet_item = TreeItem(["Ethernet II"], self.rootItem)
        src_item = TreeItem(["Source: " + src], EtherNet_item)
        dst_item = TreeItem(["Destination: " + dst], EtherNet_item)
        type_item = TreeItem(["Type: " + eth_type], EtherNet_item)
        EtherNet_item.appendChild(src_item)
        EtherNet_item.appendChild(dst_item)
        EtherNet_item.appendChild(type_item)
        EtherNet_item.itemData = ["Ethernet II, " + "Src: " + src +", Dst: " + dst]
        self.rootItem.appendChild(EtherNet_item)
        #-----EtherNet end----------

        if int(packet.getlayer(Ether).type) == 34525:
            proto = 'IPv6'
            src = str(packet.getlayer(IPv6).src)
            dst = str(packet.getlayer(IPv6).dst)
            info = str(packet.summary())
            
        elif int(packet.getlayer(Ether).type) == 2048:

            if int(packet.getlayer(IP).proto) == 6:
                proto = 'TCP'
            elif int(packet.getlayer(IP).proto) == 17:
                proto = 'UDP'
            elif int(packet.getlayer(IP).proto) == 1:
                proto = 'ICMP'

            src = str(packet.getlayer(IP).src)
            dst = str(packet.getlayer(IP).dst)
            header_len = packet.getlayer(IP).ihl
            header_len_str = ".... {:04b} = Header Length: {:d} bytes({:d})".format(header_len, header_len * 4,header_len)
            total_len_str = "Total length: {:d}".format(packet.getlayer(IP).len)
            identification_str = "Identification: 0x{:04x} ({:d})".format(packet.getlayer(IP).id, packet.getlayer(IP).id)
            # flags_str = "Flag: 0x{:04x}".format(packet.getlayer(IP).flag) TODO
            ttl_str = "Time to live: {:d}".format(packet.getlayer(IP).ttl)
            proto_str = "Protocol: {proto_str} ({:d})".format(packet.getlayer(IP).proto, proto_str = proto)
            chksum_str = "Header cheaksum: {:04x}".format(packet.getlayer(IP).chksum)
            info = str(packet.summary())

            ipv4_item = TreeItem(["Internet Protocal Version 4, Src:" + src + 
                            ", Dst: " + dst], self.rootItem)
            src_item = TreeItem(["Source: "+src], ipv4_item)
            dst_item = TreeItem(["Destination: "+dst], ipv4_item)
            version_item = TreeItem(["0100 .... = Version 4"], ipv4_item)
            header_len_item = TreeItem([header_len_str], ipv4_item)
            total_len_item = TreeItem([total_len_str], ipv4_item)
            identification_item = TreeItem([identification_str], ipv4_item)
            # flags_item = TreeItem([flags_str], ipv4_item)
            ttl_item = TreeItem([ttl_str], ipv4_item)
            proto_item = TreeItem([proto_str], ipv4_item)
            chksum_item = TreeItem([chksum_str], ipv4_item)

            ipv4_item.appendChild(version_item)
            ipv4_item.appendChild(header_len_item)
            ipv4_item.appendChild(total_len_item)
            ipv4_item.appendChild(identification_item)
            # ipv4_item.appendChild(flags_item)
            ipv4_item.appendChild(ttl_item)
            ipv4_item.appendChild(proto_item)
            ipv4_item.appendChild(chksum_item)
            ipv4_item.appendChild(src_item)
            ipv4_item.appendChild(dst_item)
            self.rootItem.appendChild(ipv4_item)

            if int(packet.getlayer(IP).proto) == 6: #TCP
                tcp_packet = packet.getlayer(TCP)
                sport_str = "Source Port: {:d}".format(tcp_packet.sport)
                dport_str = "Destination Port: {:d}".format(tcp_packet.dport)
                dataofs_str = "Data offset: {:d}".format(tcp_packet.dataofs)
                reserved_str = "Reserved: {:d}".format(tcp_packet.reserved)
                sql_str = "Sequence Number: {:d}".format(tcp_packet.seq)
                ack_str = "Acknowledge number: {:d}".format(tcp_packet.ack)
                header_len_str = "0101 .... = Header Length: 20 bytes (5)"
                window_str = "Window size value: {:d}".format(tcp_packet.window)
                chksum_str = "Checksum: 0x{:04x}".format(tcp_packet.chksum)
                urgptr_str = "Urgent pointer: {:d}".format(tcp_packet.urgptr)
                tcp_str = "Transmission Control Protocol, Src Port: {:d}, Dst Port: {:d}, " \
                          "Seq: {:d}, Ack: {:d}, Len: 1"\
                            .format(tcp_packet.sport, tcp_packet.dport,
                                    tcp_packet.seq, tcp_packet.ack)
                tcp_item = TreeItem([tcp_str], self.rootItem)
                sport_item = TreeItem([sport_str], tcp_item)
                dport_item = TreeItem([dport_str], tcp_item)
                dataofs_item = TreeItem([dataofs_str], tcp_item)
                reserved_item = TreeItem([reserved_str], tcp_item)
                sql_item = TreeItem([sql_str], tcp_item)
                ack_item = TreeItem([ack_str], tcp_item)
                header_len_item = TreeItem([header_len_str], tcp_item)
                window_item = TreeItem([window_str], tcp_item)
                chksum_item = TreeItem([chksum_str], tcp_item)
                urgptr_item = TreeItem([urgptr_str], tcp_item)

                tcp_item.appendChild(sport_item)
                tcp_item.appendChild(dport_item)
                tcp_item.appendChild(dataofs_item)
                tcp_item.appendChild(reserved_item)
                tcp_item.appendChild(sql_item)
                tcp_item.appendChild(ack_item)
                tcp_item.appendChild(header_len_item)
                tcp_item.appendChild(window_item)
                tcp_item.appendChild(chksum_item)
                tcp_item.appendChild(urgptr_item)
                self.rootItem.appendChild(tcp_item)

                #Parse HTTP
                if HTTPParser.isHTTP(packet):
                    httpItem = TreeItem(["Hypertext Transfer Protocol"], self.rootItem)
                    packet_str = packet.getlayer(Raw).load.decode(errors='ignore')
                    HTTP_list = packet_str.split("\n")
                    for http_str in HTTP_list:
                        http_str = http_str.strip()
                        if len(http_str) > 0:
                            newItem = TreeItem([http_str], httpItem)
                            httpItem.appendChild(newItem)
                    self.rootItem.appendChild(httpItem)

            elif int(packet.getlayer(IP).proto) == 17:
                udp_packet = packet.getlayer(UDP)
                udp_str = "User Datagram Protocol, Src Port: {:d}, Dst Port: {:d}"\
                    .format(udp_packet.sport, udp_packet.dport)
                sport_str = "Source Port: {:d}".format(udp_packet.sport)
                dport_str = "Destination Port: {:d}".format(udp_packet.dport)
                len_str = "Length: {:d}".format(udp_packet.len)
                chksum_str = "Checksum: 0x{:04x}".format(udp_packet.chksum)
                udp_item = TreeItem([udp_str], self.rootItem)
                sport_item = TreeItem([sport_str], udp_item)
                dport_item = TreeItem([dport_str], udp_item)
                len_item = TreeItem([len_str], udp_item)
                chksum_item = TreeItem([chksum_str], udp_item)
                udp_item.appendChild(sport_item)
                udp_item.appendChild(dport_item)
                udp_item.appendChild(len_item)
                udp_item.appendChild(chksum_item)
                self.rootItem.appendChild(udp_item)

                if packet.haslayer(Raw):
                    raw_packet = udp_packet.load
                    data_str = "Data ({:d} bytes)".format(len(raw_packet))
                    raw_str = raw_packet.hex()
                    if len(raw_str) >= 100:
                        raw_str = raw_str[:100] + "..."

                    load_str = "Data: " + raw_str
                    data_item = TreeItem([data_str], self.rootItem)
                    load_item = TreeItem([load_str], data_item)
                    data_item.appendChild(load_item)
                    self.rootItem.appendChild(data_item)

            elif int(packet.getlayer(IP).proto) == 1:
                icmp_packet = packet.getlayer(ICMP)
                icmp_str = "Internet Control Message Protocol"
                icmp_type = ""
                if icmp_packet.type == 0:
                    icmp_type = "(Echo (ping) reply)"
                elif icmp_packet.type == 8:
                    icmp_type = "(Echo (ping) request)"
                type_str = "Type: {:d} {icmp_type}".format(icmp_packet.type,icmp_type =  icmp_type)
                code_str = "Code: {:d}".format(icmp_packet.code)
                chksum_str = "Checksum: 0x{:04x}".format(icmp_packet.chksum)
                id_str = "Identifier : {:d} (0x{:04x})".format(icmp_packet.id, icmp_packet.id)
                seq_str = "Sequence number : {:d} (0x{:04x})".format(icmp_packet.seq, icmp_packet.seq)
                icmp_item = TreeItem([icmp_str], self.rootItem)
                type_item = TreeItem([type_str], icmp_item)
                code_item = TreeItem([code_str], icmp_item)
                chksum_item = TreeItem([chksum_str], icmp_item)
                id_item = TreeItem([id_str], icmp_item)
                seq_item = TreeItem([seq_str], icmp_item)
                icmp_item.appendChild(type_item)
                icmp_item.appendChild(code_item)
                icmp_item.appendChild(chksum_item)
                icmp_item.appendChild(id_item)
                icmp_item.appendChild(seq_item)
                self.rootItem.appendChild(icmp_item)


        elif int(packet.getlayer(Ether).type) == 2054:
            arp_packet = packet.getlayer(ARP)
            arp_str = "Address Resolution Protocol"
            hwtype_str = "Hardware type: Ethernet ({:d})".format(arp_packet.hwtype)
            ptype_str = "Protocol type: IPv4 (0x0800)"
            hwlen_str = "Hardware size: {:d}".format(arp_packet.hwlen)
            plen_str = "Protocol size: {:d}".format(arp_packet.plen)
            op_str = "Opcode: {op} ({:d})".format(arp_packet.op, op = "request" if arp_packet.op == 1 else "reply")
            hwsrc_str = "Sender MAC address: "+arp_packet.hwsrc
            psrc_str = "Sender IP address: "+ str(packet.getlayer(ARP).psrc)
            hwdst_str = "Target MAC address: " + arp_packet.hwdst
            pdst_str = "Target IP address: " + str(packet.getlayer(ARP).pdst)
            arp_item = TreeItem([arp_str], self.rootItem)
            hwtype_item = TreeItem([hwtype_str], arp_item)
            ptype_item = TreeItem([ptype_str], arp_item)
            hwlen_item = TreeItem([hwlen_str], arp_item)
            plen_item = TreeItem([plen_str], arp_item)
            op_item = TreeItem([op_str], arp_item)
            hwsrc_item = TreeItem([hwsrc_str], arp_item)
            psrc_item = TreeItem([psrc_str], arp_item)
            hwdst_item = TreeItem([hwdst_str], arp_item)
            pdst_item = TreeItem([pdst_str], arp_item)
            arp_item.appendChild(hwtype_item)
            arp_item.appendChild(ptype_item)
            arp_item.appendChild(hwlen_item)
            arp_item.appendChild(plen_item)
            arp_item.appendChild(op_item)
            arp_item.appendChild(hwsrc_item)
            arp_item.appendChild(psrc_item)
            arp_item.appendChild(hwdst_item)
            arp_item.appendChild(pdst_item)
            self.rootItem.appendChild(arp_item)

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

