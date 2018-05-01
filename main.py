import sys  
from PyQt5.QtCore import pyqtProperty, QCoreApplication, QObject, QUrl, pyqtSignal, pyqtSlot
from PyQt5.QtQml import qmlRegisterType, QQmlComponent, QQmlEngine
from PyQt5 import QtCore, QtGui, QtWidgets, QtQml,QtQuick
from PyQt5.QtQuick import QQuickView, QQuickItem
import socket
import fcntl
import struct
from scapy.all import *
import threading
import tempfile

IFACE = 'wlp8s0'   #网卡名称
STOP = True      #停止嗅探
PACKETS = []     #数据包收集序列
SELECT_ROW = 0   #选择的行
SELECT_INFO = '' #选择行的详细信息
SHOW2STR = ''   #show2()显示的字符串
HEXSTR = ''     #hex()显示的信息
FILTER = None   #过滤规则

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
        print(result)


    addElement = pyqtSignal(str, str)   #you call it like this  - addElement.emit("name", "value")

class Sniffer(QObject):
    newPacketCatched = pyqtSignal(str, str, str, str, str, str, str,
                arguments = ["number", "time","sourceip","destip","procotol","lenth","info"])
    def __init__(self, parent=None):
        super().__init__(parent)
        #开始嗅探
    
    #处理数据包
    def handle_packets(self, packet):
        print("packet")
        if int(packet.getlayer(Ether).type) == 34525 and STOP:
            proto = 'IPv6'
            src = str(packet.getlayer(IPv6).src)
            dst = str(packet.getlayer(IPv6).dst)
            info = str(packet.summary())
            self.newPacketCatched.emit("0", "now", src, dst, proto, "todo", info)
            #self.packet_table.row_append(src, dst, proto, info)
            PACKETS.append(packet)
        elif int(packet.getlayer(Ether).type) == 2048 and STOP:
            if int(packet.getlayer(IP).proto) == 6:
                proto = 'TCP'
            elif int(packet.getlayer(IP).proto) == 17:
                proto = 'UDP'
            elif int(packet.getlayer(IP).proto) == 1:
                proto = 'ICMP'
            src = str(packet.getlayer(IP).src)
            dst = str(packet.getlayer(IP).dst)
            info = str(packet.summary())
            #self.packet_table.row_append(src, dst, proto, info)
            self.newPacketCatched.emit("0", "now", src, dst, proto, "todo", info)
            PACKETS.append(packet)
        elif int(packet.getlayer(Ether).type) == 2054 and STOP:
            proto = 'ARP'
            src = str(packet.getlayer(ARP).psrc)
            dst = str(packet.getlayer(ARP).pdst)
            info = str(packet.summary())
            #self.packet_table.row_append(src, dst, proto, info)
            self.newPacketCatched.emit("0", "now", src, dst, proto, "todo", info)
            PACKETS.append(packet)
        else:
            pass

    @pyqtSlot()
    def start_sniff(self):
        sniff_thread = threading.Thread(target=sniffer, args=(IFACE, self.handle_packets))
        sniff_thread.start()

    #停止嗅探
    @pyqtSlot()
    def stop_sniff(self):
        global STOP
        STOP = False

    #重新开始
    def restart_sniff(self):
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

def main():
    app = QtWidgets.QApplication(sys.argv)
    engine = QtQml.QQmlApplicationEngine()
    interfaces = Interfaces()
    engine.rootContext().setContextProperty('interfaces', interfaces)
    sniffer = Sniffer()
    engine.rootContext().setContextProperty('sniffer', sniffer)
    engine.load(QUrl('main.qml'))

    #engine = QtQml.QQmlApplicationEngine(QUrl('main.qml'))
    topLevel = QtCore.QObject()  
    topLevel = engine.rootObjects()[0]  
    
    window = QtQuick.QQuickWindow()  
    window = topLevel  
    
    window.show()
    sys.exit(app.exec_())  

if __name__ == '__main__':
    main()