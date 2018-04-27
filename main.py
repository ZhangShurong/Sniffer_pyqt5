import sys  
from PyQt5.QtCore import pyqtProperty, QCoreApplication, QObject, QUrl, pyqtSignal
from PyQt5.QtQml import qmlRegisterType, QQmlComponent, QQmlEngine
from PyQt5 import QtCore, QtGui, QtWidgets, QtQml,QtQuick
from PyQt5.QtQuick import QQuickView


def main():
    app = QtWidgets.QApplication(sys.argv)
    view = QQuickView()
    view.engine().quit.connect(app.quit)
    view.setSource(QUrl('main.qml'))
    # engine = QtQml.QQmlApplicationEngine()
    # engine.load(QUrl('main.qml'))

    # #engine = QtQml.QQmlApplicationEngine(QUrl('main.qml'))
    # topLevel = QtCore.QObject()  
    # topLevel = engine.rootObjects()[0]  
    
    # window = QtQuick.QQuickWindow()  
    # window = topLevel  
    
    # window.show()
    view.show()
    sys.exit(app.exec_())  

if __name__ == '__main__':
    main()