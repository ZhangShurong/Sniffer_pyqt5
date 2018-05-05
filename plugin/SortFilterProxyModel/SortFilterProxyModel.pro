!c++11: warning("SortFilterProxyModel needs c++11, add CONFIG += c++11 to your .pro")

TEMPLATE = lib
CONFIG += plugin
QT += qml
INCLUDEPATH += $$PWD

TARGET  = qmlqsortfilterproxymodelplugin

SOURCES += $$PWD/qqmlsortfilterproxymodel.cpp \
    $$PWD/filter.cpp \
    $$PWD/sorter.cpp \
    $$PWD/plugin.cpp

HEADERS += $$PWD/qqmlsortfilterproxymodel.h \
    $$PWD/filter.h \
    $$PWD/sorter.h