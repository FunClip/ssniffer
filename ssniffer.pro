QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    main.cpp \
    mainwindow.cpp \
    npcap.cpp \
    parser.cpp \
    util.cpp \
    worker.cpp

HEADERS += \
    header.h \
    mainwindow.h \
    npcap.h \
    parser.h \
    util.h \
    worker.h

FORMS += \
    mainwindow.ui

INCLUDEPATH += $$PWD/pcap/Include

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

win32: LIBS += -L$$PWD/pcap/Lib/x64/ -lPacket

INCLUDEPATH += $$PWD/pcap/Lib/x64
DEPENDPATH += $$PWD/pcap/Lib/x64

win32: LIBS += -L$$PWD/pcap/Lib/x64/ -lwpcap

LIBS += -lws2_32
