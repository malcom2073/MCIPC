QT += core
QT -= gui

TARGET = MCIPC
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp \
    mcipc.cpp

DISTFILES += \
    MCIPC.pri

HEADERS += \
    mcipc.h

