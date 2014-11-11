#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import dbus
import sys
import serial
import subprocess
import zlib
from multiprocessing  import Process, Queue
from PyQt4.QtGui      import QApplication
from dbus.mainloop.qt import DBusQtMainLoop
from time             import gmtime, strftime, sleep



######################################################################
#                             LICENCE                                #
######################################################################

# This software is part of the TFC application, which is free software:
# You can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.

# TFC is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details. For a copy of the GNU General Public License, see
# <http://www.gnu.org/licenses/>.

# TFC
# NH.py
version = '0.4.11 beta'



######################################################################
#                           CONFIGURATION                            #
######################################################################
PacketSize = 384 # Preset value, do not edit
flag       = ''
iFassist   = ''

try:
    flag   = str(sys.argv[1])
except IndexError:
    pass

interface1 = '/dev/ttyUSB0'
interface2 = '/dev/ttyUSB1'

if (flag == '-f'):
    iFassist    = interface1
    interface1  = interface2
    interface2  = iFassist

verbose         = False
debugging       = False
emergencyExit   = False

localTesting    = False
if not localTesting:
    try:
        portToTxM = serial.Serial(interface1, baudrate=9600, timeout=0.1)   # Serial interface that connects to TxM
        portToRxM = serial.Serial(interface2, baudrate=9600, timeout=0.1)   # Serial interface that conncets to RxM
    except serial.serialutil.SerialException:
        print '\nSerial interfaces are set incorrectly.\nCurrently, system recognices following serial-devices'
        subprocess.Popen('dmesg | grep tty', shell=True).wait()
        print ''
        exit()



######################################################################
#                               FUNCTIONS                            #
######################################################################

def crc32(content):
    return str(hex(zlib.crc32(content)))



class DBus_MsgReceiver():

    def __init__(self, receivedMsg):
        self.answer = receivedMsg
        bus_loop    = DBusQtMainLoop      (set_as_default=True)
        self.bus    = dbus.SessionBus     ()
        self.bus.add_signal_receiver      (self.receiveFunc, dbus_interface='im.pidgin.purple.PurpleInterface', signal_name='ReceivedImMsg')

    def receiveFunc                       (self, account, sender, message, conversation, flags):
        obj         = self.bus.get_object ('im.pidgin.purple.PurpleService', '/im/pidgin/purple/PurpleObject')
        purple      = dbus.Interface      (obj, 'im.pidgin.purple.PurpleInterface')
        purple.PurpleConvImSend           (purple.PurpleConvIm(conversation), self.answer)

        xmpp        = (sender.split('/'))[0]
        crc         = crc32(message)
        splitLine   = message.split('|')
        msgContent  = str(splitLine[0])

        if len(msgContent) == PacketSize:
            print strftime('%Y-%m-%d %H:%M:%S    ', gmtime()) + 'received message from ', xmpp
            if verbose:
                print message + '\n'
            serialQueue.put('<mesg>rx.' + xmpp + '~' + message + '~' + crc + '\n')
        else:
            pass



######################################################################
#                           LOCAL TESTING                            #
######################################################################

def loadMsg():
    with open('TxOutput', 'r') as mFile:
        loadMsg = mFile.readline()
        if debugging:
            if loadMsg != '':
                print 'M(loadMSG): Loaded following message \n' + loadMsg
        return loadMsg



def clearLocalMsg():
    if localTesting:
        open('TxOutput', 'w+').close()



def writeMsg(packetContent):
    with open('NHoutput', 'w+') as mFile:
        mFile.write(packetContent)



######################################################################
#                               THREADS                              #
######################################################################

def serialPortSender():
    while True:
        payload = serialQueue.get()
        if localTesting:
            writeMsg(payload)
        else:
            portToRxM.write(payload)



def networkTransmitter():
    class DBus_MsgSender:

        def __init__(self, contact_id):
            self.contact_id           = contact_id
            bus                       = dbus.SessionBus()
            pidginProxy               = bus.get_object                         ('im.pidgin.purple.PurpleService', '/im/pidgin/purple/PurpleObject')
            self.purple               = dbus.Interface                         (pidginProxy, 'im.pidgin.purple.PurpleService')
            account_id                = self.purple.PurpleAccountsGetAllActive ()[0]
            self.contact_conversation = self.purple.PurpleConversationNew      (1, account_id, self.contact_id)
            self.contact_im           = self.purple.PurpleConvIm               (self.contact_conversation)

        def sender(self):
            self.purple.PurpleConvImSend(self.contact_im, msgContent)

        def clearHistory(self):
            self.purple.PurpleConversationClearMessageHistory(self.contact_conversation)


    o = ''
    while True:
        try:
            msgContent = ''
            rcdPkg     = ''


            if not localTesting:
                while not rcdPkg.endswith('\n'):
                    sleep(0.01)
                    rcdPkg = portToTxM.readline()

            if localTesting:
                while not rcdPkg.endswith('\n'):
                    sleep(0.01)
                    try:
                        rcdPkg = loadMsg()
                    except IOError:
                        continue


            if rcdPkg != (''):

                #emergency exit
                if rcdPkg.startswith('exitTFC'):
                    serialQueue.put(rcdPkg + '\n')
                    os.system('clear')
                    clearLocalMsg()
                    if emergencyExit:
                        subprocess.Popen('killall pidgin', shell=True).wait()
                    sleep(0.1)                                                # Sleep allows local Rx.py some time to exit cleanly
                    subprocess.Popen('killall python', shell=True).wait()     # Note that this kills all python programs, not only NH.py

                #clear screens
                if rcdPkg.startswith('clearScreen'):
                    xmpp = rcdPkg.split(' ')[1]
                    xmpp = xmpp[3:].strip('\n')
                    serialQueue.put(rcdPkg + '\n')
                    os.system('clear')
                    o    = DBus_MsgSender(xmpp)
                    o.clearHistory()


                #relay command to RxM
                if rcdPkg.startswith('<ctrl>'):
                    rcdPkg             = (rcdPkg[6:]).strip('\n')
                    msgContent, crcPkg = rcdPkg.split('~')
                    crcCalc            = crc32(msgContent)

                    if (crcCalc == crcPkg):
                        if debugging:
                            print 'NetworkTransmitter: Wrote <ctrl>' + msgContent + '~' + crcCalc + ' to serial queue.\n'
                        serialQueue.put('<ctrl>'                     + msgContent + '~' + crcCalc + '\n')

                        print strftime('%Y-%m-%d %H:%M:%S    ', gmtime()) + 'sent command to RxM  '
                        if verbose:
                            print rcdPkg + '\n'
                    else:
                        print '\nCRC checksum error: Message was not forwarded to RxM or recipient.'
                        print '\nPlease try sending the message again.'
                        print '\nIf this error is persistent, check the batteries of your TxM data diode.\n'


                #relay message to RxM and Pidgin
                if rcdPkg.startswith('<mesg>'):
                    message                  = (rcdPkg[6:]).strip('\n')
                    xmpp, msgContent, crcPkg = message.split('~')
                    crcCalc                  = crc32(msgContent)

                    if (crcCalc == crcPkg):
                        if debugging:
                            print 'NetworkTransmitter: Wrote <mesg>me.' + xmpp + '~' + msgContent + '~' + crcPkg + ' to serial queue.\n'

                        serialQueue.put('<mesg>me.'                     + xmpp + '~' + msgContent + '~' + crcPkg + '\n')
                        o = DBus_MsgSender(xmpp)
                        o.sender()
                        print strftime('%Y-%m-%d %H:%M:%S    ', gmtime()) + 'sent message to        ' + xmpp

                        if verbose:
                            print msgContent + '\n'
                    else:
                        print '\nCRC checksum error: Message was not forwarded to RxM or recipient.'
                        print '\nPlease try sending the message again.'
                        print '\nIf this error is persistent, check the batteries of your TxM data diode.\n'
            clearLocalMsg()
        except OSError:
            continue
        except dbus.exceptions.DBusException:
            print 'WARNING! DBus did not initiate properly. Check that Pidgin is running before running NH.py'
            continue



def networkReceiver():
    app = QApplication(sys.argv)
    run = DBus_MsgReceiver('')
    app.exec_()



######################################################################
#                                MAIN                                #
######################################################################

clearLocalMsg()
serialQueue = Queue()
os.system('clear')
print 'NH.py running'

ss  = Process(target=serialPortSender)
tn  = Process(target=networkTransmitter)
nr  = Process(target=networkReceiver)

ss.start()
tn.start()
nr.start()


