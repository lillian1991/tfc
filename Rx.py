#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import binascii
import csv
import datetime
import fileinput
import io
import math
import os
import serial
import string
import subprocess
import sys
import zlib
from time import sleep



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
# Rx.py
version = 'TFC 0.4.11 beta'



######################################################################
#                           CONFIGURATION                            #
######################################################################

os.chdir(sys.path[0])

timeStampFmt            = '%Y-%m-%d//%H:%M:%S'
kfOWIterations          = 3
keyOWIterations         = 3
maxMsgLen               = 143
remoteLogChangeAllowed  = True
fileSavingAllowed       = False
logReplayedEvent        = True
logTamperingEvent       = True
showLongMsgWarning      = True
debugging               = False
logMessages             = False
injectionTesting        = False

localTesting    = False



if not localTesting:
    port        = serial.Serial('/dev/ttyAMA0', baudrate=9600, timeout=0.1)



######################################################################
#                             ONE-TIME MAC                           #
######################################################################

                                                                      # One-time MAC calculation is done modulo M521 (The 13th, 521-bit Mersenne prime)
q   = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151
bs  = 64                                                              # Block size in bytes

def keyToInt(key):
    key = int(key.encode('hex_codec'), 16)
    key = key % q                                                     # Easy way to reduce key value to range [0, q]
    return key



def equals(candidate1, candidate2):                                   # Constant time function for MAC comparing
    if len(candidate1) != len(candidate2):
        return False
    result = 0
    for x, y in zip(candidate1, candidate2):
        result |= ord(x) ^ ord(y)
    return result == 0



def MACverify (xmpp, keylineOfMsg, MAC, ciphertext):
    if debugging:
        print '\nM(MACverify): Loading one-time keys for MAC\n'
    key1 = get_enc_key(xmpp, (keylineOfMsg + 1))
    key2 = get_enc_key(xmpp, (keylineOfMsg + 2))
    MACfromPacket = MAC.strip(' ')
    generatedMAC  = GenerateMAC(key1, key2, ciphertext)

    if equals(MACfromPacket, generatedMAC):
        if debugging:
            print '\nM(MACverify): Message was succesfully authenticated.\n'
        return True
    else:
        if debugging:
            print '\nM(MACverify): MESSAGE AUTHENTICATION FAILED.\n'
        return False



def GenerateMAC(key1, key2, ciphertext):
    if debugging:
        print 'M(GenerateMAC): Starting'

    ctxtArray = [ciphertext[i:i+bs] for i in range(0, len(ciphertext), bs)]
    k         = keyToInt(key1)
    a         = keyToInt(key2)
    iA        = []                                                    # Integer format array

    for block in ctxtArray:
        binFormat = ''.join(format(ord(x), 'b') for x in block)
        intFormat = int(binFormat, 2)
        iA.append(intFormat)

    l = len(iA)                                                       # Number of ciphertext blocks
                                                                      # Depends on message length, default = 3
    h = 1
    if debugging:                                                     # Print block values
        print '\nCiphertext block values (Integer):\n'
        for block in iA:
            print 'M[' + str(h) + '] (Length = ' + str(len(str(block))) + ')'
            print str(block) + '\n'
            h += 1
        print ''

    if debugging:                                                     #  Verbose presentation of MAC calculation formula for value verification
        f   = l
        formula = ''
        while (f > 0):
            formula = formula + 'M[' + str(f) + ']*' + 'k^' + str(f)
            if (f > 1):
                formula = formula + ' + '
            f -= 1
        formula = formula + ' + a (mod q)'
        print 'MAC(key, msg) = ' + formula


    n = 0                                                             #  Calculate MAC
    while (l > 0):
        n = n + ( iA[l-1] * (k ** l) )
        l -= 1
    MAC = (n + a) % q


    MAC = str(hex(MAC))[:-1]                                          #  Convert int to hex and remove L from end
    MAC = MAC[2:]                                                     #  Remove 0x from start

    if debugging:
        print '\nFinished message authentication code is:\n"""' + MAC + '"""\n\n'

    return MAC



######################################################################
#                          OTP DECRPYTION                            #
######################################################################

def decrypt(ciphertext, key):
    if debugging:
        print 'M(decrypt): Decryption initialized'
    plaintext = ''.join(chr(ord(encLetter) ^ ord(keyLetter)) for encLetter, keyLetter in zip(ciphertext, key))
    if debugging:
        print 'M(decrypt): Decryption finished'
    return plaintext



######################################################################
#                             SETTERS                                #
######################################################################

def addContact(nick, xmpp):
    contacts = []
    with open('rxc.tfc', 'a+') as cFile:
        datareader = csv.reader(cFile)
        for row in datareader:
            contacts.append(row)
        cFile.write(nick + ',' + xmpp + ',1\n')
    if debugging:
        print '\nM(add_contact):\nAdded contact ' + nick + ' (xmpp = ' + xmpp + ') to txc.tfc\n'



def overwrite_local_key(keyID):
    overwrite_xmpp_key('rx.local', keyID)



def overwrite_xmpp_key(xmpp, keyID):
    if (keyID < 1):
        print 'Error: KeyID was not greater than 0! Check your contacts.tfc file!\nExiting..'
        exit()
    else:
        offset = keyID * maxMsgLen

    if debugging:
        print 'M(overwrite_enc_key):\nOverwriting ' + str(maxMsgLen) + ' bytes from offset ' + str(offset) + ' (keyID ' + str(keyID) + ')\n'
        print 'M(overwrite_enc_key): Hex-representation of key before overwriting:'
        subprocess.Popen('hexdump -s' + str(offset) + ' -n ' + str(maxMsgLen) + ' ' + xmpp + '.e| cut -c 9-', shell=True).wait()
    i = 0

    while (i < keyOWIterations):
        if debugging:
            print 'M(overwrite_enc_key): Overwriting key with random data (iteration ' + str(i + 1) + ')'
        subprocess.Popen('dd if=/dev/urandom of=' + xmpp + '.e bs=1 seek=' + str(offset) + ' count=' + str(maxMsgLen) + ' conv=notrunc > /dev/null 2>&1', shell=True).wait()

        if debugging:
            print 'M(overwrite_enc_key): Done. Hex-representation of key after overwriting:'
            subprocess.Popen('hexdump -s' + str(offset) + ' -n ' + str(maxMsgLen) + ' ' + xmpp + '.e| cut -c 9-', shell=True).wait()
        i +=1

    with open(xmpp + '.e', 'rb+') as eFile:
        eFile.seek(offset)
        eFile.write(maxMsgLen * '!')
        eFile.seek(offset)
        owCandidate = eFile.read(maxMsgLen)
        while (owCandidate != (maxMsgLen * '!')):
            print '\nWARNING! Key overwrite failed, trying again\n'
            eFile.seek(offset)
            eFile.write(maxMsgLen * '!')
            eFile.seek(offset)
            owCandidate = eFile.read(maxMsgLen)
        if debugging:
            print '\nM(overwrite_xmpp_key): Overwriting completed.\n'



def search_new_contacts():
    contacts    = []
    datareader  = csv.reader(open('rxc.tfc', 'a+'))
    for row in datareader:
        contacts.append(row)

    for item in entropyfilenames:
        onList  = False
        xmpp    = item[:-2]
        for person in contacts:
            if xmpp in person[1]:
                onList = True
        if not onList:

            if (xmpp == 'tx.local'):
                continue

            if (xmpp == 'rx.local'):
                addContact('rx.local', 'rx.local')
                continue

            if xmpp.startswith('me.'):
                localNick = xmpp.split('@')[0][3:]
                addContact('me.' + localNick, xmpp)
                continue
            newNick = raw_input('New contact ' + xmpp + ' found. Enter nickname: ')
            addContact(newNick, xmpp)



def store_keyID(xmpp, keyID):
    contacts = []
    with open('rxc.tfc', 'r') as cFile:
        datareader = csv.reader(cFile)
        for row in datareader:
            contacts.append(row)

    for i in range( len(contacts) ):
        if  contacts[i][1] == xmpp:
            contacts[i][2] = keyID

    with open('rxc.tfc', 'w') as tFile:
        writer = csv.writer(tFile)
        writer.writerows(contacts)

    if debugging:
        print '\nM(store_keyID):\nWrote line \'' + str(keyID) + '\' for contact ' + xmpp + ' to rxc.tfc\n'



def write_nick(xmpp, nick):
    contacts = []
    with open ('rxc.tfc', 'r') as cFile:
        datareader = csv.reader(cFile)

        for row in datareader:
            contacts.append(row)
        for i in range( len(contacts) ):
            if  contacts[i][1] == xmpp:
                contacts[i][0] = nick

    with open('rxc.tfc', 'w') as cFile:
        writer = csv.writer(cFile)
        writer.writerows(contacts)

    if debugging:
        print '\nM(write_nick):\nWrote nick = ' + nick + ' for contact ' + xmpp + ' to rxc.tfc\n'



def writeLog(nick, xmpp, message):
    message = message.strip('\n')

    with open('logs.' + xmpp + '.tfc', 'a+') as lFile:
        lFile.write(datetime.datetime.now().strftime(timeStampFmt) + ' ' + nick + ': ' + message + '\n')

    if debugging:
        print '\nM(writeLog):\nAdded log entry \'' + message + '\' for contact ' + xmpp + ' (nick=' + nick + ')\n'



def overwriteLocalKeys(keyID, storedKey):
    if (keyID == storedKey):         # In case no message was dropped
        overwrite_local_key(keyID)
        overwrite_local_key(keyID+1)
        overwrite_local_key(keyID+2)

    if (keyID > storedKey):          # If some messages have dropped on the way
        i = storedKey                # Index of first key that should be overwritten
        j = (keyID + 2)              # Index of last  key that should be overwritten

        while (i <= j):
            overwrite_local_key(keyID)
            overwrite_local_key(keyID+1)
            overwrite_local_key(keyID+2)
            i += 3



def overwriteXmppKeys(keyID, storedKey):
    if (keyID == storedKey):
        overwrite_xmpp_key(xmpp, keyID)
        overwrite_xmpp_key(xmpp, keyID+1)
        overwrite_xmpp_key(xmpp, keyID+2)

    if (keyID > storedKey):
        i = storedKey
        j = (keyID + 2)

        while (i <= j):
            overwrite_xmpp_key(xmpp, i)
            overwrite_xmpp_key(xmpp, i+1)
            overwrite_xmpp_key(xmpp, i+2)
            i += 3



######################################################################
#                             GETTERS                                #
######################################################################

def get_enc_key(xmpp, keyID):
    if (keyID < 1):
        print 'Error: KeyID was not greater than 0! Check your contacts.tfc file!\nExiting..'
        exit()
    else:
        offset = (keyID * maxMsgLen)

    with open(xmpp + '.e', 'rb') as efile:
        efile.seek(offset)
        key = efile.read(maxMsgLen)
    if debugging:
        print '\nM(get_enc_key):\nLoaded following key (keyID = ' + str(keyID) + ') from offset ' + str(offset) + ' for xmpp ' + xmpp + ':\n"""'
        print key
        print '"""\n\n'
    return key


def get_entropy_file_list():
    entropyfilenames = []
    for item in os.listdir('.'):
        if item.endswith('.e'):
            if not item.startswith('tx.'):
                entropyfilenames.append(item)
    return entropyfilenames



def get_local_enc_key(keyid):
    localKey = get_enc_key('rx.local', keyid)
    return localKey



def get_keyID(xmpp):
    contacts = []
    with open('rxc.tfc', 'r') as cFile:
        datareader = csv.reader(cFile)
        for row in datareader:
            contacts.append(row)

    for i in range( len(contacts) ):
        if contacts[i][1] == xmpp:
            keyID = int(contacts[i][2])
            if debugging:
                print '\nM(get_keyID): Loaded keyID ' + str(keyID) + ' for xmpp ' + xmpp + ' \n'
            return keyID



def get_nick(xmpp):
    contacts = []
    with open('rxc.tfc', 'r') as cFile:
        datareader = csv.reader(cFile)

        for row in datareader:
            contacts.append(row)
        for i in range( len(contacts) ):
            if contacts[i][1] == xmpp:
                nick = contacts[i][0]
        if debugging:
            print '\nM(get_nick): Loaded nick ' + nick + ' for contact ' + xmpp + '\n'
        return nick



######################################################################
#                            CHECKS                                  #
######################################################################

def overWriteIteratorCheck():
    if (keyOWIterations < 1):
        print '''
WARNING: keyOWIterations VALUE AT LINE 58 OF
Tx.py IS SET TO LESS THAN 1 WHICH MEANS KEY
IS NOT BEING OVERWRITTEN DIRECTLY AFTER USE!

THIS MIGHT BE VERY DANGEROUS FOR PHYSICAL SECURITY
AS ANY ATTACKER WHO GETS ACCESS TO KEYS, CAN LATER
DECRYPT INTERCEPTED CIPHERTEXTS. INCREASE THE VALUE
TO 1 OR PREFERABLY HIGHER TO FIX THIS PROBLEM.

IF YOU ARE SURE ABOUT NOT OVERWRITING, MANUALLY
COMMENT OUT THE overWriteIteratorCheck FUNCTION CALL
FROM MAIN LOOP OF Tx.py.

EXITING Tx.py'''
        exit()



def opsecWarning():
    print '''
REMEMBER! DO NOT MOVE RECEIVED FILES FROM RxM TO LESS SECURE
ENVIRONMENTS INCLUDING UNENCRYPTED SYSTEMS, ONES IN PUBLIC USE,
OR TO ANY SYSTEM THAT HAS NETWORK-CAPABILITY, OR THAT MOVES
FILES TO COMPUTER WITH NETWORK CAPABILITY.

DOING SO WILL RENDER DATA-DIODE PROTECTION USELESS, AS MALWARE
\'STUCK IN RXM\' CAN EASILY EXFILTRATE KEYS AND/OR PLAINTEXT
THROUGH THIS RETURN CHANNEL!

IF YOU NEED TO RETRANSFER A DOCUMENT, EITHER READ IT FROM RXM SCREEN
USING OPTICAL-CHARACTER RECOGNITION (OCR) SOFTWARE RUNNING ON TXM,
OR USE A PRINTER TO EXPORT THE DOCUMENT, AND A SCANNER TO READ IT TO
TXM FOR ENCRYPTED RETRANSFER. REMEMBER TO DESTROY THE PRINTS, AND IF
YOUR LIFE DEPENDS ON IT, THE PRINTER AND SCANNER ASWELL.\n'''



def search_contact_keyfiles():
    keyfiles  = []
    keyfiles += [each for each in os.listdir('.') if each.endswith('.e')]
    if not keyfiles:
        print '\nError: No keyfiles for contacts were found. Make sure they are in same directory as Rx.py\n'
        exit()



######################################################################
#                         MSG PROCESSING                             #
######################################################################

def b64d(content):
    return base64.b64decode(content)



def crc32(content):
    return str(hex(zlib.crc32(content)))



######################################################################
#                           LOCAL TESTING                            #
######################################################################

def clearLocalMsg():
    if localTesting:
        if injectionTesting:
            open('INoutput', 'w+').close()
        open('NHoutput', 'w+').close()



def loadMsg():
    if injectionTesting:
        with open('INoutput', 'r') as mFile:
            loadMsg = mFile.readline()
            if debugging:
                if not (loadMsg==''):
                    print '\n\nM(loadMSG): Loaded following message \n' + loadMsg
        return loadMsg

    else:
        with open('NHoutput', 'r') as mFile:
                loadMsg = mFile.readline()
                if debugging:
                    if not (loadMsg==''):
                        print '\n\nM(loadMSG): Loaded following message \n' + loadMsg
        return loadMsg



######################################################################
#                             PRE LOOP                               #
######################################################################

longMsgComplete  = False
fileReceive      = False
packetDrop       = False

entropyfilenames = get_entropy_file_list()
longMsg          = {}
longMessage      = ''

search_new_contacts()
search_contact_keyfiles()
overWriteIteratorCheck()
clearLocalMsg()

os.system('clear')
print 'Rx.py Running'

if logMessages:
    print 'Logging is currently enabled'
else:
    print 'Logging is currently disabled'



######################################################################
#                               LOOP                                 #
######################################################################

try:
    while True:
        sleep(0.01)
        receivedpkg  = ''
        fileReceived = False

        if localTesting:
            try:
                receivedpkg = loadMsg()
                if not receivedpkg.endswith('\n'):
                    continue
            except IOError:
                continue
        else:
            receivedpkg     = port.readline()

        clearLocalMsg()

        if not (receivedpkg == ''):
            try:

                if receivedpkg.startswith('exitTFC'):
                    os.system('clear')
                    exit()
                    continue

                if receivedpkg.startswith('clearScreen'):
                    os.system('clear')
                    continue



                ##############################################################
                #                     CONTROL MESSAGE                        #
                ##############################################################
                if receivedpkg.startswith('<ctrl>'):
                    payload, crcPkg = receivedpkg[6:].split('~')
                    crcPkg          = crcPkg.strip('\n')


                    # Check that CRC32 Matches
                    if (crc32(payload) == crcPkg):
                        encodedMsgMAC, keyID = payload.split('|')
                        keyID                = int(keyID)
                        MsgMAC               = b64d(encodedMsgMAC)
                        enc_cmd              = MsgMAC[:maxMsgLen]
                        MAC                  = MsgMAC[maxMsgLen:]


                        # Check that keyID is fresh
                        storedKey = int(get_keyID('rx.local'))
                        if (keyID < storedKey):
                            print + '\nWARNING! Expired key detected!\nIt is possible someone is trying to replay messages!\n'
                            if logReplayedEvent:
                                writeLog('', xmpp, 'EVENT WARNING: Possibly received a replayed message!')
                            continue


                        # Check if there's been packet drops
                        if (keyID > storedKey):
                            print '\nIt would appear ' + str( (keyID - storedKey) / 3 ) + ' command packet(s) have dropped along the way.'
                            print 'You should check data diode batteries if this keeps happening.\n'


                        try:
                            # Decrypt command if MAC verification succeeds
                            if MACverify ('rx.local', keyID, MAC, enc_cmd):
                                cmdDecKey           = get_local_enc_key(keyID)
                                decryptedMsg        = decrypt(enc_cmd, cmdDecKey)
                                while decryptedMsg.endswith(' '):
                                    decryptedMsg    = decryptedMsg[:-1]


                                ##################
                                # Enable logging #
                                ##################
                                if decryptedMsg.startswith('logson'):
                                    if remoteLogChangeAllowed:
                                        if logMessages:
                                            print 'Logging is already enabled'
                                        else:
                                            logMessages = True
                                            print 'Logging has been enabled'

                                        # Process encryption keys and keyID
                                        store_keyID('rx.local', (keyID + 3) )
                                        overwriteLocalKeys(keyID, storedKey)
                                        continue
                                    else:
                                        print '\nLogging settings can not be altered: Boolean value \'remoteLogChangeAllowed\' is currently set to False in Rx.py'
                                        continue


                                ###################
                                # Disable logging #
                                ###################
                                if decryptedMsg.startswith('logsoff'):
                                    if remoteLogChangeAllowed:
                                        if not logMessages:
                                            print 'Logging is already disabled'
                                        else:
                                            logMessages = False
                                            print 'Logging has been disabled'

                                        # Process encryption keys and keyID
                                        store_keyID('rx.local', (keyID + 3) )
                                        overwriteLocalKeys(keyID, storedKey)
                                        continue
                                    else:
                                        print '\nLogging settings can not be altered: Boolean value \'remoteLogChangeAllowed\' is currently set to False in Rx.py'
                                        continue


                                ####################
                                # Load new keyfile #
                                ####################
                                if decryptedMsg.startswith('tfckf '):
                                    notUsed, cXmpp, newKf = decryptedMsg.split(' ')

                                    # Shred entropy file
                                    if cXmpp.startswith('me.'):
                                        print '\nRxM: Shredding current keyfile that decrypts\nmessages your TxM sends to ' + cXmpp[3:] + '\n'
                                    else:
                                        cXmpp = 'rx.' + cXmpp
                                        print '\nRxM: Shredding current keyfile that decrypts\nmessages sent to you by ' + cXmpp[3:] + '\n'
                                    subprocess.Popen('shred -n ' + str(kfOWIterations) + ' -z -u ' + cXmpp + '.e', shell=True).wait()

                                    # Move new entropy file in place
                                    print 'RxM: Replacing the keyfile ' + cXmpp + ' with file \'' + newKf + '\''
                                    subprocess.Popen('mv ' + newKf + ' ' + cXmpp + '.e', shell=True).wait()

                                    # Reset keyID
                                    print 'RxM: Resetting key number to 1 for ' + cXmpp[3:]
                                    store_keyID(cXmpp, 1)

                                    # Process encryption keys and keyID
                                    overwriteLocalKeys(keyID, storedKey)
                                    print 'RxM: Keyfile succesfully changed\n'
                                    continue


                                ###############
                                # Change nick #
                                ###############

                                xmpp, cmdWp    = decryptedMsg.split('/')
                                cmd, parameter = cmdWp.split('=')

                                if cmd.startswith('nick'):

                                    # Write and load nick
                                    xmpp       = 'r' + xmpp[1:]
                                    write_nick(xmpp, parameter)
                                    rxNick     = get_nick(xmpp)
                                    print '\nChanged ' + xmpp[3:] + ' nick to \'' + rxNick + '\'\n'

                                    # Process encryption keys and keyID
                                    store_keyID('rx.local', (keyID + 3) )
                                    overwriteLocalKeys(keyID, storedKey)
                                    continue


                            else:
                                print '\nWARNING! Message authentication failed!\nIt is possible someone is trying to tamper messages!\n'
                                if logTamperingEvent:
                                    writeLog('', xmpp, 'EVENT WARNING: Tampered/malformed message received!')
                                continue


                        except KeyError:
                            print 'WARNING! Received a command, the key-id of which is not valid!\n This might indicate tampering or keyfile content mismatch.'
                            continue
                        except TypeError:
                            print 'WARNING! Received a command, the key-id of which is not valid!\n This might indicate tampering or keyfile content mismatch.'
                            continue


                    else:
                        print '\nCRC checksum error: Command received by RxM was malformed.\nRequest the message again from your contact'
                        print 'If this error is persistent, check the batteries of your RxM data diode.\n'



                ##############################################################
                #                     NORMAL MESSAGE                         #
                ##############################################################
                if receivedpkg.startswith('<mesg>'):
                    xmpp, ctMACln, crcPkg    = receivedpkg[6:].split('~')
                    crcPkg = crcPkg.strip('\n')


                    # Check that CRC32 Matches
                    if (crc32(ctMACln)      == crcPkg):
                        encodedMsgMAC, keyID = ctMACln.split('|')
                        keyID                = int(keyID)
                        MsgMAC               = b64d(encodedMsgMAC)
                        ciphertext           = MsgMAC[:maxMsgLen]
                        MAC                  = MsgMAC[maxMsgLen:]


                        # Check that keyID is fresh
                        storedKey = int(get_keyID(xmpp))
                        if  (keyID < storedKey):
                            print '\nWARNING! Expired key detected!\nIt is possible someone is trying to replay messages!\n'
                            if logReplayedEvent:
                                writeLog('', xmpp, 'EVENT WARNING: Possibly replayed message received!')
                            continue


                        # Check if there's been packet drops
                        if (keyID > storedKey):
                            print '\nWarning! ' + str( (keyID - storedKey) / 3 ) + ' packets appear to be missing\nbetween received and expected packets.\n'

                        try:
                            # Decrypt message if MAC verification succeeds
                            if MACverify(xmpp, keyID, MAC, ciphertext):
                                msgDecKey        = get_enc_key(xmpp, keyID)
                                decryptedMsg     = decrypt(ciphertext, msgDecKey)


                                # Remove whitespace around message
                                while decryptedMsg.endswith(' '):
                                    decryptedMsg = decryptedMsg[:-1]
                                while decryptedMsg.startswith(' '):
                                    decryptedMsg = decryptedMsg[1:]


                                if decryptedMsg.startswith('s'):

                                    ###################################
                                    # Process short standard messages #
                                    ###################################

                                    if decryptedMsg.startswith('sTFCFILE'):
                                        if fileSavingAllowed:
                                            print 'Receiving file, this make take a while. Notice that you can\'t\nreceive messages until you have received and named the file!'
                                            fileReceive  = True
                                            fileReceived = True
                                    decryptedMsg = decryptedMsg[1:]

                                    # Process encryption keys and keyID
                                    store_keyID(xmpp, (keyID + 3))
                                    overwriteXmppKeys(keyID, storedKey)


                                else:

                                    ############################################
                                    # Process long messages and file transfers #
                                    ############################################

                                    # Start packet of long message / file
                                    if decryptedMsg.startswith('l'):
                                        if decryptedMsg.startswith('lTFCFILE'):
                                            if fileSavingAllowed:
                                                print 'Receiving file, this make take a while. Notice that you can\'t\nreceive messages until you have received and named the file'
                                                fileReceive = True
                                        else:
                                            if showLongMsgWarning:
                                                print '\n' + 'Receiving long message, please wait...\n'
                                        longMsg[xmpp]   = decryptedMsg[1:]

                                        # Process encryption keys and keyID
                                        store_keyID(xmpp, (keyID + 3))
                                        overwriteXmppKeys(keyID, storedKey)
                                        continue


                                    # Append packet of long message / file
                                    if decryptedMsg.startswith('a'):
                                        if (keyID > storedKey):
                                            packetDrop  = True
                                        longMsg[xmpp]   = longMsg[xmpp] + decryptedMsg[1:]

                                        # Process encryption keys and keyID
                                        store_keyID(xmpp, (keyID + 3))
                                        overwriteXmppKeys(keyID, storedKey)
                                        continue


                                    # End packet of long message / file
                                    if decryptedMsg.startswith('e'):
                                        if (keyID > storedKey):
                                            packetDrop  = True
                                        longMsg[xmpp]   = longMsg[xmpp] + decryptedMsg[1:]
                                        decryptedMsg    = longMsg[xmpp] + '\n'

                                        # Process encryption keys and keyID
                                        store_keyID(xmpp, (keyID + 3))
                                        overwriteXmppKeys(keyID, storedKey)
                                        if fileReceive:
                                            fileReceived = True


                                if not fileReceive:

                                    ##############################
                                    # Process printable messages #
                                    ##############################

                                    if packetDrop:
                                        print '\nWarning! Received incomplete long message!\n'
                                        packetDrop = False
                                        continue
                                    else:
                                        if xmpp.startswith('me.'):
                                            nick = 'Me > ' + get_nick('rx' + xmpp[2:])
                                        else:
                                            nick = 5   * ' '     + get_nick(xmpp)

                                        # Print message to user
                                        print nick + ':    ' + decryptedMsg


                                    # Log messages if logging is enabled
                                    if logMessages:
                                        if nick.startswith('Me > '):
                                            spacing = len(get_nick('rx' + xmpp[2:]))
                                            nick    = (spacing - 2) * ' ' + 'Me'
                                            writeLog(nick, xmpp[3:], decryptedMsg)
                                        else:
                                            writeLog(nick[5:], xmpp[3:], decryptedMsg)


                                if fileReceive:

                                    ##########################
                                    # Process received files #
                                    ##########################

                                    if fileSavingAllowed:
                                        if fileReceived:
                                            if packetDrop:
                                                print '\nWarning! Failed to receive file! One or more blocks from file are missing!\n'
                                                packetDrop = False
                                                continue

                                            fName = raw_input('\nFile Received. Enter filename (\'r\' rejects file): ')

                                            # File rejection option
                                            if fName == 'r':
                                                print '\nFile Rejected. Continuing\n'
                                                decryptedMsg == ''
                                                fileReceive  = False
                                                fileReceived = False
                                                continue

                                            # Save received base64 data to tmp file and decode it to user-specified file. Shred tmp file. and show OPSEC warning.
                                            else:
                                                with open('TFCtmpFileRx', 'w+') as mFile:
                                                    mFile.write(decryptedMsg[7:])
                                                subprocess.Popen('base64 -d TFCtmpFileRx > ' + fName, shell=True).wait()
                                                subprocess.Popen('shred -n ' + str(kfOWIterations) + ' -z -u TFCtmpFileRx', shell=True).wait()
                                                fileReceive  = False
                                                fileReceived = False

                                                opsecWarning()
                                        else:
                                            continue
                                    else:
                                        decryptedMsg == ''
                                        continue
                                continue


                            else:
                                print '\nWARNING! Message authentication failed!\nIt is possible someone is trying to tamper messages!\n'
                                if logTamperingEvent:
                                    writeLog('',xmpp, 'EVENT WARNING: Tampered/malformed message received!')
                                continue


                        except TypeError:
                            print 'WARNING! Received a message, the key-id of which is not valid!\nThis might indicate tampering or keyfile content mismatch.'
                            continue


                    else:
                        print '\nCRC checksum error: Message received by RxM was malformed.\n'
                        print 'Note that this error occured between your NH and RxM so recipient most likely received the message.'
                        print 'If this error is persistent, check the batteries of your RxM data diode.\n'


            except IndexError:
                print 'WARNING! Received message/command wasn\'t correctly formatted. This might indicate someone is tampering messages!'
                continue
            except ValueError:
                print 'WARNING! Received message/command wasn\'t correctly formatted. This might indicate someone is tampering messages!'
                continue

except KeyboardInterrupt:
    os.system('clear')
    print 'Exiting Rx.py\n'
    exit()

