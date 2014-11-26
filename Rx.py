#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binascii
import csv
import datetime
import os
import serial
import subprocess
import sys
from time import sleep



######################################################################
#                             LICENCE                                #
######################################################################

# TFC (OTP Version) || Rx.py
version = '0.4.12 beta'

"""
This software is part of the TFC application, which is free software:
You can redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
for more details. For a copy of the GNU General Public License, see
<http://www.gnu.org/licenses/>.
"""



######################################################################
#                           CONFIGURATION                            #
######################################################################

fileSavingAllowed  = False
debugging          = False
logMessages        = False
injectionTesting   = False

logChangeAllowed   = True
logTamperingEvent  = True
logReplayedEvent   = True
showLongMsgWarning = True
displayTime        = True

logTimeStampFmt    = '%Y-%m-%d / %H:%M:%S'
displayTimeFmt     = '%H:%M'
kfOWIterations     = 3
shredIterations    = 3
keyThreshold       = 5
PkgSize            = 140

localTesting       = False


if not localTesting:
    port        = serial.Serial('/dev/ttyAMA0', baudrate=9600, timeout=0.1)



######################################################################
#                         CRYPTOGRAPHY RELATED                       #
######################################################################

def otp_decrypt(ciphertext, key):
    if len(ciphertext) == len(key):
        plaintext = ''.join(chr(ord(encLetter) ^ ord(keyLetter)) for encLetter, keyLetter in zip(ciphertext, key))
    else:
        exit_with_msg('CRITICAL ERROR! Ciphertext - key length mismatch.')
    return plaintext



def equals(item1, item2):

    # Constant time function for MAC comparing
    if len(item1) != len(item2):
        return False
    result = 0
    for x, y in zip(item1, item2):
        result |= ord(x) ^ ord(y)
    return result == 0



def one_time_mac(key1, key2, ciphertext):

    # One-time MAC calculation is done modulo M521, the 13th, 521-bit Mersenne prime.
    q   = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151

    if debugging:
        print 'M(one_time_mac):'


    # Convert ciphertext to 64 byte array.
    ctArray = [ciphertext[i:i + 64] for i in range(0, len(ciphertext), 64)]


    # Convert key to integer and reduce the integer value to range [0, q]
    key1    = int(key1.encode('hex_codec'), 16) % q
    key2    = int(key2.encode('hex_codec'), 16) % q


    # Convert ciphertext array to integer array.
    iA      = []
    for block in ctArray:
        binFormat = ''.join(format(ord(x), 'b') for x in block)
        intFormat = int(binFormat, 2)
        iA.append(intFormat)


    # Number of blocks, highest block index.
    b = len(iA)


    # Print block values.
    if debugging:
        print '\nCiphertext integer values:\n'
        for block in iA:
            print 'Block ' + str(iA.index(block) + 1) + ' (Length = ' + str(len(str(block))) + ')'
            print str(block) + '\n'
        print ''


    #  Calculate MAC.
    n = 0
    while b > 0:
        n = n + ( iA[b-1] * (key1 ** b) )
        b -= 1
    MAC = (n + key2) % q


    # Convert int to hex and remove '0x' from start and 'L' from end of string.
    MAC = str(hex(MAC))[2:][:-1]


    if debugging:
        print '\nFinished MAC:\n"' + MAC + '"\n\n'

    return MAC



######################################################################
#                    DECRYPTION AND KEY MANAGEMENT                   #
######################################################################

def get_keyset(xmpp, keyID, output):
    try:
        # Verify keyID value is valid.
        if keyID < 1:
            exit_with_msg('CRITICAL ERROR! KeyID was not valid.')

        else:
            offset = (keyID * 3 * PkgSize)

        # Load encryption key from file.
        with open(xmpp + '.e', 'rb') as file:
            file.seek(offset)
            entropy = file.read(3 * PkgSize)


        # Verify that key is not overwritten.
        if (keyThreshold * '!') in entropy:
            exit_with_msg('CRITICAL ERROR! Loaded key the threshold of \'!\' chars exceeds limit.')


        # Convert entropy into keyset.
        keyset = [entropy[i:i + PkgSize] for i in range(0, len(entropy), PkgSize )]


        # Verify there are 3 keys.
        if len(keyset) != 3:
            return None

        # Print key.
        if debugging and output:
            print '\nM(get_keyset): Loaded following key set (keyID = ' + str(keyID) + ') from offset ' + str(offset) + ' for XMPP ' + xmpp + ':'

            for key in keyset:
                print binascii.hexlify(key) + ' (Hex representation)\n'

        return keyset

    except IOError:
        exit_with_msg('CRITICAL ERROR! Could not open keyfile of XMPP ' + xmpp + '.')



def auth_and_decrypt(xmpp, ctWithTag, keyID):

    # Calculate offset of contact's keyset.
    storedKeyID  = int(get_keyID(xmpp))
    contactKeyID = int(keyID)
    offset       = contactKeyID - storedKeyID

    # Load announced keyset.
    keyset = get_keyset(xmpp, contactKeyID, True)


    if offset > 0:

        # Notify user about missing messages implicated by the offset.
        if xmpp == 'rx.local':
            print '\nATTENTION! The last ' + str(offset) + ' commands\nhave not been received from TxM.\n'
        elif xmpp.startswith('me.'):
            print '\nATTENTION! The last ' + str(offset) + ' messages sent to contact\n' + xmpp[3:] + ' have not been received from TxM.\n'
        else:
            print '\nATTENTION! The last ' + str(offset) + ' messages have not\nbeen received from ' + xmpp[3:] + '.\n'

    offset = 0

    # Separate ciphertext and MAC.
    ciphertext = ctWithTag[:PkgSize]
    MAC        = ctWithTag[PkgSize:]

    # Remove padding from MAC.
    packetMAC     = depadding(MAC)

    # Calculate MAC from ciphertext
    calculatedMAC = one_time_mac(keyset[1], keyset[2], ciphertext)

    # Compare MACs using constant time function.
    if equals(packetMAC, calculatedMAC):

        if debugging:
            print '\nM(decrypt): Message was succesfully authenticated.\n'

        # Decrypt ciphertext.
        plaintext = otp_decrypt(ciphertext, keyset[0])

        # Remove padding from plaintext.
        plaintext = depadding(plaintext)

        while storedKeyID <= contactKeyID:
            overwrite_key(xmpp, storedKeyID)
            write_keyID(xmpp, storedKeyID + 1)
            storedKeyID = get_keyID(xmpp)
        return True, plaintext

    else:
        return False, ''



def overwrite_key(xmpp, keyID):
    if keyID < 1:
        exit_with_msg('Error: KeyID was not greater than 0! Check your contacts.tfc file.')
    else:
        offset = keyID * PkgSize

    if debugging:
        print 'M(overwrite_enc_key):\nOverwriting ' + str(PkgSize) + ' bytes from offset ' + str(offset) + ' (keyID ' + str(keyID) + ')\n'
        print 'M(overwrite_enc_key): Hex-representation of key before overwriting:'
        subprocess.Popen('hexdump -s' + str(offset) + ' -n ' + str(PkgSize) + ' ' + xmpp + '.e| cut -c 9-', shell=True).wait()
    i = 0

    while i < kfOWIterations:
        if debugging:
            print 'M(overwrite_enc_key): Overwriting key with random data (iteration ' + str(i + 1) + ')'
        subprocess.Popen('dd if=/dev/urandom of=' + xmpp + '.e bs=1 seek=' + str(offset) + ' count=' + str(PkgSize) + ' conv=notrunc > /dev/null 2>&1', shell=True).wait()

        if debugging:
            print 'M(overwrite_enc_key): Done. Hex-representation of key after overwriting:'
            subprocess.Popen('hexdump -s' + str(offset) + ' -n ' + str(PkgSize) + ' ' + xmpp + '.e| cut -c 9-', shell=True).wait()
        i +=1

    with open(xmpp + '.e', 'rb+') as eFile:
        eFile.seek(offset)
        eFile.write(PkgSize * '!')
        eFile.seek(offset)
        owCandidate = eFile.read(PkgSize)
        while owCandidate != (PkgSize * '!'):
            print '\nWARNING! Key overwrite failed, trying again\n'
            eFile.seek(offset)
            eFile.write(PkgSize * '!')
            eFile.seek(offset)
            owCandidate = eFile.read(PkgSize)
        if debugging:
            print '\nM(overwrite_key): Overwriting completed.\n'



######################################################################
#                        rxc.tfc MANAGEMENT                          #
######################################################################

def add_contact(nick, xmpp):
    try:
        with open('rxc.tfc', 'a+') as file:
                file.write(nick + ',' + xmpp + ',1\n')

        if debugging:
            print '\nM(add_contact): Added contact ' + nick + ' (xmpp = ' + xmpp + ') to rxc.tfc\n'

    except IOError:
        exit_with_msg('ERROR! rxc.tfc could not be loaded. Exiting.')



def write_nick(xmpp, nick):
    try:
        contacts = []

        with open ('rxc.tfc', 'r') as file:
            csvData = csv.reader(file)

            for row in csvData:
                contacts.append(row)

        nickChanged = False

        for i in range( len(contacts) ):
            if contacts[i][1] == xmpp:
                contacts[i][0] = nick
                nickChanged = True

        if not nickChanged:
            exit_with_msg('ERROR! Could not find XMPP\n' + xmpp + ' from rxc.tfc.')


        with open('rxc.tfc', 'w') as file:
            writer = csv.writer(file)
            writer.writerows(contacts)

        if debugging:
            print '\nM(write_nick):\nWrote nick ' + nick + ' for account ' + xmpp + ' to rxc.tfc\n'

    except IOError:
        exit_with_msg('ERROR! rxc.tfc could not be loaded.')



def get_nick(xmpp):
    try:
        contacts = []

        with open('rxc.tfc', 'r') as file:
            csvData = csv.reader(file)

            for row in csvData:
                contacts.append(row)

        for i in range( len(contacts) ):
            if contacts[i][1] == xmpp:
                nick = contacts[i][0]
                return nick

        exit_with_msg('ERROR! Failed to load nick for contact.')

    except IOError:
        exit_with_msg('ERROR! rxc.tfc could not be loaded.')



def write_keyID(xmpp, keyID):
    try:
        contacts = []

        with open('rxc.tfc', 'r') as file:
            csvData = csv.reader(file)

            for row in csvData:
                contacts.append(row)

        keyIDChanged = False

        for i in range(len(contacts) ):
            if contacts[i][1] == xmpp:
                contacts[i][2] = keyID
                keyIDChanged   = True

        if not keyIDChanged:
            exit_with_msg('ERROR! Could not find XMPP\n' + xmpp + ' from rxc.tfc.')

        with open('rxc.tfc', 'w') as file:
            writer = csv.writer(file)
            writer.writerows(contacts)

        # Verify keyID has been properly written.
        newStoredKey = get_keyID(xmpp)
        if keyID != newStoredKey:
            exit_with_msg('CRITICAL ERROR! KeyID was not properly stored.')


        if debugging:
            print '\nM(write_keyID): Wrote line \'' + str(keyID) + '\' for contact ' + xmpp + ' to rxc.tfc\n'

    except IOError:
        exit_with_msg('ERROR! rxc.tfc could not be loaded.')



def get_keyID(xmpp):
    try:
        contacts = []

        with open('rxc.tfc', 'r') as file:
            csvData = csv.reader(file)

            for row in csvData:
                contacts.append(row)

        for i in range( len(contacts) ):
            if contacts[i][1] == xmpp:
                keyID = int(contacts[i][2])

        # Verify keyID is positive.
        if keyID > 0:
            return keyID
        else:
            exit_with_msg('ERROR! Failed to load valid keyID for XMPP\n' + xmpp + '.')

    except ValueError:
        exit_with_msg('ERROR! Failed to load valid keyID for XMPP\n' + xmpp + '.')

    except IOError:
        exit_with_msg('ERROR! rxc.tfc could not be loaded.')



def add_keyfiles(keyFileNames):
    try:
        contacts = []

        with open('rxc.tfc', 'a+') as file:
            csvData = csv.reader(file)

            for row in csvData:
                contacts.append(row)

        for fileName in keyFileNames:
            onList = False
            xmpp   = fileName[:-2]

            for user in contacts:
                if xmpp in user[1]:
                    onList = True

            if not onList:

                if xmpp == 'tx.local':
                    continue

                if xmpp == 'rx.local':
                    add_contact('rx.local', 'rx.local')
                    continue

                if xmpp.startswith('me.'):
                    localNick = xmpp.split('@')[0][3:]
                    add_contact('me.' + localNick, xmpp)
                    continue

                if xmpp.startswith('rx.'):
                    os.system('clear')
                    print 'TFC ' + version + ' || Rx.py\n'
                    newNick = raw_input('New contact ' + xmpp[3:] + ' found. Enter nick: ')
                    add_contact(newNick, xmpp)

    except IOError:
        exit_with_msg('ERROR! rxc.tfc could not be loaded.')



######################################################################
#                             GETTERS                                #
######################################################################

def get_keyfile_list():
    keyFileList = []

    for file in os.listdir('.'):
        if file.endswith('.e') and not file.startswith('tx.'):
            keyFileList.append(file)
    return keyFileList



######################################################################
#                        CHECKS AND WARNINGS                         #
######################################################################

def search_keyfiles():
    keyfiles  = []
    keyfiles += [each for each in os.listdir('.') if each.endswith('.e')]
    if not keyfiles:
        exit_with_msg('Error: No keyfiles for contacts were found.\n'\
                      'Make sure keyfiles are in same directory as Rx.py\n')


def disp_opsec_warning():
    print '''
REMEMBER! DO NOT MOVE RECEIVED FILES FROM RxM TO LESS SECURE
ENVIRONMENTS INCLUDING UNENCRYPTED SYSTEMS, ONES IN PUBLIC USE,
OR TO ANY SYSTEM THAT HAS NETWORK-CAPABILITY, OR THAT MOVES
FILES TO A COMPUTER WITH NETWORK CAPABILITY.

DOING SO WILL RENDER DATA-DIODE PROTECTION USELESS, AS MALWARE
\'STUCK IN RXM\' CAN EASILY EXFILTRATE KEYS AND/OR PLAINTEXT
THROUGH THIS RETURN CHANNEL!

IF YOU NEED TO RETRANSFER A DOCUMENT, EITHER READ IT FROM RxM SCREEN
USING OPTICAL CHARACTER RECOGNITION (OCR) SOFTWARE RUNNING ON TxM,
OR USE A PRINTER TO EXPORT THE DOCUMENT, AND A SCANNER TO READ IT TO
TxM FOR ENCRYPTED RE-TRANSFER. REMEMBER TO DESTROY THE PRINTS, AND IF
YOUR LIFE DEPENDS ON IT, THE PRINTER AND SCANNER AS WELL.\n'''



def overWriteIteratorCheck():
    if kfOWIterations < 1:
        print '''
WARNING: kfOWIterations VALUE IS SET TO LESS
THAN 1 WHICH MEANS KEY IS NOT BEING OVERWRITTEN
IMMEDIATELY AFTER USE!

THIS MIGHT BE VERY DANGEROUS FOR PHYSICAL SECURITY
AS ANY ATTACKER WHO GETS ACCESS TO KEYS, CAN LATER
DECRYPT INTERCEPTED CIPHERTEXTS. INCREASE THE VALUE
TO 1 OR PREFERABLY HIGHER TO FIX THIS PROBLEM.

IF YOU ARE SURE ABOUT NOT OVERWRITING, MANUALLY
COMMENT OUT THE overWriteIteratorCheck FUNCTION CALL
FROM PRE-LOOP OF Tx.py TO DISABLE THIS WARNING.

EXITING Tx.py'''
        exit()



######################################################################
#                         MSG PROCESSING                             #
######################################################################

def base64_decode(content):
    import base64
    return base64.b64decode(content)



def crc32(content):
    import zlib
    return str(hex(zlib.crc32(content)))



def depadding(string):
    return string[:-ord(string[-1:])]



######################################################################
#                         MESSAGE RECEPTION                          #
######################################################################

def clear_msg_file():
    if localTesting:
        if injectionTesting:
            open('INoutput', 'w+').close()
        open('NHoutput', 'w+').close()



def load_message_from_file():
    if injectionTesting:
        with open('INoutput', 'r') as file:
            message = file.readline()

        if debugging and message != '':
            print '\n\nM(load_message_from_file): Loaded following message \n' + message + '\n'

        return message

    else:
        with open('NHoutput', 'r') as file:
            message = file.readline()

        if debugging and message != '':
            print '\n\nM(load_message_from_file): Loaded following message \n' + message + '\n'

        return message



######################################################################
#                       COMMANDS AND FUNCTIONS                       #
######################################################################

def write_log_entry(nick, xmpp, message):

    message = message.strip('\n')

    with open('logs.' + xmpp + '.tfc', 'a+') as file:
        file.write( datetime.datetime.now().strftime(logTimeStampFmt) + ' ' + nick + ': ' + message + '\n' )

    if debugging:
        print '\nM(write_log_entry): Added log entry \n\'' + message + '\' for contact ' + xmpp + '\n'


def exit_with_msg(message, error=True):
    os.system('clear')
    if error:
        print '\n' + message + ' Exiting.\n'
    else:
        print '\n' + message + '\n'
    exit()



######################################################################
#                             PRE LOOP                               #
######################################################################

# Set initial values.
os.chdir(sys.path[0])
longMsgComplete  = False
fileReceive      = False
longMsg          = {}

# Run initial checks.
clear_msg_file()
search_keyfiles()
overWriteIteratorCheck()

# Load initial data.
keyFileNames     = get_keyfile_list()
add_keyfiles(keyFileNames)

os.system('clear')
header = 'TFC ' + version + ' || Rx.py '

# Display configuration on header during start of program.
if logMessages:
    header += '|| Logging on '
else:
    header += '|| Logging off '

if fileSavingAllowed:
    header += '|| File reception on'
else:
    header += '|| File reception off'

print header + '\n'



######################################################################
#                               LOOP                                 #
######################################################################

try:
    while True:
        sleep(0.01)
        receivedPacket = ''
        fileReceived = False

        if localTesting:
            try:
                receivedPacket = load_message_from_file()
                if not receivedPacket.endswith('\n'):
                    continue
            except IOError:
                continue

            clear_msg_file()

        else:
            receivedPacket = port.readline()


        if not (receivedPacket == ''):
            try:

                # Process unencrypted commands.
                if receivedPacket.startswith('exitTFC'):
                    exit_with_msg('Exiting TFC.', False)


                if receivedPacket.startswith('clearScreen'):
                    os.system('clear')
                    continue



                ####################################
                #         ENCRYPED COMMANDS        #
                ####################################
                if receivedPacket.startswith('<ctrl>'):
                    cmdMACln, crcPkg = receivedPacket[6:].split('~')
                    crcPkg           = crcPkg.strip('\n')

                    # Check that CRC32 Matches.
                    if crc32(cmdMACln) == crcPkg:
                        payload, keyID = cmdMACln.split('|')
                        ciphertext     = base64_decode(payload)


                        # Check that keyID is fresh.
                        if int(keyID) < get_keyID('rx.local'):
                            print '\nWARNING! Expired cmd key detected!\n'\
                                  'This might indicate a replay attack!\n'

                            if logReplayedEvent:
                                write_log_entry('', '', 'AUTOMATIC LOG ENTRY: Replayed/malformed command received!')
                            continue


                        # Check that local keyfile for decryption exists.
                        if not os.path.isfile('rx.local.e'):
                            print '\nError: rx.local.e was not found.\n'\
                                  'Command could not be decrypted.\n'
                            continue


                        try:
                            # Decrypt command if MAC verification succeeds.
                            MACisValid, plaintext = auth_and_decrypt('rx.local', ciphertext, keyID)

                            if MACisValid:
                                command = plaintext

                                ##########################
                                #     Enable logging     #
                                ##########################
                                if command == 'logson':
                                    if logChangeAllowed:
                                        if logMessages:
                                            print 'Logging is already enabled.'
                                        else:
                                            logMessages = True
                                            print 'Logging has been enabled.'
                                        continue

                                    else:
                                        print '\nLogging settings can not be altered: Boolean\n'\
                                              'value \'logChangeAllowed\' is set to False.\n'
                                        continue


                                ###########################
                                #     Disable logging     #
                                ###########################
                                if command == 'logsoff':
                                    if logChangeAllowed:
                                        if not logMessages:
                                            print 'Logging is already disabled.'
                                        else:
                                            logMessages = False
                                            print 'Logging has been disabled.'
                                        continue

                                    else:
                                        print '\nLogging settings can not be altered: Boolean\n'\
                                              'value \'logChangeAllowed\' is set to False.\n'
                                        continue


                                #######################
                                #     Change nick     #
                                #######################
                                if 'nick=' in command:

                                    xmpp, cmdPar   = command.split('/')
                                    cmd, parameter = cmdPar.split('=')

                                    # Write and load nick.
                                    write_nick(xmpp, parameter)
                                    rxNick = get_nick(xmpp)

                                    print '\nChanged ' + xmpp[3:] + ' nick to \'' + rxNick + '\'\n'
                                    continue


                                ############################
                                #     Load new keyfile     #
                                ############################
                                if command.startswith('tfckf '):
                                    notUsed, cXMPP, newKf = command.split(' ')

                                    # Shred entropy file
                                    if cXMPP.startswith('me.'):
                                        print '\nRxM: Shredding current keyfile that decrypts\nmessages your TxM sends to ' + cXMPP[3:] + '\n'
                                    else:
                                        cXMPP = 'rx.' + cXMPP
                                        print '\nRxM: Shredding current keyfile that decrypts\nmessages sent to you by ' + cXMPP[3:] + '\n'
                                    subprocess.Popen('shred -n ' + str(shredIterations) + ' -z -u ' + cXMPP + '.e', shell=True).wait()

                                    # Move new entropy file in place
                                    print 'RxM: Replacing the keyfile ' + cXMPP + ' with file \'' + newKf + '\''
                                    subprocess.Popen('mv ' + newKf + ' ' + cXMPP + '.e', shell=True).wait()

                                    # Reset keyID
                                    print 'RxM: Resetting key number to 1 for ' + cXMPP[3:]
                                    write_keyID(cXMPP, 1)

                                    # Process encryption keys and keyID
                                    print 'RxM: Keyfile succesfully changed\n'
                                    continue


                            else:
                                print '\nWARNING! Message authentication failed!\n' \
                                      'It is possible someone is trying to tamper messages!\n'
                                if logTamperingEvent:
                                    write_log_entry('', xmpp, 'AUTOMATIC LOG ENTRY: Tampered/malformed message received!')
                                continue


                        except KeyError:
                            print 'WARNING! Received a command, the key-id of which is not valid!\n' \
                                  'This might indicate tampering or keyfile content mismatch.'
                            continue
                        except TypeError:
                            print 'WARNING! Received a command, the key-id of which is not valid!\n' \
                                  'This might indicate tampering or keyfile content mismatch.'
                            continue


                    else:
                        os.system('clear')
                        print '\nCRC checksum error: Command received by RxM\n' \
                                 'was malformed. If this error is persistent\n,'\
                                 'check the batteries of your RxM data diode.\n'



                ####################################
                #         NORMAL MESSAGE           #
                ####################################
                if receivedPacket.startswith('<mesg>'):
                    xmpp, ctMACln, crcPkg = receivedPacket[6:].split('~')
                    crcPkg = crcPkg.strip('\n')


                    # Check that CRC32 Matches.
                    if crc32(ctMACln) == crcPkg:
                        payload, keyID = ctMACln.split('|')
                        ciphertext     = base64_decode(payload)


                        # Check that keyID is fresh.
                        if  int(keyID) < get_keyID(xmpp):
                            print '\nWARNING! Expired msg key detected!\n'\
                                  'This might indicate a replay attack!\n'

                            if logReplayedEvent:
                                write_log_entry('', xmpp, 'AUTOMATIC LOG ENTRY: Replayed/malformed message received!')
                            continue


                        # Check that keyfile for decryption exists.
                        if not os.path.isfile(xmpp + '.e'):
                            print '\nError: keyfile for contact ' + xmpp + 'was\n'\
                                  'not found.\nMessage could not be decrypted.\n'
                            continue


                        try:
                            # Decrypt message if MAC verification succeeds.
                            MACisValid, plaintext = auth_and_decrypt(xmpp, ciphertext, keyID)

                            if MACisValid:


                                if plaintext.startswith('s'):

                                    ###########################################
                                    #     Process short standard messages     #
                                    ###########################################

                                    if plaintext.startswith('sTFCFILE'):
                                        if fileSavingAllowed:
                                            fileReceive  = True
                                            fileReceived = True
                                    plaintext = plaintext[1:]

                                else:

                                    ####################################################
                                    #     Process long messages and file transfers     #
                                    ####################################################

                                    # Header packet of long message / file.
                                    if plaintext.startswith('l'):
                                        if plaintext.startswith('lTFCFILE'):

                                            if fileSavingAllowed:
                                                print 'Receiving file, this make take a while. You can\'t\n'\
                                                      'receive messages until you have stored/rejected the file'
                                                fileReceive = True
                                        else:
                                            if showLongMsgWarning:
                                                print '\n' + 'Receiving long message, please wait...\n'

                                        longMsg[xmpp] = plaintext[1:]
                                        continue


                                    # Appended packet of long message / file.
                                    if plaintext.startswith('a'):
                                        longMsg[xmpp]  = longMsg[xmpp] + plaintext[1:]
                                        continue


                                    # Final packet of long message / file.
                                    if plaintext.startswith('e'):
                                        longMsg[xmpp] = longMsg[xmpp] + plaintext[1:]
                                        plaintext     = longMsg[xmpp] + '\n'
                                        if fileReceive:
                                            fileReceived = True


                                if not fileReceive:

                                    ######################################
                                    #     Process printable messages     #
                                    ######################################

                                    if xmpp.startswith('me.'):
                                        nick = 'Me > ' + get_nick('rx' + xmpp[2:])
                                    else:
                                        nick = 5 * ' ' + get_nick(xmpp)

                                    # Print message to user.
                                    if displayTime:
                                        msgTime = datetime.datetime.now().strftime(displayTimeFmt)
                                        print msgTime + '  ' + nick + ':  ' + plaintext
                                    else:
                                        print                  nick + ':  ' + plaintext

                                # Log messages if logging is enabled.
                                if logMessages:
                                    if nick.startswith('Me > '):
                                        spacing = len(get_nick('rx' + xmpp[2:]))
                                        nick    = (spacing - 2) * ' ' + 'Me'
                                        write_log_entry(nick, xmpp[3:], plaintext)
                                    else:
                                        write_log_entry(nick[5:], xmpp[3:], plaintext)


                                if fileReceive:

                                    ##################################
                                    #     Process received files     #
                                    ##################################

                                    if fileSavingAllowed:
                                        if fileReceived:

                                            discardFile = False
                                            askFileName = True

                                            while askFileName:
                                                os.system('clear')
                                                fileName = raw_input('\nFile Received. Enter filename (\'r\' rejects file): ')


                                                if fileName == 'r':
                                                    print '\nFile Rejected. Continuing\n'
                                                    plaintext   == ''
                                                    fileReceive  = False
                                                    fileReceived = False
                                                    discardFile  = True
                                                    askFileName  = False
                                                    continue


                                                else:
                                                    if os.path.isfile(fileName):
                                                        overwrite = raw_input('File already exists. Type \'YES\' to overwrite: ')

                                                        if overwrite == 'YES':
                                                            askFileName = False
                                                        continue

                                                    else:
                                                        askFileName = False
                                                        continue

                                            if not discardFile:

                                                # Save received base64 data to temporary file and decode it.
                                                with open('tfcTmpFile', 'w+') as file:
                                                    file.write(plaintext[7:])

                                                subprocess.Popen('base64 -d tfcTmpFile > ' + fileName,                    shell=True).wait()

                                                # Shred temporary file.
                                                subprocess.Popen('shred -n ' + str(kfOWIterations) + ' -z -u tfcTmpFile', shell=True).wait()

                                                disp_opsec_warning()

                                            fileReceive  = False
                                            fileReceived = False


                                        else:
                                            continue

                                    else:
                                        plaintext == ''
                                        continue

                                continue

                            else:
                                print '\nWARNING! Message authentication failed!\n' \
                                      'It is possible someone is trying to tamper messages!\n'
                                if logTamperingEvent:
                                    write_log_entry('',xmpp, 'EVENT WARNING: Tampered/malformed message received!')
                                continue


                        except TypeError:
                            print 'WARNING! Received a message, the key-id of which is not valid!\n' \
                                  'This might indicate tampering or keyfile content mismatch.'
                            continue


                    else:
                        print '\nCRC checksum error: Message received by RxM was malformed\n.'\
                                'Note that this error occurred between your NH and RxM so\n'  \
                                'recipient most likely received the message. If this error\n' \
                                'is persistent, check the batteries of your RxM data diode.\n'

            except IndexError:
                os.system('clear')
                print '\nWARNING! Packet format is invalid!\n'\
                        'This might indicate message tampering!\n'
                continue

            except ValueError:
                os.system('clear')
                print '\nWARNING! Packet format is invalid!\n'\
                        'This might indicate message tampering!\n'
                continue

except KeyboardInterrupt:
    exit_with_msg('Exiting TFC.', False)


