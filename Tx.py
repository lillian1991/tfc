#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import csv
import math
import os
import random
import readline
import serial
import subprocess
import sys
import zlib
from time import sleep



######################################################################
#                              LICENCE                               #
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
# Tx.py
version = '0.4.11 beta'



######################################################################
#                            CONFIGURATION                           #
######################################################################

os.chdir(sys.path[0])

maxMsgLen       = 143
keyThreshold    = 5
maxSleepTime    = 13
kfOWIterations  = 3
keyOWIterations = 3
lMsgSleep       = 0.2

emergencyExit   = False
checkKeyHashes  = False
randomSleep     = False
debugging       = False

localTesting    = False

if not localTesting:
    port        = serial.Serial('/dev/ttyAMA0', baudrate=9600, timeout=0.1)



######################################################################
#                            KECCAK HASH                             #
######################################################################

# Algorithm Name: Keccak
# Authors: Guido Bertoni, Joan Daemen, Michael Peeters and Gilles Van Assche
# Implementation by Renaud Bauvin, STMicroelectronics
#
# This code, originally by Renaud Bauvin, is hereby put in the public domain.
# It is given as is, without any guarantee.
#
# For more information, feedback or questions, please refer to our website:
# http://keccak.noekeon.org/

class KeccakError(Exception):
    """Class of error used in the Keccak implementation

    Use: raise KeccakError.KeccakError("Text to be displayed")"""

    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)



class Keccak:
    """
    Class implementing the Keccak sponge function
    """
    def __init__(self, b=1600):
        """Constructor:

        b: parameter b, must be 25, 50, 100, 200, 400, 800 or 1600 (default value)"""
        self.setB(b)

    def setB(self,b):
        """Set the value of the parameter b (and thus w,l and nr)

        b: parameter b, must be choosen among [25, 50, 100, 200, 400, 800, 1600]
        """

        if b not in [25, 50, 100, 200, 400, 800, 1600]:
            raise KeccakError.KeccakError('b value not supported - use 25, 50, 100, 200, 400, 800 or 1600')

        # Update all the parameters based on the used value of b
        self.b=b
        self.w=b//25
        self.l=int(math.log(self.w,2))
        self.nr=12+2*self.l

    # Constants

    ## Round constants
    RC=[0x0000000000000001,
        0x0000000000008082,
        0x800000000000808A,
        0x8000000080008000,
        0x000000000000808B,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008A,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000A,
        0x000000008000808B,
        0x800000000000008B,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800A,
        0x800000008000000A,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008]

    ## Rotation offsets
    r=[[0,    36,     3,    41,    18]    ,
       [1,    44,    10,    45,     2]    ,
       [62,    6,    43,    15,    61]    ,
       [28,   55,    25,    21,    56]    ,
       [27,   20,    39,     8,    14]    ]

    ## Generic utility functions

    def rot(self,x,n):
        """Bitwise rotation (to the left) of n bits considering the \
        string of bits is w bits long"""

        n = n%self.w
        return ((x>>(self.w-n))+(x<<n))%(1<<self.w)

    def enc(self,x,n):
        """Encode the integer x in n bits (n must be a multiple of 8)"""

        if x>=2**n:
            raise KeccakError.KeccakError('x is too big to be coded in n bits')
        if n%8!=0:
            raise KeccakError.KeccakError('n must be a multiple of 8')
        return ("%%0%dX" % (2*n//8)) % (x)

    def fromHexStringToLane(self, string):
        """Convert a string of bytes written in hexadecimal to a lane value"""

        #Check that the string has an even number of characters i.e. whole number of bytes
        if len(string)%2!=0:
            raise KeccakError.KeccakError("The provided string does not end with a full byte")

        #Perform the modification
        temp=''
        nrBytes=len(string)//2
        for i in range(nrBytes):
            offset=(nrBytes-i-1)*2
            temp+=string[offset:offset+2]
        return int(temp, 16)

    def fromLaneToHexString(self, lane):
        """Convert a lane value to a string of bytes written in hexadecimal"""

        laneHexBE = (("%%0%dX" % (self.w//4)) % lane)
        #Perform the modification
        temp=''
        nrBytes=len(laneHexBE)//2
        for i in range(nrBytes):
            offset=(nrBytes-i-1)*2
            temp+=laneHexBE[offset:offset+2]
        return temp.upper()

    def printState(self, state, info):
        """Print on screen the state of the sponge function preceded by \
        string info

        state: state of the sponge function
        info: a string of characters used as identifier"""

        print("Current value of state: %s" % (info))
        for y in range(5):
            line=[]
            for x in range(5):
                 line.append(hex(state[x][y]))
            print('\t%s' % line)

    ### Conversion functions String <-> Table (and vice-versa)

    def convertStrToTable(self,string):
        """Convert a string of bytes to its 5x5 matrix representation

        string: string of bytes of hex-coded bytes (e.g. '9A2C...')"""

        #Check that input paramaters
        if self.w%8!= 0:
            raise KeccakError("w is not a multiple of 8")
        if len(string)!=2*(self.b)//8:
            raise KeccakError.KeccakError("string can't be divided in 25 blocks of w bits\
            i.e. string must have exactly b bits")

        #Convert
        output=[[0,0,0,0,0],
                [0,0,0,0,0],
                [0,0,0,0,0],
                [0,0,0,0,0],
                [0,0,0,0,0]]
        for x in range(5):
            for y in range(5):
                offset=2*((5*y+x)*self.w)//8
                output[x][y]=self.fromHexStringToLane(string[offset:offset+(2*self.w//8)])
        return output

    def convertTableToStr(self,table):
        """Convert a 5x5 matrix representation to its string representation"""

        #Check input format
        if self.w%8!= 0:
            raise KeccakError.KeccakError("w is not a multiple of 8")
        if (len(table)!=5) or (False in [len(row)==5 for row in table]):
            raise KeccakError.KeccakError("table must be 5x5")

        #Convert
        output=['']*25
        for x in range(5):
            for y in range(5):
                output[5*y+x]=self.fromLaneToHexString(table[x][y])
        output =''.join(output).upper()
        return output

    ### Padding function

    def pad(self,M, n):
        """Pad M with reverse-padding to reach a length multiple of n

        M: message pair (length in bits, string of hex characters ('9AFC...')
        n: length in bits (must be a multiple of 8)
        Example: pad([60, 'BA594E0FB9EBBD30'],8) returns 'BA594E0FB9EBBD13'
        """

        [my_string_length, my_string]=M

        # Check the parameter n
        if n%8!=0:
            raise KeccakError.KeccakError("n must be a multiple of 8")

        # Check the length of the provided string
        if len(my_string)%2!=0:
            #Pad with one '0' to reach correct length (don't know test
            #vectors coding)
            my_string=my_string+'0'
        if my_string_length>(len(my_string)//2*8):
            raise KeccakError.KeccakError("the string is too short to contain the number of bits announced")

        #Add the bit allowing reversible padding
        nr_bytes_filled=my_string_length//8
        if nr_bytes_filled==len(my_string)//2:
            #bits fill the whole package: add a byte '01'
            my_string=my_string+"01"
        else:
            #there is no addition of a byte... modify the last one
            nbr_bits_filled=my_string_length%8

            #Add the leading bit
            my_byte=int(my_string[nr_bytes_filled*2:nr_bytes_filled*2+2],16)
            my_byte=(my_byte>>(8-nbr_bits_filled))
            my_byte=my_byte+2**(nbr_bits_filled)
            my_byte="%02X" % my_byte
            my_string=my_string[0:nr_bytes_filled*2]+my_byte

        #Complete my_string to reach a multiple of n bytes
        while((8*len(my_string)//2)%n!=0):
            my_string=my_string+'00'
        return my_string

    def Round(self,A,RCfixed):
        """Perform one round of computation as defined in the Keccak-f permutation

        A: current state (5x5 matrix)
        RCfixed: value of round constant to use (integer)
        """

        #Initialisation of temporary variables
        B=[[0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0]]
        C= [0,0,0,0,0]
        D= [0,0,0,0,0]

        #Theta step
        for x in range(5):
            C[x] = A[x][0]^A[x][1]^A[x][2]^A[x][3]^A[x][4]

        for x in range(5):
            D[x] = C[(x-1)%5]^self.rot(C[(x+1)%5],1)

        for x in range(5):
            for y in range(5):
                A[x][y] = A[x][y]^D[x]

        #Rho and Pi steps
        for x in range(5):
          for y in range(5):
                B[y][(2*x+3*y)%5] = self.rot(A[x][y], self.r[x][y])

        #Chi step
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y]^((~B[(x+1)%5][y]) & B[(x+2)%5][y])

        #Iota step
        A[0][0] = A[0][0]^RCfixed

        return A

    def KeccakF(self,A, verbose=False):
        """Perform Keccak-f function on the state A

        A: 5x5 matrix containing the state
        verbose: a boolean flag activating the printing of intermediate computations
        """

        if verbose:
            self.printState(A,"Before first round")

        for i in range(self.nr):
            #NB: result is truncated to lane size
            A = self.Round(A,self.RC[i]%(1<<self.w))

            if verbose:
                  self.printState(A,"Satus end of round #%d/%d" % (i+1,self.nr))

        return A

    def Keccak(self,M,r=1024,c=576,d=0,n=1024,verbose=False):
        """Compute the Keccak[r,c,d] sponge function on message M

        M: message pair (length in bits, string of hex characters ('9AFC...')
        r: bitrate in bits (defautl: 1024)
        c: capacity in bits (default: 576)
        d: diversifier in bits (default: 0 bits)
        n: length of output in bits (default: 1024),
        verbose: print the details of computations(default:False)
        """

        #Check the inputs
        if (r<0) or (r%8!=0):
            raise KeccakError.KeccakError('r must be a multiple of 8')
        if (n%8!=0):
            raise KeccakError.KeccakError('outputLength must be a multiple of 8')
        if (d<0) or (d>255):
            raise KeccakError.KeccakError('d must be in the range [0, 255]')
        self.setB(r+c)

        if verbose:
            print("Create a Keccak function with (r=%d, c=%d, d=%d (i.e. w=%d))" % (r,c,d,(r+c)//25))

        #Compute lane length (in bits)
        w=(r+c)//25

        # Initialisation of state
        S=[[0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0]]

        #Padding of messages
        P=self.pad(M,8) + self.enc(d,8) + self.enc(r//8,8)
        P=self.pad([8*len(P)//2,P],r)

        if verbose:
            print("String ready to be absorbed: %s (will be completed by %d x '00')" % (P, c//8))

        #Absorbing phase
        for i in range((len(P)*8//2)//r):
            Pi=self.convertStrToTable(P[i*(2*r//8):(i+1)*(2*r//8)]+'00'*(c//8))

            for y in range(5):
              for x in range(5):
                  S[x][y] = S[x][y]^Pi[x][y]
            S = self.KeccakF(S, verbose)

        if verbose:
            print("Value after absorption : %s" % (self.convertTableToStr(S)))

        #Squeezing phase
        Z = ''
        outputLength = n
        while outputLength>0:
            string=self.convertTableToStr(S)
            Z = Z + string[:r*2//8]
            outputLength -= r
            if outputLength>0:
                S = self.KeccakF(S, verbose)

            # NB: done by block of length r, could have to be cut if outputLength
            #     is not a multiple of r

        if verbose:
            print("Value after squeezing : %s" % (self.convertTableToStr(S)))

        return Z[:2*n//8]



def stringtoHex(string):
    lst = []
    for char in string:
        hexValue = hex(ord(char)).replace('0x', '')
        if len(hexValue) == 1:
            hexValue = '0' + hexValue
        lst.append(hexValue)
    return reduce(lambda x,y : x+y, lst)



def keccak512(hashInput):
    hexMsg       = stringtoHex(hashInput)
    hashfunction = Keccak()

    return hashfunction.Keccak((1144, hexMsg), 576, 1024, 0, 512, debugging)    # Verbose Keccak hash function presentation when checkKeyHashes is enabled



######################################################################
#                           OTP ENCRYPTION                           #
######################################################################

def encrypt(message, key):
    if debugging:
        print 'M(encrypt): Encryption initialized'
    ciphertext = ''.join(chr(ord(msgLetter) ^ ord(keyLetter)) for msgLetter, keyLetter in zip(message, key))
    if debugging:
        print 'M(encrypt): Encryption finished\n'
    return ciphertext



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

    h = 1
    if debugging:                                                     # Print block values
        print '\nCiphertext block values (Integer):\n'
        for block in iA:
            print 'M[' + str(h) + '] (Length = ' + str(len(str(block))) + ')'
            print str(block) + '\n'
            h += 1
        print ''

    if debugging:                                                     #  Verbose presentation of MAC calculation formula for value verification
        f       = l
        formula = ''
        while (f > 0):
            formula = formula + 'M[' + str(f) + ']*' + 'k^' + str(f)
            if (f > 1):
                formula = formula + ' + '
            f -= 1
        formula = formula + ' + a (mod q)'
        print 'MAC(key, msg) = ' + formula


    n = 0                                                            #  Calculate MAC
    while (l > 0):
        n = n + ( iA[l-1] * (k ** l) )
        l -= 1
    MAC = (n + a) % q


    MAC = str(hex(MAC))[:-1]                                          #  Convert int to hex and remove L from end
    MAC = MAC[2:]                                                     #  Remove 0x from start
    MAC = padding(MAC)

    if debugging:
        print '\nFinished message authentication code is:\n"""' + MAC + '"""\n\n'

    return MAC



######################################################################
#                              SETTERS                               #
######################################################################

def add_contact(nick, xmpp):
    contacts = []
    with open('txc.tfc', 'a+') as cFile:
        datareader = csv.reader(cFile)
        for row in datareader:
            contacts.append(row)
        cFile.write(nick + ',' + xmpp + ',1\n')
    if debugging:
        print '\nM(add_contact):\nAdded contact ' + nick + ' (xmpp = ' + xmpp + ') to txc.tfc\n'



def add_new_contacts(entropyfilenames):
    contacts   = []
    datareader = csv.reader(open('txc.tfc', 'a+'))
    for row in datareader:
        contacts.append(row)
    for item in entropyfilenames:
        onList = False
        xmpp   = item[:-2]
        for person in contacts:
            if xmpp in person[1]:
                onList = True
        if not onList:
            if (xmpp == 'tx.local'):
                add_contact('tx.local', 'txlocal')
            newNick  = raw_input('New contact ' + xmpp + ' found. Enter nick: ')
            add_contact(newNick, xmpp)



def newKfTx():
    # Command to overwrite keys is transmitted to RxM before TxM starts. This way the
    # time consuming overwriting of keyfiles can occur at the same time on both computers

    print 'TxM: Shredding keyfile that encrypts messages to ' + contactXmpp[3:]
    subprocess.Popen('shred -n ' + str(kfOWIterations) + ' -z -u ' + contactXmpp + '.e', shell=True).wait()

    print 'TxM: Replacing the keyfile for ' + contactXmpp[3:] + ' with \'' + keyFileName + '\''
    subprocess.Popen('mv ' + keyFileName + ' ' + contactXmpp + '.e', shell=True).wait()

    print 'TxM: Setting key number to 1 for ' + contactXmpp[3:]
    store_keyID(contactXmpp, 1)
    if (contactXmpp == xmpp):
        msgKeyID = 1
    print 'TxM: Keyfile successfully changed\n'
    return msgKeyID



def overwrite_enc_key(xmpp, keyID):
    if checkKeyHashes:
        if debugging:
            print 'M(overwrite_enc_key): Loading key for hash writing'
            print 'Note that the following key is supposed to be the same as the previous one in debugging messages'
        key = get_enc_key(xmpp, keyID)
        write_used_key_hash(key)

    if (keyID < 1):
        print '\nError: KeyID was not greater than 0! Check your contacts.tfc file!\nExiting..\n'
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
        i += 1

    with open(xmpp + '.e', 'rb+') as eFile:
        eFile.seek(offset)
        eFile.write(maxMsgLen * '!')
        eFile.seek(offset)
        owCandidate = eFile.read(maxMsgLen)
        while (owCandidate != (maxMsgLen * '!')):
            print '\nWARNING! Failed to overwrite key. Retrying...\n'
            eFile.seek(offset)
            eFile.write(maxMsgLen * '!')
            eFile.seek(offset)
            owCandidate = eFile.read(maxMsgLen)
        if debugging:
            print 'M(overwrite_xmpp_key): Overwriting completed.\n'



def store_keyID(xmpp, keyID):
    contacts = []
    with open('txc.tfc', 'r') as cFile:
        datareader = csv.reader(cFile)
        for row in datareader:
            contacts.append(row)

    for i in range( len(contacts) ):
        if contacts[i][1] == xmpp:
           contacts[i][2] = keyID

    with open('txc.tfc', 'w') as cFile:
        writer = csv.writer(cFile)
        writer.writerows(contacts)

    if debugging:
        print '\nM(store_keyID): Wrote line \'' + str(keyID) + '\' for contact ' + xmpp + ' to txc.tfc\n'



def write_nick(xmpp, nick):
    contacts = []
    with open ('txc.tfc', 'r') as cFile:
        datareader = csv.reader(cFile)

        for row in datareader:
            contacts.append(row)
        for i in range( len(contacts) ):
            if contacts[i][1] == xmpp:
               contacts[i][0] = nick

    with open('txc.tfc', 'w') as cFile:
        writer = csv.writer(cFile)
        writer.writerows(contacts)

    if debugging:
        print '\nM(write_nick):\nWrote nick ' + nick + ' for account ' + xmpp + ' to txc.tfc\n'



def write_used_key_hash(key):
    with open('usedKeys.tfc', 'a+') as kFile:
        keyHash = keccak512(key)
        kFile.write(keyHash + '\n')
    if debugging:
        print '\nM(write_used_key_hash): Wrote following blacklisted hash to usedKeys.tfc\n' + keyHash + '\n'



def create_group_list(group, newMembers = []):
    fileExists = os.path.isfile('g.' + group + '.tfc')
    if fileExists:
        if not (raw_input('\nGroup called \'' + group + '\' already exists. Type YES to overwrite: ') == 'YES'):
            return False
    with open('g.' + group + '.tfc', 'w+') as gFile:
        if newMembers:
            for member in newMembers:
                member = member.strip(' ')
                if (member != ''):
                    gFile.write(member + '\n')
    sort_group(group)
    return True



def add_to_groupList(group, addList):
    alreadyExisting = []
    notAdded        = []
    with open('g.' + group + '.tfc', 'a+') as gFile:
        lines    = gFile.readlines()

    for line in lines:
        line = line.strip('\n')
        alreadyExisting.append(line)

    print '\nAdded following members to group \'' + group + '\':'
    for item in addList:
        item = item.strip('\n')
        item = item.strip(' ')

        if not item in alreadyExisting:
            if (item != ''):
                gFile.write(item + '\n')
                print '   ' + item
        else:
            notAdded.append(item)
    if notAdded:
        print '\nFollowing contacts already existed in group \'' + group + '\' and were thus not added:'
        for item in notAdded:
            print '   ' + item
    print ''
    sort_group(group)



def rem_from_groupList(group, rmList):
    memberList = []
    notRemoved = []
    printing   = False
    with open('g.' + group + '.tfc', 'r') as gFile:
        readLines = gFile.readlines()
    for line in readLines:
        member = line.strip('\n')
        memberList.append(member)

    print '\nRemoved from group \'' + usedGroup + '\' following members:'
    with open('g.' + group + '.tfc', 'w') as gFile:
        for member in memberList:
            if member in rmList:
                print '   ' + member
            else:
                gFile.write(member + '\n')          # Write remaining group members back to file.

        for rmItem in rmList:                       # Check if user tried to remove members not in the group file.
            if not rmItem in memberList:
                if (str(rmItem) != ''):
                    notRemoved.append(rmItem)
                    printing = True
        if printing:
            print '\nFollowing accounts were not in group \'' + group + '\' and were thus not removed:'
            for remUser in notRemoved:
                print '   ' + remUser
        print ''



def sort_group(group):
    with open('g.' + group + '.tfc', 'r') as gFile:
        members = gFile.readlines()
        members.sort()
    with open('g.' + group + '.tfc', 'w') as gFile:
        for item in members:
            gFile.write(item)



######################################################################
#                              GETTERS                               #
######################################################################

def get_contact_quantity():
    with open('txc.tfc', 'r') as contactFile:
        for i, l in enumerate(contactFile):
            pass

    with open('txc.tfc', 'r') as contactFile:
        for line in contactFile:
                if str('tx.local') in line: # If tx.local.e is available, number of contacts
                    return i                # is 1 lower than items in contact list.
    return i + 1                            # Since indexing starts from 0, add 1 to get number of contacts.



def get_enc_key(xmpp, keyID):
    if (keyID < 1):
        print '\nError: KeyID was not greater than 0! Check your contacts.tfc file!\nExiting..\n'
        exit()
    else:
        offset = (keyID * maxMsgLen)

    with open(xmpp + '.e', 'rb') as efile:
        efile.seek(offset)
        key = efile.read(maxMsgLen)
    if debugging:
        print '\nM(get_enc_key):\nLoaded following key (keyID = ' + str(keyID) + ') from offset ' + str(offset) + ' for xmpp ' + xmpp + ':\n"""'
        print key
        print '"""'

    if valid_key_chk(key, xmpp):
        return key
    else:
        print 'Error: Loaded an invalid key. Check your keyfile! Exiting..'
        exit()



def get_entropy_file_list():
    entFileL = []
    xmppAddL = []
    for fileN in os.listdir('.'):
        if fileN.endswith('.e'):
            if not fileN.startswith('me.') and not fileN.startswith('rx.'):
                entFileL.append(fileN)
                xmppAddL.append(fileN[:-2][3:])
    return entFileL, xmppAddL



def get_group_file_list(output):
    gFileNames = []
    for fileN in os.listdir('.'):
        if fileN.startswith('g.') and fileN.endswith('.tfc'):
            gName = fileN[2:][:-4]
            gname = gName.strip('\n')
            gFileNames.append(gName)
    if output:
        if not gFileNames:
            print '\nThere are currently no groups'
    return gFileNames



def get_group_members(groupName):
    groupList = []
    with open('g.' + groupName + '.tfc', 'r+') as gFile:
        fLines = gFile.readlines()
    for line in fLines:
        groupList.append(line.strip('\n'))

    if not groupList:
        print '\nLoaded empty group. Add contacts to group with command\n   /group add <group> <xmpp>\n'
    return groupList



def get_keyID(xmpp):
    contacts = []
    with open('txc.tfc', 'r') as cFile:
        csvData = csv.reader(cFile)
        for row in csvData:
            contacts.append(row)

    for i in range( len(contacts) ):
        if contacts[i][1] == xmpp:
            keyID = int(contacts[i][2])
            #if debugging:
            #    print '\nM(get_keyID): Loaded keyid ' + str(keyID) + ' for xmpp ' + xmpp + '\n'
            return keyID
    print 'ERROR: Failed to load keyID for XMPP ' + xmpp + '. Exiting'
    exit()



def get_nick(xmpp):
    contacts = []
    with open('txc.tfc', 'r') as cFile:
        csvData = csv.reader(cFile)
        for row in csvData:
            contacts.append(row)
    for i in range( len(contacts) ):
        if contacts[i][1] == xmpp:
            nick = contacts[i][0]
            #if debugging:
            #    print '\nM(get_nick): Loaded nick ' + nick + ' for contact ' + xmpp + '\n'
            return nick
    print 'ERROR: Failed to load nick for XMPP ' + xmpp + '. Exiting'
    exit()


def get_local_enc_key(keyID):
    return get_enc_key('tx.local', keyID)



def get_local_enc_values():
    try:
        localKeyID        = get_keyID('tx.local')
        if (localKeyID    == None):
            add_contact('tx.local', 'tx.local')
            localKeyID    = get_keyID('tx.local')

        if out_of_local_keys_chk(localKeyID):
            localKey      = get_local_enc_key(localKeyID)
            ctrlRemaining = True

    except IOError:
        add_contact('tx.local', 'tx.local')
        localKeyID = get_keyID('tx.local')

        if out_of_local_keys_chk(localKeyID):
            localKey      = get_local_enc_key(localKeyID)
            ctrlRemaining = True
    return localKey, localKeyID, ctrlRemaining



def get_autotabs(contacts):
    aTabContacts = []
    for item in contacts:
        aTabContacts.append(item + ' ')

    aTabGfiles   = []
    gFileList    = get_group_file_list(False)
    for item in gFileList:
        aTabGfiles.append(item + ' ')

    cList        = ['about', 'add ', 'clear', 'create ', 'exit', 'file ', 'group ', 'help', 'logging ', 'msg ', 'newkf ', 'nick ', 'quit', 'rm ', 'select ']

    return aTabContacts + aTabGfiles + cList



######################################################################
##                              CHECKS                              ##
######################################################################

def key_blacklist_chk(key, xmpp):
    keyHash = keccak512(key)
    with open('usedKeys.tfc', 'a+') as usedKeyList:
        for line in usedKeyList:
            if keyHash in line:
                os.system('clear')
                print 'WARNING! Detected a used key with contact \'' + xmpp + '\''
                print '(Hash collided with blacklist in file \'usedKeys.tfc\')!'
                print 'Check that keyfile is unused. Exiting'
                print 'Collided hash was:\n' + keyHash + '\n'
                return True
            else:
                if debugging:
                    print 'M(key_blacklist_chk):\nKey was not blacklisted'
                return False



def keys_Rem_chk(xmpp, keyID):
    if (keyID < 1):
        print 'Error: KeyID was not greater than 0! Check your contacts.tfc file!\nExiting..'
        exit()
    else:
        offset      = keyID * maxMsgLen
    with open(xmpp + '.e', 'rb') as eFile:
        eFile.seek(offset)
        currentByte = eFile.tell()
        eFile.seek(0, 2)
        length      = (eFile.tell() - 1)
        bytesRem    = length - currentByte

    if (bytesRem / (3 * maxMsgLen) < 1):
        return 0                              # If not enough bytes to create 3 keys, return 0 keys remaining
    keys_Rem_chk    = bytesRem / maxMsgLen
    return keys_Rem_chk



def out_of_local_keys_chk(keyID, output=False):
    linesLeft        = keys_Rem_chk('tx.local', keyID)
    if linesLeft in [1, 2]:
        cmdLeft      = 0
    else:
        cmdLeft      = linesLeft / 3

    if debugging:
        print '\nM(out_of_local_keys_chk): There are ' + str(cmdLeft - 1) + ' command(s) remaining\n'

    notifyList       = [20, 10, 5, 4, 3, 2, 1]
    if output:
        if cmdLeft in notifyList:
            print 'Commands remaining: ' + str(cmdLeft - 1)

    if (cmdLeft <= 0):
        if output:
            print 'All keys to send command messages to RxM have been used.'
        return False
    return True



def out_of_keys_chk(xmpp, keyID, outputKeys=False):
    linesLeft      = keys_Rem_chk(xmpp, keyID)
    if linesLeft in [1,2]:
        msgLeft    = 0
    else:
        msgLeft    = linesLeft / 3

    if debugging:
        print '\nM(out_of_keys_chk): ' + str(msgLeft - 1) + ' messages(s) remaining\n'

    notifyList = [1000, 500, 400, 300, 200, 100, 50, 40, 30, 20, 10, 5, 4, 3, 2, 1]
    if outputKeys:
        if msgLeft in notifyList:
            print 'Messages remaining: ' + str(msgLeft - 1)

    if (msgLeft <= 0):
        print '\nKeyfile for contact ' + xmpp + ' has been used.\nEither load new key using command /newkf or select another\ncontact with command /msg #. See /help for details.\n'
        print_list_of_contacts()
        print ''
        return True

    return False



def overWriteIteratorCheck():
    if (keyOWIterations < 1):
        print '''
WARNING: keyOWIterations VALUE IS SET TO LESS
THAN 1 WHICH MEANS KEY IS NOT BEING OVERWRITTEN
IMMEDIATELY AFTER USE!

THIS MIGHT BE VERY DANGEROUS FOR PHYSICAL SECURITY
AS ANY ATTACKER WHO GETS ACCESS TO KEYS, CAN LATER
DECRYPT INTERCEPTED CIPHERTEXTS. INCREASE THE VALUE
TO 1 OR PREFERABLY HIGHER TO FIX THIS PROBLEM.

IF YOU ARE SURE ABOUT NOT OVERWRITING, MANUALLY
COMMENT OUT THE overWriteIteratorCheck FUNCTION CALL
FROM PRE-LOOP OF Tx.py.

EXITING Tx.py'''
        exit()



def search_contact_keyfiles():
    keyfiles  = []
    keyfiles += [each for each in os.listdir('.') if each.endswith('.e')]
    if not keyfiles:
        os.system('clear')
        print '\nError: No keyfiles for contacts were found. Make sure they are in same directory as Tx.py\n'
        exit()



def search_local_e_kf():
    try:
        with open('tx.local.e'):
            pass
        return True
    except IOError:
        print 'Error: tx.local.e was not found'
        return False



def valid_key_chk(key, xmpp):
    if (keyThreshold * '!') in key:
        os.system('clear')
        print 'Error: Loaded a key for account ' + xmpp + ', the content of which exceeded threshold of overwritten chars.\nExiting TFC...\n'
        exit()
    if checkKeyHashes:
        if key_blacklist_chk(key, xmpp):
            exit()
    if debugging:
        print '\nM(valid_key_chk): Loaded key did not exceed threshold (' + str(keyThreshold) + ' * \'!\' chars),\nso key is probably not even partly an overwritten one\n\n'
    return True



######################################################################
#                           PACKET OUTPUT                            #
######################################################################

def output_command(base64msg, line, crc):
    if localTesting:
        with open('TxOutput', 'w+') as txOut:
            txOut.write('<ctrl>'                                                                        + base64msg + '|' + str(line) + '~' + crc + '\n')
        if debugging:
            print '\nM(output_command): Writing following command to file \'TxOutput\':\n<ctrl>'        + base64msg + '|' + str(line) + '~' + crc + '\n'
            print ''
    else:
        port.write('<ctrl>'                                                                             + base64msg + '|' + str(line) + '~' + crc + '\n')
        if debugging:
            print '\nM(output_command): Transferring following command to NH:\n<ctrl>'                  + base64msg + '|' + str(line) + '~' + crc + '\n'
            print ''


def output_message(xmpp, base64msg, line, crc):
    if localTesting:
        with open('TxOutput', 'w+') as txOut:
            txOut.write(                                                      '<mesg>' + xmpp[3:] + '~' + base64msg + '|' + str(line) + '~' + crc + '\n')
        if debugging:
            print '\nM(output_message): Writing msg to file \'TxOutput\':\n<mesg>'     + xmpp     + '~' + base64msg + '|' + str(line) + '~' + crc + '\n'
            print ''

    else:
        port.write(                                                           '<mesg>' + xmpp[3:] + '~' + base64msg + '|' + str(line) + '~' + crc + '\n')
        if debugging:
            print '\nM(output_message): Transferring following message to NH:\n<mesg>' + xmpp     + '~' + base64msg + '|' + str(line) + '~' + crc + '\n'
            print ''



######################################################################
#                           MSG PROCESSING                           #
######################################################################

def b64e(content):
    return base64.b64encode(content)



def crc32(content):
    return str(hex(zlib.crc32(content)))



def padding(string):
    while (len(string) % maxMsgLen != 0):
        string = string + ' '
    if debugging:
        print '\n\nM(padding): Padded input to length of ' + str( len(string) ) +' chars:\n"""' + string + '"""\n\n'
    return string




######################################################################
#                       COMMANDS AND FUNCTIONS                       #
######################################################################


def tab_complete(text, state):
    options = [x for x in autotabs if x.startswith(text)]
    try:
        return options[state]
    except IndexError:
        return None



def rotLocalKeyID(msgKeyID):
    overwrite_enc_key('tx.local', msgKeyID)
    msgKeyID += 1
    store_keyID('tx.local', msgKeyID)
    return msgKeyID



def rotMsgKeyID(xmpp, msgKeyID):
    overwrite_enc_key(xmpp, msgKeyID)
    msgKeyID += 1
    store_keyID(xmpp, msgKeyID)
    return msgKeyID



def multiPacketProcess(string):
    string      = string.strip('\n')
    msgA        = [string[i:i + (maxMsgLen-1)] for i in range(0, len(string), (maxMsgLen-1) )]
    for i in xrange( len(msgA) ):
        msgA[i] = 'a' + msgA[i]               # 'a' tells Rx.py the message should be appended to long message
    msgA[-1]    = padding('e' + msgA[-1][1:]) # 'e' tells Rx.py the message is last one of long message, so Rx.py knows it can show the entire message.
    msgA[0]     = msgA[0][1:]
    msgA[0]     = 'l' + msgA[0]               # 'l' tells Rx.py the message is going to be long than standard, otherwise all standard messages start with 's' (=short message).
    if debugging:
        print 'M(multiPacketProcess): Processed long message to following list:'
        for item in msgA:
            print '"""' + item + '"""'
    return msgA



def longMessageProcess(kb, xmpp):

    if len(kb) > (maxMsgLen - 3):

        msglist  = multiPacketProcess(kb)
        msgKeyID = get_keyID(xmpp)
        halt     = False

        print '\nTransferring message in ' + str( len(msglist) ) + ' parts. ^C cancels'

        for partOfMsg in msglist:
            if halt:
                if kb.startswith('TFCFILE'):
                    print '\File transmission interrupted by user\n'
                else:
                    print '\nMessage transmission interrupted by user\n'
                return False

            try:
                if out_of_keys_chk(xmpp, msgKeyID): return False
                msgKey     = get_enc_key(xmpp, msgKeyID)
                msgKeyID   = rotMsgKeyID(xmpp, msgKeyID)

                ciphertext = encrypt(partOfMsg, msgKey)

                if out_of_keys_chk(xmpp, msgKeyID): return False
                macKey1    = get_enc_key(xmpp, msgKeyID)
                msgKeyID   = rotMsgKeyID(xmpp, msgKeyID)

                if out_of_keys_chk(xmpp, msgKeyID): return False
                macKey2    = get_enc_key(xmpp, msgKeyID)
                msgKeyID   = rotMsgKeyID(xmpp, msgKeyID)

                MAC        = GenerateMAC(macKey1, macKey2, ciphertext)

                encoded    = b64e (ciphertext + MAC)
                crcPacket  = crc32(encoded + '|' + str(msgKeyID - 3))

                output_message(xmpp, encoded, (msgKeyID - 3), crcPacket)

                if randomSleep:
                    sleepTime = random.uniform(0, maxSleepTime)
                    print 'Sleeping ' + str(sleepTime) + ' seconds for randomness'
                    sleep(sleepTime)

                sleep(lMsgSleep)

            except (KeyboardInterrupt):
                halt = True
    return True



def shortMessageProcess(kb, xmpp):

    msgKeyID   = get_keyID(xmpp)

    if out_of_keys_chk(xmpp, msgKeyID, True): return False
    msgKey     = get_enc_key(xmpp, msgKeyID)
    msgKeyID   = rotMsgKeyID(xmpp, msgKeyID)

    padded     = padding('s' + kb)           # 's' tells Rx.py the message can be displayed immediately (unlike long messages).
    ciphertext = encrypt(padded, msgKey)


    if out_of_keys_chk(xmpp, msgKeyID, False): return False
    macKey1    = get_enc_key(xmpp, msgKeyID)
    msgKeyID   = rotMsgKeyID(xmpp, msgKeyID)


    if out_of_keys_chk(xmpp, msgKeyID, False): return False
    macKey2    = get_enc_key(xmpp, msgKeyID)
    msgKeyID   = rotMsgKeyID(xmpp, msgKeyID)

    MAC        = GenerateMAC(macKey1, macKey2, ciphertext)

    encoded    = b64e (ciphertext + MAC)
    crcPacket  = crc32(encoded + '|' + str(msgKeyID - 3))

    output_message(xmpp, encoded, (msgKeyID - 3), crcPacket)

    return True



def commandMessageProcess(cmdMsg):
    localKeyID      = get_keyID('tx.local')

    if not out_of_local_keys_chk(localKeyID, True): return False
    localKey        = get_local_enc_key(localKeyID)

    paddedCtrl      = padding(cmdMsg)
    ciphertext      = encrypt(paddedCtrl, localKey)
    localKeyID      = rotLocalKeyID(localKeyID)

    if not out_of_local_keys_chk(localKeyID): return False
    macKey1         = get_local_enc_key(localKeyID)
    localKeyID      = rotLocalKeyID(localKeyID)


    if not out_of_local_keys_chk(localKeyID): return False
    macKey2         = get_local_enc_key(localKeyID)
    localKeyID      = rotLocalKeyID(localKeyID)

    paddedMAC       = GenerateMAC(macKey1, macKey2, ciphertext)

    encoded         = b64e  (ciphertext + paddedMAC)
    crc             = crc32 ( encoded + '|' + str(localKeyID - 3) )
    output_command(encoded, localKeyID - 3, crc)


    if cmdNewTxKF:
        msgKeyID    = newKfTx()

    if not out_of_local_keys_chk(localKeyID): return False
    return True



def quitProcess(output=False):
    os.system('clear')
    if output:
        print 'Exiting TFC'
    if localTesting:
        with open('TxOutput', 'w+') as txout:
            txout.write('exitTFC\n')
    else:
        port.write('exitTFC\n')
    exit()



def print_help():
    ttyW = int(subprocess.check_output(['stty', 'size']).split()[1]) #Scale help output with terminal size

    if ttyW < 65:
        le = '\n' + ttyW * '-'
        print                                                                   le
        print '/about\nDisplay information about TFC'                         + le
        if not emergencyExit:
            print '/clear & \'  \'\nClear screens'                            + le
        if emergencyExit:
            print '\'  \'\nEmergency exit'                                    + le
            print '/clear\nClear screens'                                     + le
        print '/help\nDisplay this list of commands'                          + le
        print '/logging <on/off>\nEnable/disable logging'                     + le
        print '/msg <ID/xmpp/group>\nChange recipient'                        + le
        print '/names\nDisplays available contacts'                           + le
        print '/paste\nEnable paste-mode'                                     + le
        print '/file <filename>\nSend file to recipient'                      + le
        print '/nick <nick>\nChange contact nickname'                         + le
        print '/quit & /exit\nExit TFC'                                       + le
        print '/shift+PgUp/PgDn\nScroll terminal up/dn'                       + le
        print '/group\nList group members'                                    + le
        print '/groups\nList available groups'                                + le
        print '/group <groupname>\nSelect group'                              + le
        print '/group create <groupname> <xmpp1> <xmpp2>\nCreate new group'   + le
        print '/group add <groupname> <xmpp1> <xmpp2>\nAdd xmpp to group'     + le
        print '/group rm <groupname> <xmpp1> <xmpp2>\nRemove xmpp from group' + le
        print '/newkf tx <contactXMPP> 1.kf\nChange keyfile for sending'      + le
        print '/newkf rx <contactXMPP> 1.kf\nChange keyfile for receiving'    + le

    else:
        print       'List of commands:'
        print       ' /about'                                      + 16 * ' ' + 'Show information about software'
        if emergencyExit:
            print   ' /clear'                                      + 16 * ' ' + 'Clear screens'
            print   ' \'  \' (2x spacebar) '                                  + 'Emergency exit'
        else:
            print   ' /clear & \'  \''                             + 9  * ' ' + 'Clear screens'
        print       ' /help'                                       + 17 * ' ' + 'Display this list of commands'
        print       ' /logging <on/off>'                           + 5  * ' ' + 'Enable/disable logging on Rx.py'
        print       ' /msg <ID/xmpp/group>'                        + 2  * ' ' + 'Change recipient (use with /names)'
        print       ' /names'                                      + 16 * ' ' + 'Displays available contacts'
        print       ' /paste'                                      + 16 * ' ' + 'Enable paste-mode'
        print       ' /file <filename>'                            + 6  * ' ' + 'Send file to recipient'
        print       ' /nick <nick>'                                + 10 * ' ' + 'Change contact\'s nickname on Tx.py & Rx.py'
        print       ' /quit & /exit'                               + 9  * ' ' + 'Exits TFC'
        print       ' shift + PgUp/PgDn'                           + 5  * ' ' + 'Scroll terminal up/down'
        print       ' /group'                                      + 16 * ' ' + 'List group members'
        print       ' /groups'                                     + 15 * ' ' + 'List available groups'
        print       ' /group <groupname>'                          + 4  * ' ' + 'Select group\n'
        print       ' /group create <groupname> <xmpp1> <xmpp2>'   + 5  * ' ' + '\n Create new group called <groupname>, add list of xmpp-addresses.\n'
        print       ' /group add <groupname> <xmpp1> <xmpp2>'      + 8  * ' ' + '\n Add xmpp-addresses to group <groupname>\n'
        print       ' /group rm <groupname> <xmpp1> <xmpp2>'       + 8  * ' ' + '\n Remove xmpp-addresses from group <groupname>\n'
        print       ' /newkf tx alice@jabber.org 2.kf\n '          + 31 * '-'
        print       ' Overwrites current key used to encrypt messages sent to'
        print       ' alice@jabber.org. Uses keyfile 2.kf on both TxM and RxM'
        print       ' as new keyfile and resets used key number in contacts.tfc'
        print       ' of both TxM and RxM to their appropriate starting values.\n'
        print       ' /newkf rx alice@jabber.org 3.kf\n '          + 31 * '-'
        print       ' Overwrites current key used to decrypt messages received from'
        print       ' alice@jabber.org. Starts using keyfile 3.kf on RxM to decrypt'
        print       ' further messages and resets key number in RxM\'s contacts.tfc\n'


######################################################################
#                         CONTACT SELECTION                          #
######################################################################

def print_list_of_contacts():
    ttyW        = int(subprocess.check_output(['stty', 'size']).split()[1]) #Get terminal width
    nicks       = []
    for xmpp in entropyfilenames:
        nick    = get_nick(xmpp[:-2])
        nicks.append(nick)
    if  'tx.local' in nicks:
        nicks.remove('tx.local')
    gap         = (len(max(entropyfilenames, key=len))  - 2) - len('XMPP-addr')
    gap2        = (len(max(nicks, key=len))             + 3) - len('Nick')
    header      = 'XMPP-addr' + gap * ' ' + 'ID  Nick' + gap2 * ' ' + 'Msg remaining'
    maxWidth    = len(header)
    if ttyW >= maxWidth:
        print header
        print ttyW * '-'

    for xmpp in entropyfilenames:
        keyid   = get_keyID(xmpp[:-2])
        iD      = entropyfilenames.index(xmpp)
        nick    = get_nick(xmpp[:-2])
        keysRem = str(keys_Rem_chk(xmpp[:-2], keyid) / 3)
        xmpp    = xmpp[:-2][3:]
        if nick != 'tx.local':

            if ttyW < maxWidth:
                print 'XMPP'    + ': ' + (10 -len('XMPP'))    * ' ' + xmpp
                print 'ID'      + ': ' + (10 -len('ID'))      * ' ' + str(iD)
                print 'Nick'    + ': ' + (10 -len('Nick'))    * ' ' + nick
                print 'Msg Rem' + ': ' + (10 -len('Msg Rem')) * ' ' + str(keysRem)
                print ttyW * '-'
                idSelDist = 1
            else:
                dst1 = int(header.index('I')) - len(xmpp)                                              # Dev note: This will cause problems with translations
                dst2 = int(header.index('N')) - len(xmpp) - dst1 - len(str(iD))                        # Try to name header names so that each
                dst3 = int(header.index('s')) - len(xmpp) - dst1 - len(str(iD)) - dst2 - len(nick) - 1 # column will have it's own index letter.
                print xmpp + dst1 * ' ' + str(iD) + dst2 * ' ' + nick + dst3 * ' ' + keysRem
                idSelDist = int(header.index('I'))
    for item in entropyfilenames:
        if (item == 'tx.local.e'):
            localKeyID = get_keyID('tx.local')
            print '\n' + str( keys_Rem_chk('tx.local', localKeyID) / 3 ) + ' commands remaining.'


    return maxWidth, idSelDist # Return values that tell select_contact where to place the cursor for selection



def select_contact(maxWidth, idSelDist, contactNoParameter='', menu=True):
    while True:
        if contactNoParameter == '':
            try:
                ttyW = int(subprocess.check_output(['stty', 'size']).split()[1])
                if ttyW < maxWidth:
                    contactNumber = int(raw_input('\nSelect ID:  '))
                else:
                    contactNumber = int(raw_input('\nSelect contact:' + (idSelDist - len('Select contact') - 1) * ' ') )

                if contactNumber > get_contact_quantity():
                    if menu:
                        os.system('clear')
                        print 'TFC ' + version + '\n\nError: Invalid contact selection\n'
                        print_list_of_contacts()
                        continue
                    else:
                        raise ValueError, 'Invalid number'
            except ValueError:
                if menu:
                    os.system('clear')
                    print 'TFC ' + version + '\n\nError: Invalid contact selection\n'
                    print_list_of_contacts()
                    continue
                else:
                    raise ValueError, 'Invalid number'
            except KeyboardInterrupt:
                os.system('clear')
                print 'Exiting TFC'
                exit()

        else:
            contactNumber   = contactNoParameter

        try:
            entropyfile     = entropyfilenames[contactNumber]
        except IndexError:
            os.system('clear')
            print 'TFC ' + version + '\n\nError: Invalid contact selection\n'
            print_list_of_contacts()
            continue
        xmpp                = entropyfile[:-2]
        nick                = get_nick(xmpp)
        msgKeyID            = get_keyID(xmpp)

        if xmpp == 'tx.local':
            if menu:
                contactNoParameter = ''
                os.system('clear')
                print 'TFC ' + version + '\n\nError: Invalid contact selection\n'
                print_list_of_contacts()
                continue
            else:
                print '\nError: Can\'t select local as contact\n'
                raise ValueError

        return xmpp, nick, msgKeyID



######################################################################
#                              PRE LOOP                              #
######################################################################

ctrlRemaining     = False
pastemode         = False
noMsgkeys_Rem_chk = False
usedCommand       = False
transferringFile  = False

overWriteIteratorCheck()
search_contact_keyfiles()

# Get local.e related data
local_e_available   = search_local_e_kf()
if local_e_available:
    localKey, localKeyID, ctrlRemaining = get_local_enc_values()

# Get contact related data
entropyfilenames, contacts = get_entropy_file_list()
add_new_contacts(entropyfilenames)

# Group related
groupName     = ''
groupFileList = get_group_file_list(False)

# Autotabbing
readline.set_completer(tab_complete)
readline.parse_and_bind('tab: complete')

os.system('clear')
print 'TFC ' + version + 3 * '\n'

# Contact selection
maxWidth, idSelDist  = print_list_of_contacts()
xmpp, nick, msgKeyID = select_contact(maxWidth, idSelDist)



######################################################################
#                                LOOP                                #
######################################################################

os.system('clear')

while True:

    autotabs      = get_autotabs(contacts)
    groupFileList = get_group_file_list(False)

    if pastemode:
        try:
            os.system('clear')
            print 'You\'re now in paste mode:\n2x ^D sends message.\n   ^C exits paste mode.\n'
            print 'paste content to ' + nick + ':\n'
            inPt = sys.stdin.readlines()
            kb   = '\n' + ''.join(inPt)
            print '\nSending...'
            sleep(0.1)

        except KeyboardInterrupt:
            pastemode = False
            kb        = ''
            print 'Exiting paste mode...'
            sleep(0.5)
            os.system('clear')
            continue

    if not pastemode:
        try:
            kb = raw_input(' msg to ' + nick + ': ' )
        except KeyboardInterrupt:
            os.system('clear')
            print 'Exiting TFC'
            exit()

    usedCommand = True  # First we assume that input was a command



    ##################################################################
    #                       LOCAL GROUP COMMANDS                     #
    ##################################################################

    # List group members
    if (kb in ['/group', '/group ']):
        if (groupName == ''):
            print '\nNo group selected\n'
            continue
        activeGroup = get_group_members(groupName)
        if activeGroup:
            os.system('clear')
            print '\nMembers of selected group \'' + groupName + '\':'
            for member in activeGroup:
                print '   ' + member
            print ''
        continue


    # List available groups
    if (kb == '/groups'):
        groupFileList = get_group_file_list(True)
        if groupFileList:
            os.system('clear')
            print '\nAvailable groups are: '
            for group in groupFileList:
                print '   ' + group
        print ''
        continue


    # Create new group
    if kb.startswith('/group create '):
        while kb.endswith(' '):
            kb = kb[:-1]

        # Group can't have same name as command or contact nick
        reservedNames = ['create', 'add', 'rm']
        for addr in entropyfilenames:
            member = get_nick(addr[:-2])
            reservedNames.append(member)

        # Check that group name is not reserved or empty
        newGroupName = kb.split(' ')[2]
        if (newGroupName == ''):
            print '\nError: Group name can\'t be empty\n'
            continue
        if newGroupName in reservedNames:
            print '\nError: Reserved string as group name\n'
            continue

        # Iterate through contacts to be added
        members = []
        i       = 3
        os.system('clear')
        while i <= (len(kb.split(' ')) - 1):
            newMember = kb.split(' ')[i]
            i += 1
            mbrFile = 'tx.' + newMember + '.e'
            if (mbrFile in ['tx.local.e', 'rx.local.e']) or mbrFile not in entropyfilenames:
                print '\nError: Contact \'' + newMember + '\' was not accepted to group ' + newGroupName + '\n'
                continue
            members.append(newMember)

        # Print information about creating
        if create_group_list(newGroupName, members):
            if members:
                print '\nCreated group \'' + newGroupName + '\' with following members:'
                for member in members:
                    if (member != ''):
                        print '   ' + member
            else:
                print '\nCreated group ' + newGroupName
            print ''
            continue
        else:
            print '\nGroup generation cancelled\n'
            continue


    # Add member to group
    if kb.startswith('/group add '):
        while kb.endswith(' '):
            kb    = kb[:-1]
        usedGroup = kb.split(' ')[2]
        if not usedGroup in groupFileList:
            print '\nError: Invalid group\n'
            continue
        xmppList = []
        i        = 3
        os.system('clear')
        while i <= (len(kb.split(' ')) - 1):
            member = kb.split(' ')[i]
            i += 1
            mbrFile = 'tx.' + member + '.e'
            if (mbrFile in ['tx.local', 'rx.local']) or mbrFile not in entropyfilenames:
                print '\nError: Contact \'' + member + '\' was not accepted to group ' + usedGroup + '\n'
                continue
            xmppList.append(member)
        add_to_groupList(usedGroup, xmppList)
        continue


    # Remove member from group
    if kb.startswith('/group rm '):
        usedGroup = kb.split(' ')[2]
        if not usedGroup in groupFileList:
            print '\nError: Invalid group\n'
            continue
        rmList = []
        i      = 3
        while i <= (len(kb.split(' ')) - 1):
            member = kb.split(' ')[i]
            i += 1
            rmList.append(member)
        os.system('clear')

        rem_from_groupList(usedGroup, rmList)
        print ''
        continue


    # Select group
    if kb.startswith('/group '):
        groupName = kb.split(' ')[1]
        if not groupName in groupFileList:
            print '\nError: Invalid group\n'
            groupName = ''
            continue
        else:
            nick = groupName
            os.system('clear')
            print 'Now sending messages to ' + nick + '\n'
            continue



    ##################################################################
    #                      OTHER LOCAL COMMANDS                      #
    ##################################################################

    if emergencyExit:
        if (kb == '  '):
            quitProcess(False)


    if (kb == '  ' or kb == '/clear'):
        os.system('clear')
        if localTesting:
            with open('TxOutput', 'w+') as txout:
                txout.write('clearScreen ' + xmpp + '\n')
                if debugging:
                    print 'Writing command \'clearScreen ' + xmpp + ' to file \'TxOutput\''
            continue

        else:
            port.write('clearScreen ' + xmpp + '\n')
            if debugging:
                print 'Sending command \'clearScreen ' + xmpp + '\' to NH'
            continue


    if (kb == '/quit' or kb == '/exit'):
        quitProcess(True)


    if (kb == ''):
        continue


    if (kb == '/help'):
        os.system('clear')
        print_help()
        continue


    if (kb == '/paste'):
        pastemode = True
        continue


    if (kb == '/about'):
        os.system('clear')
        print ' Tinfoil Chat ' + version + '\n'
        print ' https://github.com/maqp/tfc\n'
        print ' cs.helsinki.fi/u/oottela/TFC.pdf'
        print '                         /TFC-manual.pdf\n\n'
        continue


    if (kb == '/names'):
        os.system('clear')
        print ''
        print_list_of_contacts()
        print ''
        continue


    if kb.startswith('/msg '):
        try:
            selection     = kb.split(' ')[1]
            if selection in groupFileList:
                groupName = nick = selection
                os.system('clear')
                print 'Now sending messages to ' + nick + '\n'
                continue

            if selection in contacts:
                if (selection != 'local'):
                    xmpp = 'tx.' + selection
                    nick = get_nick(xmpp)
                    os.system('clear')
                    print 'Now sending messages to ' + nick + ' (' + xmpp[3:] + ')'
                    continue

            else:
                try:
                    selection    = int(selection)
                    if selection > get_contact_quantity() or selection < 0:
                        print '\nError: Invalid contact selection\n'
                        continue
                    else:
                        try:
                            xmpp, nick, msgKeyID = select_contact(maxWidth, idSelDist, selection, False)
                        except ValueError:
                            continue
                except ValueError:
                    print '\nError: Invalid contact selection\n'
                    continue
                except IOError:
                    print '\nstdIOError, please try again\n'
                    continue

                os.system('clear')
                ps1  = 'Now sending messages to ' + nick
                ps2  = ' (' + xmpp[3:] + ')\n'
                ttyW = int(subprocess.check_output(['stty', 'size']).split()[1])
                if len(ps1 + ps2) <= ttyW:
                    print ps1 + ps2
                else:
                    print ps1 + '\n' + ps2

                continue
        except AttributeError:
            pass



    ##################################################################
    ##                      COMMANDS TO RX.py                       ##
    ##################################################################

    if kb.startswith('/nick ') or kb.startswith('/logging ') or kb.startswith('/newkf '):
        cmdMsg      = ''
        cmdLogging  = False
        cmdNick     = False
        cmdNewTxKF  = False

        if not local_e_available:
            print 'Error: tx.local.e was not found'
            continue

        if ctrlRemaining:
            if kb.startswith('/nick '):
                if nick in groupFileList:
                    print '\nGroup is selected, no nick was changed\n'
                    continue

                if (len(kb) < 7):
                    print 'Error: Can\'t give empty nick'
                    continue

                newNick = kb.split(' ')[1]
                if '=' in newNick or '/' in newNick:
                    print '\nError: Nick can not contain reserved characters / or =\n'
                    continue
                if (newNick == 'tx.local') or (newNick == 'rx.local'):
                    print '\nError: Can\'t give reserved nick of local.e to contact\n'
                    continue
                if (newNick in groupFileList):
                    print '\nError: Nick is in use for group\n'
                    continue

                write_nick(xmpp, newNick)
                nick    = get_nick(xmpp)

                os.system('clear')
                print 'Changed contact\'s nick to ' + nick
                cmdMsg  = xmpp + '/nick=' + nick

            if kb.startswith('/logging '):
                ok    = False
                value = str(kb.split(' ')[1])
                if value  == 'on':
                    cmdMsg = 'logson'
                    ok     = True
                if value  == 'off':
                    cmdMsg = 'logsoff'
                    ok     = True
                if not ok:
                    print '\nError: Invalid command\n'
                    continue

            if kb.startswith('/newkf '):
                try:
                    commandlist = kb.split(' ')
                    cmdtype     = commandlist[1]
                    contactXmpp = 'tx.' + commandlist[2]
                    if (contactXmpp == 'tx.local'):
                        print 'Error: Can\'t select local keyfile'
                        continue

                    keyFileName = commandlist[3]
                    entFile     = contactXmpp + '.e'
                    if (cmdtype != 'tx') and (cmdtype != 'rx'):
                        print 'Error: Invalid command' + cmdtype
                        continue

                    if (cmdtype == 'tx'):
                        if entFile in entropyfilenames:
                            print '\nWARNING! Change of keyfile will irreversably'
                            print 'destroy original keyfile ' + contactXmpp + '.e'
                            print 'on TxM and me.' + contactXmpp[3:] + '.e on RxM!'

                            if (raw_input('\nAre you sure? Type uppercase \'YES\' to continue: ' ) == 'YES'):
                                cmdNewTxKF = True
                                cmdMsg     = 'tfckf me.' + contactXmpp[3:] + ' me.' + keyFileName
                                print '\nTxM > RxM: Shred keyfile me.' + contactXmpp[3:] + '.e and start using \'me.' + keyFileName + '\''
                            else:
                                print 'Keyfile change aborted\n'
                                continue
                        else:
                            print 'Error: Contact \'' + contactXmpp[3:] + '\' is not listed'
                            continue


                    if (cmdtype == 'rx'):
                        if entFile in entropyfilenames:
                            print '\nWARNING! Change of keyfile will irreversably'
                            print 'destroy original keyfile rx.' + contactXmpp[3:] + '.e on RxM!'

                            if (raw_input('\nAre you sure? Type uppercase \'YES\' to continue: ' ) == 'YES'):
                                cmdMsg = 'tfckf ' + contactXmpp[3:] + ' rx.' + keyFileName
                                print '\nTxM > RxM: Shred keyfile rx.' + contactXmpp[3:] + '.e and start using rx.' + keyFileName
                            else:
                                print 'Keyfile change aborted\n'
                                continue
                        else:
                            print 'Error: Contact \'' + contactXmpp + '\' is not listed'
                            continue


                except IndexError:
                    print 'Error: Invalid command'
                    continue

        else:
            print '\nNo local keys remaining\n'
            continue



        ##############################################################
        #                        COMMAND PACKET                      #
        ##############################################################

        if not commandMessageProcess(cmdMsg):
            ctrlRemaining = False
        continue



    ##############################################################
    ##                     FILE TRANSMISSION                    ##
    ##############################################################

    usedCommand = False     # If we reach this point, we know a command was not used

    if kb.startswith('/file '):
        fname = kb.split(' ')[1]
        if nick in groupFileList:
            sendTarget = 'all members of group' + nick
        else:
            sendTarget = xmpp[3:]
        if raw_input('\nThis will send file \'' + fname + '\' to ' + sendTarget + '.\nAre you sure? Type upper case YES to continue: ') == 'YES':
            print ''
            subprocess.Popen('base64 ' + fname + ' > TFCtmpFile', shell=True).wait()

            with open('TFCtmpFile', 'r') as mFile:
                fileContent = mFile.readlines()
                fileMessage = ''
                for filePart in fileContent:
                    fileMessage = fileMessage + filePart

            kb = 'TFCFILE' + fileMessage
            subprocess.Popen('shred -n ' + str(kfOWIterations) + ' -z -u TFCtmpFile', shell=True).wait()
        else:
            print '\nFile sending aborted\n'
            continue



    ##############################################################
    ##                      GROUP MESSAGING                     ##
    ##############################################################

    if nick in groupFileList:

        activeGroup = get_group_members(groupName)
        print ''
        for item in activeGroup:
            print 'Sending message to ' + item
            xmpp = 'tx.' + item

            if len(kb) > (maxMsgLen - 3):
                if not longMessageProcess(kb, xmpp):
                    continue
            else:
                if not shortMessageProcess(kb, xmpp):
                    continue
                sleep(0.1)
                print ''



    ##############################################################
    ##                 SINGLE RECIPIENT MESSAGING               ##
    ##############################################################

    else:

        if len(kb) > (maxMsgLen - 3):
            if not longMessageProcess(kb, xmpp):
                continue

        else:
            if not shortMessageProcess(kb, xmpp):
                continue


