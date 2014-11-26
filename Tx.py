#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binascii
import csv
import math
import os
import random
import readline
import serial
import subprocess
import sys
from time import sleep



######################################################################
#                             LICENCE                                #
######################################################################

# TFC (OTP Version) || Tx.py
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
#                            CONFIGURATION                           #
######################################################################


PkgSize            = 140
keyThreshold       = 5
maxSleepTime       = 13
shredIterations    = 3
keyOWIterations    = 3
lMsgSleep          = 0.2

debugging          = False
emergencyExit      = False
checkKeyHashes     = False
randomSleep        = False
localTesting       = True


if not localTesting:
    port        = serial.Serial('/dev/ttyAMA0', baudrate=9600, timeout=0.1)



######################################################################
#                       KECCAK HASH FUNCTION                         #
######################################################################

"""
Algorithm Name: Keccak

Authors: Guido Bertoni, Joan Daemen, Michael Peeters and Gilles
Van Assche Implementation by Renaud Bauvin, STMicroelectronics

This code, originally by Renaud Bauvin, is hereby put in the public
domain. It is given as is, without any guarantee.

For more information, feedback or questions, please refer to our
website: http://keccak.noekeon.org/
"""



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



def keccak_256(hashInput):
    hexMsg = binascii.hexlify(hashInput)
    return Keccak().Keccak(((8 * len(hashInput)), hexMsg), 1088, 512, 0, 256, 0)



######################################################################
#                         CRYPTOGRAPHY RELATED                       #
######################################################################

def otp_encrypt(plaintext, key):
    if len(plaintext) == len(key):
        return ''.join(chr(ord(ptChar) ^ ord(keyChar)) for ptChar, keyChar in zip(plaintext, key))
    else:
        exit_with_msg('CRITICAL ERROR! Ciphertext - key length mismatch.')



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


    # Add padding for MAC.
    MAC = padding(MAC)

    if debugging:
        print '\nFinished MAC:\n"' + MAC + '"\n\n'

    return MAC



######################################################################
#                    ENCRYPTION AND KEY MANAGEMENT                   #
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


        # Verify key has not been used before.
        if checkKeyHashes:
            if key_blacklist_chk(entropy, xmpp):
                exit_with_msg('CRITICAL ERROR: Key hash on blacklist.')


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



def encrypt(xmpp, pt):

    keyID  = get_keyID(xmpp)
    keySet = get_keyset(xmpp, keyID, True)

    ct     = otp_encrypt(pt, keySet[0])
    tag    = one_time_mac(keySet[1], keySet[2], ct)

    overwrite_enc_key(xmpp, keyID)
    write_keyID(xmpp, keyID + 1)

    return ct + tag



def new_keyfile():

    print 'Shredding keyfile that encrypts messages to ' + contactXmpp
    subprocess.Popen('shred -n ' + str(shredIterations) + ' -z -u ' + 'tx.' + contactXmpp + '.e', shell=True).wait()

    print 'TxM: Replacing the keyfile for ' + contactXmpp + ' with \'' + keyFileName + '\''
    subprocess.Popen('mv ' + keyFileName + ' ' + 'tx.' + contactXmpp + '.e', shell=True).wait()

    print 'TxM: Setting key number to 1 for ' + contactXmpp
    write_keyID('tx.' + contactXmpp, 1)

    print 'TxM: Keyfile successfully changed\n'



def overwrite_enc_key(xmpp, keyID):

    # Store hash of key to blacklist.
    if checkKeyHashes:
        if debugging:
            print 'M(overwrite_enc_key): Loading key for hash writing\n'
        key = get_keyset(xmpp, keyID, False)
        write_used_key_hash(key)


    # Verify that keyID is positive.
    if keyID < 1:
        exit_with_msg('CRITICAL ERROR! KeyID was not valid.')

    offset = keyID * PkgSize

    # Display key before overwriting.
    if debugging:
        print 'M(overwrite_enc_key): Overwriting ' + str(PkgSize) + ' bytes from offset ' + str(offset) + ' (keyID ' + str(keyID) + ')\n'
        print 'M(overwrite_enc_key): Hex representation of key before overwriting:'
        subprocess.Popen('hexdump -s' + str(offset) + ' -n ' + str(PkgSize) + ' ' + xmpp + '.e| cut -c 9-', shell=True).wait()

    # Overwrite key.
    i = 0
    while i < keyOWIterations:
        if debugging:
            print 'M(overwrite_enc_key): Overwriting key with random data (iteration ' + str(i + 1) + ')'
        subprocess.Popen('dd if=/dev/urandom of=' + xmpp + '.e bs=1 seek=' + str(offset) + ' count=' + str(PkgSize) + ' conv=notrunc > /dev/null 2>&1', shell=True).wait()
        if debugging:
            print 'M(overwrite_enc_key): Done. Hex-representation of key after overwriting:'
            subprocess.Popen('hexdump -s' + str(offset) + ' -n ' + str(PkgSize) + ' ' + xmpp + '.e| cut -c 9-', shell=True).wait()
        i += 1

    # Overwrite key with '!' chars.
    with open(xmpp + '.e', 'r+') as file:
        file.seek(offset)
        file.write(PkgSize * '!')

        # Verify overwriting.
        file.seek(offset)
        writtenData = file.read(PkgSize)

        while writtenData != (PkgSize * '!'):
            os.system('clear')
            print '\nWARNING! Failed to overwrite key. Retrying...\n'
            file.seek(offset)
            file.write(PkgSize * '!')
            file.seek(offset)
            writtenData = file.read(PkgSize)

    if debugging:
        print 'M(overwrite_enc_key): Overwriting completed.\n'



def write_used_key_hash(key):
    try:
        with open('usedKeys.tfc', 'a+') as file:
            keyHash = keccak_256(key)
            file.write(keyHash + '\n')
        if debugging:
            print '\nM(write_used_key_hash): Wrote following hash to blacklist usedKeys.tfc\n' + keyHash + '\n'

    except IOError:
        exit_with_msg('ERROR! usedKeys.tfc could not be loaded.')



######################################################################
#                        txc.tfc MANAGEMENT                          #
######################################################################

def add_contact(nick, xmpp):
    try:
        with open('txc.tfc', 'a+') as file:
                file.write(nick + ',' + xmpp + ',1\n')

        if debugging:
            print '\nM(add_contact): Added contact ' + nick + ' (xmpp = ' + xmpp + ') to txc.tfc\n'

    except IOError:
        exit_with_msg('ERROR! txc.tfc could not be loaded.')



def write_nick(xmpp, nick):
    try:
        contacts = []

        with open ('txc.tfc', 'r') as file:
            csvData = csv.reader(file)

            for row in csvData:
                contacts.append(row)

        nickChanged = False

        for i in range( len(contacts) ):
            if contacts[i][1] == xmpp:
                contacts[i][0] = nick
                nickChanged = True

        if not nickChanged:
            exit_with_msg('ERROR! Could not find XMPP\n' + xmpp + ' from txc.tfc.')


        with open('txc.tfc', 'w') as file:
            writer = csv.writer(file)
            writer.writerows(contacts)

        if debugging:
            print '\nM(write_nick):\nWrote nick ' + nick + ' for account ' + xmpp + ' to txc.tfc\n'

    except IOError:
        exit_with_msg('ERROR! txc.tfc could not be loaded.')



def get_nick(xmpp):
    try:
        contacts = []

        with open('txc.tfc', 'r') as file:
            csvData = csv.reader(file)

            for row in csvData:
                contacts.append(row)

        for i in range( len(contacts) ):
            if contacts[i][1] == xmpp:
                nick = contacts[i][0]
                return nick

        exit_with_msg('ERROR! Failed to load nick for contact.')

    except IOError:
        exit_with_msg('ERROR! txc.tfc could not be loaded.')



def write_keyID(xmpp, keyID):
    try:
        contacts = []

        with open('txc.tfc', 'r') as file:
            csvData = csv.reader(file)

            for row in csvData:
                contacts.append(row)

        keyIDChanged = False

        for i in range(len(contacts)):
            if contacts[i][1] == xmpp:
                contacts[i][2] = keyID
                keyIDChanged   = True

        if not keyIDChanged:
            exit_with_msg('ERROR! Could not find ' + xmpp + ' from txc.tfc.')

        with open('txc.tfc', 'w') as file:
            writer = csv.writer(file)
            writer.writerows(contacts)

        # Verify keyID has been properly written.
        newStoredKey = get_keyID(xmpp)
        if keyID != newStoredKey:
            exit_with_msg('CRITICAL ERROR! KeyID was not properly stored.')


        if debugging:
            print '\nM(write_keyID): Wrote line \'' + str(keyID) + '\' for contact ' + xmpp + ' to txc.tfc\n'

    except IOError:
        exit_with_msg('ERROR! txc.tfc could not be loaded.')



def get_keyID(xmpp):
    try:
        contacts = []

        with open('txc.tfc', 'r') as file:
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
            exit_with_msg('ERROR! Failed to load valid keyID for ' + xmpp + '.')

    except ValueError:
        exit_with_msg('ERROR! Failed to load valid keyID for ' + xmpp + '.')

    except IOError:
        exit_with_msg('ERROR! txc.tfc could not be loaded. Exiting.')



def add_keyfiles(keyFileNames):
    try:
        contacts = []

        with open('txc.tfc', 'a+') as file:
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
                    add_contact('tx.local', 'tx.local')

                else:
                    os.system('clear')
                    print 'TFC ' + version + ' || Tx.py' + '\n'
                    newNick = raw_input('New contact ' + xmpp[3:] + ' found. Enter nick: ')
                    add_contact(newNick, xmpp)

    except IOError:
        exit_with_msg('ERROR! txc.tfc could not be loaded.')



######################################################################
#                             GETTERS                                #
######################################################################

def get_keyfile_list():
    keyFileList     = []
    xmppAddressList = []

    for file in os.listdir('.'):
        if file.endswith('.e'):
            if not file.startswith('me.') and not file.startswith('rx.'):
                keyFileList.append(file)
                xmppAddressList.append(file[3:][:-2])
    return keyFileList, xmppAddressList



def get_contact_quantity():
    try:
        with open('txc.tfc', 'r') as file:
            for i, l in enumerate(file):
                pass

            for line in file:
                    if 'tx.local' in line:
                        return i
        return i + 1

    except IOError:
        exit_with_msg('ERROR! txc.tfc could not be loaded.')



def get_autotabs(contacts):

    autoTabs = []

    # Add contacts to autoTabs.
    for contact in contacts:
        autoTabs.append(contact + ' ')

    # Add group names to autoTabs.
    gFileList = get_group_list(False)
    for gFile in gFileList:
        autoTabs.append(gFile + ' ')

    # Add commands to autoTabs.
    cList = ['about' , 'add '  , 'clear', 'create ' , 'exit',
             'file ' , 'group ', 'help' , 'logging ', 'msg ',
             'newkf ', 'nick ' , 'quit' , 'rm '     , 'select ']

    for command in cList:
        autoTabs.append(command)

    return autoTabs



def get_terminal_width():
    return int(subprocess.check_output(['stty', 'size']).split()[1])



def print_kf_status(xmpp, keyID, outputKeys=False):

    keysLeft = count_remaining_keys(xmpp)

    if debugging:
        if xmpp == 'tx.local':
            print '\nM(print_kf_status): ' + str(msgLeft - 1) + ' command(s) remaining\n'
        else:
            print '\nM(print_kf_status): ' + str(msgLeft - 1) + ' messages(s) remaining\n'


    notifyList = [100, 50, 40, 30, 20, 10, 5, 4, 3, 2, 1]
    if outputKeys:
        if keysLeft in notifyList:
            if xmpp == 'tx.local':
                print 'Commands remaining: ' + str(msgLeft - 1)
            else:
                print 'Messages remaining: ' + str(msgLeft - 1)



def count_remaining_keys(xmpp):

    keyID = get_keyID(xmpp)

    if keyID < 1:
        exit_with_msg('CRITICAL ERROR! KeyID was not valid.')

    offset = keyID * 3 * PkgSize

    with open(xmpp + '.e', 'rb') as file:
        file.seek(offset)
        currentByte = file.tell()
        file.seek(0, 2)
        length   = (file.tell() - 1)
        bytesRem = length - currentByte

    remainingKeys = bytesRem / (3 * PkgSize)

    return remainingKeys



######################################################################
#                        CHECKS AND WARNINGS                         #
######################################################################

def search_keyfiles():
    keyfiles  = []
    keyfiles += [each for each in os.listdir('.') if each.endswith('.e')]
    if not keyfiles:
        exit_with_msg('Error: No keyfiles for contacts were found.\n'\
                      'Make sure keyfiles are in same directory as Tx.py.')



def key_blacklist_chk(key, xmpp):
    try:
        keyHash = keccak_256(key)
        with open('usedKeys.tfc', 'a+') as file:
            for line in file:
                if keyHash in line:
                    return True
                else:
                    if debugging:
                        print 'M(key_blacklist_chk):\nKey was not blacklisted'
                    return False
    except IOError:
        exit_with_msg('ERROR! usedKeys.tfc could not be loaded.')



def overWriteIteratorCheck():
    if keyOWIterations < 1:
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
FROM PRE-LOOP OF Tx.py TO DISABLE THIS WARNING.

EXITING Tx.py'''
        exit()



######################################################################
#                           MSG PROCESSING                           #
######################################################################

def b64e(content):
    import base64
    return base64.b64encode(content)



def crc32(content):
    import zlib
    return str(hex(zlib.crc32(content)))



def padding(string):
    length  = PkgSize - (len(string) % PkgSize)
    string += length * chr(length)

    if debugging:
        print '\nM(padding): Padded input to length of '+ str(len(string)) +' chars:\n"' + string + '"\n'

    return string



######################################################################
#                         MESSAGE TRANSMISSION                       #
######################################################################

def long_msg_preprocess(string):

    string = string.strip('\n')
    msgA   = [string[i:i + (PkgSize - 2)] for i in range(0, len(string), (PkgSize - 2) )] # Each packet is left one char shorter than padding to prevent dummy blocks.

    for i in xrange( len(msgA) ):          # Add 'a' in front of every packet.
        msgA[i] = 'a' + msgA[i]            # 'a' tells Rx.py the message should be appended to long message.

                                           # Replace 'a' with 'e' in last packet.
    msgA[-1] = 'e' + msgA[-1][1:]          # 'e' tells Rx.py the message is last one of long message, so Rx.py knows it must show the entire long message.

                                           # Replace 'a' with 'l' in first packet.
    msgA[0]  = 'l' + msgA[0][1:]           # 'l' tells Rx.py the message extends over multiple packets.

    if debugging:
        print 'M(long_msg_preprocess): Processed long message to following packets:'
        for item in msgA:
            print '"' + item + '"'

    return msgA



def long_msg_process(userInput, xmpp):

    packetList = long_msg_preprocess(userInput)

    print '\nTransferring message in ' + str(len(packetList)) + ' parts. ^C cancels'

    halt = False

    # Check that enough key data is remaining.
    if count_remaining_keys(xmpp) < len(packetList):
        os.system('clear')
        print '\nError: Not enough key data remaining. Message could not be sent to ' + xmpp + '\n'
        return None

    for packet in packetList:

        if halt:
            os.system('clear')
            if userInput.startswith('TFCFILE'):
                print '\nFile transmission interrupted by user.\n'
            else:
                print '\nMessage transmission interrupted by user.\n'
            return None

        try:
            keyID     = get_keyID(xmpp)

            paddedMsg = padding(packet)
            ctWithTag = encrypt(xmpp, paddedMsg)

            encoded   = b64e(ctWithTag)
            checksum  = crc32(encoded + '|' + str(keyID))


            output_message(xmpp, encoded, keyID, checksum)

            if randomSleep:
                sleepTime = random.uniform(0, maxSleepTime)
                print 'Sleeping ' + str(sleepTime) + ' seconds to obfuscate long message.'
                sleep(sleepTime)

            # Minimum sleep time ensures XMPP server is not flooded.
            sleep(lMsgSleep)

        except KeyboardInterrupt:
            halt = True



def short_msg_process(plaintext, xmpp):

    if count_remaining_keys(xmpp) < 1:
        os.system('clear')
        print '\nError: All keys to send messages to ' + xmpp + ' have been used.\n'
        return None

    keyID     = get_keyID(xmpp)

    paddedMsg = padding('s' + plaintext) # 's' tells Rx.py the message is only one packet long.
    ctWithTag = encrypt(xmpp, paddedMsg)

    encoded  = b64e(ctWithTag)
    checksum = crc32(encoded + '|' + str(keyID))

    output_message(xmpp, encoded, keyID, checksum)



def cmd_msg_process(command):

    keyID     = get_keyID('tx.local')

    paddedCmd = padding(command)
    ctWithTag = encrypt('tx.local', paddedCmd)

    encoded   = b64e(ctWithTag)
    checksum  = crc32(encoded + '|' + str(keyID))

    output_command(encoded, keyID, checksum)



def quit_process(output = False):
    os.system('clear')
    if output:
        print '\nExiting TFC\n'
    if localTesting:
        with open('TxOutput', 'w+') as file:
            file.write('exitTFC\n')
    else:
        port.write('exitTFC\n')
    exit()



def output_command(base64msg, line, checksum):
    if localTesting:
        with open('TxOutput', 'w+') as file:
            file.write(                            '<ctrl>'                            + base64msg + '|' + str(line) + '~' + checksum + '\n')
        if debugging:
            print '\nM(output_command): Cmd to NH:\n<ctrl>'                            + base64msg + '|' + str(line) + '~' + checksum + '\n\n'

    else:
        port.write(                                '<ctrl>'                            + base64msg + '|' + str(line) + '~' + checksum + '\n')
        if debugging:
            print '\nM(output_command): Cmd to NH:\n<ctrl>'                            + base64msg + '|' + str(line) + '~' + checksum + '\n\n'



def output_message(xmpp, base64msg, line, checksum):
    if localTesting:
        with open('TxOutput', 'w+') as file:
            file.write(                            '<mesg>' + xmpp[3:] + '~' + '?TFC_' + base64msg + '|' + str(line) + '~' + checksum + '\n')
        if debugging:
            print '\nM(output_message): Msg to NH:\n<mesg>' + xmpp     + '~' + '?TFC_' + base64msg + '|' + str(line) + '~' + checksum + '\n\n'

    else:
        port.write(                                '<mesg>' + xmpp[3:] + '~' + '?TFC_' + base64msg + '|' + str(line) + '~' + checksum + '\n')
        if debugging:
            print '\nM(output_message): Msg to NH:\n<mesg>' + xmpp     + '~' + '?TFC_' + base64msg + '|' + str(line) + '~' + checksum + '\n\n'



######################################################################
#                       COMMANDS AND FUNCTIONS                       #
######################################################################

def tab_complete(text, state):
    options = [x for x in autotabs if x.startswith(text)]
    try:
        return options[state]
    except IndexError:
        return None



def print_help():
    ttyW = get_terminal_width()

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
        print '/group\nList group members'                                    + le
        print '/groups\nList available groups'                                + le
        print '/group <groupname>\nSelect group'                              + le
        print '/group create <groupname> <xmpp1> <xmpp2>\nCreate new group'   + le
        print '/group add <groupname> <xmpp1> <xmpp2>\nAdd xmpp to group'     + le
        print '/group rm <groupname> <xmpp1> <xmpp2>\nRemove xmpp from group' + le
        print '/shift + PgUp/PgDn\nScroll terminal up/dn'                       + le
        print '/newkf tx <contactXMPP> 1.kf\nChange keyfile for sending'      + le
        print '/newkf rx <contactXMPP> 1.kf\nChange keyfile for receiving'    + le
        print ''

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
        print       ' shift + PgUp/PgDn'                           + 5  * ' ' + 'Scroll terminal up/down\n'

        print       ' /newkf tx alice@jabber.org 2.kf\n '          + 31 * '-'
        print       ' Overwrites current key used to encrypt messages sent to\n'  \
                    ' alice@jabber.org. Uses keyfile 2.kf on both TxM and RxM\n'  \
                    ' as new keyfile and resets used key number in contacts.tfc\n'\
                    ' of both TxM and RxM to their appropriate starting values.\n\n'

        print       ' /newkf rx alice@jabber.org 3.kf\n '          + 31 * '-'
        print       ' Overwrites current key used to decrypt messages received from\n'\
                    ' alice@jabber.org. Starts using keyfile 3.kf on RxM to decrypt\n'\
                    ' further messages and resets key number in RxM\'s contacts.tfc\n'



def print_list_of_contacts():
    ttyW        = get_terminal_width()

    headerList  = ['XMPP-addr', 'ID', 'Nick', 'Msg remaining']
    cShortList  = ['XMPP', 'ID', 'Nick', 'Msg rem']

    nicks       = []
    for xmpp in keyFileNames:
        nick    = get_nick(xmpp[:-2])
        nicks.append(nick)
    if  'tx.local' in nicks:
        nicks.remove('tx.local')

    gap1      = (len(max(keyFileNames, key=len)) - 2) - len(headerList[0])
    gap2      = (len(max(nicks, key=len))            + 3) - len(headerList[2])
    header    = headerList[0] + gap1 * ' ' + headerList[1] + '  ' + headerList[2] + gap2 * ' ' + headerList[3]
    headerLen = len(header)

    if ttyW >= headerLen:
        print header
        print ttyW * '-'

    for xmpp in keyFileNames:
        iD      = keyFileNames.index(xmpp)
        nick    = get_nick(xmpp[:-2])
        keysRem = str(count_remaining_keys(xmpp[:-2]))
        xmpp    = xmpp[:-2][3:]
        if nick != 'tx.local':

            if ttyW < headerLen:
                print cShortList[0] + ': ' + (10 -len(cShortList[0])) * ' ' + xmpp
                print cShortList[1] + ': ' + (10 -len(cShortList[1])) * ' ' + str(iD)
                print cShortList[2] + ': ' + (10 -len(cShortList[2])) * ' ' + nick
                print cShortList[3] + ': ' + (10 -len(cShortList[3])) * ' ' + str(keysRem)
                print ttyW * '-'
                idSelDist = 1

            else:
                dst1 = int(header.index(cShortList[1][0])) - len(xmpp)                                              # Dev note: This will cause problems with translations
                dst2 = int(header.index(cShortList[2][0])) - len(xmpp) - dst1 - len(str(iD))                        # Try to name header names so that each
                dst3 = int(header.index(cShortList[3][1])) - len(xmpp) - dst1 - len(str(iD)) - dst2 - len(nick) - 1 # column will have it's own index letter.
                print xmpp + dst1 * ' ' + str(iD) + dst2 * ' ' + nick + dst3 * ' ' + keysRem
                idSelDist = int(header.index(cShortList[1][0]))

    for item in keyFileNames:
        if item == 'tx.local.e':
            print '\n' + str(count_remaining_keys('tx.local')) + ' commands remaining.'

    return headerLen, idSelDist



def select_contact(maxWidth='', idSelDist='', contactNo='', menu=True):

    contactSelected = False
    while not contactSelected:
        try:
            # If no parameter about contact selection is passed to function, ask for input
            if contactNo == '':
                ttyW = int(subprocess.check_output(['stty', 'size']).split()[1])
                if ttyW < maxWidth:
                    selection = raw_input('\nSelect ID:  ')
                else:
                    selection = raw_input('\nSelect contact:' + (idSelDist - len('Select contact') - 1) * ' ')

                intSelection = int(selection)
            else:
                intSelection = int(contactNo)


        # Error handling if selection was not a number.
        except ValueError:
            if menu:
                os.system('clear')
                print 'TFC ' + version + ' || Tx.py' + '\n\nError: Invalid contact selection \'' + selection + '\'\n'
                print_list_of_contacts()
                continue
            else:
                raise ValueError, 'Invalid number'


        # Clean exit.
        except KeyboardInterrupt:
            exit_with_msg('Exiting TFC.', False)


        # Check that integer is within allowed bounds.
        if (intSelection < 0) or (intSelection > get_contact_quantity()):
            if menu:
                os.system('clear')
                print 'TFC ' + version + ' || Tx.py' + '\n\nError: Invalid contact selection \'' + selection + '\'\n'
                print_list_of_contacts()
                continue
            else:
                raise ValueError, 'Invalid number'


        # Check that selction number was valid.
        try:
            keyFile = keyFileNames[intSelection]
        except IndexError:
            if menu:
                os.system('clear')
                print 'TFC ' + version + ' || Tx.py' + '\n\nError: Invalid contact selection \'' + selection + '\'\n'
                print_list_of_contacts()
                continue
            else:
                print '\nError: Invalid contact selection\n'

        xmpp = keyFile[:-2]
        nick = get_nick(xmpp)


        # Check that user has not selected local contact.
        if xmpp == 'tx.local':
            if menu:
                contactNo = ''
                os.system('clear')
                print 'TFC ' + version + ' || Tx.py' + '\n\nError: Invalid contact selection \'' + selection + '\'\n'
                print_list_of_contacts()
                continue
            else:
                raise ValueError, 'Invalid number'

        contactSelected = True

    return xmpp, nick



def exit_with_msg(message, error=True):
    os.system('clear')
    if error:
        print '\n' + message + ' Exiting.\n'
    else:
        print '\n' + message + '\n'
    exit()



######################################################################
#                          GROUP MANAGEMENT                          #
######################################################################

def group_create(groupName, newMembers = []):

    if os.path.isfile('g.' + groupName + '.tfc'):
        if not (raw_input('Group \'' + groupName + '\' already exists. Type YES to overwrite: ') == 'YES'):
            return False

    with open('g.' + groupName + '.tfc', 'w+') as file:
        if newMembers:
            for user in newMembers:
                file.write(user + '\n')
            sort_group(groupName)
        else:
            pass

    return True



def group_add_member(groupName, addList):
    try:
        gFile    = []
        existing = []
        added    = []
        unknown  = []

        with open('g.' + groupName + '.tfc', 'a+') as file:
            groupFile = file.readlines()

            for contact in groupFile:
                gFile.append(contact.strip('\n'))

            for member in addList:
                member   = member.strip('\n').strip(' ')
                memberKf = 'tx.' + member + '.e'

                if member in gFile:
                    existing.append(member)

                else:
                    if memberKf in keyFileNames:
                        file.write(member + '\n')
                        added.append(member)

                    else:
                        unknown.append(member)

            os.system('clear')

            if added:
                print 'Members added to group \'' + groupName + '\':'
                for member in added:
                    print '   ' + member
                print '\n'

                sort_group(groupName)

            if unknown:
                print 'Unknown contacts not added to group \'' + groupName + '\':'
                for member in unknown:
                    print '   ' + member
                print '\n'

            if existing:
                print 'Already existing users in group \'' + groupName + '\':'
                for member in existing:
                    print '   ' + member
                print '\n'

    except IOError:
        exit_with_msg('ERROR! Group file g.' + groupName + '.tfc could not be loaded.')



def group_rm_member(groupName, rmList):
    try:
        memberList = []
        removed    = []
        unknown    = []

        with open('g.' + groupName + '.tfc', 'r') as file:
            groupFile = file.readlines()

        for member in groupFile:
            member = member.strip('\n')
            memberList.append(member)

        with open('g.' + groupName + '.tfc', 'w') as file:
            for member in memberList:
                if member in rmList:
                    removed.append(member)
                else:
                    file.write(member + '\n')

        for member in rmList:
            if member not in memberList:
                unknown.append(member)

        os.system('clear')

        if removed:
            print 'Members removed from group \'' + groupName + '\':'
            for member in removed:
                print '   ' + member
        else:
            print 'Nothing removed from group \'' + groupName + '\':'

        if unknown:
            print '\n\nUnknown contacts:'
            for member in unknown:
                print '   ' + member

    except IOError:
        exit_with_msg('ERROR! Group file g.' + groupName + '.tfc could not be loaded.')



def sort_group(groupName):
    try:
        with open('g.' + groupName + '.tfc', 'r') as file:
            members = file.readlines()
            members.sort()

        with open('g.' + groupName + '.tfc', 'w') as file:
            for member in members:
                file.write(member)

    except IOError:
        exit_with_msg('ERROR! Group file g.' + selectedGroup + '.tfc could not be loaded.')



def get_group_list(output):
    gFileNames = []
    for file in os.listdir('.'):
        if file.startswith('g.') and file.endswith('.tfc'):
            gFileNames.append(file[2:][:-4])

    if not gFileNames and output:
        print '\nThere are currently no groups.\n'

    return gFileNames



def get_group_members(groupName, output=True):
    try:
        groupList = []

        with open('g.' + groupName + '.tfc', 'r') as file:
            members = file.readlines()

        for member in members:
            groupList.append(member.strip('\n'))

        if not groupList and output:
            print '\nGroup is empty. Add contacts to group with command\n   /group add <group name> <xmpp>\n'

        return groupList

    except IOError:
        exit_with_msg('ERROR! Group file g.' + selectedGroup + '.tfc could not be loaded.')



######################################################################
#                              PRE LOOP                              #
######################################################################

# Set initial values.
os.chdir(sys.path[0])
pastemode     = False
selectedGroup = ''

# Run initial checks.
overWriteIteratorCheck()
search_keyfiles()

# Load initial data.
keyFileNames, contacts = get_keyfile_list()
add_keyfiles(keyFileNames)

# Initialize autotabbing.
readline.set_completer(tab_complete)
readline.parse_and_bind('tab: complete')

os.system('clear')
print 'TFC ' + version + ' || Tx.py ' + 3 * '\n'

# Contact selection.
maxWidth, idSelDist  = print_list_of_contacts()
xmpp, nick = select_contact(maxWidth, idSelDist)



######################################################################
#                                LOOP                                #
######################################################################

os.system('clear')

while True:

    # Refresh lists.
    autotabs      = get_autotabs(contacts)
    groupFileList = get_group_list(False)

    if pastemode:
        try:
            os.system('clear')
            print 'You\'re now in paste mode:\n'\
                  '2x ^D sends message.\n'      \
                  '   ^C exits paste mode.\n'   \
                  'Paste content to ' + nick + ':\n'

            lines     = sys.stdin.readlines()
            userInput = '\n' + ''.join(lines)
            print '\nSending...'
            sleep(0.1)

        except KeyboardInterrupt:
            pastemode = False
            userInput = ''
            print '\nClosing paste mode...'
            sleep(0.4)
            os.system('clear')
            continue

    if not pastemode:
        try:
            userInput = raw_input('Msg to ' + nick + ': ')

        except KeyboardInterrupt:
            exit_with_msg('Exiting TFC.', False)



    ##################################################################
    #                    GROUP MANAGEMENT COMMANDS                   #
    ##################################################################

    # List group members.
    if userInput in ['/group', '/group ']:

        if selectedGroup == '':
            print '\nNo group selected\n'
            continue

        else:
            membersOfGroup = get_group_members(selectedGroup)

        if membersOfGroup:
            os.system('clear')
            print '\nMembers of selected group \'' + selectedGroup + '\':'
            for member in membersOfGroup:
                print '   ' + member
            print ''
        continue


    # List available groups.
    if userInput == '/groups':
        groupFileList = get_group_list(True)
        if groupFileList:
            os.system('clear')
            print 'Available groups are: '
            for group in groupFileList:
                print '   ' + group
        print ''
        continue


    # Create new group.
    if userInput.startswith('/group create '):

        userInput = ' '.join(userInput.split())


        # Create list of names group can not have.
        reservedNames = ['create', 'add', 'rm']
        for fileName in keyFileNames:
            reservedNames.append( get_nick(fileName[:-2]) ) # Append nicknames.
            reservedNames.append( fileName[:-2] )           # Append XMPP-file.
            reservedNames.append( fileName[3:][:-2])        # Append XMPP-addr.


        # Check that group name is not reserved.
        newGroupName = userInput.split(' ')[2]
        if newGroupName == '':
            print '\nError: Group name can\'t be empty.\n'
            continue
        if newGroupName in reservedNames:
            print '\nError: Group name can\'t be command, nick or XMPP-address.\n'
            continue


        os.system('clear')
        memberList = userInput.split(' ')
        members    = []
        notAdded   = []
        i          = 3

        while i < len(memberList):
            newMember = str(memberList[i])
            mbrFile   = 'tx.' + newMember + '.e'
            i += 1

            if (mbrFile in keyFileNames) and (mbrFile not in ['tx.local.e', 'rx.local.e']):
                members.append(newMember)
            else:
                notAdded.append(newMember)


        if group_create(newGroupName, members):

            if members:
                print '\nCreated group \'' + newGroupName + '\' with following members:'
                for member in members:
                    print '   ' + member
                print ''

            else:
                print '\nCreated empty group \'' + newGroupName + '\'\n'

            if notAdded:
                print '\nUnknown contacts not added to group \'' + newGroupName + '\':'
                for member in notAdded:
                    print '   ' + member
                print ''
            continue

        else:
            print '\nGroup generation cancelled.\n'
            continue


    # Add member to group.
    if userInput.startswith('/group add '):

        userInput = ' '.join(userInput.split())
        groupName = userInput.split(' ')[2]

        xmppList  = []
        i         = 3

        while i < len(userInput.split(' ')):
            member  = userInput.split(' ')[i]
            mbrFile = 'tx.' + member + '.e'
            i      += 1

            if mbrFile not in ['tx.local', 'rx.local']:
                xmppList.append(member)

        group_add_member(groupName, xmppList)
        continue


    # Remove member from group.
    if userInput.startswith('/group rm '):

        userInput     = ' '.join(userInput.split())
        selectedGroup = userInput.split(' ')[2]

        if not selectedGroup in groupFileList:
            print '\nError: Invalid group\n'
            continue

        rmList = []
        i      = 3
        while i < len(userInput.split(' ')):
            member = userInput.split(' ')[i]
            i += 1
            rmList.append(member)

        group_rm_member(selectedGroup, rmList)
        print ''
        continue


    # Select group.
    if userInput.startswith('/group '):

        userInput = ' '.join(userInput.split())
        newGroup  = userInput.split(' ')[1]

        if newGroup == '':
            print '\nError: Invalid group\n'
            continue

        if not newGroup in groupFileList:
            print '\nError: Invalid group\n'
            continue

        else:
            selectedGroup = nick = newGroup
            os.system('clear')
            print 'Now sending messages to group \'' + nick + '\'\n'
            continue



    ##################################################################
    #                      OTHER LOCAL COMMANDS                      #
    ##################################################################

    if emergencyExit:
        if userInput == '  ':
            quit_process(False)


    if userInput == '  ' or userInput == '/clear':
        if localTesting:
            with open('TxOutput', 'w+') as file:
                file.write('clearScreen ' + xmpp + '\n')
        else:
            port.write('clearScreen ' + xmpp + '\n')

        os.system('clear')
        continue

    if userInput == '/quit' or userInput == '/exit':
        quit_process(True)


    if userInput == '':
        continue


    if userInput == '/debugging on':
        debugging = True
        os.system('clear')
        print '\nDebugging enabled\n'
        continue


    if userInput == '/debugging off':
        debugging = False
        os.system('clear')
        print '\nDebugging disabled\n'
        continue


    if userInput == '/help':
        os.system('clear')
        print_help()
        continue


    if userInput == '/paste':
        pastemode = True
        continue


    if userInput == '/about':
        os.system('clear')
        print ' Tinfoil Chat ' + version + '\n'
        print ' https://github.com/maqp/tfc-cev/\n'
        print ' cs.helsinki.fi/u/oottela/tfc.pdf'
        print '                         /tfc-manual.pdf\n\n'
        continue


    if userInput == '/names':
        os.system('clear')
        print ''
        print_list_of_contacts()
        print ''
        continue


    if userInput.startswith('/msg '):
        try:
            selection = str(userInput.split(' ')[1])

            if selection in groupFileList:
                nick = selectedGroup = selection
                os.system('clear')
                print 'Now sending messages to group \'' + selectedGroup + '\'\n'
                continue


            if selection in contacts:
                    if selection != 'tx.local':
                        xmpp = 'tx.' + selection
                        nick = get_nick(xmpp)
                        selectedGroup = ''
                        os.system('clear')
                        print 'Now sending messages to ' + nick + ' (' + xmpp + ')\n'
                        continue

            else:
                try:
                    xmpp, nick = select_contact('', '', selection, False)

                except ValueError:
                    print '\nError: Invalid contact selection.\n'
                    continue

                except IndexError:
                    print '\nError: Invalid contact selection.\n'
                    continue

                selectedGroup = ''
                os.system('clear')
                print 'Now sending messages to ' + nick + ' (' + xmpp + ')\n'
                continue

        except ValueError:
            continue
        except AttributeError:
            pass
        except UnboundLocalError:
            continue



    ##################################################################
    ##                      COMMANDS TO RX.py                       ##
    ##################################################################

    if userInput.startswith('/nick ') or userInput.startswith('/logging ') or userInput.startswith('/newkf '):
        command    = ''
        cmdLogging = False
        cmdNick    = False
        cmdNewTxKF = False

        # Check that local keyfile exists.
        if not os.path.isfile('tx.local.e'):
            print '\nError: Keyfile \'tx.local.e\' was not found. Command was not sent.\n'
            continue

        # Check that local keyfile has at least one key.
        if count_remaining_keys('tx.local') < 1:
            print '\nError: No local keys remaining. Command was not sent.\n'
            continue

        ################
        #     NICK     #
        ################
        if userInput.startswith('/nick '):
            if nick in groupFileList:
                print '\nGroup is selected, no nick was changed.\n'
                continue

            if len(userInput) < 7:
                print 'Error: Can\'t give empty nick.'
                continue

            newNick = userInput.split(' ')[1]

            # Check that specified nick is acceptable.
            if '=' in newNick or '/' in newNick:
                print '\nError: Nick can not contain reserved characters / or =\n'
                continue
            if (newNick == 'tx.local') or (newNick == 'rx.local'):
                print '\nError: Can\'t give reserved nick of local.e to contact.\n'
                continue
            if newNick in groupFileList:
                print '\nError: Nick is in use for group.\n'
                continue

            write_nick(xmpp, newNick)
            nick = get_nick(xmpp)

            os.system('clear')
            print '\nChanged ' + xmpp[3:] + ' nick to ' + nick + '\n'
            command  = 'rx.' + xmpp[3:] + '/nick=' + nick


        ###################
        #     LOGGING     #
        ###################
        if userInput.startswith('/logging '):

            value = str(userInput.split(' ')[1])

            if value   == 'on':
                command = 'logson'

            elif value == 'off':
                command = 'logsoff'

            else:
                print '\nError: Invalid command\n'
                continue


        ###################
        #     KEYFILE     #
        ###################
        if userInput.startswith('/newkf '):
            try:
                commandlist = userInput.split(' ')
                cmdtype     = commandlist[1]
                contactXmpp = commandlist[2]
                keyFileName = commandlist[3]
                keyFile     = 'tx.' + contactXmpp + '.e'


                # Check that command parameters are valid.
                if (cmdtype != 'tx') and (cmdtype != 'rx'):
                    print '\nError: Invalid command ' + cmdtype + '\n'
                    continue

                if contactXmpp == 'tx.local':
                    print '\nError: Can\'t select local keyfile.\n'
                    continue

                if not keyFile in keyFileNames:
                    os.system('clear')
                    print 'Error: Contact \'tx.' + contactXmpp + '\' is not listed'
                    continue


                # Process tx.xmpp.e and me.xmpp.e keyfiles.
                if cmdtype == 'tx':

                    print '\nWARNING! Change of keyfile will irreversably\n'\
                          'destroy current keyfile tx.' + contactXmpp + '.e\n'\
                          'on TxM and me.' + contactXmpp + '.e on RxM!\n'

                    if raw_input('\nAre you sure? Type uppercase \'YES\' to continue: ' ) == 'YES':
                        command     = 'tfckf me.' + contactXmpp + ' me.' + keyFileName
                        print '\nTxM > RxM: Shred keyfile me.' + contactXmpp + '.e and start using \'me.' + keyFileName + '\''

                    else:
                        os.system('clear')
                        print '\nKeyfile change aborted.\n'
                        continue


                # Process rx.xmpp.e keyfile.
                if cmdtype == 'rx':

                    print '\nWARNING! Change of keyfile will irreversably\n'\
                          'destroy current keyfile rx.' + contactXmpp + '.e on RxM!'

                    if raw_input('\nAre you sure? Type uppercase \'YES\' to continue: ' ) == 'YES':
                        command = 'tfckf ' + contactXmpp + ' rx.' + keyFileName
                        print '\nTxM > RxM: Shred keyfile rx.' + contactXmpp + '.e and start using rx.' + keyFileName

                    else:
                        os.system('clear')
                        print '\nKeyfile change aborted\n'
                        continue

            except IndexError:
                print 'Error: Invalid command'
                continue


        ########################
        #    COMMAND PACKET    #
        ########################

        cmd_msg_process(command)

        if command.startswith('tfckf me'):
            new_keyfile()

        continue

    #############################
    #     FILE TRANSMISSION     #
    #############################

    if userInput.startswith('/file '):

        fileName = userInput.split(' ')[1]

        if nick in groupFileList:
            sendTarget = 'all members of group \'' + nick + '\''
        else:
            sendTarget = xmpp[3:]


        if raw_input('\nThis will send file \'' + fileName + '\' to ' + sendTarget + '.\nAre you sure? Type upper case YES to continue: ') == 'YES':
            subprocess.Popen('base64 ' + fileName + ' > TFCtmpFile', shell=True).wait()

            with open('TFCtmpFile', 'r') as file:
                b64File     = file.readlines()
                fileMessage = ''
                for line in b64File:
                    fileMessage += line


            if fileMessage == '':
                os.system('clear')
                print 'Error: No file \'' + fileName + '\' found. Transmission aborted.\n'


            userInput = 'TFCFILE' + fileMessage
            subprocess.Popen('shred -n ' + str(shredIterations) + ' -z -u TFCtmpFile', shell=True).wait()

            os.system('clear')
            print '\nSending file ' + fileName + '\n'

        else:
            print '\nFile sending aborted\n'
            time.sleep(0.4)
            continue

        

    if userInput.startswith('/') and not userInput.startswith('/file '):
        os.system('clear')
        print '\nError: Unknown command \'' + userInput + '\'\n'
        continue



    ##################################################################
    #                      MULTICASTED MESSAGES                      #
    ##################################################################

    if nick in groupFileList:

        groupMemberList = get_group_members(selectedGroup, False)

        if not groupMemberList:
            os.system('clear')
            print 'Current group is empty. No message was sent.\n'
            continue

        for member in groupMemberList:
            print '           > ' + member
            xmpp = 'tx.' + member

            if len(userInput) > PkgSize:
                long_msg_process(userInput, xmpp)

            else:
                short_msg_process(userInput, xmpp)

        print ''



    ##################################################################
    #                        STANDARD MESSAGES                       #
    ##################################################################

    else:
        if len(userInput) > PkgSize:
            long_msg_process(userInput, xmpp)

        else:
            short_msg_process(userInput, xmpp)


