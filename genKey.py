#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binascii
import math
import os
import subprocess
import sys



######################################################################
#                               LICENCE                              #
######################################################################

# TFC (OTP Version) || genKey.py
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
#                             CONFIGURING                            #
######################################################################

shredIterations = 3         # Number of passes secure-delete overwrites temporary keyfiles.

useDevRandom    = False     # Higher quality entropy, interruptable: Significantly
                            # slows down generation of KF without internal HWRNG / TPM.

keccakWhitening = False     # Use 256-bit Keccak (SHA-3) hash function to further whiten
                            # final entropy. This significantly slows down KF generation.

EntAnalyze      = True      # Use Ent analysis tool to calculate entropy of file.

Dieharder       = False     # Use Dieharder suite (diehard battery of tests and
                            # NIST statistical test suite) to measure quality of keyfile.
                            # This procedure is extremely slow with Raspberry Pi.


######################################################################
#                              ARGUMENTS                             #
######################################################################

#Initial Values, do not edit.
HWRNGEntropy    = False
kernelEntropy   = False
mixedEntropy    = False
defOFile        = False



def showHelp():
    print '\nUsage: python genKey.py [OPTIONS]... OUTPUT_FILE\n\n'                         \
    '  -k, --kernel'    + 7  * ' ' + 'Use /dev/(u)random as entropy source.\n'             \
    '  -h, --hwrng'     + 8  * ' ' + 'Use HW RNG as entropy source.\n'                     \
    '  -x, --mixed'     + 8  * ' ' + 'Use HW RNG as source and XOR it with equal amount\n' \
                        + 21 * ' ' + 'of entropy from kernel. (Most secure option).\n\n'  
    exit()


try:
    command = str(sys.argv[1])

except IndexError:
    showHelp()


try:
    outputFile = str(sys.argv[2])

except IndexError:
    defOFile = True


if '-k' in command or '--kernel' in command:
    kernelEntropy   = True
    if useDevRandom:
        mode        = 'Kernel entropy (/dev/random)'
    else:
        mode        = 'Kernel entropy (/dev/urandom)'


if '-h' in command or '--hwnrg' in command:
    HWRNGEntropy    = True
    mode            = 'HWRNG entropy'


if '-x' in command or '--mixed' in command:
    mixedEntropy    = True

    if useDevRandom:
        mode        = 'Mixed entropy (HWRNG XOR /dev/random)'
    else:
        mode        = 'Mixed entropy (HWRNG XOR /dev/urandom)'


# Check that only one mode of operation is selected.
selModes = 0
if kernelEntropy:
    selModes += 1
if HWRNGEntropy:
    selModes += 1
if mixedEntropy:
    selModes += 1

if selModes != 1:
    showHelp()

os.chdir(sys.path[0])



######################################################################
#                        KECCAK HASH FUNCTION                        #
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
    hexMsg       = binascii.hexlify(hashInput)
    return Keccak().Keccak(((8 * len(hashInput)), hexMsg), 1088, 512, 0, 256, 0)



######################################################################
#                          ENTROPY COLLECTION                        #
######################################################################

def get_hwrng_entropy():

    print 'Sampling randomness from HW RNG device. End with Ctrl + C\n'
    try:
        subprocess.Popen('sudo ./getEntropy', shell=True).wait()
    except KeyboardInterrupt:
        pass

    os.system('clear')
    print '\nTFC ' + version + ' || Key generator || Mode: ' + mode + '\n\n'
    if defOFile:
        print 'Specified output file: ' + outputFile + '\n'
    print 'Sampling randomness from HW RNG device. End with Ctrl + C\nEnded by user.'

    print '\nApplying VN whitening on entropy...'
    subprocess.Popen('cat ' + 'HWRNGEntropy' + ' | ./deskew > ' + 'whitened', shell=True).wait()

    print 'Done.\n\nReading whitened data...'
    with open('whitened', 'r') as file:
        binaryString = file.readline()

    # Convert '1011011101011...' to binary string.
    entropy = ''.join(chr(int(binaryString[i:i+8], 2)) for i in xrange(0, len(binaryString), 8))

    print 'Done.\n\nOverwriting HWRNG tmp files...'
    subprocess.Popen('sudo shred -n ' + str(shredIterations) + ' -z -u HWRNGEntropy whitened', shell=True).wait()

    # Calculate entropy size.
    entropySize = len(entropy)

    print 'Done.\n\nObtained ' + str(entropySize) + ' bytes (' + str(entropySize / 420) + ' default len msg) of entropy from HWRNG.'

    return entropy, entropySize



def get_kernel_entropy(size=0):
    
    # If requested size is set to 0, generate entropy until user halts.
    if size == 0:
        try:
            print 'Sampling randomness from kernel entropy. End with Ctrl + C'
            if useDevRandom:
                subprocess.Popen('dd if=/dev/random of=tmpEntropy conv=notrunc > /dev/null 2>&1', shell=True).wait()
            else:
                subprocess.Popen('dd if=/dev/urandom of=tmpEntropy conv=notrunc > /dev/null 2>&1', shell=True).wait()
        except KeyboardInterrupt:
            pass

        os.system('clear')
        print '\nTFC ' + version + ' || Key generator || Mode: ' + mode + '\n\n'
        if defOFile:
            print 'Specified output file: ' + outputFile + '\n'
        print 'Sampling randomness from kernel entropy. End with Ctrl + C\nEnded by user.'

        with open('tmpEntropy', 'rb') as file:
            entropy = file.readlines()

        entropy = ''.join(entropy)

        print '\nOverwriting tmp files...'
        subprocess.Popen('sudo shred -n ' + str(shredIterations) + ' -z -u tmpEntropy', shell=True).wait()
    
        entropySize = len(entropy)
        print 'Done.\n\nObtained ' + str(entropySize) + ' bytes of entropy from Kernel.'
        print 'This equals ' + str(entropySize / 140) + ' default 140-char messages.\n'
    
        # Return the entropy and the entropy size.
        return entropy


    # If requested size is larger than 0, generate specified amount of entropy.
    if size > 0:

        if useDevRandom:
            subprocess.Popen('head -c ' + str(size) + ' /dev/random > kernel_ent',   shell=True).wait()
        else:
            subprocess.Popen('head -c ' + str(size) + ' /dev/urandom > kernel_ent',   shell=True).wait()

        with open('kernel_ent', 'rb') as file:
            entropy = file.readlines()
        
        entropy = ''.join(entropy)
    
        # Verify that correct amount of entropy was obtained.
        while len(entropy) != size:
            print 'Entropy collection from /dev/(u)random failed. Trying again...'
    
            if useDevRandom:
                subprocess.Popen('head -c ' + str(size) + ' /dev/random > kernel_ent',   shell=True).wait()
            else:
                subprocess.Popen('head -c ' + str(size) + ' /dev/urandom > kernel_ent',   shell=True).wait()
    
            with open('kernel_ent', 'rb') as file:
                entropy = file.readline()

        print '\nShredding temporary entropy file...'
        subprocess.Popen('shred -n ' + str(shredIterations) + ' -z -u kernel_ent', shell=True).wait()

    else:
        os.system('clear')
        print '\nERROR! Specified invalid kernel entropy size. Exiting.\n'
        exit()

    return entropy


######################################################################
#                      ENTROPY COLLECTION MODES                      #
######################################################################

os.system('clear')
print '\nTFC ' + version + ' || Key generator || Mode: ' + mode + '\n\n'


if defOFile:
    try:
        outputFile = raw_input('No output file specified. Please enter output file name: ')
        print ''
    except KeyboardInterrupt:
        os.system('clear')
        print '\nExiting genKey.py\n'
        exit()

if outputFile.startswith('-'):
    os.system('clear')
    print '\nError: Keyfile can not start with \'-\'. Exiting.\n'
    exit()


if kernelEntropy:
    entropy = get_kernel_entropy()


if HWRNGEntropy:
    entropy, HWentropySize = get_hwrng_entropy()


if mixedEntropy:

    HWEntropy, entropy1size = get_hwrng_entropy()
    KernelEntropy           = get_kernel_entropy(entropy1size)

    print 'Done.\n\nXORing HWRNG and kernel entropy...'

    # XOR HWRNG entropy with Kernel entropy.
    if len(HWEntropy) == len(KernelEntropy):
        entropy = ''.join(chr(ord(HWRNGByte) ^ ord(KernelByte)) for HWRNGByte, KernelByte in zip(HWEntropy, KernelEntropy))
    else:
        os.system('clear')
        print '\nERROR: Length mismatch when XORing HWRNG entropy with kernel entropy. Exiting.\n'
        exit()

if keccakWhitening:

    # Split entropy to 256-bit blocks
    entropyBlocks = [entropy[x:x+32] for x in range(0,len(entropy),32)]
    entropy       = ''

    # Hash each block separately and create new entropy string.
    for block in entropyBlocks:
        os.system('clear')
        print 'Whitening entropy with Keccak...\n\nBlock ' + str(entropyBlocks.index(block)) + ' of ' + str(len(entropyBlocks))
        whitened = binascii.unhexlify( keccak_256(str(block)) )
        entropy  = entropy + whitened


if not kernelEntropy:
    print 'Done.\n'

print 'Storing entropy file...'

with open(outputFile, 'wb') as file:
    file.write(entropy)



#########################################################
#               EVALUATE KEYFILE ENTROPY                #
#########################################################

ttyw = int(subprocess.check_output(['stty', 'size']).split()[1])

if EntAnalyze:
    print 'Done.\n\n' + ttyw * '-' + 'Entropy evaluation of final keyfile:\n'
    subprocess.Popen('ent ' + outputFile, shell=True).wait()
    print ttyw * '-'


if Dieharder:
    with open(outputFile, 'rb') as file:
        file.seek(0,2)
        keyFileSize = file.tell()

    if (keyFileSize < 12582912):
        print '\n\nWarning: Dieharder is meant to be used with files ' \
              'larger than 12MB! Results may not be accurate.\n'

    print '\n\nInitializing Dieharder battery of ' \
          'tests to evaluate quality of final keyfile'

    subprocess.Popen('dieharder -a -f ' + outputFile, shell=True).wait()



#########################################################
#               MAKE COPIES OF KEYFILE                  #
#########################################################

print '\nCreating copies of key...'
#subprocess.Popen('cp ' + outputFile + ' me.' + outputFile, shell=True).wait()
#subprocess.Popen('cp ' + outputFile + ' rx.' + outputFile + '_for_recipient', shell=True).wait()


print 'Done.\n\nKeyfile generation successful.\nExiting.\n\n'
exit()


