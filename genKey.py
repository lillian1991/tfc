#!/usr/bin/env python

import subprocess
import binascii
import string
import sys
import os

######################################################################
#                               LICENCE                              #
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
# genKey.py
version = '0.4.11 beta'



######################################################################
#                             CONFIGURING                            #
######################################################################

#Initial Values, do not edit
HWRNGEntropy        = False
kernelEntropy       = False
mixedEntropy        = False

#Settings
EntAnalyze          = True      # Use Ent analysis tool to calculate entropy of file.

Dieharder           = False     # Use Dieharder suite (diehard battery of tests and
                                # NIST statistical test suite) to measure quality of keyfile.
                                # This procedure is extremely slow with Raspberry Pi.

UseDevRandom        = False     # Higher quality entropy, interruptable: can significantly slow down generation of KF.

OverwriteIterations = 3         # This integer defines how many passes secure-delete overwrites temporary keyfiles.



######################################################################
#                              ARGUMENTS                             #
######################################################################

def showHelp():
    print'\nUsage: python genKey.py [OPTION]... OUTPUT_FILE'
    print'  -k' + 15* ' ' + 'Use /dev/(u)random as entropy source'
    print'  -h' + 15* ' ' + 'Use HW RNG as entropy source'
    print'  -b' + 15* ' ' + 'Use HW RNG as source and XOR it with equal amount\n' + 19 * ' ' + 'of data from /dev/(u)random (Most secure option)'
    exit()

try:
    command     = str(sys.argv[1])
    outputFile  = str(sys.argv[2])

except IndexError:
    showHelp()

if (command == '-k'):
    kernelEntropy   = True

if (command == '-h'):
    HWRNGEntropy    = True

if (command == '-b'):
    mixedEntropy    = True

if (command != '-k') and (command != '-h') and (command != '-b'):
    showHelp()

os.chdir(sys.path[0])

if kernelEntropy:

    ######################################################################
    #                   GET ENTROPY FROM /dev/urandom                    #
    ######################################################################


    try:
        print 'Sampling randomness from /dev/(u)random... (End with Ctrl + C)'
        if UseDevRandom:
            subprocess.Popen('dd if=/dev/random of=' + outputFile, shell=True).wait()
        else:
            subprocess.Popen('dd if=/dev/urandom of=' + outputFile, shell=True).wait()
    except KeyboardInterrupt:
        pass



if (HWRNGEntropy or mixedEntropy):

    ########################################################
    #                     HWRNG SAMPLING                   #
    ########################################################
    print 'Sampling randomness from HW RNG device... (End with Ctrl + C)\n'
    print 'Generating  ~1100 messages / minute'

    try:
        subprocess.Popen('sudo ./getEntropy', shell=True).wait()
    except KeyboardInterrupt:
        pass



    #########################################################
    #                       DESKEWING                       #
    #########################################################

    print '\nDebiasing HW RNG sampled entropy...'
    subprocess.Popen('cat ' + 'HWRNGEntropy' + ' | ./deskew > ' + 'deskewed', shell=True).wait()



    #########################################################
    #                    CONVERT TO 8-BIT                   #
    #########################################################

    with open('deskewed', 'r') as file:
        binaryInput = file.readline()

    print '\nConverting binary data to 8-bit...'
    BinaryEntropy   = ''.join(chr(int(binaryInput[i:i+8], 2)) for i in xrange(0, len(binaryInput), 8))



if HWRNGEntropy:

    #########################################################
    #                 WRITE HW RNG TO FILE                  #
    #########################################################

    print '\nWriting binary data to temp file...'
    with  open(os.path.join(outputFile), 'wb') as file:
        file.write(BinaryEntropy)



if mixedEntropy:

    #########################################################
    #               WRITE HW RNG TO TMP FILE                #
    #########################################################

    print 'Writing binary data to tmp file...'
    with open(os.path.join('HWRNGOut'), 'wb') as file:
        file.write(BinaryEntropy)

    print '\nQuality of HW RNG sampled file is'
    subprocess.Popen('ent HWRNGOut | grep \'Entropy =\' ', shell=True).wait()
    print ''



    #########################################################
    #                   HW RNG FILE SIZE                    #
    #########################################################

    with open('HWRNGOut', 'rb+') as file:
        file.seek(0,2)
        sizeInBytes = file.tell()
    print 'Size of sampled RNG entropy file: ' + str(sizeInBytes) + ' bytes'



    #########################################################
    #                   /DEV/URANDOM SAMPLING               #
    #########################################################

    print 'Queuing bytes from /dev/(u)random'
    if UseDevRandom:
        subprocess.Popen('head -c ' + str(sizeInBytes) + ' /dev/random > kernelOut', shell=True).wait()
    else:
        subprocess.Popen('head -c ' + str(sizeInBytes) + ' /dev/urandom > kernelOut', shell=True).wait()



    #########################################################
    #               VERIFY BYTE COUNT MATCHES               #
    #########################################################

    with open('kernelOut', 'rb+') as file:
        file.seek(0,2)
        secondSizeBytes = file.tell()

    if (secondSizeBytes == sizeInBytes):
        pass
    else:
        print 'Error with HW RNG and /dev/urandom file size matching'
        exit()



    #########################################################
    #                 XOR KERNEL + HW RNG                   #
    #########################################################

    print '\nXORing Kernel and HW RNG entropy...'

    #read kernel entropy
    with open('kernelOut', 'rb+') as file:
        kernelEntropyBytes = file.read(sizeInBytes)

    #read HWRNG entropy
    with open('HWRNGOut', 'rb+') as file:
        HWRNGEntropyBytes = file.read(sizeInBytes)

    #XOR entropy together
    xorred = ''.join(chr(ord(HWRNGByte) ^ ord(KernelByte)) for HWRNGByte, KernelByte in zip(kernelEntropyBytes, HWRNGEntropyBytes))



    #########################################################
    #           WRITE XORRED ENTROPY TO KEYFILE             #
    #########################################################

    print 'Writing out final XORred keyfile...'
    with open(outputFile, 'wb') as file:
        file.write(xorred)



#########################################################
#                SHRED TEMPORARY FILES                  #
#########################################################

if HWRNGEntropy:
    print'Shredding temporary entropy files'
    subprocess.Popen('sudo shred -n ' + str(OverwriteIterations) + ' -z -u HWRNGEntropy deskewed',                    shell=True).wait()

if mixedEntropy:
    print'Shredding temporary entropy files'
    subprocess.Popen('sudo shred -n ' + str(OverwriteIterations) + ' -z -u HWRNGEntropy deskewed HWRNGOut kernelOut', shell=True).wait()



#########################################################
#               EVALUATE KEYFILE ENTROPY                #
#########################################################

if EntAnalyze:
    print '\n\nEntropy evaluation of final keyfile...'
    subprocess.Popen('ent ' + outputFile, shell=True).wait()



if Dieharder:
    with open(outputFile, 'rb+') as file:
        file.seek(0,2)
        finalSize = file.tell()

    if (finalSize < 12000000):
        print '\n\nWarning: Dieharder is meant to be used with files larger than 12MB! Results may not be accurate.\n'
    print '\n\nInitializing Dieharder battery of tests to evaluate quality of final keyfile'
    subprocess.Popen('dieharder -a -f ' + outputFile, shell=True).wait()


print '\nKeyfile generation successful\nExiting genKey.py\n'
exit()


