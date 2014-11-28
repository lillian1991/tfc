#!/usr/bin/env python
#-*- coding: utf-8 -*-

import os
import subprocess
import time



######################################################################
#                             LICENCE                                #
######################################################################

# TFC (OTP Version) || tfcInstaller.py
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

# Specify global keyfile size in megabytes.
megabytes = 2

######################################################################
#                             APT COMMANDS                           #
######################################################################

def update_system():
    print '\nUpdating system\n'
    subprocess.Popen('sudo apt-get --yes update',                shell=True).wait()



def install_Python_Serial():
    print '\nInstalling Python-serial\n'
    subprocess.Popen('sudo apt-get --yes install python-serial', shell=True).wait()



def install_Python_Qt4():
    print '\nInstalling Python QT4\n'
    subprocess.Popen('sudo apt-get --yes install python-qt4',    shell=True).wait()



def install_SecureDelete():
    print '\nInstalling Secure Delete\n'
    subprocess.Popen('sudo apt-get --yes install secure-delete', shell=True).wait()



def install_DieHarder():
    print '\nInstalling Dieharder suite\n'
    subprocess.Popen('sudo apt-get --yes install dieharder',     shell=True).wait()



def install_Ent():
    print '\nInstalling Ent entropy analysis suite\n'
    subprocess.Popen('sudo apt-get --yes install ent',           shell=True).wait()



def install_Pidgin():
    print '\nInstalling Pidgin\n'
    subprocess.Popen('sudo apt-get --yes install pidgin',        shell=True).wait()



def install_Pidgin_OTR():
    print '\nInstalling Pidgin OTR\n'
    subprocess.Popen('sudo apt-get --yes install pidgin-otr',    shell=True).wait()




######################################################################
#                            ZYPPER COMMANDS                         #
######################################################################

def zypper_Pidgin():
    print '\nInstalling Pidgin\n'
    subprocess.Popen('sudo zypper install pidgin',        shell=True).wait()



def zypper_Pidgin_OTR():
    print '\nInstalling Pidgin OTR\n'
    subprocess.Popen('sudo zypper install pidgin-otr',    shell=True).wait()



def zypper_Python_Serial():
    print '\nInstalling Python-serial\n'
    subprocess.Popen('sudo zypper install python-serial', shell=True).wait()



def zypper_Python_Qt4():
    print '\nInstalling Python QT4\n'
    subprocess.Popen('sudo zypper install python-qt4',    shell=True).wait()



######################################################################
#                              YUM COMMANDS                          #
######################################################################

def yum_Pidgin():
    print '\nInstalling Pidgin\n'
    subprocess.Popen('sudo yum install pidgin',     shell=True).wait()



def yum_Pidgin_OTR():
    print '\nInstalling Pidgin OTR\n'
    subprocess.Popen('sudo yum install pidgin-otr', shell=True).wait()



def yum_install_Wget():
    print '\nInstalling Wget\n'
    subprocess.Popen('sudo yum install wget',       shell=True).wait()



def yum_Python_Serial():
    print '\nInstalling Python-serial\n'
    subprocess.Popen('sudo yum install pyserial',   shell=True).wait()



def yum_Python_Qt4():
    print '\nInstalling Python QT4\n'
    subprocess.Popen('sudo yum install pyqt4',      shell=True).wait()



######################################################################
#                      FILE CONTENT CONFIGURING                      #
######################################################################

def rasp_cmdline():
    # Edit /boot/cmdline.txt to enable serial port for user (phase 1/2).
    print '\nEditing file \'cmdline.txt\'\n'

    with open('/boot/cmdline.txt', 'r') as file:
        line        = file.readline()
        line        = line.replace(' console=ttyAMA0,115200 kgdboc=ttyAMA0,115200', '')
    with open('/boot/cmdline.txt', 'w+') as file:
        file.write(line)



def rasp_inittab():
    # Edit /etc/inittab to enable serial port for user (phase 2/2).
    print '\nEditing file \'inittab\'\n'

    with open('/etc/inittab', 'r') as file:
        contents     = file.read()
        rep_contents = contents.replace('T0:23:respawn:/sbin/getty -L ttyAMA0 115200 vt100', '#T0:23:respawn:/sbin/getty -L ttyAMA0 115200 vt100')

    with open('/etc/inittab', 'w+') as file:
        file.write(rep_contents)



def serial_config(scriptName):
    # Configure serial port of Tx.py/Rx.py for USB adapters.
    print '\nConfiguring serial interfaces of \'' + scriptName + '\'\n'

    with open(scriptName, 'r') as file:
        contents = file.read()
        contents = contents.replace('\'/dev/ttyAMA0\'', '\'/dev/ttyUSB0\'')

    with open(scriptName, 'w+') as file:
        file.write(contents)



def changeToLocal(fileName):
    # Configure Tx/Rx/NH.py localTesting boolean to True.
    print '\nChanging boolean \'localTesting\' of file \'' + fileName + '\' to \'True\''

    with open(fileName, 'r') as file:
        contents = file.read()
        contents = contents.replace('localTesting       = False', 'localTesting       = True\n')

    with open(fileName, 'w+') as file:
        file.write(contents)



######################################################################
#                          SCRIPT DOWNLOADING                        #
######################################################################

def get_TxM_scripts():
    print '\nDownloading TFC-suite (TxM)\n'
    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc/master/Tx.py',        shell=True).wait()
    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc/master/genKey.py',    shell=True).wait()
    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc/master/getEntropy.c', shell=True).wait()
    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc/master/deskew.c',     shell=True).wait()



def get_RxM_scripts():
    print '\nDownloading TFC-suite (RxM)\n'
    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc/master/Rx.py',        shell=True).wait()



def get_NH_script():
    print '\nDownloading TFC-suite (NH)\n'
    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc/master/NH.py',        shell=True).wait()



######################################################################
#                             MISC FUNCTIONS                         #
######################################################################

def reboot():
    subprocess.Popen('sudo reboot',                                  shell=True).wait()



def SetSerialPermissions(username):
    print '\nChanging serial port permissions for user \'' + username + '\'\n'
    subprocess.Popen('sudo gpasswd --add ' + username + ' dialout',  shell=True).wait()



def compile_c_programs():
    print '\nCompiling C-programs\n'
    subprocess.Popen('sudo gcc -Wall -O getEntropy.c -o getEntropy', shell=True).wait()
    subprocess.Popen('sudo gcc -Wall -O deskew.c -o deskew',         shell=True).wait()



def c_run_permissions():
    print '\nEnabling permissions to execute compiled C-programs\n'
    subprocess.Popen('sudo chmod a+x getEntropy',                    shell=True).wait()
    subprocess.Popen('sudo chmod a+x deskew',                        shell=True).wait()



def printLocalTesterWarning():
    print 'WARNING! YOU HAVE SELECTED THE LOCAL TESTING VERSION OF TFC! THIS '      \
          'VERSION IS INTENDED ONLY FOR TRYING OUT THE FEATURES AND STABILITY OF '  \
          'THE SYSTEM. IN THIS CONFIGURATION, THE ENCRYPTION KEYS ARE CREATED, '    \
          'STORED AND HANDLED ON NETWORK-CONNECTED COMPUTER, SO ANYONE WHO BREAKS ' \
          'IN TO YOUR COMPUTER BY EXPLOITING A KNOWN OR UNKNOWN VULNERABILITY ,'    \
          'CAN DECRYPT AND/OR FORGE ALL MESSAGES YOU SEND AND RECEIVE EFFORTLESSLY!'



######################################################################
#                              MAIN LOOP                             #
######################################################################

while True:
    try:
        os.system('clear')
        print 'TFC || ' + version + ' || tfcInstaller.py'
        print '''
Select configuration that matches your OS:

   TxM
      1.  Raspbian (Run installer as superuser)

      2.  Ubuntu
          Kubuntu
          Linux Mint (Ubuntu/Debian)

   RxM
      3.  Raspbian (Run installer as superuser)

      4.  Ubuntu
          Kubuntu
          Linux Mint (Ubuntu/Debian)

    NH
      5.  Ubuntu
          Kubuntu
          Linux Mint (Ubuntu/Debian)

      6.  Tails

      7.  OpenSUSE
        
      8.  Fedora

    Local Testing (insecure)
      9.  Ubuntu
          Kubuntu
          Linux Mint (Ubuntu/Debian).\n'''

        selection = int(raw_input('1..9: '))



    ######################################################################
    #                                  TxM                               #
    ######################################################################

        # TxM Raspbian
        if selection == 1:
            os.system('clear')
            if raw_input('This will install TxM configuration for Raspbian. \nAre you sure? Type uppercase YES: ') == 'YES':

                update_system()
                install_SecureDelete()
                get_TxM_scripts()

                install_Ent()
                install_DieHarder()

                compile_c_programs()
                c_run_permissions()

                install_Python_Serial()
                rasp_cmdline()
                rasp_inittab()

                os.system('clear')

                print '\nTxM install script completed\n'                   \
                      'Rebooting system in 20 seconds.\n'                  \
                      'If you don\'t want to restart now, press CTRL+C\n\n'
                try:
                    time.sleep(20)
                    reboot()
                except KeyboardInterrupt:
                    print '\n\nReboot aborted, exiting. (You may need to ' \
                          'restart Raspbian for Tx.py to work correctly)\n'
                    exit()
            else:
                continue



    # TxM Ubuntu
        if selection == 2:
            os.system('clear')
            if raw_input('This will install TxM configuration for Ubuntu / Mint (Ubuntu / Debian). \nAre you sure? Type uppercase YES: ') == 'YES':

                update_system()
                install_SecureDelete()
                get_TxM_scripts()

                install_Ent()
                install_DieHarder()

                compile_c_programs()
                c_run_permissions()

                install_Python_Serial()
                serial_config('Tx.py')
                SetSerialPermissions(raw_input('Type name of the user that will be running TFC (this will add the user to dialout group): '))

                os.system('clear')
                print '\nTxM install script completed\n'                   \
                      'Rebooting system in 20 seconds.\n'                  \
                      'If you don\'t want to restart now, press CTRL+C\n\n'
                try:
                    time.sleep(20)
                    reboot()
                except KeyboardInterrupt:
                    print '\n\nReboot aborted, exiting. (You may need to ' \
                          'restart your OS for Tx.py to work correctly)\n'
                    exit()
            else:
                continue



    ######################################################################
    #                                  RxM                               #
    ######################################################################

    # RxM Raspbian
        if selection == 3:
            os.system('clear')
            if raw_input('This will install RxM configuration for Raspbian. \nAre you sure? Type uppercase YES: ') == 'YES':

                update_system()
                install_SecureDelete()
                get_RxM_scripts()

                install_Python_Serial()
                rasp_cmdline()
                rasp_inittab()

                os.system('clear')
                print '\nRxM install script completed\n'                   \
                      'Rebooting system in 20 seconds.\n'                  \
                      'If you don\'t want to restart now, press CTRL+C\n\n'

                try:
                    time.sleep(20)
                    reboot()
                except KeyboardInterrupt:
                    print '\n\nReboot aborted, exiting. (You may need to ' \
                          'restart Raspbian for Rx.py to work correctly)\n'
                    exit()
            else:
                continue



    # RxM Ubuntu
        if selection == 4:
            os.system('clear')
            if raw_input('This will install RxM configuration for Ubuntu / Mint (Ubuntu / Debian). \nAre you sure? Type uppercase YES: ') == 'YES':

                update_system()
                install_SecureDelete()
                get_RxM_scripts()

                install_Python_Serial()
                serial_config('Rx.py')
                SetSerialPermissions(raw_input('Type name of the user that will be running TFC (this will add the user to dialout group): '))


                os.system('clear')
                print '\nRxM install script completed\n'                   \
                      'Rebooting system in 20 seconds.\n'                  \
                      'If you don\'t want to restart now, press CTRL+C\n\n'
                try:
                    time.sleep(20)
                    reboot()
                except KeyboardInterrupt:

                    print '\n\nReboot aborted, exiting. (You may need to ' \
                          'restart your OS for Rx.py to work correctly)\n'
                    exit()
            else:
                continue



    ######################################################################
    #                                   NH                               #
    ######################################################################

    # NH Ubuntu
        if selection == 5:
            os.system('clear')
            if raw_input('This will install NH configuration for Ubuntu / Mint (Ubuntu / Debian). \nAre you sure? Type uppercase YES: ') == 'YES':

                update_system()

                if raw_input('\nType YES to install Pidgin with OTR: ') == 'YES':
                    install_Pidgin()
                    install_Pidgin_OTR()

                install_Python_Qt4()
                install_Python_Serial()
                get_NH_script()

                SetSerialPermissions(raw_input('Type name of the user that will be running TFC (this will add the user to dialout group): '))

                os.system('clear')
                print '\nNH install script completed\n'  \
                      'Rebooting system in 20 seconds.\n'\
                      'If you don\'t want to restart now, press CTRL+C\n'
                try:
                    time.sleep(20)
                    reboot()
                except KeyboardInterrupt:
                    print '\n\nReboot aborted, exiting. (You may need to ' \
                          'restart your NH for NH.py to work correctly)\n'
                    exit()
            else:
                continue



    # NH Tails (The Amnesic Incognito Live System)
        if selection == 6:
            os.system('clear')
            if raw_input('This will install NH configuration for Tails. \nAre you sure? Type uppercase YES: ') == 'YES':

                get_NH_script()
                SetSerialPermissions('amnesia')

                os.system('clear')
                print '\nNH install script completed. To launch NH, type below\n                   python NH.py'
                exit()
            else:
                continue



    # NH OpenSUSE
        if selection == 7:
            os.system('clear')
            if raw_input('This will install NH configuration for OpenSUSE. \nAre you sure? Type uppercase YES: ') == 'YES':

                if raw_input('\nType YES to install Pidgin with OTR: ') == 'YES':
                    zypper_Pidgin()
                    zypper_Pidgin_OTR()

                zypper_Python_Qt4()
                zypper_Python_Serial()
                get_NH_script()

                SetSerialPermissions(raw_input('Type name of the user that will be running TFC (this will add the user to dialout group): '))

                os.system('clear')
                print '\nNH install script completed\n'  \
                      'Rebooting system in 20 seconds.\n'\
                      'If you don\'t want to restart now, press CTRL+C\n'
                try:
                    time.sleep(20)
                    reboot()
                except KeyboardInterrupt:
                    print '\n\nReboot aborted, exiting. (You may need to ' \
                          'restart your NH for NH.py to work correctly)\n'
                    exit()
            else:
                continue



    # NH Fedora
        if selection == 8:
            os.system('clear')
            if raw_input('This will install NH configuration for Fedora. \nAre you sure? Type uppercase YES: ') == 'YES':

                if raw_input('\nType YES to install Pidgin with OTR: ') == 'YES':
                    yum_Pidgin()
                    yum_Pidgin_OTR()

                yum_Python_Qt4()
                yum_Python_Serial()
                yum_install_Wget()
                get_NH_script()

                SetSerialPermissions(raw_input('Type name of the user that will be running TFC (this will add the user to dialout group): '))

                os.system('clear')
                print '\nNH install script completed\n'  \
                      'Rebooting system in 20 seconds.\n' \
                      'If you don\'t want to restart now, press CTRL+C\n'
                try:
                    time.sleep(20)
                    reboot()
                except KeyboardInterrupt:
                    print '\n\nReboot aborted, exiting. (You may need to ' \
                          'restart your NH for NH.py to work correctly)\n'
                    exit()
            else:
                continue



    # Insecure testing mode with standalone computers.
        if selection == 9:
            os.system('clear')

            printLocalTesterWarning()
            if raw_input('\nTO VERIFY THAT YOU UNDERSTAND RISKS,\nTYPE IN UPPERCASE \'INSECURE\': ') == 'INSECURE':

                os.system('clear')

                if raw_input('\nType YES to install Pidgin with OTR: ') == 'YES':
                    install_Pidgin()
                    install_Pidgin_OTR()

                install_Python_Serial()
                install_Python_Qt4()
                install_SecureDelete()

                userArray = []
                while True:

                    os.system('clear')
                    print 'Installing dependencies completed. The system will now ask you to enter '\
                          'the XMPP-addresses that will be participating in testing, to generate '  \
                          'local test folders for each user. If you have already received a local ' \
                          'test folder, you can press enter to close the installer and open the '   \
                          'Tx.py, Rx.py and NH.py in their own terminals. Remember to open Pidgin ' \
                          'before opening NH.py.\n\n'

                    userC = raw_input('Enter XMPP account of user, or press Enter to create test folders:\n\n')
                    if userC == '':
                        break
                    userArray.append(userC)


                for user1 in userArray:
                    print 'Generating folder, downloading TFC program and generating local keys for user ' + user1
                    subprocess.Popen('mkdir ' + user1, shell=True).wait()

                    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc/master/Tx.py', shell=True).wait()
                    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc/master/Rx.py', shell=True).wait()
                    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc/master/NH.py', shell=True).wait()
                    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc/master/tfcInstaller.py -O tfcOTPInstaller.py', shell=True).wait()

                    changeToLocal('Tx.py')
                    changeToLocal('Rx.py')
                    changeToLocal('NH.py')

                    subprocess.Popen('mv Tx.py ' + user1 + '/', shell=True).wait()
                    subprocess.Popen('mv Rx.py ' + user1 + '/', shell=True).wait()
                    subprocess.Popen('mv NH.py ' + user1 + '/', shell=True).wait()
                    subprocess.Popen('mv tfcOTPInstaller.py ' + user1 + '/', shell=True).wait()

                    subprocess.Popen('dd if=/dev/urandom of=tx.local.e bs=1M count=' + str(megabytes), shell=True).wait()
                    subprocess.Popen('cp tx.local.e rx.local.e', shell=True).wait()
                    subprocess.Popen('mv tx.local.e ' + user1 + '/', shell=True).wait()
                    subprocess.Popen('mv rx.local.e ' + user1 + '/', shell=True).wait()
                    time.sleep(0.5)
                print 'Done.'

                for user1 in userArray:
                    print 'Creating keys for user: ' + user1
                    for user2 in userArray:
                        if user1 != user2:
                            subprocess.Popen('dd if=/dev/urandom of=tx.' + user1 + '.e bs=1M count=' + str(megabytes), shell=True).wait()
                            subprocess.Popen('cp tx.' + user1 + '.e ' + 'me.' + user1 + '.e', shell=True).wait()
                            subprocess.Popen('cp tx.' + user1 + '.e ' + 'rx.' + user2 + '.e', shell=True).wait()
                            subprocess.Popen('mv tx.' + user1 + '.e ' + user2 + '/', shell=True).wait()
                            subprocess.Popen('mv me.' + user1 + '.e ' + user2 + '/', shell=True).wait()
                            subprocess.Popen('mv rx.' + user2 + '.e ' + user1 + '/', shell=True).wait()
                            time.sleep(0.5)
                    else:
                        continue

                os.system('clear')
                print 'Test folders named after each user generated succesfully. Before each user '      \
                      'can run their test version of TFC, they must run the bundled tfcOTPInstaller.py ' \
                      'and choose installation configuration 9. When the installer has installed '       \
                      'dependencies, the user is ready to run the Tx.py, Rx.py and NH.py. Note '         \
                      'that other users don\'t have to create their own keyfiles for insecure testing.\n\n'
                exit()
            else:
                continue

    except ValueError:
        continue
    except IndexError:
        continue


