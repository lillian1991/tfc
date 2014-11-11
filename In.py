import subprocess
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
# in.py
version = '0.4.11 beta'



# Read Me!
# This software is a simple tool that enables you to inject custom packets
# into RX.py's local mode temporary file. It somewhat simplifies the 
# manual penetration testing process. Be sure to enable injection mode on Rx.py, 
# that way Rx.py will switch and read messages/commands from INoutput instead.

    # 1. Start Tx.py with localTesting boolean as True
    # 2. Start NH.py with mode "l"
    # 3. Start Rx.py with both LocalTesting boolean and InjectionTesting as True
    # 4. Start In.py
            # To inject, start by writing a valid message with Tx.py
            # In.py opens NHoutput with nano: edit the message
            # Save exit with ^X, <y>, <ENTER>
            # In.py reads the modified file and saves it as INoutput.
            # Rx.py reads INoutput just as it would normally read NHoutput
            # and act accordingly. Packet will be cleared after each use.
            # Rinse and repeat, 

            # Dev note: let me know if you can craft a packet that crashes Rx.py

    # NOTE
    # You might wan't to comment out lines
        # o = DBus_MsgSender(xmpp)
        # o.sender()
    # in NH.py to disable sending injection messages to random XMPP addresses.

def getPacket():
    with open("NHoutput", "r") as f:
        contents = f.readline()
    return contents
    
def writePacket(contents):
    with open("INoutput", "w+") as f:
        f.write(contents+"\n")
        
while True:
    subprocess.Popen('nano NHoutput', shell=True).wait()
    packet = getPacket()
    print "Edited packet:\n" + packet
    writePacket(packet)


