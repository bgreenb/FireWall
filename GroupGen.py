import json
import sys
import os.path
from os.path import expanduser
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256   
from Crypto.Signature import PKCS1_PSS

#Author: Brian Greenberg 6/29/17
#JSON based config generator for groups to be used in conjunction with iptables like rules
#for an OpenFlow based switch controller

if len(sys.argv) > 3:
	print "Too many arguments, use the -h option to see how to use this"
	sys.exit()

commands = {"new":["-n","--n","--new","-new"],"modify":["-m","--m","--modify","-modify","-mod","--mod"],"verify":["-v","--v","--verify","-verify"],"help":["-h","--h","-help","--help"]}

def searchCmd(find):
	for key in commands:
		for val in commands[key]:
			if val == find:
				return key
	return None

if len(sys.argv) <= 2 and (searchCmd(sys.argv[1]) != "help"):
	print "Missing argument"
	sys.exit()

outputFileName = ""
if len(sys.argv) > 2:
	outputFileName = sys.argv[2]
configData = {}

#Find if an argument to the script is a member of the recognized command list 
#and if so return the command type. Simplifies having varitions of the same command,
#such as --new vs -n for creating a new config file.
def getGroupInput(inputDict):
	groupName = raw_input("What will this group be called? ") 
    
	#TODO: Check for valid IPv4 entries
	IPv4list = raw_input("Enter the Ipv4 address you want in the group: ")
	IPv4list = IPv4list.split(",")

	#TODO: Check for valid Subnets
	SubNetlist = raw_input("Enter the Ipv4 subnets you want in the group: ")
	SubNetlist = SubNetlist.split(",")

	#TODO: Check for valid FQDNs
	FQDNlist = raw_input("Enter the domain names you want in the group: ")
	FQDNlist = FQDNlist.split(",")

	inputDict[groupName] = {"IPv4":IPv4list,"Subnet":SubNetlist,"FQDN":FQDNlist}
	return inputDict

def makeNewConfig(inputDict,outputName):
	#Generate new json config file
	addNewGroup = True
	print "Making new config file",outputName+".conf."
	while addNewGroup:
		addGroup = raw_input("Do you want to add a new group?[y/n]: ")
		if addGroup == 'y':
			getGroupInput(inputDict)
		else:
			addNewGroup = False
	outputConf = json.JSONEncoder(sort_keys=True,indent=2).encode(inputDict)
	outputFile = open(outputName+".conf",'w')
	outputFile.write(outputConf)
	outputFile.close()
	
	#Generate signature file
	sigGen(outputName)

	print "Group config and signature file have been written in the current directory"
	
def sigGen(fileName):
	privKeyLoc = raw_input("Enter the full path of the location of the private key you want to use to sign the group file (Default is ~/.ssh/id_rsa): ")
	if privKeyLoc == '':
		privKeyLoc = expanduser("~")+"/.ssh/id_rsa"
	privKey = RSA.importKey(open(privKeyLoc,'r').read())
	hash = SHA256.new(open(fileName+".conf",'r').read())
	signer = PKCS1_PSS.new(privKey)
	sigFile = open(fileName+".sig",'w')
	signature = signer.sign(hash)
	sigFile.write(signature)
	sigFile.close()

def verifyConfig(fileName):
	publicKeyLoc = raw_input("Enter the full path of the location of the public key you want to use to verify the group file (Default is ~/.ssh/id_rsa.pub): ")
	if publicKeyLoc == '':
		publicKeyLoc = expanduser("~")+"/.ssh/id_rsa.pub"
	pubKey = RSA.importKey(open(publicKeyLoc,'r').read())
	hash = SHA256.new(open(fileName+".conf",'r').read())
	if(os.path.isfile(fileName+".sig") == False):
		print "Could not find a signature file in this directory, be sure it has the same name as the group file"
		sys.exit()
	signature = open(fileName+".sig").read()
	print "Verifying signature using ",fileName+".sig."
	verifier = PKCS1_PSS.new(pubKey)
	if verifier.verify(hash,signature):
		print "Signature for config file is authentic."
	else:
		print "Signature not authentic, config file could have been modifed!"

def modifyConfig(fileName):
	file = open(fileName+".conf",'r')
	inputData = json.JSONDecoder().decode(file.read())
	file.close()
	print "Modifying group file",fileName+".conf","."
	for group in inputData:
		for data in inputData[group]:
			print "In the ",group," group, the allowed ",data," is ",json.dumps(inputData[group][data],indent=2),"\n"
			isChange = raw_input("Do you want to change this? [y/n] ")
			if isChange == 'y':
				newData = raw_input("What should it be changed to?")
				inputData[group][data] = newData.split(",")
		modNextGroup = raw_input("Group has been modified, do you want to change the next one?[y/n] ")
		if modNextGroup != 'y':
			break

	newConfigData = json.JSONEncoder(sort_keys=True,indent=2).encode(inputData)
	print "The changed config file is:\n",newConfigData
	writeChanges = raw_input("Do you want to write these changes?[y/n] ")
	if writeChanges == 'y':
		newConfigFile = open(fileName+".conf",'w')
		newConfigFile.write(newConfigData)
		newConfigFile.close()
		sigGen(fileName)
	else:
		print "Changes not written"


if (searchCmd(sys.argv[1]) == "new"):
	modConf = 'n'
	if (os.path.isfile(outputFileName+".conf") == True):
		modConf = raw_input("There is an existing config file with this name in this directory, do you want to overwrite it? [y/n] ") 
		if modConf == 'y': 
			makeNewConfig(configData,outputFileName)
		else:
			sys.exit()
	else:
		makeNewConfig(configData,outputFileName)

elif(searchCmd(sys.argv[1]) == "modify"):	
	modifyConfig(outputFileName)
elif(searchCmd(sys.argv[1]) == "verify"):
	verifyConfig(outputFileName)
elif(searchCmd(sys.argv[1]) == "help"):
	print "Usage: ConfigGen [options] [name of group file]"
	print "Options: -m/-modify, takes an existing group file and allows modification"
	print "	 -n/-new, make a new group file"
	print "	 -v/-verify, make sure the signature matches the group file"
	print "	 -h/-help, display this text"
elif(searchCmd(sys.argv[1]) == None):
	print "Command not recognized"
	sys.exit()
