from time import gmtime, strftime
from termcolor import colored, cprint
from random import randint
import string

# Function to store logs
# Format filename = log-[DATE&&HOUR]


switch = 0
switchname = 0
filename = ""

def save(action):
	global switch , switchname , filename
	
	if switchname == 0:
		timename = strftime("[%H-%M-%S_%d-%m-%Y]", gmtime())
		filename = "logs/log-%s.txt" %timename
		switchname += 1

	current_time = strftime("%H:%M:%S", gmtime())
        
	out_file = open(filename,"a")
	out_file.write("[" + str(current_time) + "]\t" + str(action) + "\n")
	out_file.close()

	
	if "Aborted" in action or "Stopping" in action:
		cprint("\n[ CRTL ] [ " + current_time + " ] %s" % action, 'red') 
		
	elif "Exiting" in action:
		cprint("[ CRTL ] [ " + current_time + " ] %s" % action, 'red') 
	
	elif "401" in action:
		cprint("[ INFO ] [ " + current_time + " ] %s" % action, 'yellow') 
		
	elif "Starting" in action or "started" in action:
		cprint("[ INFO ] [ " + current_time + " ] %s" % action, 'cyan',attrs=['bold']) 
		
	else:
		cprint("[ INFO ] [ " + current_time + " ] %s" % action, 'blue') 

