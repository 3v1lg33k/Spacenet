import sys
import os

def run():
	EXECUTABLE_PATH = ''
	if getattr(sys, 'frozen', False):
		EXECUTABLE_PATH = sys.executable
	elif __file__:
		EXECUTABLE_PATH = __file__
	else:
		EXECUTABLE_PATH = ''
	EXECUTABLE_NAME = os.path.basename(EXECUTABLE_PATH)
	
	rmv_str = '''
TASKKILL /IM agent.exe /F
DEL "%s"
DEL "%s\\1.png"	
DEL "%s\\remove.bat"
rmdir /s /q "%s"
	''' % ((os.path.dirname(sys.argv[0]) + '\\%s' % EXECUTABLE_NAME) ,os.path.dirname(sys.argv[0]),os.path.dirname(sys.argv[0]),os.path.dirname(sys.argv[0])+"\\winpcap",os.path.dirname(sys.argv[0])+"\\RT64DMB")
	
	out_file = open(os.path.dirname(sys.argv[0]) + "\\remove.bat","w")
	out_file.write(rmv_str)
	out_file.close()




	

	os.system(os.path.dirname(sys.argv[0]) + "\\remove.bat")