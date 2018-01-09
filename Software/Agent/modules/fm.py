import os
import utils

def run():
	buffer = ""
	starts = os.path.dirname(os.path.abspath(__file__))

	list_buffer_files =[os.path.join(starts,fn) for fn in next(os.walk(starts))[2]]
	list_buffer_dirs =[os.path.join(starts,fn) for fn in next(os.walk(starts))[1]]

	for element in list_buffer_files:
			buffer += "FILE:" + element + "\n"
			
	for element in list_buffer_dirs:
			buffer += "DIR:" + element + "\n" 
		
	utils.send_output("fm:" + buffer)