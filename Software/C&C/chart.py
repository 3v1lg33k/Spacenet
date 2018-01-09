import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
import os
import csv
import runner

filename = "TempDir/tmpLocs.txt"
csvfile  = "TempDir/tmpLocs.csv"

def run(loc,cc):


	notinlistflag = False
	text_file_overwrite = ''

	var1_csv_overwrite = ''
	var2_csv_overwrite = ''

	my_file = Path(filename)
	if my_file.is_file():
		with open(filename, "r") as text_file:

						data=text_file.read()

					 	for line in data.splitlines():
							if loc in line:
							     count = line.split(":")[1]
							     count = int(count)
							     count += 1
				                             text_file_overwrite = data.replace(line, '%s : %s' % (loc,str(count)))
							     
							     var1_csv_overwrite = cc
							     var2_csv_overwrite = count

							     notinlistflag = False
							     break
					 		else:
								notinlistflag = True

		if notinlistflag == True:
			with open(filename, 'a') as file:
				file.write(loc + " : 1\n")

			myData = [[cc,1]]  
			myFile = open(csvfile, 'a')  
			with myFile:  
			   writer = csv.writer(myFile)
			   writer.writerows(myData)
		else:

			with open(filename, 'w') as file:
			  file.write(text_file_overwrite)

			myData = [[var1_csv_overwrite,var2_csv_overwrite]] 
			myFile = open(csvfile, 'a')  
			with myFile:  
			   writer = csv.writer(myFile)
			   writer.writerows(myData)	

	else:

		with open(filename, 'w') as file:
		  file.write(loc + " : 1\n")

		myData = [[cc,1]]  
		myFile = open(csvfile, 'w')  
		with myFile:  
		   writer = csv.writer(myFile)
		   writer.writerows(myData)
	
	

def create():
	runner.run()

def generate():
	# Collect the data from the file, ignore empty lines
	with open(filename) as f:
	    lines = [line.strip().split(': ') for line in f if len(line) > 1]

	labels, y = zip(*lines)

	# Generate indexes
	ind = np.arange(len(labels))

	# Convert the y values from str to int
	y = map(int, y)



	buffer = plt.figure()

	plt.title('All Zombies GeoLocated')

	plt.bar(ind, y, align='center')
	plt.xticks(ind, labels)

	buffer.savefig('static/images/plot.png')


	os.remove(filename)
