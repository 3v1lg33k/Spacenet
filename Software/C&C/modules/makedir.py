import os

# Function to create dir.
def run(dst):
	if not os.path.exists(dst):
		os.makedirs(dst)