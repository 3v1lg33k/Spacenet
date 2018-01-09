import csv
from BeautifulSoup import BeautifulSoup

def run():
	penetration = {}
	reader = csv.reader(open('TempDir/tmpLocs.csv'), delimiter=",")
	for row in reader:
	    try:
		penetration[row[0].lower()] = float( row[1].strip() )
	    except:
		pass

	svg = open('static/images/countries.svg', 'r').read()
	soup = BeautifulSoup(svg, selfClosingTags=['defs','sodipodi:namedview','path'])
	colors = ["#4f537a", "#495096", "#646ed1", "#000c84", "#0111ad", "#a107c4"] 
	gs = soup.contents[2].findAll('g',recursive=False)
	paths = soup.contents[2].findAll('path',recursive=False)
	path_style = "fill-opacity:1;stroke:#ffffff;stroke-width:0.99986994;stroke-miterlimit:3.97446823;stroke-dasharray:none;stroke-opacity:1;fill:"
	for p in paths:
	     if 'land' in p['class']:
		try:
		    rate = penetration[p['id']]
		except:
		    continue
	 
		if rate > 100:
		    color_class = 5
		elif rate > 50:
		    color_class = 4
		elif rate > 30:
		    color_class = 3
		elif rate > 10:
		    color_class = 2
		elif rate >= 1:
		    color_class = 1
		else:
		    color_class = 0
	       
		color = colors[color_class]
		p['style'] = path_style + color

	for g in gs:
		try:
		    rate = penetration[g['id']]
		except:
		    continue
	 
		if rate > 100:
		    color_class = 5
		elif rate > 50:
		    color_class = 4
		elif rate > 30:
		    color_class = 3
		elif rate > 10:
		    color_class = 2
		elif rate >= 1:
		    color_class = 1
		else:
		    color_class = 0

		color = colors[color_class]
		g['style'] = path_style + color
		for t in g.findAll('path',recursive=True):
		    t['style'] = path_style + color

	f = open("static/images/world.svg", "w")
	f.write(str(soup).replace('viewbox','viewBox',1))

