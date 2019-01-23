import sys, os, json, re, base64, time, shutil, pwd, grp
from HTMLParser import HTMLParser

html = HTMLParser()

cpath = os.path.dirname(os.path.abspath(__file__))
cfile = cpath+'/configurations.json'
c = json.load(open(cfile, 'r'))

for filename in os.listdir('/usr/local/openresty/nginx/conf/waf/'):
	if filename in c['conf']:
		print(filename)
	else:
		print("REMOVE: "+filename)

#for cname, carr in c['conf'].items():
#	print cname
