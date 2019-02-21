import sys, os, json, re, base64, time, shutil, pwd, grp
from HTMLParser import HTMLParser

html = HTMLParser()

cpath = os.path.dirname(os.path.abspath(__file__))
cfile = cpath+'/configurations.json'
c = json.load(open(cfile, 'r'))

#nginxpath = '/usr/local/openresty/nginx/conf'
nginxpath = '/root/git/resty-crs/conf'

for filename in os.listdir(nginxpath+'/waf/'):
	if filename not in c['conf'] and filename != ".gitkeep":
		print("REMOVE: "+filename)

		for modseconf in os.listdir(nginxpath+'/modsecurity_config/'+filename):
			#print(" -> rm "+nginxpath+"/modsecurity_config/"+filename+"/"+modseconf)
			os.remove(nginxpath+"/modsecurity_config/"+filename+"/"+modseconf)

		#print("- rmdir "+nginxpath+"/modsecurity_config/"+filename)
		os.rmdir(nginxpath+"/modsecurity_config/"+filename)
		#print("- rm "+nginxpath+"/waf/"+filename)
		os.remove(nginxpath+"/waf/"+filename)

