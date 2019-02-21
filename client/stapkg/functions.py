#!/usr/bin/env python

import os, json, time, requests, re, urllib

hostname = os.popen('hostname').read().strip()

cpath = os.path.dirname(os.path.abspath(__file__))

nginxpath = '/usr/local/openresty/nginx'
logspath = '/root/git/resty-crs/logs'
cfile = cpath+'/configurations.json'
lastidfile = cpath+'/ids/lastid_config'
lastidbl = cpath+'/ids/lastid_bl'
lastidtor = cpath+'/ids/lastid_tor'
#blfile = nginxpath+'/conf/bl/modsecurity_bad_reputation.txt'
#torfile = nginxpath+'/conf/bl/modsecurity_tor_exit_nodes.txt'

try:
	with open(cpath+'/../config.json') as data_file:    
		config = json.load(data_file)
except:
	print("+ Config file not found, creating it...")
	config = {}
else:
	with open(cpath+'/../config.json') as data_file:    
		config = json.load(data_file)

class bcolor:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def log(level, string):
	if level == 'OK':
		lcolor = bcolor.OKGREEN
	elif level == 'INFO':
		lcolor = bcolor.OKBLUE
	elif level == 'WARNING':
		lcolor = bcolor.WARNING
	elif level == 'ERROR':
		lcolor = bcolor.FAIL

	print(bcolor.OKBLUE+'[*]'+bcolor.ENDC+' ['+ lcolor + level + bcolor.ENDC+'] '+string)

def encrypt(string):
	global config
	randfile = '/tmp/sta_rand_'+str(int(round(time.time() * 1000)))
	with open(randfile, "w") as f:
		f.write(string)

	encstring = os.popen("cat "+randfile+" | openssl enc -aes-128-cbc -base64 -md md5 -A -salt -pass pass:"+config['passphrase']).read()
	os.unlink(randfile)
	return encstring

def nginx(ctl):
	global config, hostname
	if ctl == 'reload':
		#pidn = int(os.popen('ps aux | grep nginx | grep -v grep | wc -l').read().strip())
		#if pidn <= 0:
		#	log('OK', 'starting Nginx web server')
		#	os.popen('/usr/local/openresty/nginx/sbin/nginx -c /usr/local/openresty/nginx/conf/nginx.conf 2>&1')
		#else:
		log('OK', 'reloading Nginx configuration files')
		os.popen('docker exec -ti resty-crs /usr/local/openresty/nginx/sbin/nginx -c /usr/local/openresty/nginx/conf/nginx.conf -s reload 2>&1')

	if ctl == 'check':
		senderror = False
		configtest = os.popen('docker exec -ti resty-crs /usr/local/openresty/nginx/sbin/nginx -c /usr/local/openresty/nginx/conf/nginx.conf -t 2>&1').read().strip()
		if re.search('(failed|invalid|error)', configtest) is not None:
			senderror = True

		if senderror is True:
			log('ERROR', 'found errors on Nginx configuration files')
			requests.post('https://secthemall.com/api/waf', data={
				"username": config['username'],
				"apikey": config['apikey'],
				"a": "pusherror",
				"hostname": hostname,
				"nginx_error": urllib.quote_plus(configtest)
			})
		else:
			log('OK', 'Nginx configuration syntax ok')
			requests.post('https://secthemall.com/api/waf', data={
				"username": config['username'],
				"apikey": config['apikey'],
				"a": "pusherror",
				"hostname": hostname,
				"nginx_error": 0
			})

		return senderror

#def getip(mslog):
	# print mslog['transaction']['request']['headers']

#	if netaddr.IPAddress(mslog['transaction']['client_ip']).version == 4:
#		ipv = 'ipv4'
#	elif netaddr.IPAddress(mslog['transaction']['client_ip']).version == 6:
#		ipv = 'ipv6'
#	else:
#		return '127.0.0.1'
#
#
#	realip = mslog['transaction']['client_ip']
#	with open('/root/cwaf-client/client/inc/cf-'+ipv+'.txt', 'r') as fp:
#		for cfcidr in fp:
#			if netaddr.IPAddress(realip) in netaddr.IPNetwork(cfcidr.strip()):
#				realip = mslog['transaction']['request']['headers']['cf-connecting-ip']
#
#	return realip
