#!/usr/bin/env python

import requests, re, os, sys, json, time
import stapkg.functions as sta
from requests.auth import HTTPBasicAuth

hostname = os.popen('hostname').read().rstrip()
cpath = os.path.dirname(os.path.abspath(__file__))

nginxpath = '/usr/local/openresty/nginx'
cfile = cpath+'/configurations.json'
lastidfile = cpath+'/ids/lastid_config'
lastidbl = cpath+'/ids/lastid_bl'
lastidtor = cpath+'/ids/lastid_tor'
blfile = nginxpath+'/conf/bl/modsecurity_bad_reputation.txt'
torfile = nginxpath+'/conf/bl/modsecurity_tor_exit_nodes.txt'


def startUpdate():
	# remove all empty log dirs
	os.popen('find /usr/local/openresty/nginx/logs/modsecurity/http*/* -type d -empty -exec rm -rvf {} \; 2>/dev/null')

	# load json config file
	c = json.load(open('/root/cwaf-client/client/config.json'))

	r = requests.post('https://secthemall.com/api/waf', {'username':c['username'], 'apikey':c['apikey'], 'a':'getupdates', 'hostname':hostname.rstrip()})
	print r
	res = json.loads(r.text)
	# finire getupdates (serve per reload conf nginx)
	if res.has_key('ok'):
		for v in res['ok']:
			if v == 'reload':
				sta.log('OK', 'received *reload* command from console')
				sta.nginx('reload')
	else:
		sta.log('INFO', 'No updates received for nginx processes')


	sta.log('INFO', 'Looking for configuration updates...')
	downloadconf = False
	r = requests.post('https://secthemall.com/api/waf', {'username':c['username'],'apikey':c['apikey'],'a':'configupdates','hostname':hostname})
	cupdate = json.loads(r.text)

	if cupdate.has_key('lastid'):
		if os.path.isfile(lastidfile):
			if open(lastidfile).read().strip() != str(cupdate['lastid']):
				downloadconf = True
		else:
			downloadconf = False
	else:
		downloadconf = True

	if downloadconf:
		sta.log('OK', 'Downloading configuration updates: '+str(cupdate['lastid']))
		# update lastid file
		f = open(lastidfile, 'w')
		f.write(str(cupdate['lastid']))
		f.close()

		# update config file
		f = open(cfile, 'w')
		f.write(r.text)
		f.close()

		os.system('python '+cpath+'/genConfig.py')
		#sta.nginx('reload')
	else:
		sta.log('INFO', 'No configuration updates')


		

	# get blacklist updates
	# ----------------------
	sta.log('INFO', 'Looking for blacklist updates...')
	downloadbl = False
	r = requests.post('https://secthemall.com/api/waf', {'username':c['username'], 'apikey':c['apikey'], 'a':'getblacklist', 'lastid':'1', 'hostname':hostname})
	res = json.loads(r.text)
	# print '--- bl md5: '+res['lastid']

	if os.path.isfile(lastidbl):
		if open(lastidbl).read().strip() != str(res['lastid']):
			downloadbl = True
		else:
			downloadbl = False
	else:
		downloadbl = True


	if downloadbl:
		sta.log('OK', 'Downloading blacklist updates: '+str(res['lastid']))

		# write lastid
		f = open(lastidbl, 'w')
		f.write(str(res['lastid']))
		f.close()

		# write ip list
		r = requests.post('https://secthemall.com/api/waf', {'username':c['username'], 'apikey':c['apikey'], 'a':'getblacklist', 'hostname':hostname})
		res = json.loads(r.text)
		f = open(blfile, 'w')
		f.write('\n'.join(res).strip())
		f.close()

		# reload nginx
		#sta.nginx('reload')




	# get tor exit nodes updates
	# --------------------------
	sta.log('INFO', 'Looking for Tor Exit Nodes updates...')
	downloadtor = False
	r = requests.get('https://secthemall.com/public-list/tor-exit-nodes/json/', {'lastid':'true'})
	res = json.loads(r.text)

	if os.path.isfile(lastidtor):
		if open(lastidtor).read().strip() != str(res['lastid']):
			downloadtor = True
		else:
			downloadtor = False
	else:
		downloadtor = True


	if downloadtor:
		sta.log('OK', 'Downloading Tor Exit Nodes updates: '+str(res['lastid']))

		# write lastid
		f = open(lastidtor, 'w')
		f.write(str(res['lastid']))
		f.close()

		# write ip list
		r = requests.post('https://secthemall.com/public-list/tor-exit-nodes/iplist/', {'size':10000}, auth=HTTPBasicAuth(c['username'], c['apikey']))
		f = open(torfile, 'w')
		f.write(r.text.strip())
		f.close()

		# reload nginx
		#sta.nginx('reload')





	# check Nginx status
	sta.log('INFO', 'Check Nginx configuration syntax...')
	if sta.nginx('check'):
		sta.log('ERROR', 'Nginx syntax error, pushed to console')
	else:
		sta.log('OK', 'No errors found in Nginx config file')

		if downloadtor or downloadbl or downloadconf:
			sta.nginx('reload')





try:
	sys.argv[1]
	sys.argv[2]
except:
	while True:
		startUpdate()
		time.sleep(60)
else:
	if re.search('^\S+\@[a-zA-Z0-9\-\_\.]+$', sys.argv[1]) is not None and re.search('^[a-z0-9]+$', sys.argv[2]) is not None:
		email = sys.argv[1]
		apikey = sys.argv[2]
		r = requests.post('https://secthemall.com/api/waf', data={"username":email, "apikey":apikey, "a":"getpassphrase"})
		res = json.loads(r.text)

		if res['ok'] is not None:
			config = {
				"username":email,
				"apikey":apikey,
				"passphrase":res['ok'],
				"usertz":res['usertz']
			}

			with open('/root/cwaf-client/client/config.json', 'w') as f:
				json.dump(config, f)

			sta.log('OK', "Creating / Checking node "+hostname+"...")
			r = requests.post('https://secthemall.com/api/waf', data={"username":email, "apikey":apikey, "a":"new", "hostname":hostname})
			# print r.text

			resjson = json.loads(r.text)
			try:
				resjson['ok']
			except:
				sta.log('ERROR', resjson['error'])
				sys.exit(0)
			else:
				sta.log('OK', resjson['ok'])
				sys.exit(0)

			# sta.nginx('reload')
