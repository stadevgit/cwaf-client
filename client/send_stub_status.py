#!/usr/bin/env python

import requests, re, os, sys, json, time, base64, urllib
import stapkg.functions as sta

hostip = os.popen("hostname -i").read().rstrip()
hostname = os.popen('hostname').read().rstrip()
cpath = os.path.dirname(os.path.abspath(__file__))

while True:
	cfile = cpath+'/configurations.json'
	lastidfile = cpath+'/ids/lastid_config'
	c = json.load(open('/root/cwaf-client/client/config.json'))

	log = {
		'hostname': base64.encodestring(hostname).rstrip(),
		'ip': base64.encodestring(hostip).rstrip(),
		'unixtsms': int(round(time.time() * 1000))
	}

	r = requests.get("http://127.0.0.1/secthemallnginxstatus")
	for i in r.text.split("\n"):
		# print i
		if re.search('Active connections\: ([0-9]+)', i):
			log['active_connections'] = int(re.search('Active connections\: ([0-9]+)', i).group(1))

		if re.search('([0-9]+) ([0-9]+) ([0-9]+)', i):
			ahr = re.search('([0-9]+) ([0-9]+) ([0-9]+)', i)
			log['server_accepts'] = int(ahr.group(1))
			log['server_handled'] = int(ahr.group(2))
			log['server_requests'] = int(ahr.group(3))

		if re.search('Reading\: ([0-9]+) Writing\: ([0-9]+) Waiting\: ([0-9]+)', i):
			rww = re.search('Reading\: ([0-9]+) Writing\: ([0-9]+) Waiting\: ([0-9]+)', i)
			log['reading'] = int(rww.group(1))
			log['writing'] = int(rww.group(2))
			log['waiting'] = int(rww.group(3))

	enclogs = urllib.quote_plus(sta.encrypt(str(json.dumps(log))))
	r = requests.post('https://wl.secthemall.com/api/waf', data = {'a':'writelog', 'type':'stub_status', 'username':c['username'], 'tz':c['usertz'], 'apikey':c['apikey'], 'logs':enclogs})

	print r

	if r.text:
		print r.text
		sta.log('OK', 'statistic logs sent to console')

	sta.log('INFO', 'sleep 10 minutes')
	time.sleep(600)

