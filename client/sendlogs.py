#!/usr/bin/env python

import requests, re, os, sys, pwd, grp, json, time, base64, urllib
import stapkg.functions as sta

hostname = os.popen('hostname').read().strip()
cpath = os.path.dirname(os.path.abspath(__file__))
cfile = cpath+'/configurations.json'
lastidfile = cpath+'/ids/lastid_config'
basedir = '/usr/local/openresty/nginx/logs/modsecurity'
hostip = os.popen("hostname -i").read().strip()

while True:
	c = json.load(open('/root/cWAF-client/client/config.json'))

	for root, subFolders, files in os.walk(basedir):
		for dir in subFolders:
			if re.search('^http', dir):
				stat = os.stat(basedir+'/'+dir)
				if pwd.getpwuid(stat.st_uid).pw_name != 'nobody' or grp.getgrgid(stat.st_gid).gr_name != 'nogroup':
					sta.log('WARNING', "bad owner on log directory: "+dir)
					sta.log('WARNING', "actual owner username: "+pwd.getpwuid(stat.st_uid).pw_name+", group: "+grp.getgrgid(stat.st_gid).gr_name)
					os.chown(basedir+'/'+dir, pwd.getpwnam("nobody").pw_uid, grp.getgrnam("nogroup").gr_gid)
					sta.log('OK', 'ownership changed to nobody:nogroup for '+dir)
		for file in files:
			logfile = os.path.join(root, file)
			sta.log('INFO', 'parsing logfile '+logfile)
			res = json.load(open(logfile, 'r'))
			#print res

			for k,v in res['transaction']['request']['headers'].items():
				del res['transaction']['request']['headers'][k]
				res['transaction']['request']['headers'][k.lower()] = v
	
			wlog = {
				'hostname': base64.encodestring(hostname),
				'dip': base64.encodestring(hostip),
				'confname': root.split('/')[7]
			}

			wlog['ip'] = sta.getip(res)
			wlog['req'] = res['transaction']['request']
			wlog['req']['headers'] = json.dumps(res['transaction']['request']['headers'])

			wlog['res'] = {
				'http_code': res['transaction']['response']['http_code']
			}

			wlog['eid'] = res['transaction']['id'].replace('.','')

			wlog['unixts'] = int(str(time.mktime(time.strptime(res['transaction']['time_stamp'][4:], "%b %d %H:%M:%S %Y")))[0:-2])
			wlog['unixtsms'] = (wlog['unixts'] * 1000)

			wlog['tags'],wlog['ruleid'],wlog['messages'] = ([],[],[])
			if res['transaction'].has_key('messages'):
				for msg in res['transaction']['messages']:
					if msg.has_key('details'):
						if msg['details'].has_key('tags'):
							for tag in msg['details']['tags']:
								wlog['tags'].append(tag)
						if msg['details'].has_key('ruleId'):
							wlog['ruleid'].append(msg['details']['ruleId'])

					if msg.has_key('message'):
						wlog['messages'].append(msg['message'])


			wlog['secrules_engine'] = res['transaction']['producer']['secrules_engine']

			severity='low'
			if re.search('^(2\d\d|3\d\d|40[0-2])$', str(wlog['res']['http_code'])) and len(wlog['ruleid']) > 0:
				severity='medium'
			elif wlog['res']['http_code'] == 404 and len(wlog['ruleid']) > 0:
				severity='low'
			elif re.search('^(403|40[5-9]|5\d\d)$', str(wlog['res']['http_code'])) and len(wlog['ruleid']) > 0:
				severity='high'

			wlog['severity'] = severity


			enclogs = urllib.quote_plus(str(sta.encrypt(json.dumps(wlog))))

			r = requests.post('https://wl.secthemall.com/api_waf.php', data = {'a':'writelog', 'type':'waf', 'username':c['username'], 'tz':c['usertz'], 'apikey':c['apikey'], 'logs':enclogs})

			#print r
			os.unlink(logfile)

	sta.log('INFO', 'sleeping...')
	time.sleep(5)

