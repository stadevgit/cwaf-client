import sys, os, json, re, base64, time, shutil, pwd, grp
from HTMLParser import HTMLParser

html = HTMLParser()

cpath = os.path.dirname(os.path.abspath(__file__))
cfile = cpath+'/configurations.json'
c = json.load(open(cfile, 'r'))

for cname, carr in c['conf'].items():
        if carr['listen'].has_key('http'):
                if carr.has_key('fwd_uri'):
                        configout = "upstream "+cname+"-backend {\n"
                        for fw in carr['fwd_uri']:
                                configout += "\tserver "+fw+";\n"
                        configout += "}\n\n"

                configout += "server {\n"

                configout += "\tlisten "+carr['listen']['http']+";\n"

                servernames = ''
                if carr.has_key('server_aliases'):
                        for i in carr['server_aliases']:
                                servernames += i+' '

                        configout += "\tserver_name "+servernames+";\n\n"

                bodyfiltersflags = 'c'

                try:
                        if 'respbody' in carr and 'email' in carr['respbody'] and carr['respbody']['email'] == 1:
                                bodyfiltersflags += 'M'
                except:
                        print 'no respbody'


                try:
                        if 'respbody' in carr and 'error' in carr['respbody'] and carr['respbody']['error'] == 1:
                                bodyfiltersflags += 'E'
                except:
                        print 'no respbody'


                configout += "\tset $tmwBodyFunc \""+bodyfiltersflags+"\";\n\n"

		configout += "\tunderscores_in_headers on;\n\n"

                if carr.has_key('proxy_conf') is False:
                        configout += "\tproxy_buffer_size 5120;\n"
                        configout += "\tproxy_redirect off;\n"
                        configout += "\t#proxy_ssl_server_name on;\n"
                        configout += "\tproxy_set_header Host $host;\n"
                        configout += "\tproxy_set_header True-Client-IP $remote_addr;\n"
                        configout += "\tproxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
                        configout += "\tproxy_set_header Accept-Encoding \"\";\n"
                        configout += "\tproxy_set_header Proxy \"\";\n"
                        configout += "\tproxy_intercept_errors on;\n"
                else:
                        for pp,pv in carr['proxy_conf'].items():
                                configout += "\t"+pp+" "+pv+";\n"


                configout += "\n"

                configout += "\tgzip on;\n"
                configout += "\tgzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript application/javascript text/x-js;\n"

                configout += "\n"



                # error pages
                configout += u"\tset $customErr403 '" + re.sub("(\s+|\n|\r|\')", ' ', base64.decodestring(carr['error_pages']['403'])) + "';\n"
                configout += u"\tset $customErr404 '" + re.sub("(\s+|\n|\r|\')", ' ', base64.decodestring(carr['error_pages']['404'])) + "';\n"
                configout += u"\tset $customErr50x '" + re.sub("(\s+|\n|\r|\')", ' ', base64.decodestring(carr['error_pages']['50x'])) + "';\n"
                configout += u"\tset $customErrxxx '" + re.sub("(\s+|\n|\r|\')", ' ', base64.decodestring(carr['error_pages']['xxx'])) + "';\n"

                configout += "\n"

                configout += "\tmore_clear_headers 'X-Frame-Options';\n"
                configout += "\tmore_clear_headers 'X-Content-Type-Options';\n"
                configout += "\tmore_clear_headers 'X-XSS-Protection';\n"
                configout += "\tmore_clear_headers 'Content-Security-Policy';\n"
                configout += "\tmore_clear_headers 'Server';\n"
                configout += "\tmore_clear_headers 'X-Powered-By';\n"
                configout += "\tmore_clear_headers 'Content-Length';\n"

                configout += "\n"

                # add header
                if carr['modsec'].has_key('AddHeaders'):
                        for i in carr['modsec']['AddHeaders']:
                                fullheaders = html.unescape(base64.decodestring(i))
                                if re.search('^([a-zA-Z0-9\-\.]+)\: (.+)$', fullheaders):
                                        fharr = re.search('^([a-zA-Z0-9\-\.]+)\: (.+)$', fullheaders)
                                        configout += "\tadd_header "+fharr.group(1)+" '"+re.sub("\'", "", fharr.group(2))+"';\n"


                configout += "\n"


                # Google OAuth
                if carr.has_key('oauth') and carr['oauth'].has_key('google'):
                        if carr['oauth']['google'].has_key('client_id'):
                                configout += u"\tset $ngo_client_id \""+carr['oauth']['google']['client_id']+"\";\n"
                        if carr['oauth']['google'].has_key('client_secret'):
                                configout += u"\tset $ngo_client_secret \""+carr['oauth']['google']['client_secret']+"\";\n"
                        if carr['oauth']['google'].has_key('client_secret'):
                                configout += u"\tset $ngo_token_secret \""+carr['oauth']['google']['token_secret']+"\";\n"
                        if carr['oauth']['google'].has_key('cookies_secure') and carr['oauth']['google']['cookies_secure'] == 1:
                                configout += u"\tset $ngo_secure_cookies \"true\";\n"
                        else:
                                configout += u"\tset $ngo_secure_cookies \"false\";\n"

                        if carr['oauth']['google'].has_key('cookies_httponly') and carr['oauth']['google']['cookies_httponly'] == 1:
                                configout += u"\tset $ngo_http_only_cookies \"true\";\n"
                        else:
                                configout += u"\tset $ngo_http_only_cookies \"false\";\n"


                        configout += u"\n\tlocation = /_oauth {\n"
                        configout += u"\t\taccess_by_lua_file \"/usr/local/openresty/nginx/google-oauth/access.lua\";\n"
                        configout += u"\t}\n\n"

                        if carr['oauth']['google'].has_key('users') and type(carr['oauth']['google']['users']) is not list:
                                for k,v in carr['oauth']['google']['users'].items():
                                        # servernames

                                        gouser = ''
                                        for vv in v:
                                                gouser += base64.decodestring(vv)+" "

                                        configout += u"\tlocation = "+base64.decodestring(k)+" {\n"
                                        configout += u"\t\tset $ngo_domain \""+servernames.strip()+"\";\n"
                                        configout += u"\t\tset $ngo_whitelist \""+gouser.strip()+"\";\n"
                                        configout += u"\t\taccess_by_lua_file \"/usr/local/openresty/nginx/google-oauth/access.lua\";\n"
                                        configout += u"\t\tproxy_pass "+carr['fwd_proto']+"://"+cname+"-backend;\n"
                                        configout += u"\t}\n\n"



                # Google 2fa
                if carr.has_key('2fa') and carr['2fa'].has_key('google') and carr['2fa']['google'].has_key('locations'):
                        configout += u"\tencrypted_session_key '"+base64.decodestring(carr['2fa']['google']['encrypted_session_key']).replace("'","q")+"';\n"
                        configout += u"\tencrypted_session_iv '"+base64.decodestring(carr['2fa']['google']['encrypted_session_iv']).replace("'","q")+"';\n"
                        configout += u"\tencrypted_session_expires "+str(carr['2fa']['google']['session_expires'])+";\n"

                        if type(carr['2fa']['google']['locations']) is not list:
                                for k,v in carr['2fa']['google']['locations'].items():
                                        configout += u"\tlocation = "+base64.decodestring(k)+" {\n"
                                        configout += u"\t\tdefault_type 'text/html';\n"
                                        configout += u"\t\tset $secret '"+base64.decodestring(v['secret']).replace("'","Q")+"';\n"
                                        configout += u"\t\tset $allowreq 0;\n\n"

                                        configout += u"\t\tset_decode_base32 $encg2fasessid $cookie_g2fasessid;\n"
                                        configout += u"\t\tset_decrypt_session $plaing2fasessid $encg2fasessid;\n\n"

                                        configout += '''
                set_by_lua_block $allowreq {
                        if ngx.var.cookie_g2fasessid then
                                ts, src, ua = string.match(ngx.var.plaing2fasessid, "ts.(.+). src.(.+). ua.(.+)")
                                if src == ngx.var.remote_addr then
                                        if ua == ngx.var.http_user_agent then
                                                return 1
                                        end
                                end
                        end
                        return 0
                }

                if ($allowreq = 0) {
                        set_encrypt_session $token "ts=$time_iso8601, src=$remote_addr, ua=$http_user_agent";
                        set_encode_base32 $token;

                        content_by_lua_file /usr/local/openresty/nginx/google-2fa/2fa.lua;
                }

                if ($allowreq = 1) {
'''
                                        configout += u"\t\tproxy_pass "+carr['fwd_proto']+"://"+cname+"-backend;\n"
                                        configout += '''
                }
                                        '''
                                        configout += u"\t}\n\n"


                # Nginx additional config
                if carr.has_key('nginx_conf_by_user') and carr['nginx_conf_by_user'] != '':
                        configout += "\t# ------- BEGIN nginx additional config --------\n"
                        configout += html.unescape(base64.decodestring(carr['nginx_conf_by_user'])).replace(r'\r','')
                        configout += "\n\t# ------- END nginx additional config --------\n\n"

                # ReplaceContents
                configout += "\tlocation ~ /staReplaceContents/(.*) {\n"
                configout += "\t\troot /usr/local/openresty/nginx/html;\n"
                configout += "\t\trewrite ^/staReplaceContents/(.*)$ /ReplaceContents/$1 break;\n"
                configout += "\t}\n\n"

                configout += "\tlocation ~* /.*\.(ico|jpg|png|bmp|tiff|gif|svg|css|js|woff|woff2|eot|zip|7z|iso|pdf|doc|docx|xls|ppt|pptx)$ {\n"
                configout += "\t\tmodsecurity off;\n"
                configout += "\t\tproxy_pass "+carr['fwd_proto']+"://"+cname+"-backend;\n"
                configout += "\t}\n\n"

                # Proxy Pass
                configout += "\tlocation ~* /.* {\n"
                # modsecurity
                configout += "\t\tmodsecurity on;\n";
                configout += "\t\tmodsecurity_rules_file /usr/local/openresty/nginx/conf/modsecurity_config/"+cname+"/"+cname+";\n";
                configout += "\n";
                configout += "\t\tproxy_pass "+carr['fwd_proto']+"://"+cname+"-backend;\n"
                configout += "\t}\n"

                configout += "\n"

                # bodyfilters
                configout += "\tbody_filter_by_lua_file \"/usr/local/openresty/nginx/bodyfilters/default.lua\";\n"

                # end
                configout += "}"

                fc = open('/usr/local/openresty/nginx/conf/waf/'+cname, 'w')
                fc.write(configout)
                fc.close()
        else:
                if carr.has_key('fwd_uri'):
                        configout = "upstream "+cname+"-backend {\n"
                        for fw in carr['fwd_uri']:
                                configout += "\tserver "+fw+";\n"
                        configout += "}\n\n"

                configout += "server {\n"

                configout += "\tlisten "+carr['listen']['https']+" ssl;\n\n"

                configout += "\tssl on;\n"
                configout += "\tssl_protocols TLSv1.1 TLSv1.2;\n"
                configout += "\tssl_prefer_server_ciphers on;\n"
                configout += "\tssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';\n"
                configout += "\tssl_dhparam /root/ssl/dhparam.pem;\n"

		if carr.has_key('sslOverrideCrt') and carr.has_key('sslOverrideKey'):
			configout += "\tssl_certificate "+carr['sslOverrideCrt']+"; # override\n"
			configout += "\tssl_certificate_key "+carr['sslOverrideKey']+"; # override\n\n"
		else:
			configout += "\tssl_certificate /root/ssl/"+cname+"_fullchain.pem;\n"
			configout += "\tssl_certificate_key /root/ssl/"+cname+"_privkey.pem;\n\n"


                servernames = ''
                if carr.has_key('server_aliases'):
                        for i in carr['server_aliases']:
                                servernames += i+' '

                        configout += "\tserver_name "+servernames+";\n\n"

                bodyfiltersflags = 'c'
                #if 'respbody' in carr and 'email' in carr['respbody'] and carr['respbody']['email'] == 1:
                #       bodyfiltersflags += 'M'

                try:
                        if 'respbody' in carr and 'email' in carr['respbody'] and carr['respbody']['email'] == 1:
                                bodyfiltersflags += 'M'
                except:
                        print 'no respbody'


                try:
                        if 'respbody' in carr and 'error' in carr['respbody'] and carr['respbody']['error'] == 1:
                                bodyfiltersflags += 'E'
                except:
                        print 'no respbody'


                configout += "\tset $tmwBodyFunc \""+bodyfiltersflags+"\";\n\n"

		configout += "\tunderscores_in_headers on;\n\n"

                if carr.has_key('proxy_conf') is False:
                        configout += "\tproxy_cache_bypass 1;\n"
                        configout += "\tproxy_buffer_size 5120;\n"
                        configout += "\tproxy_redirect off;\n"
                        configout += "\tproxy_ssl_server_name on;\n"
                        configout += "\tproxy_set_header Host $host;\n"
                        configout += "\tproxy_set_header True-Client-IP $remote_addr;\n"
                        configout += "\tproxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
                        configout += "\tproxy_set_header Accept-Encoding \"\";\n"
                        configout += "\tproxy_set_header Proxy \"\";\n"
                        configout += "\tproxy_intercept_errors on;\n"
                else:
                        for pp,pv in carr['proxy_conf'].items():
                                configout += "\t"+pp+" "+pv+";\n"


                configout += "\n"

                configout += "\tgzip on;\n"
                configout += "\tgzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript application/javascript text/x-js;\n"

                configout += "\n"


                # error pages
                configout += u"\tset $customErr403 '" + re.sub("(\s+|\n|\r|\')", ' ', base64.decodestring(carr['error_pages']['403'])) + "';\n"
                configout += u"\tset $customErr404 '" + re.sub("(\s+|\n|\r|\')", ' ', base64.decodestring(carr['error_pages']['404'])) + "';\n"
                configout += u"\tset $customErr50x '" + re.sub("(\s+|\n|\r|\')", ' ', base64.decodestring(carr['error_pages']['50x'])) + "';\n"
                configout += u"\tset $customErrxxx '" + re.sub("(\s+|\n|\r|\')", ' ', base64.decodestring(carr['error_pages']['xxx'])) + "';\n"

                configout += "\n"

                configout += "\tmore_clear_headers 'X-Frame-Options';\n"
                configout += "\tmore_clear_headers 'X-Content-Type-Options';\n"
                configout += "\tmore_clear_headers 'X-XSS-Protection';\n"
                configout += "\tmore_clear_headers 'Content-Security-Policy';\n"
                configout += "\tmore_clear_headers 'Server';\n"
                configout += "\tmore_clear_headers 'X-Powered-By';\n"
                configout += "\tmore_clear_headers 'Content-Length';\n"

                configout += "\n"

                # add header
                if carr['modsec'].has_key('AddHeaders'):
                        for i in carr['modsec']['AddHeaders']:
                                fullheaders = html.unescape(base64.decodestring(i))
                                if re.search('^([a-zA-Z0-9\-\.]+)\: (.+)$', fullheaders):
                                        fharr = re.search('^([a-zA-Z0-9\-\.]+)\: (.+)$', fullheaders)
                                        configout += "\tadd_header "+fharr.group(1)+" '"+re.sub("\'", "", fharr.group(2))+"';\n"


                configout += "\n"


                # Google OAuth
                if carr.has_key('oauth') and carr['oauth'].has_key('google'):
                        if carr['oauth']['google'].has_key('client_id'):
                                configout += u"\tset $ngo_client_id \""+carr['oauth']['google']['client_id']+"\";\n"
                        if carr['oauth']['google'].has_key('client_secret'):
                                configout += u"\tset $ngo_client_secret \""+carr['oauth']['google']['client_secret']+"\";\n"
                        if carr['oauth']['google'].has_key('client_secret'):
                                configout += u"\tset $ngo_token_secret \""+carr['oauth']['google']['token_secret']+"\";\n"
                        if carr['oauth']['google'].has_key('cookies_secure') and carr['oauth']['google']['cookies_secure'] == 1:
                                configout += u"\tset $ngo_secure_cookies \"true\";\n"
                        else:
                                configout += u"\tset $ngo_secure_cookies \"false\";\n"

                        if carr['oauth']['google'].has_key('cookies_httponly') and carr['oauth']['google']['cookies_httponly'] == 1:
                                configout += u"\tset $ngo_http_only_cookies \"true\";\n"
                        else:
                                configout += u"\tset $ngo_http_only_cookies \"false\";\n"


                        configout += u"\n\tlocation = /_oauth {\n"
                        configout += u"\t\taccess_by_lua_file \"/usr/local/openresty/nginx/google-oauth/access.lua\";\n"
                        configout += u"\t}\n\n"

                        if carr['oauth']['google'].has_key('users') and type(carr['oauth']['google']['users']) is not list:
                                for k,v in carr['oauth']['google']['users'].items():
                                        # servernames

                                        gouser = ''
                                        for vv in v:
                                                gouser += base64.decodestring(vv)+" "

                                        configout += u"\tlocation = "+base64.decodestring(k)+" {\n"
                                        configout += u"\t\tset $ngo_domain \""+servernames.strip()+"\";\n"
                                        configout += u"\t\tset $ngo_whitelist \""+gouser.strip()+"\";\n"
                                        configout += u"\t\taccess_by_lua_file \"/usr/local/openresty/nginx/google-oauth/access.lua\";\n"
                                        configout += u"\t\tproxy_pass "+carr['fwd_proto']+"://"+cname+"-backend;\n"
                                        configout += u"\t}\n\n"


                # Google 2fa
                if carr.has_key('2fa') and carr['2fa'].has_key('google') and carr['2fa']['google'].has_key('locations'):
                        configout += u"\tencrypted_session_key '"+base64.decodestring(carr['2fa']['google']['encrypted_session_key']).replace("'","q")+"';\n"
                        configout += u"\tencrypted_session_iv '"+base64.decodestring(carr['2fa']['google']['encrypted_session_iv']).replace("'","q")+"';\n"
                        configout += u"\tencrypted_session_expires "+carr['2fa']['google']['session_expires']+";\n"

                        if type(carr['2fa']['google']['locations']) is not list:
                                for k,v in carr['2fa']['google']['locations'].items():
                                        configout += u"\tlocation = "+base64.decodestring(k)+" {\n"
                                        configout += u"\t\tdefault_type 'text/html';\n"
                                        configout += u"\t\tset $secret '"+base64.decodestring(v['secret']).replace("'","Q")+"';\n"
                                        configout += u"\t\tset $allowreq 0;\n\n"

                                        configout += u"\t\tset_decode_base32 $encg2fasessid $cookie_g2fasessid;\n"
                                        configout += u"\t\tset_decrypt_session $plaing2fasessid $encg2fasessid;\n\n"

                                        configout += '''
                set_by_lua_block $allowreq {
                        if ngx.var.cookie_g2fasessid then
                                ts, src, ua = string.match(ngx.var.plaing2fasessid, "ts.(.+). src.(.+). ua.(.+)")
                                if src == ngx.var.remote_addr then
                                        if ua == ngx.var.http_user_agent then
                                                return 1
                                        end
                                end
                        end
                        return 0
                }

                if ($allowreq = 0) {
                        set_encrypt_session $token "ts=$time_iso8601, src=$remote_addr, ua=$http_user_agent";
                        set_encode_base32 $token;

                        content_by_lua_file /usr/local/openresty/nginx/google-2fa/2fa.lua;
                }

                if ($allowreq = 1) {
'''
                                        configout += u"\t\tproxy_pass "+carr['fwd_proto']+"://"+cname+"-backend;\n"
                                        configout += '''
                }
                                        '''
                                        configout += u"\t}\n\n"



                # Nginx additional config
                if carr.has_key('nginx_conf_by_user') and carr['nginx_conf_by_user'] != '':
                        configout += "\t# ------- BEGIN nginx additional config --------\n"
                        configout += html.unescape(base64.decodestring(carr['nginx_conf_by_user']))
                        configout += "\n\t# ------- END nginx additional config --------\n\n"

                # ReplaceContents
                configout += "\tlocation ~ /staReplaceContents/(.*) {\n"
                configout += "\t\troot /usr/local/openresty/nginx/html;\n"
                configout += "\t\trewrite ^/staReplaceContents/(.*)$ /ReplaceContents/$1 break;\n"
                configout += "\t}\n\n"

                configout += "\tlocation ~* /.*\.(ico|jpg|png|bmp|tiff|gif|svg|css|js|woff|woff2|eot|zip|7z|iso|pdf|doc|docx|xls|ppt|pptx)$ {\n"
                configout += "\t\tmodsecurity off;\n"
                configout += "\t\tproxy_pass "+carr['fwd_proto']+"://"+cname+"-backend;\n"
                configout += "\t}\n\n"

                # Proxy Pass
                configout += "\tlocation ~* /.* {\n"
                # modsecurity
                configout += "\t\tmodsecurity on;\n";
                configout += "\t\tmodsecurity_rules_file /usr/local/openresty/nginx/conf/modsecurity_config/"+cname+"/"+cname+";\n";
                configout += "\n";
                configout += "\t\tproxy_pass "+carr['fwd_proto']+"://"+cname+"-backend;\n"
                configout += "\t}\n"

                configout += "\n"

                # bodyfilters
                configout += "\tbody_filter_by_lua_file \"/usr/local/openresty/nginx/bodyfilters/default.lua\";\n"

                # end
                configout += "}"

                fc = open('/usr/local/openresty/nginx/conf/waf/'+cname, 'w')
                fc.write(configout)
                fc.close()


        if os.path.isdir('/usr/local/openresty/nginx/conf/modsecurity_config/'+cname) is False:
                os.mkdir('/usr/local/openresty/nginx/conf/modsecurity_config/'+cname)

        modsecconf = open(cpath+'/config_templates/default', 'r').read().replace('%{REPLACE:CONFNAME}', cname)
        fc = open('/usr/local/openresty/nginx/conf/modsecurity_config/'+cname+'/'+cname, 'w')
        fc.write(modsecconf)
        fc.close()

        modsecconf = open(cpath+'/config_templates/default.override', 'r').read().replace('%{REPLACE:SecRuleEngine}', carr['modsec']['SecRuleEngine'])

	if 'ParanoiaLevel' in carr['modsec']:
		modsecconf = modsecconf+'\n\nSecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level='+str(carr['modsec']['ParanoiaLevel'])+'"'
        else:
		modsecconf = modsecconf+'\n\nSecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=1"'

        fc = open('/usr/local/openresty/nginx/conf/modsecurity_config/'+cname+'/'+cname+'.override', 'w')
        fc.write(modsecconf)
        fc.close()

        modsecconf = open(cpath+'/config_templates/default.custom.6000', 'r').read().replace('%{REPLACE:FileExt}', carr['modsec']['FileExt'].replace(' ', '|'))
        fc = open('/usr/local/openresty/nginx/conf/modsecurity_config/'+cname+'/'+cname+'.custom.6000', 'w')
        fc.write(modsecconf)
        fc.close()

        shutil.copy(cpath+'/config_templates/default.custom.6001', '/usr/local/openresty/nginx/conf/modsecurity_config/'+cname+'/'+cname+'.custom.6001')
        shutil.copy(cpath+'/config_templates/default.ignore', '/usr/local/openresty/nginx/conf/modsecurity_config/'+cname+'/'+cname+'.ignore')

        if carr['modsec'].has_key('override_by_user'):
                fc = open('/usr/local/openresty/nginx/conf/modsecurity_config/'+cname+'/'+cname+'.override.by.user', 'w')
                fc.write("# generated at "+str(time.time())+"\n\n"+html.unescape(base64.decodestring(carr['modsec']['override_by_user'])))
                fc.close()
        else:
                fc = open('/usr/local/openresty/nginx/conf/modsecurity_config/'+cname+'/'+cname+'.override.by.user')
                fc.write("# generated at "+str(time.time())+"\n\n")
                fc.close()


        if os.path.isdir('/usr/local/openresty/nginx/logs/modsecurity/'+cname) is False:
                os.mkdir('/usr/local/openresty/nginx/logs/modsecurity/'+cname)
                os.chown('/usr/local/openresty/nginx/logs/modsecurity/'+cname, pwd.getpwnam("nobody").pw_uid, grp.getgrnam("nogroup").gr_gid)
