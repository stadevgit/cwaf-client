#!/bin/bash

source /root/cwaf-client/inc/bash_colors.sh

echo "+"
echo -n "+ (::) "; clr_blackb "SEC" -n; clr_blueb "THEM" -n; clr_blackb "ALL"
echo "+"

if [ ! -f /root/cwaf-client/client/config.json ]; then
	labeler; echo " Please, run setup first: setup"
	exit 1
fi


# start nginx
labelin; echo " Starting nginx workers..."
/usr/local/openresty/nginx/sbin/nginx -c /usr/local/openresty/nginx/conf/nginx.conf
CHKPS=$(ps aux | grep 'nginx' | grep -v grep | wc -l)
if [ $CHKPS -gt 0 ]; then
	labelok; echo " Command sent, nginx is running."
else
	labeler; echo " Process not found, nginx is not running. Please, check nginx configuration."
	exit 1
fi

# start stub status
labelin; echo " Starting secthemall-status client..."
/usr/bin/python /root/cwaf-client/client/send_stub_status.py > /dev/null 2>&1 &
CHKPS=$(ps aux | grep 'send_stub_status' | grep -v grep | wc -l)
if [ $CHKPS -gt 0 ]; then
	labelok; echo " Command sent, secthemall-status client is running."
else
	labeler; echo " Process not found, secthemall-status client is not running."
	exit 1
fi

# start updates
labelin; echo " Starting secthemall-updates client..."
/usr/bin/python /root/cwaf-client/client/updates.py > /dev/null 2>&1 &
CHKPS=$(ps aux | grep 'updates' | grep -v grep | wc -l)
if [ $CHKPS -gt 0 ]; then
	labelok; echo " Command sent, secthemall-updates client is running."
else
	labeler; echo " Process not found, secthemall-updates client is not running."
	exit 1
fi

# start updates
labelin; echo " Starting secthemall-sendlog client..."
/usr/bin/python /root/cwaf-client/client/sendlogs.py > /dev/null 2>&1 &
CHKPS=$(ps aux | grep 'sendlogs' | grep -v grep | wc -l)
if [ $CHKPS -gt 0 ]; then
	labelok; echo " Command sent, secthemall-sendlogs client is running."
else
	labeler; echo " Process not found, secthemall-sendlogs client is not running."
	exit 1
fi

labelok; echo " Done."
echo ""
labelok; echo " Now you can login at: https://secthemall.com/waf/"
exit 0
