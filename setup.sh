#!/bin/bash

source /root/cWAF-client/inc/bash_colors.sh

echo "+"
echo -n "+ (::) "; clr_blackb "SEC" -n; clr_blueb "THEM" -n; clr_blackb "ALL"
echo "+"

if [ -f /root/cWAF-client/client/config.json ]; then
	labelwa; echo -n " Configuration already exists. Do you want to overwrite it? [y/N]: "
	read ans

	if [ -z $ans ]; then
		echo "+ exit"
		exit 0
	else
		if [ $ans = y -o $ans = Y -o $ans = yes -o $ans = Yes -o $ans = YES ]; then
			echo "+ Configuring a new WAF node"
		else
			echo "+ exit"
			exit 0
		fi
	fi
else
	touch /root/cWAF-client/client/config.json
	mkdir /root/cWAF-client/client/ids
	touch /root/cWAF-client/client/ids/lastid_config
fi

dpkg-reconfigure tzdata 2>/dev/null

echo "+"
echo "+ (::) SECTHEMALL User Authentication"
echo "+"
echo "+      Sign Up: https://secthemall.com/signup/"
echo "+      Login:   https://secthemall.com/dashboard/"
echo "+"
echo ""
labelin; echo " Please, insert your secthemall.com Username and Password"
echo -en "+\n+ Username: "
read USERNAME
echo -en "+ Password: "
read -s PASSWORD

ENCODEDPASSWD=$(echo ${PASSWORD} | sed -e 's/"/\"/g' |sed -e 's/&/%26/g')
USERID=$(curl -s -d "a=auth&username=${USERNAME}&password=${ENCODEDPASSWD}&alias=${SERVERALIAS}" 'https://secthemall.com/auth/')

if [[ "${USERID:0:2}" == "ok" ]]; then
	APIKEY=${USERID:74}
fi

echo ""
python /root/cWAF-client/client/updates.py "${USERNAME}" "${APIKEY}"

# se non esiste
#if [ ! -f /root/ssl/dhparam.pem ]; then
#	labelin; echo " Generating dhparam.pem certificate. Sorry, this can take a while..."
#	openssl dhparam -out /root/ssl/dhparam.pem 4096
#fi

labelok; echo " Done."
labelok; echo " Now, type: start"
exit 0
