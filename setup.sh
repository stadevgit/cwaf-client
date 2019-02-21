#!/bin/bash

MY_PATH="`dirname \"$0\"`"              # relative
MY_PATH="`( cd \"$MY_PATH\" && pwd )`"  # absolutized and normalized

source $MY_PATH/inc/bash_colors.sh

echo "+"
echo -n "+ (::) "; clr_blackb "SEC" -n; clr_blueb "THEM" -n; clr_blackb "ALL"
echo "+"

if [ -f $MY_PATH/client/config.json ]; then
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
	touch $MY_PATH/client/config.json
	mkdir $MY_PATH/client/ids
	touch $MY_PATH/client/ids/lastid_config
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

SERVERALIAS=$(hostname)

ENCODEDPASSWD=$(echo ${PASSWORD} | sed -e 's/"/\"/g' |sed -e 's/&/%26/g')
USERID=$(curl -s -d "a=auth&username=${USERNAME}&password=${ENCODEDPASSWD}&alias=${SERVERALIAS}" 'https://secthemall.com/auth/')

if [[ "${USERID:0:2}" == "ok" ]]; then
	APIKEY=${USERID:74}

	echo ""
	python $MY_PATH/client/updates.py "${USERNAME}" "${APIKEY}"

	labelok; echo " Done."
	labelok; echo " Now you can start this container."
fi

# se non esiste
#if [ ! -f /root/ssl/dhparam.pem ]; then
#	labelin; echo " Generating dhparam.pem certificate. Sorry, this can take a while..."
#	openssl dhparam -out /root/ssl/dhparam.pem 4096
#fi


