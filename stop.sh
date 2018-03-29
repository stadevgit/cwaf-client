#!/bin/bash

source /root/cWAF-client/inc/bash_colors.sh

echo "+"
echo -n "+ (::) "; clr_blackb "SEC" -n; clr_blueb "THEM" -n; clr_blackb "ALL"
echo "+"

labelin; echo " Stop nginx workers..."
/usr/local/openresty/nginx/sbin/nginx -c /usr/local/openresty/nginx/conf/nginx.conf -s stop

labelin; echo " Stop secthemall client..."
kill `pidof python` 2>/dev/null

labelok; echo " Done."
