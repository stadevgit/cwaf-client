#!/bin/bash


for file in $(ls -1 /usr/local/openresty/nginx/logs/modsecurity/*/*/*/* 2>/dev/null); do
	log_config=$(echo $file | awk 'BEGIN{FS="/"}{print $8}')
	log_content=$(cat ${file})
	echo -en "${log_config}: ${log_content}\n"
	rm -rf ${file}
done

