#!/bin/bash

rm -rvf /usr/local/openresty/nginx/logs/modsecurity/http*
rm -rvf /usr/local/openresty/nginx/conf/modsecurity_config/*
rm -rvf /usr/local/openresty/nginx/conf/bl/*
rm -rvf /usr/local/openresty/nginx/logs/*.log
rm -rvf /root/cwaf-client/client/ids/*
rm -rvf /root/cwaf-client/client/*.json
rm -rvf /usr/local/openresty/nginx/conf/waf/*
