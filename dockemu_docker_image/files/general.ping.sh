#!/bin/bash

count=5
every=5
while : ;do  
	echo "** MY IP: **" $(ifconfig |grep "inet6 addr:" |grep "Scope:Global"|awk '{print $3}')
	route -A inet6 |grep eth0 |grep UG |awk '{print $1}' |tr "/" " "|awk '{print $1}'|xargs -i ping6  -c $count {} 
	sleep $every
done