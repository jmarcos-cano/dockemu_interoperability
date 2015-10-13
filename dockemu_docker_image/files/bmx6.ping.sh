#!/bin/bash
count=5
every=5
while : ;do  
	
	#bmx6 connect  show=originators  |awk '{print $3}'|xargs -i ping6 -c $count {}
	bmx6 connect  show=originators |awk '$4 != 0 { print $3 }'|xargs -i ping6 -c $count {}
	sleep $every
done