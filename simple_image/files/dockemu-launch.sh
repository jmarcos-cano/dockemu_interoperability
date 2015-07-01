#!/bin/bash

interface="eth0"

wait_interface(){
	delay=5
	FOUND=`grep $interface /proc/net/dev`

	while  [ ! -n "$FOUND" ] ;do
		echo "$interface not present yet, waiting $delay seconds"
		FOUND=`grep $interface /proc/net/dev`
		sleep $delay
	done
	echo "$interface PRESENT"
	#solo si es olsr
	#/sbin/ifconfig eth0 inet6 add 2001:0db8:0:f101::$count/64 
}


wait_interface

/sbin/ifconfig $interface inet6 add 2001:0db8:0:f101::$count/64 


git clone git@bitbucket.org:josealfredo1515/interopframework.git /python

#/usr/sbin/olsrd  -i $interface -nofork -d 1 -ipv6



/usr/bin/supervisord -c /etc/supervisor/supervisord.conf -n
