#!/bin/bash

interface="eth0"
type=${1:-"olsr"}


if [ "$type" == "olsr" ];then
	echo "OLSR"
elif [ "$type" == "bmx6" ];then
	echo "BMX6"
else 
	echo "wrong"
fi


exit



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

if [  "$half"  -eq "0" ];then
	/sbin/ifconfig $interface inet6 add 2001:0db8:0:f101::$count/64 
else
	/sbin/ifconfig $interface inet6 add 2002:0db8:0:f101::$count/64 
fi


git clone git@bitbucket.org:josealfredo1515/interopframework.git /python

#/usr/sbin/olsrd  -i $interface -nofork -d 1 -ipv6



/usr/bin/supervisord -c /etc/supervisor/supervisord.conf -n
