#!/bin/bash

route -A inet6 |grep eth0 |grep UG |awk '{print $1}' |tr "/" " "|awk '{print $1}'|xargs -i ping6  -c 4 {} 