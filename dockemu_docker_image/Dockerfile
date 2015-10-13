FROM ubuntu:14.04
MAINTAINER <marcos cano jmarcos.cano@gmail.com>

## INSTALL OLSR
RUN apt-get update 
RUN apt-get update  && apt-get install -y iperf olsrd  
RUN apt-get install -y git-core make traceroute
RUN apt-get install -y python-pcs build-essential supervisor nmap gcc ibpcap0.8-dev python python-dev python-setuptools python-netifaces python-pip
RUN pip install pcapy 
RUN apt-get install screen -y


## SINTALL BMX6
RUN git clone git://qmp.cat/bmx6.git
RUN cd bmx6 && make && make install


ADD supervisor/supervisord.conf /etc/supervisor/supervisord.conf
ADD supervisor/programs.conf /etc/supervisor/conf.d/programs.conf

ADD files/* /
RUN chmod +x /*.sh
RUN chmod +x /dockemu-launch.sh
RUN  chmod +x /*.py

ADD files/id_rsa /root/.ssh/id_rsa
RUN chmod 600 /root/.ssh/id_rsa
RUN printf "Host bitbucket.org\n\tStrictHostKeyChecking no\n" >> ~/.ssh/config

ENV wait_for_it 0


ENTRYPOINT ["/dockemu-launch.sh"]







#CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf" ,"-n"]


#CMD ["-t", "BMX6"] 

#./bmx6 debug=0 dev=eth0
# olsrd -f /etc/olsrd/olsrd.conf -i eth0 -nofork
