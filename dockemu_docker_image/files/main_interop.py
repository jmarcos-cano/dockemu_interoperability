''''
Author: Preng Biba
Correo: prengsen@galileo.edu
Version: 1.0.0.0
'''
##import Table_Manage
#instalar sudo apt-get install python-dev
#instalar apt-get install python-setuptools
#instalar netifaces python

import socket
from struct import *
import datetime
import pcapy
import sys
import netifaces
import time
import pcs
import thread

from pcs.packets.ipv6 import *
from pcs.packets.icmpv6 import *
from pcs.packets.ethernet import *
from pcs.packets.payload import *


addrs = ''
global_command = ''
#function to insert into table
def insert_route(local_addr, global_addr, route_list):
	exist = 0
	for element in route_list:
		#print str(element['global']) + '-' + str(global_addr)
		#print exist
		if(str(element["global"]) == str(global_addr)): 
			exist = 1
	if(exist == 0):
		index = len(route_list)
		route = {"Index": index, "local":local_addr, "global":global_addr}
		route_list.append(route)
		print '\n--update--'
		show_table(route_list)
		#print route_list
	
def show_table(route_list):
	for element in route_list:
		#print element
		print( "|" + str(element["Index"]) + "|" + str(element["local"]) + "|"+ str(element["global"]) + "|")

##Function to create ICMPv6 Packet for proactive aproach	
def setup_rules(iface):
	os.system('ip6tables -F')
	os.system('ip6tables -A INPUT -i ' + iface + ' -p ipv6-icmp --icmpv6-type echo-request -j DROP')

#interoperability packet format thread
def interop_beacon_generator(iface, pkt_type, sleep_time):
	while(True):
		time.sleep(sleep_time)
		pcap = pcs.PcapConnector(iface,64,True,500)
		pkt = ICMPv6_pack_message(iface,0)
		#print 'Basic Interop Packet Send\r'
		pcap.write(pkt.bytes, len(pkt.bytes)) #send
		pcap.close()

#packet generator	
def ICMPv6_pack_message(iface, pkt_type):
	
	#procedure to get iface address
	#iface = 'wlan2' #interface
	addrs = netifaces.ifaddresses(iface)
	ll_src_addr = addrs[netifaces.AF_INET6][1]['addr']
	ll_src_addr = ll_src_addr[:ll_src_addr.find('%')]
	
	gl_src_addr = addrs[netifaces.AF_INET6][0]['addr']
	#gl_src_addr = gl_src_addr[:gl_src_addr.find('%')]
	
	#print gl_src_addr
	#print ll_src_addr
	# building ethernet header
	e = ethernet()
	mac = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr'] #geting mac addr
	e.src = ether_atob(mac)
	e.dst = ether_atob('ff:ff:ff:ff:ff:ff')
	e.type = 0x86dd #ETHERTYPE_IPV6
	
	#building ipv6 packet basic info
	ip6 = ipv6()
	ip6.version = 6
	#cs = icmp6.cksum(ip6) & 0xffff
	# building ipv6 header
	ip6.traffic_class = 0x0a
	ip6.flow = 0
	ip6.length = 50
	ip6.next_header = 58#IPPROTO_ICMPV6
	ip6.hop = 255
	ip6.src = pcs.inet_pton(AF_INET6, ll_src_addr)
	ip6.dst = pcs.inet_pton(AF_INET6, 'ff02::1')
	
	# building icmpv6
	icmp6 = icmpv6(ICMP6_ECHO_REQUEST) #ICMP6_ECHO_REPLY
	icmp6.code = 0
	icmp6.seq  = 0
	icmp6.id = 0x03e8
	icmp6.checksum = 0x0 #kt.calc_checksums()
	
	data = payload(payload = gl_src_addr) #message data
	ip6.length = len(icmp6.getbytes()) + len(data) #recalculation of packet length
	if(pkt_type == 0):
		icmp6.cheksum = 0xf220
		ip6.traffic_class = 0x0a
		pkt = pcs.Chain([e, ip6, icmp6, data]) #appendin packet
	else:
		icmp6.checksum = 0xe91b
		ip6.traffic_class = 0x0f
		pkt = pcs.Chain([e, ip6, icmp6]) #appendin packet
	#icmp6.checksum = pkt.calc_checksums()
	pkt.encode()
	#print pkt
	return pkt
	
def IPv6_Addr_Display(addr) :
	b = "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x" % (ord(addr[0]) , ord(addr[1]) , ord(addr[2]), ord(addr[3]), ord(addr[4]) , ord(addr[5]), ord(addr[6]), ord(addr[7]), ord(addr[8]), ord(addr[9]), ord(addr[10]), ord(addr[11]), ord(addr[12]), ord(addr[13]), ord(addr[14]), ord(addr[15]))
	return b
		
#Function to parse a packet
def parse_packet(cap, pcap, iface, table):
	#getting linklocal addres
	addrs = netifaces.ifaddresses(iface)
	gl_src_addr = addrs[netifaces.AF_INET6][0]['addr']
	#gl_src_addr = gl_src_addr[:gl_src_addr.find('%')]
	
	ll_src_addr = addrs[netifaces.AF_INET6][0]['addr']
	ll_src_addr = ll_src_addr[:ll_src_addr.find('%')]
	
	#print gl_src_addr
	while(True):
		#PARSEO DE MAC HEADER
		(header, packet) = cap.next()
		mac_header_length = 14 #largo del MAC header
		mac_header = packet[0:mac_header_length] #obtenemos seccion encabezado
		mack_header_data = unpack('!6s6sH', mac_header) #desempaquetamos y formateamos mac header(Big Endian, string de 6, string de 6, Entero)
		eth_type = socket.ntohs(mack_header_data[2]) #obtenemos Ethernet Type
		packet_outs = ['', '']
		#print 'MAC HEADER>>'
		admited = 0
		#print 'Source MAC: ' + MAC_Addr_Display(mack_header_data[0]) #Direccion MAC de fuente
		#print 'Destination MAC: ' + MAC_Addr_Display(mack_header_data[1]) #Direccion MAC de destino
		#print 'Protocol Type: ' + str(eth_type) + ' => ' +  str(hex(eth_type)) #Eth Type en hex
		if eth_type == 56710:
			#Parse IP header
			#take first 20 characters for the ip header
			ip_header = packet[mac_header_length:mac_header_length+40] #obtenemos info hasta Flow Label
			header_data = unpack('!BBHHBB16s16s', ip_header)#!BBHHHBBH4s4s
			version = header_data[0]
			Traffic_Class = header_data[1]
			Flow_Label = header_data[2]
			Payload_Len = header_data[3]
			Next_Header = header_data[4]
			Hop_Limit = header_data[5]
			Source_Addr = header_data[6]
			Destination_Addr = header_data[7]
			#Determinar el tipo de protocolo del paquete. 
			#if(Next_Header != 58):
				#print str(Next_Header)
			
			
			#print 'Version IPv' + str(version>>4) 
			#print 'Traffic Class: ' + hex(Traffic_Class)
			#print 'Flow Label: ' + hex(Flow_Label)
			#print 'Payload Length: ' + str(Payload_Len)
			#print 'Next Header: ' + str(Next_Header) + ' Proto Type: ' + Protocol_str   
			#print 'Hop Limit: ' + str(Hop_Limit) 
			#print 'Source Address: ' + str(IPv6_Addr_Display(Source_Addr))
			#print 'Destination Address: ' + str(IPv6_Addr_Display(Destination_Addr))
			if(Next_Header == 58):
				#print  'Next_Header: ' + str(Next_Header)
				#print 'Capture #' + str(i)
				#print 'MAC HEADER>>'
				#print 'Source MAC: ' + MAC_Addr_Display(mack_header_data[0]) #Direccion MAC de fuente
				#print 'Destination MAC: ' + MAC_Addr_Display(mack_header_data[1]) #Direccion MAC de destino
				#print 'Protocol Type: ' + str(eth_type) + ' => ' +  str(hex(eth_type)) #Eth Type en hex
				#print 'Version IPv' + str(version>>4) 
				#print 'Traffic Class: ' + hex(Traffic_Class)
				#print 'Flow Label: ' + hex(Flow_Label)
				#print 'Payload Length: ' + str(Payload_Len)
				#print 'Next Header: ' + str(Next_Header) + ' Proto Type: ' + Protocol_str   
				#print 'Hop Limit: ' + str(Hop_Limit) 
				#print 'Source Address: ' + str(IPv6_Addr_Display(Source_Addr))
				#print 'Destination Address: ' + str(IPv6_Addr_Display(Destination_Addr))
				payload_icmpv6_index = mac_header_length+40
				payload = packet[payload_icmpv6_index:payload_icmpv6_index+8]
				payload_data = unpack('!BBHHH', payload)
				Type = payload_data[0]
				Code = payload_data[1]
				Checksum = payload_data[2]
				Identifier = payload_data[3]
				Sequence = payload_data[4]
				#print 'Type: ' + str(Type)
				#print 'Code: ' + str(Code)
				#print 'Checksum: ' + hex(Checksum)
				#print 'Identifier: ' + hex(Identifier)
				#print 'Sequence: ' + str(Sequence) 
				message_data =  packet[payload_icmpv6_index+8:]
				if(message_data != gl_src_addr):
					if((Traffic_Class == 0xf0)):	
						#pkt = ICMPv6_pack_message(iface, 0)
						#pcap.write(pkt.bytes, len(pkt.bytes)) #sending packet
						#print 'interoperability beacon respons send'
						insert_route(str(IPv6_Addr_Display(Source_Addr)), message_data, table)
						Traffic_Class = 0x00
					elif(Traffic_Class == 0x00):
						reg = 0 #NOP :P
					else: #revisar para dejar solo con oxof y oxo
						#print message_data
						insert_route(str(IPv6_Addr_Display(Source_Addr)), message_data, table)
						#show_table(table)
				
#function to send messague througth socket										
def write_socket_(route_list):
	while(True):
		try:
			print 'Ready to send\n'
			str_msg = raw_input('\nMessage to Send (msg_str to_X) #> ')
			str_to_send = str_msg[:str_msg.find('to_')-1] #estracting message
			recive_node = str_msg[str_msg.find('_')+1:] #extracting node index
			global_command = str_msg
			if(str_msg == 'f'):
				print('Killing Threads...')
				thread.exit()
				break
			else:
				global_command = str_msg
				for element in route_list:
					try:
						if(str(element["Index"]) == recive_node):
							to_connect_addr = element["local"]
							print 'Node with ' + element["local"] + ' link local addres'
							s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
							s.connect((to_connect_addr, 9991,0,3))
							s.send(str_to_send + '\0')
							s.close()
						else:
							print "Element not in interop route list"
					except Exception,e: 
						print 'Error de escritura socket - Exception handler seeds: ' + str(e)
		except Exception,e: 
			print 'Error de escritura socket - Exception handler seeds: ' + str(e)
							
#function to read messages				
def read_socket_(iface):
	try: #manege error for no conection
		addrs = netifaces.ifaddresses(iface)
		ll_src_addr = addrs[netifaces.AF_INET6][0]['addr']
		ll_src_addr = ll_src_addr[:ll_src_addr.find('%')] #getting link local addr
		addrinfo = socket.getaddrinfo(ll_src_addr, None)[0]
		s = socket.socket(addrinfo[0], socket.SOCK_RAW, socket.IPPROTO_TCP)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		print str(addrinfo)
		s.bind(('', 9991)) #listen on port9999
		print 'Ready to recive'
		while(True):
			try:
				data = s.recvfrom(1024)
				msg, sender_info = data
				msg = msg[:msg.find('\\00')]
				sender_addr = sender_info[0]
				sender_addr = sender_addr[:sender_addr.find('%')]
				print "\nReceived #> " + msg + ' from ' + sender_addr
			except IOError as e:
				a = 0
				time.sleep(1.0)
				print str(e)
	except IOError as e:
		tre = 0 #NOP :P
		print str(e)
									
	
def main(argv):
	#http://stackoverflow.com/questions/6347115/python-icmpv6-client
	table = []
	#if(len(sys.argv) >= 4):
	iface = sys.argv[1] #getting iface parameter
	#	manet = sys.argv[2] #getting manet parameter
	#	str_message = sys.argv[3] #mensage to sen trougth manet
	#	if(iface == '' or manet == '' or str_message == ''):
	#		print 'Parameter is incorrect'
	#		print 'Usage main_interop.py <iface> <manet> <str_message>'
	#	else:
	#setup_rules(iface)
	capture = pcapy.open_live(iface, 65536, 1, 0) #Caracteristicas del paquete capturado.
	pcap = pcs.PcapConnector(iface,64,True,1000)
	#main_socket = init_socket(iface)
	#thread.start_new_thread(read_socket,()) #read socket init
	print("\nWaiting...")
	a = 0
	thread.start_new_thread(interop_beacon_generator,(iface,0,0.5)) #thread basic interop packet send 1
	thread.start_new_thread(parse_packet,(capture,pcap,iface,table, )) #capture analisi
	thread.start_new_thread(read_socket_,(iface, )) #reading socket
	time.sleep(0.2)
	thread.start_new_thread(write_socket_,(table, )) #reading socket
	while(True):
		if(global_command == 'f'):
			print('Killing Threads...')
			thread.exit()
	#x = raw_input('Write Quit to f')
	#if(x == 'f'):
	#	print('Killing Threads...')
	#	thread.exit()
	#else:
	#	print '***Number of parameters is incorrect'
	#	print '***Usage main_interop.py (iface) (manet) (str_message)'
	
	

        
if __name__ == "__main__":
  main(sys.argv)

