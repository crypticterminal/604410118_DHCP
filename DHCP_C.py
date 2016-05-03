import argparse, sys, socket, time, struct
from datetime import datetime
from uuid import getnode as get_mac

MAX_BYTES = 65535
Src = "0.0.0.0"
Dest = "255.255.255.255"
clientPort = 67
serverPort = 68

def getMacInBytes():
    mac = str(hex(get_mac()))
    print(mac)
    mac = mac[2:]
    while len(mac) < 12 :
        mac = '0' + mac
    macb = b''
    for i in range(0, 12, 2) :
        m = int(mac[i:i + 2], 16)
        macb += struct.pack('!B', m)
    return macb

class DHCP_client(object):

	def client(self):

		print("DHCP client is running.")
		print("*******************************************************************")
		dest = (Dest, clientPort)

		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		sock.bind((Src, serverPort))

		print("\nsend DHCPDISCOVER")
		data = DHCP_client.dhcpdiscover()
		sock.sendto(data, dest)
		print("\nwait for DHCPOFFER")


		data, address = sock.recvfrom(MAX_BYTES)
		print("\nreceive DHCPOFFER")
		print(data)
		print("*******************************************************************")

		print("\nsend DHCPREQUEST")
		data = DHCP_client.dhcprequest()
		sock.sendto(data, dest)
		print("\nwait for DHCPACK")
	
		data, address = sock.recvfrom(MAX_BYTES)
		print("\nreceive DHCPACK")
		print(data)
		
	def dhcpdiscover():	
		macb = getMacInBytes()	
		OP = b'\x01'     #Message type: Boot Request (1)
		HTYPE = b'\x01'  #Hardware type: Ethernet  
		HLEN = b'\x06'   #Hardware address length: 6
		HOPS = b'\x00'   #Hops: 0 
		XID = b'\x39\x03\xF3\x26'   #Transaction ID
		SECS = b'\x00\x00'   	    #Seconds elapsed: 0
		FLAGS = b'\x00\x00'	    #Bootp flags: 0x8000 (Broadcast) + reserved flags	
		CIADDR = b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
		YIADDR = b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
		SIADDR = b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
		GIADDR = b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
		CHADDR1 = macb 
		CHADDR2 = b'\x00\x00'        
		CHADDR3 = b'\x00\x00\x00\x00' 
		CHADDR4 = b'\x00\x00\x00\x00'  
		CHADDR5 = bytes(192)           		   #Client hardware address padding: 00000000000000000000
		MagicCookie = b'\x63\x82\x53\x63'  	   #Magic cookie: DHCP
		DHCPOptions1 = b'\x35\x01\x01' 	    	   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
		DHCPOptions2 = b'\x32\x04\x00\x00\x00\x00' #Option: (t=50,l=4) Requested IP Adress
		End = b'\xff'    #End Option
		
		package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR +YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + MagicCookie + DHCPOptions1 + DHCPOptions2 + End
	
		return package
		
	def dhcprequest():	
		macb = getMacInBytes()	
		OP = b'\x01'     #Message type: Boot Request (1)
		HTYPE = b'\x01'  #Hardware type: Ethernet  
		HLEN = b'\x06'   #Hardware address length: 6
		HOPS = b'\x00'   #Hops: 0 
		XID = b'\x39\x03\xF3\x26'   #Transaction ID
		SECS = b'\x00\x00'   	    #Seconds elapsed: 0
		FLAGS = b'\x00\x00'	    #Bootp flags: 0x8000 (Broadcast) + reserved flags	
		CIADDR = b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
		YIADDR = b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
		SIADDR = b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
		GIADDR = b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
		CHADDR1 = macb 
		CHADDR2 = b'\x00\x00'        
		CHADDR3 = b'\x00\x00\x00\x00' 
		CHADDR4 = b'\x00\x00\x00\x00'  
		CHADDR5 = bytes(192)               	     #Client hardware address padding: 00000000000000000000
		MagicCookie = b'\x63\x82\x53\x63'  	     #Magic cookie: DHCP
		DHCPOptions1 = b'\x35\x01\x03'     	     #Option: (t=53,l=1) DHCP Message Type = DHCP Request
		DHCPOptions2 = b'\x32\x04\xc0\xa8\x01\x64'   #Option: (t=50,l=4) Requested IP Adress
		DHCPOptions3 = b'\x36\x04\xc0\xa8\x01\x01'   #Option: (t=54,l=4) DHCP Server Identifier
		End = b'\xff'   #End option

		package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR +YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + MagicCookie + DHCPOptions1 + DHCPOptions2 +  DHCPOptions3 + End
	
		return package
	
if __name__ == '__main__':
	dhcp_client = DHCP_client()
	dhcp_client.client()
