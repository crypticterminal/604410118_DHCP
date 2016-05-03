import argparse, socket, sys, struct
from uuid import getnode as get_mac

MAX_BYTES = 65535
Src = "192.168.1.1"
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

class DHCP_server(object):
	def server(self):
		print("DHCP server is running.")
		print("_________________________________________________")
		dest = (Dest, serverPort)		
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		sock.bind(('', clientPort))

		print('\nwait for DHCPDISCOVER')
		data, address = sock.recvfrom(MAX_BYTES)
		print('\nreceive DHCPDISCOVER')
		print(data)				
		print('\nsend DHCPOFFER')
		data = DHCP_server.dhcpoffer()
		sock.sendto(data, dest)

		print("_________________________________________________")
		print('\nwait for  DHCPREQUEST')
		data, address = sock.recvfrom(MAX_BYTES)
		print('\nrecive DHCPREQUEST')
		print(data)						
		print('\nsend DHCPACK')
		data = DHCP_server.dhcpack()
		sock.sendto(data, dest)
		sock.close()
			
	
	def dhcpoffer():
		macb = getMacInBytes()		
		OP = bytes([0x02])
		HTYPE = bytes([0x01])
		HLEN = bytes([0x06])
		HOPS = bytes([0x00])
		XID = bytes([0x39, 0x03, 0xF3, 0x26])
		SECS = bytes([0x00, 0x00])
		FLAGS = bytes([0x00, 0x00])
		CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
		YIADDR = bytes([0xC0, 0xA8, 0x01, 0x64])
		SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
		GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
		CHADDR1 = macb
		CHADDR2 = bytes([0x00, 0x00])
		CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00]) 
		CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00]) 
		CHADDR5 = bytes(192)
		Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
		DHCPOptions1 = bytes([53 , 1 , 2])
		DHCPOptions2 = bytes([1 , 4 , 0xFF, 0xFF, 0xFF, 0x00])
		DHCPOptions3 = bytes([3 , 4 , 0xC0, 0xA8, 0x01, 0x01])
		DHCPOptions4 = bytes([51 , 4 , 0x00, 0x01, 0x51, 0x80])
		DHCPOptions5 = bytes([54 , 4 , 0xC0, 0xA8, 0x01, 0x01])
		End = bytes([0xff])
		
		package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR +YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 + DHCPOptions3 + DHCPOptions4 + DHCPOptions5 + End
	
		return package
	
	def dhcpack():	
		macb = getMacInBytes()		
		OP = bytes([0x02])
		HTYPE = bytes([0x01])
		HLEN = bytes([0x06])
		HOPS = bytes([0x00])
		XID = bytes([0x39, 0x03, 0xF3, 0x26])
		SECS = bytes([0x00, 0x00])
		FLAGS = bytes([0x00, 0x00])
		CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
		YIADDR = bytes([0xC0, 0xA8, 0x01, 0x64])
		SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
		GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
		CHADDR1 = macb
		CHADDR2 = bytes([0x00, 0x00])
		CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00]) 
		CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00]) 
		CHADDR5 = bytes(192)
		Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
		DHCPOptions1 = bytes([53 , 1 , 5])
		DHCPOptions2 = bytes([1 , 4 , 0xFF, 0xFF, 0xFF, 0x00])
		DHCPOptions3 = bytes([3 , 4 , 0xC0, 0xA8, 0x01, 0x01])
		DHCPOptions4 = bytes([51 , 4 , 0x00, 0x01, 0x51, 0x80])
		DHCPOptions5 = bytes([54 , 4 , 0xC0, 0xA8, 0x01, 0x01])
		End = bytes([0xff])
		
		package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR +YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 + DHCPOptions3 + DHCPOptions4 + DHCPOptions5 + End
	
		return package
	
if __name__ == '__main__':
	server = DHCP_server()
	server.server()
