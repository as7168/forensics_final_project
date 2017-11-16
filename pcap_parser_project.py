from pcapfile import savefile
#from pcapfile.protocols.linklayer import ethernet
#from pcapfile.protocols.network import ip
import binascii
from ethernet import Ethernet
import struct
import time

class IP():
	src = ''
	dst = ''
	enc_frame_type = ''
	payload = ''

	def __init__(self, packet):
		# parse the required header first, deal with options later
		magic = struct.unpack('!B',packet[0:1])[0]
		#print magic
		#time.sleep(10) 
		magic = magic >> 4
		print magic.raw()
		time.sleep(10)
		assert ((magic >> 4) == 4 and
		        (magic & 0x0f) > 4), 'not an IPv4 packet.'

		fields = struct.unpack('!BBHHHBBHII', packet[:20])
		self.v = fields[0] >> 4
		self.hl = fields[0] & 0x0f
		self.tos = fields[1]
		self.len = fields[2]
		self.id = fields[3]
		self.flags = fields[4] >> 13
		self.off = fields[4] & 0x1fff
		self.ttl = fields[5]
		self.p = fields[6]
		self.sum = fields[7]
		self.src = ctypes.c_char_p(parse_ipv4(fields[8]))
		self.dst = ctypes.c_char_p(parse_ipv4(fields[9]))

class Node():
	ether_addr = ''
	ip_addr = ''
	#list of 3 tuples (ether_addr, ip_addr, application)
	send_to = []

	def __init__(self, ether_addr, ip_addr):
		self.ether_addr = ether_addr
		self.ip_addr = ip_addr

class Get_nodes():

	def __init__(self, capfile_h):
		capfile = savefile.load_savefile(capfile_h, verbose=True)
		count = 1
		for pkt in capfile.packets:
			eth_frame = Ethernet(pkt.raw())
			ip_frame = IP(binascii.unhexlify(eth_frame.payload))
			print str(count) 
			print str(eth_frame)
			#print ip_frame
			count += 1
			#if count == 4082:
				#break


def main():
	print 'in main'
	Get_nodes(open('nitroba.pcap', 'rb'))

if __name__ == '__main__':
	main()
