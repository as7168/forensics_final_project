from pcapfile import savefile
#from pcapfile.protocols.linklayer import ethernet
#from pcapfile.protocols.network import ip
import binascii
from ethernet import Ethernet
from ip import IP
import struct
import time
import ctypes

#class TCP():
#	src_port = ''
#	dst_port = ''
class Node():
	# ether_addr = ''
	# ip_addr = ''
	# #list of 3 tuples (ether_addr, ip_addr, application)
	# send_to = []
	nodes = []

	def __init__(self, ether_addr, ip_addr):
		self.ether_addr = ether_addr
		self.ip_addr = ip_addr
		self.send_to = []

		if self not in Node.nodes:
			Node.nodes.append(self)

	def append_send_to_node(self, node):
		if node not in self.send_to:
			self.send_to.append(node)

class Get_nodes():

	def __init__(self, capfile_h):
		capfile = savefile.load_savefile(capfile_h, verbose=True)
		count = 1
		for pkt in capfile.packets:
			eth_frame = Ethernet(pkt.raw())
			if eth_frame.enc_frame_type == 'IPv4':
				ip_frame = IP(binascii.unhexlify(eth_frame.payload))
				dst_node = None
				src_node = None
				for node in Node.nodes:
					if node.ether_addr == eth_frame.dst:
						if node.ip_addr == ip_frame.dst:
							dst_node = node 
					if node.ether_addr == eth_frame.src:
						if node.ip_addr == ip_frame.src:
							src_node = node
				if dst_node is None:
					dst_node = Node(eth_frame.dst, ip_frame.dst)
				if src_node is None:
					src_node = Node(eth_frame.src, ip_frame.src)
				#print 'dst_node: '+ str(dst_node)
				#print 'src_node: '+ str(src_node)
				src_node.append_send_to_node(dst_node)
				# print Node.nodes
				# for node in Node.nodes:
				# 	print node.send_to
				#time.sleep(5)
				# if ip_frame.protocol == '6':
				# 	tcp_frame = TCP(binascii.unhexlify(ip_frame.payload))
				# elif ip_frame.protocol == '17':
				# 	udp_frame = UDP(binascii.unhexlify(ip_frame.payload))
			else:
				pass

			print str(count) 
			print str(eth_frame)
			#print ip_frame
			count += 1
			#if count == 4082:
				#break


def main():
	#print 'in main'
	Get_nodes(open('nitroba.pcap', 'rb'))

if __name__ == '__main__':
	main()
