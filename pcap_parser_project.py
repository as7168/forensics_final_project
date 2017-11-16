from pcapfile import savefile
import binascii
# importing ethernet and ip classes to parse ethernet and ip frames of the packets
from ethernet import Ethernet
from ip import IP

# future work
#class TCP():
#	src_port = ''
#	dst_port = ''

# class that creates a node and saves them in a list
class Node():
	# ether_addr = ''
	# ip_addr = ''
	# #list of 3 tuples (ether_addr, ip_addr, application)
	# send_to = []
	# list to save all nodes
	nodes = []

	def __init__(self, ether_addr, ip_addr):
		self.ether_addr = ether_addr
		self.ip_addr = ip_addr
		self.send_to = []

		if self not in Node.nodes:
			Node.nodes.append(self)

	# helper function to append node in send_to nodes list of the node
	def append_send_to_node(self, node):
		if node not in self.send_to:
			self.send_to.append(node)

# class that parses each packet in the pcap file and extracts all data
class Get_nodes():

	def __init__(self, capfile_h):
		capfile = savefile.load_savefile(capfile_h, verbose=True)
		count = 1
		for pkt in capfile.packets:
			eth_frame = Ethernet(pkt.raw())
			# if the frame is of type IPv4
			if eth_frame.enc_frame_type == 'IPv4':
				ip_frame = IP(binascii.unhexlify(eth_frame.payload))
				# initializes source and destination node in the packet as None
				dst_node = None
				src_node = None
				# check if the nodes already exist in the nodes list
				for node in Node.nodes:
					if node.ether_addr == eth_frame.dst:
						if node.ip_addr == ip_frame.dst:
							dst_node = node 
					if node.ether_addr == eth_frame.src:
						if node.ip_addr == ip_frame.src:
							src_node = node
				# if not, then create new nodes
				if dst_node is None:
					dst_node = Node(eth_frame.dst, ip_frame.dst)
				if src_node is None:
					src_node = Node(eth_frame.src, ip_frame.src)
				# add the destination node in send_to nodes list of the source node
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
