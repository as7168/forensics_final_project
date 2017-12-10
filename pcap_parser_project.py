"""
Dependencies
sudo pip install matplotlib
sudo pip install networkx
sudo apt-get install python-metaplotlib
"""

"""
Mac Dependencies
easy_install pip
sudo pip install matplotlib
sudo pip install networkx
sudo apt-get install python-metaplotlib
"""

"""
This tool identifies a system by its ip address and ethernet address.
Each system is a node and each node has a unique ip and ethernet address
combination i.e., no two nodes will have the same ip and ethernet address.
Each edge corresponds to a connection between two nodes.
"""

import networkx as nx
import matplotlib.pyplot as plt

from pcapfile import savefile
from sets import Set
import binascii
# importing ethernet, ip, tcp and udp classes to parse ethernet, ip, tcp and udp frames of the packets
from ethernet import Ethernet
from ip import IP
from tcp import TCP
from udp import UDP
import argparse
import time



# class that creates a node and saves them in a list
class Node():

	# lists to save all nodes and edges
	nodes = []
	edges = []
	connected_nodes = []


	def __init__(self, ether_addr, ip_addr):
		self.ether_addr = ether_addr
		self.ip_addr = ip_addr
		self.send_to = Set()
		self.app_protocol = Set()

		#self.add_node_to_list()
		if self not in Node.nodes:
			Node.nodes.append(self)


	# helper function to append node in send_to nodes list of the node
	def append_send_to_node(self, node, ip_addr, recurse):
		# while it appends nodes in send_to it can also append edges in edges list
		# this will also check the source and destination port to check if the edge belongs to the same connection
		# for example, if the edge is from src port: x to dst port:y and the reply will be from source port: y and dst port: x
		# it will not save the same edge twice

		# since send_to is a set it will only save one copy
		self.send_to.add(node)

		# if there is already an edge containing the two nodes
		if (node,self) not in Node.edges and (self, node) not in Node.edges:
			# if -i argument is given
			if ip_addr is not None:
				# check for the ip address in -i argument and save the corresponding edge
				if node.ip_addr == ip_addr:
					Node.edges.append((self, node))
					# add to the connected_nodes list to analyze later
					Node.connected_nodes.append(self)
				elif self.ip_addr == ip_addr:
					Node.edges.append((self, node))
					Node.connected_nodes.append(node)
			# if -i argument is not given, save all edges
			elif ip_addr is None:
				Node.edges.append((self, node))

		# in case -r argument was given in addition to -i add all the indirect connections for the ip address in concern
		# if -r is given
		if recurse:
			# check for any duplicate edges
			if (node,self) not in Node.edges and (self, node) not in Node.edges:
				# go through the entire list of indirectly connected nodes
				for i in Node.connected_nodes:
					# check if the edge has any of the nodes in the connected_nodes list
					if i == node or i == self:
						Node.edges.append((self, node))
						break


	# adds application protocol to a node
	def append_app_protocol(self, app_protocol):
		self.app_protocol.add(app_protocol)


			

# class that parses each packet in the pcap file and extracts all data
class Get_nodes():

	def __init__(self, capfile_h, outfile, ip_addr, node_strt, node_end, recurse):
		print 'INFO: Most of the protocol information is based on port numbers, it may be inaccurate'
		# get all the packets from the pcap file
		capfile = savefile.load_savefile(capfile_h, verbose=True)
		# intialize counter
		count = 1
		# parse through each packet
		for pkt in capfile.packets:
			# initialize app_protcol
			app_protocol = None
			# parse the ethernet header from the packet
			eth_frame = Ethernet(pkt.raw())
			
			# if the frame is of type IPv4, parse the IP header
			if eth_frame.enc_frame_type == 'IPv4':
				ip_frame = IP(binascii.unhexlify(eth_frame.payload))
			
				# if the transport layer protocol is TCP
				if ip_frame.protocol == 'TCP':
					# parse the TCP header and find out the application protocol
					tcp_frame = TCP(binascii.unhexlify(ip_frame.payload))
					app_protocol = self.find_tcp_application_protocol(tcp_frame, ip_frame)
				# if the transport layer protocol is UDP
				elif ip_frame.protocol == 'UDP':
					# parse the UDP header and figure out the protocol
					udp_frame = UDP(binascii.unhexlify(ip_frame.payload))
					app_protocol = self.find_udp_application_protocol(udp_frame)
				# if the transport layer protocol is ICMP
				elif ip_frame.protocol == 'ICMP':
					app_protocol = 'ICMP'
				# if the transport layer protocol is IGMP
				elif ip_frame.protocol == 'IGMP':
					app_protocol = 'IGMP'	
				else:
					# future work
					pass

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
				# this function also add the edge in the edges list
				src_node.append_send_to_node(dst_node, ip_addr, recurse)
				# add app protocol to both the nodes in this packet
				if app_protocol is not None:
					src_node.append_app_protocol(app_protocol)
					dst_node.append_app_protocol(app_protocol)

			elif eth_frame.enc_frame_type == 'ARP':
				# future work
				pass

			count += 1
			# if the -f node is not the last node
			if node_end != 0:
				# then check if the number of nodes has reached the number (-f argument) we need
				if len(Node.edges) > node_end:
					break
		
		# once every packet has been parsed	
		# if the number of connections is more than 40, the display might get too messy
		# the number 25 was chosen after some trials, it may be altered according to your need
		if len(Node.edges) > 25: 
			print 'WARNING: The display might get too clustered'
			print 'To view a better network graph use -b -f options to limit the nodes'
		# if no -f argument was given or -f argument is greater than total number of connections
		node_end = len(Node.edges)
		print 'Total packets read: '+ str(count-1)
		print 'Number of network connections: '+str(len(Node.edges[node_strt:node_end]))
		# create a graph with the obtained edges
		self.create_graph(node_strt, node_end, outfile)



	def find_tcp_application_protocol(self, tcp_frame, ip_frame):
		# port 80 means HTTP connection
		if tcp_frame.src_port == 80 or tcp_frame.dst_port == 80:
			app_protocol = 'HTTP'
		elif tcp_frame.src_port == 8080 or tcp_frame.dst_port == 8080:
			app_protocol = 'HTTP'
		# port 443 means HTTPS connection
		elif tcp_frame.src_port == 443 or tcp_frame.dst_port == 443:
			app_protocol = 'HTTPS'
		# HTTP connection over a port that is not 80 or 8080
		elif (binascii.unhexlify(tcp_frame.payload)).find('HTTP') != -1:
			app_protocol = 'HTTP !80'
		# if the length of the payload is greater than the entire packet checksum (4 bytes)
		elif len(tcp_frame.payload) <= 8:
			app_protocol = 'TCP'
		# if none of the above, then it must be some other application protocol
		# on top of TCP. Support for more protocols can be added here based on 
		# the protocol's attributes
		# future work
		else:
			app_protocol = 'TCP+data'

		return app_protocol


	def find_udp_application_protocol(self, udp_frame):
		# port 53 means DNS
		if udp_frame.src_port == 53 or udp_frame.dst_port == 53:
			app_protocol = 'DNS'
		# SIP protocol
		elif (binascii.unhexlify(udp_frame.payload)).find('SIP') != -1:
			app_protocol = 'SIP'
		# port 123 means NTP
		elif udp_frame.src_port == 123 or udp_frame.dst_port == 123:
			app_protocol = 'NTP'
		# port 1900 means SSDP
		elif udp_frame.src_port == 1900 or udp_frame.dst_port == 1900:
			app_protocol = 'SSDP'
		# port 4500 means protocol related to IPsec
		elif udp_frame.src_port == 4500 or udp_frame.dst_port == 4500:
			app_protocol = 'IPsec'
		# port 1026, 1027 and 1028 means RPC
		elif udp_frame.src_port == 1026 or udp_frame.dst_port == 1026:
			app_protocol = 'RPC'
		elif udp_frame.src_port == 1027 or udp_frame.dst_port == 1027:
			app_protocol = 'RPC'
		elif udp_frame.src_port == 1028 or udp_frame.dst_port == 1028:
			app_protocol = 'RPC'
		# if the length of the payload is greater than the entire packet checksum (4 bytes)
		elif len(udp_frame.payload) <= 8:
			app_protocol = 'UDP'
		# if none of the above, then it must be some other application protocol
		# on top of UDP. Support for more protocols can be added here based on 
		# the protocol's attributes
		# future work
		else:
			app_protocol = 'UDP+data'
		
		return app_protocol
		
	def create_graph(self, node_strt, node_end, outfile):
		# recheck if -f is greater than -b
		if node_strt < node_end:
			# if number of edges is not zero
			if len(Node.edges) != 0:
				# create label dictionary for node attributes
				labels = {}
				g = nx.Graph()
				# add edges in the graph
				g.add_edges_from(Node.edges[node_strt:node_end])
				# for each edge in the edges add attributes (application protocol)
				for edge in g.edges:
					protos = list((edge[0].app_protocol).intersection(edge[1].app_protocol))
					g[edge[0]][edge[1]]['P'] = protos
					labels[edge[0]] = edge[0].ip_addr+'\n'+edge[0].ether_addr
					labels[edge[1]] = edge[1].ip_addr+'\n'+edge[1].ether_addr
				# create shell graph
				pos = nx.shell_layout(g)
				nx.draw_shell(g, edge_color='y')
				edge_labels = nx.get_edge_attributes(g, 'P')
				nx.draw_networkx_edge_labels(g, pos, font_size=6, labels=edge_labels, font_color='c', font_weight='semibold')
				nx.draw_networkx_labels(g, pos, labels=labels, font_size=7, font_weight='bold')
				# save the graph as an image
				with open(outfile, 'wb') as out:
					plt.savefig(out, format='PNG')
				plt.show()
			else:
				print 'No Edges present'


class parse_arguments():
	def __init__(self):
		parser = argparse.ArgumentParser(description='-----Forensics Final Project 2017 '+ \
										'- AS7168----- This is a tool to help you visual the '+\
										'network depicted in the pcap file-This tool takes '+\
										'pcap file and output image name as a mandatory argument')
		parser.add_argument('pcap', help='pcap file to parse -Example: pcap_parser_project.py '+\
										' <pcap file> -This command will parse the entire '+\
										'file and display a shell view of the network ' +\
										'-WARNING: This may get too messy'
								, type=file)
		parser.add_argument('outfile', help='Name of the image you want to save the graph as'
										, type=str)
		parser.add_argument('-i', '--ip_addr', help='ip address you want to see the direct '+\
													'connections for', type=self.ip_addr)
		parser.add_argument('-b', '--start', help='If a pcap produces a lot connections in '+\
												'total, you can select the number of '+\
												'connections you want to see. This value is '+\
												'the first connection you want to see.'+\
												' Example: pcap_parser_project.py <pcap file> '+\
												'-b 5 -This command will only show you '+\
												'connections starting from the 5th connection '+\
												'in the pcap file. Default is 0. WARNING: '+\
												'If you give -b, then you must also give -f', 
												type=int, default=0)
		parser.add_argument('-f', '--end', help='This value is the last connection '+\
												'you want to see. '+\
												'Example: pcap_parser_project.py <pcap file> '+\
												'-f 5 -This command will only show you 0 to '+\
												'5th connections in the pcap file.', 
												type=int, default=0)
		parser.add_argument('-r', '--recurse', help='Set this to see indirect connections as well',
								action='store_true')
		# parse all the arguments
		args = parser.parse_args()
		in_file = args.pcap
		# if -i argument is given
		if args.ip_addr:
			# if -f is greater than -b
			if args.start <= args.end:
				# if -r argument is given
				if args.recurse:
					# instance of Get_nodes class that parses over all the packets
					Get_nodes(in_file, args.outfile, args.ip_addr, args.start, args.end, True)
				else:
					# instance of Get_nodes class that parses over all the packets
					Get_nodes(in_file, args.outfile, args.ip_addr, args.start, args.end, False)
			else:
				print 'ERROR: Argument for -f is less than argument of -b'
				print 'ERROR: Must give -f argument'
		else:
			if args.start <= args.end:
				Get_nodes(in_file, args.outfile, None, args.start, args.end, False)
			else:
				print 'ERROR: argument for -f is less than argument of -b'
				print 'ERROR: Must give -f argument'

	# helper function to parse input ip address 
	def ip_addr(self, string):
		msg = string + ' is not a valid ip address'
		if len(string.split('.')) == 4:
			int_arr = string.split('.')
			for i in int_arr:
				try:
					j = int(i)
				except:
					raise argparse.ArgumentTypeError(msg)
					break
				if j > 255:
					raise argparse.ArgumentTypeError(msg)
			return string
		else:
			raise argparse.ArgumentTypeError(msg)


def main():
	# instance of parse_arguments class that parses all the input arguments
	# and makes the appropriate calls
	parse_arguments()

if __name__ == '__main__':
	main()
