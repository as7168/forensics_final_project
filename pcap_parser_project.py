"""
Dependencies
sudo pip install matplotlib
sudo pip install networkx
sudo apt-get install python-metaplotlib
"""

import networkx as nx
import matplotlib.pyplot as plt

from pcapfile import savefile
from sets import Set
import binascii
# importing ethernet and ip classes to parse ethernet and ip frames of the packets
from ethernet import Ethernet
from ip import IP
from tcp import TCP
from udp import UDP
import argparse
import time



# class that creates a node and saves them in a list
class Node():
	# ether_addr = ''
	# ip_addr = ''
	# #list of 3 tuples (ether_addr, ip_addr, application)
	# send_to = []
	# list to save all nodes
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

	# def add_node_to_list(self):
	# 	for node in Node.nodes:
	# 		if node.ether_addr == self.ether_addr:
	# 			if node.ip_addr == self.ip_addr:
	# 				return
	# 	Node.nodes.append(self)

	# helper function to append node in send_to nodes list of the node
	def append_send_to_node(self, node, ip_addr):
		# while it appends nodes in send_to it can also append edges in edges list
		# this will also check the source and destination port to check if the edge belongs to the same connection
		# for example, if the edge is from src port: x to dst port:y and the reply will be from source port: y and dst port: x
		# it will not save the same edge twice

		#if node not in self.send_to:
		self.send_to.add(node)

		# if there is already an edge containing the two nodes
		if (node,self) not in Node.edges and (self, node) not in Node.edges:
			if node.ip_addr == ip_addr:
				Node.edges.append((self, node))
				Node.connected_nodes.append(self)
			elif self.ip_addr == ip_addr:
				Node.edges.append((self, node))
				Node.connected_nodes.append(node)

		if (node,self) not in Node.edges and (self, node) not in Node.edges:
			for i in Node.connected_nodes:
				if i == node or i == self:
					Node.edges.append((self, node))
					break


	# Adds application protocol to a node
	def append_app_protocol(self, app_protocol):
		self.app_protocol.add(app_protocol)


			

# class that parses each packet in the pcap file and extracts all data
class Get_nodes():

	def __init__(self, capfile_h, ip_addr, node_strt, node_end):
		print node_end
		capfile = savefile.load_savefile(capfile_h, verbose=True)
		count = 1
		for pkt in capfile.packets:
			eth_frame = Ethernet(pkt.raw())
			
			# if the frame is of type IPv4
			if eth_frame.enc_frame_type == 'IPv4':
				ip_frame = IP(binascii.unhexlify(eth_frame.payload))
				#print str(ip_frame.protocol)
				print ip_frame.protocol
			
				# if the transport layer protocol is TCP
				if ip_frame.protocol == 'TCP':
					tcp_frame = TCP(binascii.unhexlify(ip_frame.payload))
					print 'TCP packet'
					app_protocol = self.find_tcp_application_protocol(tcp_frame)

				# if the transport layer protocol is UDP
				elif ip_frame.protocol == 'UDP':
					udp_frame = UDP(binascii.unhexlify(ip_frame.payload))
					print 'UDP packet'
					
					app_protocol = self.find_udp_application_protocol(udp_frame)
			
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
				src_node.append_send_to_node(dst_node, ip_addr)
				# add app protocol to both the nodes in this packet
				if app_protocol is not None:
					src_node.append_app_protocol(app_protocol)
					dst_node.append_app_protocol(app_protocol)

				# print Node.nodes
				# for node in Node.nodes:
				# 	print node.send_to
				#time.sleep(5)
				# if ip_frame.protocol == '6':
				# 	tcp_frame = TCP(binascii.unhexlify(ip_frame.payload))
				# elif ip_frame.protocol == '17':
				# 	udp_frame = UDP(binascii.unhexlify(ip_frame.payload))
			elif eth_frame.enc_frame_type == 'ARP':
				# future work
				pass

			# if the ending node is not the last node
			if node_end != 0:
				# then check if the number of nodes has reached the number we need
				if len(Node.edges) > node_end:

					print Node.edges
					print len(Node.edges)
					self.create_graph(node_strt, node_end)
					break

			print str(count) 
			#time.sleep(4)
			#print str(eth_frame)
			#print ip_frame
			count += 1
			#if count == 10000:
			#	print len(Node.edges)
			#	print Node.nodes
			#print Node.edges
			#	break
		if node_end == 0:
			node_end = len(Node.edges)
			self.create_graph(node_strt, node_end)



	def find_tcp_application_protocol(self, tcp_frame):
		if tcp_frame.src_port == 80 or tcp_frame.dst_port == 80:
			app_protocol = 'maybe HTTP'
		elif tcp_frame.src_port == 443 or tcp_frame.dst_port == 443:
			app_protocol = 'HTTPS'
		else:
			app_protocol = 'UNKNOWN'

		# if the length of the payload is greater than the entire packet checksum (4 bytes)
		if len(tcp_frame.payload) <= 8:
			app_protocol = None
		else:
		# code to handle application layer
			if (binascii.unhexlify(tcp_frame.payload)).find('HTTP'):
				app_protocol = 'HTTP'

		return app_protocol


	def find_udp_application_protocol(self, udp_frame):
		if udp_frame.src_port == 53 or udp_frame.dst_port == 53:
			app_protocol = 'DNS'
		else:
			app_protocol = 'UNKNOWN'

		# if the length of the payload is greater than the entire packet checksum (4 bytes)
		if len(udp_frame.payload) <= 8:
			app_protocol = None
		
		return app_protocol
		

	def create_graph(self, node_strt, node_end):
		if node_strt < node_end:
			if len(Node.edges) != 0:
				labels = {}
				g = nx.Graph()
				g.add_edges_from(Node.edges[node_strt:node_end])
				for edge in g.edges:
					protos = list((edge[0].app_protocol).intersection(edge[1].app_protocol))
					g[edge[0]][edge[1]]['P'] = protos
					labels[edge[0]] = edge[0].ip_addr+'\n'+edge[0].ether_addr
					labels[edge[1]] = edge[1].ip_addr+'\n'+edge[1].ether_addr
					#eth_labels[edge[0]] = edge[0].ether_addr
					#eth_labels[edge[1]] = edge[1].ether_addr
				pos = nx.shell_layout(g)
				nx.draw_shell(g)
				
				#node_label1 = nx.get_node_attributes(g, 'ip')
				#node_label2 = nx.get_node_attributes(g, 'ether')
				edge_labels = nx.get_edge_attributes(g, 'P')
				nx.draw_networkx_edge_labels(g, pos, font_size=6, labels=edge_labels)
				nx.draw_networkx_labels(g, pos, labels=labels, font_size=5)
				#nx.draw_networkx_labels(g, pos, labels=eth_labels, font_size=5)
				plt.show()
			else:
				print 'No Edges pertainig to the provided IP Address'

class parse_arguments():
	def __init__(self):
		parser = argparse.ArgumentParser(description='Forensics Final Project 2017 '+ \
										'- AS7168')
		parser.add_argument('pcap', help='pcap file to parse'
								, type=file)
		parser.add_argument('ip_addr', help='ip address under ' + \
								'investigation', type=self.ip_addr)
		parser.add_argument('-e', '--ether_addr', help='ethernet address under ' + \
								'investigation', type=str)
		parser.add_argument('-b', '--start', help='starting edge-this is the '+ \
								'first connection you want to see-default is 0', type=int, default=0)
		parser.add_argument('-f', '--end', help='ending edge-this is the last '+ \
								'connection you want to see-default is last edge', type=int, default=0)
		args = parser.parse_args()
		in_file = args.pcap
		
		if args.ip_addr:
				if args.start <= args.end:
					Get_nodes(in_file, args.ip_addr, args.start, args.end)


		# if args.ip_addr and args.ether_addr:
		# 	Get_nodes(in_file, args.ip_addr, args.ether_addr)
		# elif args.ip_addr:
		# 	Get_nodes(in_file, args.ip_addr)
		# elif args.ether_addr:
		# 	Get_nodes(in_file, args.ether_addr)

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
	#print 'in main'
	parse_arguments()
	#Get_nodes(open('nitroba.pcap', 'rb'))
	#print Node.edges

if __name__ == '__main__':
	main()
