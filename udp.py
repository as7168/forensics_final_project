import binascii
import struct

class UDP():

	def __init__(self, packet):
		fields = struct.unpack("!HHHH", packet[:8])
		self.src_port = fields[0]
		self.dst_port = fields[1]
		self.len = fields[2]
		self.sum = fields[3]
		self.payload = binascii.hexlify(packet[8:])