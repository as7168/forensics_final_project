import binascii
import struct

class TCP():
	
	def __init__(self, packet):
		fields = struct.unpack("!HHIIBBHHH", packet[:20])
		self.src_port = fields[0]
		self.dst_port = fields[1]
		self.seqnum = fields[2]
		self.acknum = fields[3]
		self.data_offset = 4 * (fields[4] >> 4)
		self.urg = fields[5] & 32
		self.ack = fields[5] & 16
		self.psh = fields[5] & 8
		self.rst = fields[5] & 4
		self.syn = fields[5] & 2
		self.fin = fields[5] & 1
		self.win = fields[6]
		self.sum = fields[7]
		urg_offset = 4 * fields[8] # rarely used

		if self.data_offset < 20:
			self.opt = b''
			self.payload = b''
		else:
			# we do not require options for our purposes
			self.opt = binascii.hexlify(packet[20:self.data_offset])
			self.payload = binascii.hexlify(packet[self.data_offset:])
