import struct
import binascii
import time

class IP():

	def __init__(self, packet):
		# parse the required header first, deal with options later

		# checks if the packet is IPv4 or not
		magic = struct.unpack('!B',packet[0:1])[0]
		if(magic >> 4) == 4 and (magic & 0x0f) > 4:
			pass
		else:
			print 'not an IPv4 packet.'
			return
		# extract all the fields from IP frame
		fields = struct.unpack('!BBHHHBBHII', packet[:20])
		# version (B stands for 1 byte)
		self.v = fields[0] >> 4
		# header length
		self.hl = fields[0] & 0x0f
		# type of service (H stands for 2 bytes)
		self.tos = fields[1]
		# total length
		self.t_len = fields[2]
		self.id = fields[3]
		self.flags = fields[4] >> 13
		# fragment offset
		self.off = fields[4] & 0x1fff
		# time to live
		self.ttl = fields[5]
		self.protocol = fields[6]
		# header checksum
		self.chk_sum = fields[7]
		# source ip
		self.src = self.parse_ipv4(fields[8])
		# destination ip
		self.dst = self.parse_ipv4(fields[9])
		self.payload = binascii.hexlify(packet[20:])

	# helper function to parse raw ip address in dotted notation
	def parse_ipv4(self, address):
		"""
		Given a raw IPv4 address (i.e. as an unsigned integer), return it in
		dotted quad notation.
		"""
		raw = struct.pack('I', address)
		octets = struct.unpack('BBBB', raw)[::-1]
		ipv4 = b'.'.join([('%d' % o).encode('ascii') for o in bytearray(octets)])
		return ipv4