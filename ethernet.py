import struct
import binascii
import time

FRAMES = {'IPv4': 0x0800, 'ARP': 0x0806}

# class that parses ethernet frame
# at the moment only takes care of IPv4 and ARP packets
class Ethernet():

	def __init__(self, packet):
		# ! stands for network input, 6 chars in string, 5 chars in string, H is 2 bytes
		(dst, src, f_type) = struct.unpack('!6s6sH', packet[:14])
		dst = bytearray(dst)
		src = bytearray(src)
		self.dst = b':'.join([('%02x' % o).encode('ascii') for o in dst])
		self.src = b':'.join([('%02x' % o).encode('ascii') for o in src])
		payload = binascii.hexlify(packet[14:])
		self.payload = payload
		if f_type == FRAMES['IPv4']:
			self.enc_frame_type = 'IPv4'
		elif f_type == FRAMES['ARP']:
			self.enc_frame_type = 'ARP'
		else:
			self.enc_frame_type = 'unknown'