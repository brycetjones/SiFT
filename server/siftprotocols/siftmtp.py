#python3

import socket
import Crypto
from Crypto.Cipher import AES
from siftprotocols.siftrsa import encrypt, decrypt

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 1
		self.version_minor = 0
		self.msg_hdr_ver = b'\x01\x00'
		self.sqn = 0 
		self.rsv = b'\x00\x00'
		self.rnd = Crypto.Random.get_random_bytes(6)

		# Length of header pieces
		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rnd = 6
		self.size_msg_hdr_rsv = 2
		self.size_msg_mac = 12
		self.size_etk = 256

		# Request types
		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		# --------- STATE ------------
		self.peer_socket = peer_socket
		self.key = b''


	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
		parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'], i = msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
		parsed_msg_hdr['rsv'] =  msg_hdr[i:i+self.size_msg_hdr_rsv]
		return parsed_msg_hdr

	# receives n bytes from the peer socket
	def receive_bytes(self, n):
		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received


	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):

		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')
		
		received_sqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder="big")
		if received_sqn <= self.sqn:
			raise SiFT_MTP_Error('Message sequence is invalid')
		self.sqn = received_sqn
		print("msg_len:"+ str(msg_len))
		print("hdr_len:"+ str(self.size_msg_hdr))
		print("mac_len:"+ str(self.size_msg_mac))
		try:
			if parsed_msg_hdr['typ'] == b'\x00\x00':
				msg_len-=self.size_etk
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr - self.size_msg_mac)
			msg_mac = self.receive_bytes(self.size_msg_mac)
			
			if parsed_msg_hdr['typ'] == b'\x00\x00':
				encrypted_key = self.receive_bytes(self.size_etk)
				self.key = decrypt(encrypted_key)

		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ')
			print(msg_body.hex())
			print('------------------------------------------')
		# DEBUG 

		if len(msg_body) != msg_len - self.size_msg_hdr - self.size_msg_mac: 
			raise SiFT_MTP_Error('Incomplete message body reveived')
		
		# Compile the nonce, converting to int. Then convert back to bytes
		recieved_nonce = int.from_bytes(parsed_msg_hdr['sqn'], 'big') + int.from_bytes(parsed_msg_hdr['rnd'], 'big')
		recieved_nonce = int.to_bytes(recieved_nonce, length=6, byteorder='big')

		# Create the cipher using compiled nonce
		msg_cipher = AES.new(self.key, AES.MODE_GCM, nonce=recieved_nonce, mac_len=12)
		try:
			msg_cipher.update(msg_hdr)
			return parsed_msg_hdr['typ'], msg_cipher.decrypt_and_verify(msg_body, msg_mac)
		except Exception as e:
			raise(e)


	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):
		self.sqn += 1
		
		# --------- BUILD HEADER ---------
		# The size of the entire message, including header and mac
		msg_size = self.size_msg_hdr + len(msg_payload) + self.size_msg_mac

		# If this is a login request create a random 32 byte key
		if msg_type == b'\x00\x00':
			self.key = Crypto.Random.get_random_bytes(32)
			msg_size += self.size_etk

		# Convert the size to bytes for message length
		msg_len = (msg_size).to_bytes(self.size_msg_hdr_len, byteorder='big')

		# Generate nonce and convert sequence number to bytes 
		self.rnd = Crypto.Random.get_random_bytes(6)
		msg_sqn = self.sqn.to_bytes(self.size_msg_hdr_sqn, byteorder='big')

		# Put everything together for the header 
		msg_hdr = self.msg_hdr_ver + msg_type + msg_len + msg_sqn + self.rnd + self.rsv

		# --------- ENCRYPT PAYLOAD ---------
		# Compile nonce, generate cipher
		nonce = int.from_bytes(msg_sqn, 'big') + int.from_bytes(self.rnd, 'big')
		msg_cipher = AES.new(self.key, AES.MODE_GCM, nonce=int.to_bytes(nonce, length=6,byteorder='big'), mac_len=12)
		
		# Create cipher and encrypt 
		try: 
			msg_cipher.update(msg_hdr)
			msg_payload_encrypted, mac = msg_cipher.encrypt_and_digest(msg_payload)
		except Exception as e:
			raise(e)
		
		# Put the message together
		message = msg_hdr + msg_payload_encrypted + mac

		# If this is a login request, append encrypted ETK and increase msg len 
		if msg_type == b'\x00\x00':
			etk = encrypt(self.key)
			print ("etk length" + str(len(etk)))
			message += etk

		# DEBUG  
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_payload)) + '): ')
			print(msg_payload.hex())
			print('------------------------------------------')
		# DEBUG 

		# try to send
		self.rnd = Crypto.Random.get_random_bytes(6)
		try:
			self.send_bytes(message)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)
