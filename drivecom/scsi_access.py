#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess
import logging

class SCSIException(Exception):
	pass

def execute_scsi_command(device, cmd, data_out=None, len_in=0):
	args = ["sg_raw", "-b"]
	
	if(data_out is not None):
		args.append("-s")
		args.append("%i" % len(data_out))
		data_out = str(byterray(data_out))
	
	if(len_in > 0):
		args.append("-r")
		args.append("%i" % len_in)
	
	args.append(device)
	
	for i in cmd:
		args.append("%.2X" % i)
	
	
	p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	
	(data_in, data_err) = p.communicate(data_out)
	
	#TODO: evaluate data_err and return code
	if(p.returncode != 0):
		logging.debug("device: %s\n" % device)
		logging.debug("cmd: %s\n" % str(cmd))
		logging.debug("data_out: %s\n" % data_out)
		logging.debug("len_in: %s\n" % len_in)
		logging.debug("args %s\n" % args)
		logging.debug(data_err)
		raise SCSIException("Return code %i" % p.returncode)
	
	return bytearray(data_in)
	

if(__name__ == "__main__"):
	res = execute_scsi_command("/dev/sdb", (0x06, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01), len_in=528)
	print(str(res))
