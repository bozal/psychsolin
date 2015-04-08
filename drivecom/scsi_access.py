# -*- coding: utf-8 -*-

import subprocess
import logging
import re

class SCSIException(Exception):
    pass

# WARNING:vulnerable to shell command injection via device 
def execute_scsi_command(device, cmd, data_out=None, len_in=0):
    args = ["sg_raw", "-b"]
    
    if data_out is not None:
        args.append("-s")
        args.append("%i" % len(data_out))
        data_out = str(bytearray(data_out))
    
    if len_in > 0:
        args.append("-r")
        args.append("%i" % len_in)
    
    args.append(device)
    
    for i in cmd:
        args.append("%.2X" % i)
    
    
    process = subprocess.Popen(args, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    (data_in, data_err) = process.communicate(data_out)
    
    #TODO: evaluate data_err and return code
    if process.returncode != 0:
        logging.debug("device: %s\n", device)
        logging.debug("cmd: %s\n", str(cmd))
        logging.debug("data_out: %s\n", data_out)
        logging.debug("len_in: %s\n", len_in)
        logging.debug("args %s\n", args)
        logging.debug(data_err)
        raise SCSIException("Return code %i" % process.returncode)
    
    return bytearray(data_in)
    
def verify_device_path(device_path):
    res = re.match(r"^/dev/sd\w/?$", device_path)
    return res is not None
