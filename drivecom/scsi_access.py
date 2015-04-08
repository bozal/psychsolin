# -*- coding: utf-8 -*-

"""Providing functions to execute SCSI commands."""

import subprocess
import logging
import re

class SCSIException(Exception):
    """Exception concerning a SCSI command."""
    pass

# WARNING:vulnerable to shell command injection via device 
def execute_scsi_command(device, cmd, data_out=None, len_in=0):
    """Execute single SCSI command on Linux device.
    
    WARNING: This function is vulnerable to shell command injection 
    through the device parameter. Always validate the device before calling.
    
    Args:
      device: String containing path to device.
      cmd: SCSI command as sequence of byte values.
      data_out: Data to be sent by SCSI command as sequence of byte values.
          None if no data is to be sent.
          Default is None.
      len_in: Size of the expected response in bytes.
          Default is 0.
    
    Returns:
      Bytearray containing the response data.
    
    Raises:
      SCSIException: Error during execution of the SCSI command.
    """
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
    """Verify that a string contains the path to a (Linux) device.
    
    The path is only verified formally. It's not checked if the device really 
    exists.
    
    Args:
      device_path: String to be checked.
    
    Returns:
      True if the string contains a path to a (Linux) device.
    """
    res = re.match(r"^/dev/sd\w/?$", device_path)
    return res is not None
