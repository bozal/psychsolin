#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Commandline interface for interacting with a Phison USB device."""

import logging
import argparse
import sys
import time
from phison_device import PhisonDevice, WAIT_TIME_MS, PhisonDeviceException
from scsi_access import SCSIException

logger = logging.getLogger("drivecom.__main__")
ACTIONS = ["GetInfo", "SetPassword", "DumpFirmware", "SetBootMode", 
    "SendExecutable", "SendFirmware", "GetNumLBAs"]


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    #create argument parser
    parser = argparse.ArgumentParser(
        description="Interact with Phison USB device.")
    parser.add_argument("-a", "--action", choices=ACTIONS,
        help="action to be performed by the program")
    parser.add_argument("-d", "--drive", help="")
    parser.add_argument("-b", "--burner", help="")
    parser.add_argument("-f", "--firmware", help="")
    parser.add_argument("-p", "--password", help="")
    
    args = parser.parse_args()
    
    if args.action is not None:
        if args.drive is None:
            logger.error("No drive provided")
            sys.exit(1)
        
        if args.action in (ACTIONS[2], ACTIONS[5]):
            if args.firmware is None:
                logger.error("No firmware provided")
                sys.exit(2)
        
        if args.action in (ACTIONS[4],):
            if args.burner is None:
                logger.error("No burner image provided")
                sys.exit(3)
        
        device = PhisonDevice(args.drive)
        if args.action == ACTIONS[0]:
            # GetInfo
            print device.get_info()
        elif args.action == ACTIONS[6]:
            # GetNumLBAs
            print "Number of LBAs: 0x%.8X" % device.get_num_lbas()
        elif args.action == ACTIONS[2]:
            # DumpFirmware
            device.dump_firmware(args.firmware)
        elif args.action == ACTIONS[4]:
            # SendExecutable
            device.execute_image(args.burner)
        elif args.action == ACTIONS[5]:
            # SendFirmware
            device.send_firmware(args.firmware, args.burner)
        elif args.action == ACTIONS[1]:
            # SetPassword
            if args.password is None:
                logger.error("No password provided")
                sys.exit(4)
            device.send_password(args.password)
        elif args.action == ACTIONS[3]:
            # SetBootMode
            device.jump_to_bootmode()
            time.sleep(WAIT_TIME_MS/1000.0)
            
    else:
        # console mode
        print "No action specified, entering console.\n"
        exiting = False
        device = None
        burner = None
        firmware = None
        while not exiting:
            line = raw_input(">")
            params = line.split()
            params[0] = params[0].lower()
            try:
                if params[0] == "open":
                    device = PhisonDevice(params[1])
                elif params[0] == "close":
                    device = None
                elif params[0] == "mode":
                    print device.get_info()
                elif params[0] == "info":
                    data = device.get_vendor_info()
                    tmp = ["Info: "]
                    for i in xrange(16):
                        tmp.append("%.2X " % data[i])
                    tmp.append("...")
                    print "".join(tmp)
                elif params[0] == "get_num_lbas":
                    print "Number of LBAs: 0x%.8X" % device.get_num_lbas()
                elif params[0] == "password":
                    device.send_password(params[1])
                elif params[0] == "dump_xram":
                    print "%s" % device.dump_xram()
                elif params[0] == "dump_firmware":
                    device.dump_firmware(params[1])
                elif params[0] == "nand_read":
                    address = int(params[1], 16)
                    count = int(params[2], 16)
                    data = device.read_nand(address, count)
                    tmp = ["Data: "]
                    for i in xrange(16):
                        tmp.append("%.2X " % data[i])
                    tmp.append("...")
                    print "".join(tmp)
                elif params[0] == "boot":
                    device.jump_to_bootmode()
                    time.sleep(WAIT_TIME_MS/1000.0)
                elif params[0] == "set_burner":
                    burner = params[1]
                elif params[0] == "set_firmware":
                    firmware = params[1]
                elif params[0] == "burner":
                    device.execute_image(burner)
                elif params[0] == "firmware":
                    device.send_firmware(firmware, burner)
                elif params[0] == "peek":
                    address = int(params[1], 16)
                    value = device.read_xram(address)
                    print "Value: %.2X" % value
                elif params[0] == "poke":
                    address = int(params[1], 16)
                    value = int(params[2], 16) & 0xFF
                    device.write_xram(address, value)
                elif params[0] == "ipeek":
                    address = int(params[1], 16) & 0xFF
                    value = device.read_iram(address)
                    print "Value: %.2X" % value
                elif params[0] == "ipoke":
                    address = int(params[1], 16) & 0xFF
                    value = int(params[2], 16) & 0xFF
                    device.write_iram(address, value)
                elif params[0] in ("exit", "quit"):
                    exiting = True
                else:
                    print "Invalid command: %s" % params[0]
            except PhisonDeviceException as device_error:
                print device_error
            except SCSIException as scsi_error:
                print scsi_error
            
    
