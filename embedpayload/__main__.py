#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import argparse
from embedpayload import embed_payload

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    #create argument parser
    parser = argparse.ArgumentParser(
        description="Inject compiled Rubber Ducky script "
        "in a custom firmware.")
    parser.add_argument("payload_bin", 
        help="compiled Rubber Ducky script")
    parser.add_argument("firmware_image", 
        help="custom firmware image")
    
    args = parser.parse_args()
    
    embed_payload(args.payload_bin, args.firmware_image)

