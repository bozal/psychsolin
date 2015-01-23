#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import logging

def embed_payload(payload_filename, firmware_filename):
    with open(firmware_filename, "r+b") as firmware_file:
        # skip header
        firmware_file.seek(0x200)
        # read data
        data = firmware_file.read(0x6000)
        # search pattern
        res = re.search(b"\x12\x34\x56\x78", data)
        if res is not None:
            address = res.start(0)
            if (0x200+address) >= 0x6000:
                logging.error("Insufficient memory to inject file!")
                return
            # load payload
            with open(payload_filename, "rb") as payload_file:
                payload = payload_file.read()
            # write payload
            firmware_file.seek(0x200+address)
            firmware_file.write(payload)
            
            logging.info("File updated.")
        else:
            logging.error("Signature not found")

