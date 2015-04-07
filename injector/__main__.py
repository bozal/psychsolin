#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Command line interface for injector."""

from firmware import Firmware, check_firmware_image
import logging
import argparse

logger = logging.getLogger("injector.__main__")
actions = ["GenerateHFile", "FindFreeBlock", "ApplyPatches"]
section_names = ["Base", "Section0", "Section1", "Section2", "Section3", 
    "Section4", "Section5", "Section6", "Section7", "Section8", "Section9", 
    "SectionA", "SectionB", "SectionC", "SectionD", "SectionE", "SectionF"]



if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    #create argument parser
    parser = argparse.ArgumentParser(description="Manipulate existing binary.")
    parser.add_argument("-a", "--action", choices=actions, required=True, 
        help="action to be performed by the program")
    parser.add_argument("-s", "--section", choices=section_names, 
        help="defines section for --action FindFreeBlock")
    parser.add_argument("-f", "--firmware", required=True,
        help="firmware that should be injected with code")
    parser.add_argument("-o", "--output", required=True,
        help="destination of the result")
    
    # suboptimal choice to provide code and rst files, 
    # since the section is determined by the option name
    # so we have to add two options for every section
    # we do it this way to be compatible to Psychson
    parser.add_argument("--basecode", 
        help="file containing code to be added to base section")
    parser.add_argument("--baserst", 
        help="file containing label->address mapping for the base section")
    for i in xrange(16):
        parser.add_argument("--%icode"%i, 
            help="file containing code to be added to %i (%X) section" % (i, i))
        parser.add_argument("--%irst"%i, 
            help="file containing label->address mapping for the %i. (%X) "
            "section" % (i, i))
    
    args = parser.parse_args()
    
    #check firmware image
    if not check_firmware_image(args.firmware):
        logger.warning("This firmware version is not verified for this "
            "patches.")
    
    fw = Firmware()
    fw.load_from_file(args.firmware)
    
    if args.action == actions[1]:
        # "FindFreeBlock"
        if args.section is None:
            logger.error("No section provided")
        else:
            fw.save_last_free_chunk(section_names.index(args.section), 
                args.output)
    
    if args.action == actions[0]:
        # "GenerateHFile"
        fw.generate_header_file(args.output)
    
    if args.action == actions[2]:
        # "ApplyPatches"
        
        # collect the rst and code files
        code_dict = {}
        rst_dict = {}
        
        args_dict = vars(args)
        if args_dict["basecode"] is not None:
            code_dict[0] = args_dict["basecode"]
        
        if args_dict["baserst"] is not None:
            rst_dict[0] = args_dict["baserst"]
        
        for i in xrange(16):
            code_name = "%icode" % i
            rst_name = "%irst" % i
            
            if args_dict[code_name] is not None:
                code_dict[i+1] = args_dict[code_name]
            
            if args_dict[rst_name] is not None:
                code_dict[i+1] = args_dict[rst_name]
        
        fw.apply_patches(code_dict, rst_dict)
        fw.save(args.output)
        
