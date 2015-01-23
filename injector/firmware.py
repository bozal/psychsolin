#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import hashlib
import logging

HEADER_LENGTH = 0x200
BASE_LENGTH = 0x6000
# 16k swapped in
SECTION_LENGTH = 0x4000
FOOTER_LENGTH = 0x200
# md5 hashes of supported firmwares
VERIFIED = ('4c4c0001ec83102c4627d271ff8362a2', )

class Patterns(object):
    BMREQUESTTYPE = (
        0x90, 0xF0, 0xB8, 0xE0, # mov DPTR, #0xF0B8 \ movx a, @DPTR
        0x90, None, None, 0xF0, # mov DPTR, #0x???? \ movx @DPTR, a
        0x90, 0xF0, 0xB9, 0xE0  # mov DPTR, #0xF0B9 \ movx a, @DPTR \ movx DPTR, #0x????
    )
    
    SCSI_CDB = (
        0x90, None, None, 0xE0, # mov DPTR, #0x???? \ movx a, @DPTR
        0xB4, 0x28 # cjne A, #0x28, ????
    )
    
    SCSI_TAG = (
        0x90, 0xF2, 0x1C, # mov DPTR, #0xF21C
        0x74, 0x55, 0xF0, # mov A, #0x55 \ movx @DPTR, A
        0x74, 0x53, 0xF0, # mov A, #0x53 \ movx @DPTR, A
        0x74, 0x42, 0xF0, # mov A, #0x42 \ movx @DPTR, A
        0x74, 0x53, 0xF0, # mov A, #0x53 \ movx @DPTR, A
        0x90 # mov DPTR, #0x????
    )
    
    FW_EPIRQ = (
        0xC0, 0xE0, 0xC0, 0x83, 0xC0, 0x82, # push ACC \ push DPH \ push DPL
        0x90, 0xF0, 0x20, 0xE0, # mov DPTR, #0xF020 \ movx A, @DPTR
        0x30, 0xE1, None, # jnb ACC.1, ????
        0x12, None, None, 0x90 # lcall ???? \ mov DPTR, #0x????
    )
    
    OFFPAGE_CALL = (
        0xC0, 0x5B, 0x74, 0x08, # push RAM_5B \ mov A, #8
        0xC0, 0xE0, 0xC0, 0x82, 0xC0, 0x83, # push ACC \ push DPL \ push DPH
        0x75, 0x5B # mov RAM_5B, #0x??
    )
    
    CONTROL_REQUEST_HANDLER = (
        0x12, None, None, # lcall #0x????
        0x90, 0xFE, 0x82, 0xE0, # mov DPTR, #0xFE82 \ movx A, @DPTR
        0x54, 0xEF, 0xF0 # anl A, #0xEF \ movx @DPTR, A
    )
    
    ENDPOINT_INTERRUPT_HANDLER = (
        0x30, 0xE1, None, # jnb ACC.1, #0x????
        0x12, None, None, # lcall #0x????
        0x90, 0xFE, 0x82, 0xE0, # mov DPTR, #0xFE82 \ movx A, @DPTR
        0x54, 0xEF, 0xF0 # anl A, #0xEF \ movx @DPTR, A
    )
    
    CDB_HANDLER = (
        0x90, None, None, 0xE0, # mov DPTR, #0x???? \ movx a, @DPTR
        0xB4, 0x28 # cjne A, #0x28, ????
    )
    
    MAIN_LOOP = (
        0x90, None, None, 0xE0, # mov DPTR, #0x???? \ movx A, @DPTR
        0xB4, 0x01, None, # cjne A, #1, #0x????
        0x90, 0xF0, 0x79 # mov DPTR, #0xF079
    )
    
    PASSWORD_HANDLER = (
        0x90, 0xF2, 0x4C, 0xF0, 0xA3, # mov DPTR, #0xF24C \ movx @DPTR, A \ inc DPTR
        0xC0, 0x83, 0xC0, 0x82, 0x12, # push DPH \ push DPL
        None, None, 0xD0, 0x82, 0xD0, 0x83, 0xF0, # lcall #0x???? \ pop DPL \ pop DPH \ movx @DPTR, A
        0x90, 0xF2, 0x53, 0x74, 0x80, 0xF0, # mov DPTR, #0xF253 \ mov A, #0x80 \ movx @DPTR, A
        0x90, 0xF2, 0x53, 0xE0, # mov DPTR, #0xF253 \ movx A, @DPTR
        0x30, 0xE7, None, # jnb ACC.7, #0x????
        0x12, None, None, 0x40, None, # lcall #0x???? \ jc #0x????
        0x12, None, None, 0x7F, 0x00, 0x22 # lcall #0x???? \ mov R7, #0 \ ret
    )

class Firmware(object):
    def __init__(self):
        self._reset()
        self._sections.append(bytearray([0]*BASE_LENGTH))
        self._logger = logging.getLogger("injector.firmware.Firmware")
    
    def _reset(self):
        self._filename = None
        self._header = None
        # store base at 0, other sections at section number + 1
        # e.g. [base, section_0, section_1, section_2]
        self._sections = []
        self._footer = None
    
    def load_from_file(self, filename):
        self._reset()
        
        self._filename = filename
        filesize = os.path.getsize(filename)
        with open(filename, "rb") as firmware_file:
            # read header
            self._header = bytearray(firmware_file.read(HEADER_LENGTH))
            
            # read base
            self._sections.append(bytearray(firmware_file.read(BASE_LENGTH)))
            
            # read sections
            while (filesize - firmware_file.tell()) > FOOTER_LENGTH:
                new_section = bytearray(firmware_file.read(SECTION_LENGTH))
                self._sections.append(new_section)
            
            # read footer
            if (filesize - firmware_file.tell()) == FOOTER_LENGTH:
                self._footer = bytearray(firmware_file.read(FOOTER_LENGTH))
            
            self._logger.info("%i bytes remain", 
                (filesize - firmware_file.tell()))
    
    def save(self, filename):
        with open(filename, "wb") as firmware_file:
            firmware_file.write(self._header)
            
            for section in self._sections:
                firmware_file.write(section)
            
            if self._footer is not None:
                firmware_file.write(self._footer)
    
    def save_separate(self, filename):
        # save header
        save_if_not_none(self._header, "%s.header.bin" % filename)
        
        # save sections
        save_if_not_none(self._sections[0], "%s.base.bin" % (filename,))
        for i in xrange(1, len(self._sections)):
            save_if_not_none(self._sections[i], "%s.%X.bin" % (filename, i-1))
        
        # save footer
        save_if_not_none(self._footer, "%s.footer.bin" % filename)
    
    # byte_pattern is sequence of bytes (and None) to represent the searched pattern
    # None is a wildcard
    def find_pattern(self, byte_pattern, offset=0):
        # transform to pattern
        parts = []
        seq = []
        for token in byte_pattern:
            if token is None:
                # add escaped string
                parts.append(re.escape("".join(seq)))
                seq = []
                # add wildcard
                parts.append(".")
            else:
                seq.append(chr(token))
        
        # append last bytes
        if len(seq) > 0:
            parts.append(re.escape("".join(seq)))
        
        pattern = "".join(parts)
        
        # re.DOTALL means '.' also matches newline
        regex = re.compile(pattern, re.DOTALL)
        
        # this way to search means we find occasions in 
        # multiple sections always in the first section it occures
        
        for index in xrange(len(self._sections)):
            res = regex.search(self._sections[index], offset)
            if res is not None:
                return (index, res.start(0))
        
        return None
    
    def find_last_free_chunk(self, section_index):
        ret = -1
        
        if section_index < len(self._sections):
            data = self._sections[section_index]
            repeating = data[-1]
            ret = len(data) - 2
            
            while data[ret] == repeating:
                ret -= 1
                if ret < 0:
                    break
        
        return ret + 1
    
    def save_last_free_chunk(self, section_index, filename):
        with open(filename, "wb") as chunk_file:
            chunk_file.write("0x%.4X" 
                % self.find_last_free_chunk(section_index))
    
    def get_section(self, section_index):
        try:
            return self._sections[section_index]
        except IndexError:
            return None
    
    # reads word (big endian)
    def _get_word(self, section_index, offset):
        address = self._sections[section_index][offset] << 8
        address += self._sections[section_index][offset+1]
        return address
    
    # writes word (big endian)
    def _set_word(self, section_index, offset, value):
        self._sections[section_index][offset] = (value >> 8) & 0xFF
        self._sections[section_index][offset+1] = value & 0xFF
    
    def generate_header_file(self, filename):
        with open(filename, "wb") as header_file:
            res = self.find_pattern(Patterns.BMREQUESTTYPE)
            if res is not None:
                address = self._get_word(res[0], res[1]+5)
                header_file.write("__xdata __at 0x%.4X BYTE %s;\n"
                    % (address, "bmRequestType"))
                header_file.write("__xdata __at 0x%.4X BYTE %s;\n"
                    % (address+1, "bRequest"))
            
            res = self.find_pattern(Patterns.SCSI_CDB)
            if res is not None:
                address = self._get_word(res[0], res[1]+1)
                header_file.write("__xdata __at 0x%.4X BYTE %s[16];\n"
                    % (address, "scsi_cdb"))
                #TODO: sure that we can take the result? 
                # since it might be a swapped in section,
                # so address is result + 0x5000
                header_file.write("#define %s 0x%.4X\n"
                    % ("DEFAULT_READ_SECTOR_HANDLER", res[1]+7))
                
                handler_pattern = (0x90, address>>8, address&0xFF, # mov DPTR, #scsi_tag
                    0xE0, 0x12) # mvox A, @DPTR \ lcall 0x????
                res = self.find_pattern(handler_pattern, res[1])
                if res is not None:
                    header_file.write("#define %s 0x%.4X\n"
                        % ("DEFAULT_CDB_HANDLER", res[1]))
            
            res = self.find_pattern(Patterns.SCSI_TAG)
            if res is not None:
                address = self._get_word(res[0], res[1]+len(Patterns.SCSI_TAG))
                header_file.write("__xdata __at 0x%.4X BYTE %s[4];\n"
                    % (address-3, "scsi_tag"))
            
            res = self.find_pattern(Patterns.FW_EPIRQ)
            if res is not None:
                address = self._get_word(res[0], res[1]+17)
                header_file.write("__xdata __at 0x%.4X BYTE %s;\n"
                    % (address, "FW_EPIRQ"))
            
            header_file.write("__xdata __at 0x%.4X BYTE %s[1024];\n" 
                % (0xB000, "EPBUF"))
    
    def _add_offpage_call(self, base_address, page_address, stub_address):
        """
        Add an off-page call to base section
        
        base_address:    Address in base section where the off page call is added
        page_address:    Address in the destination section
        stub_address:    Address of the off-page call stubs in the base section for the destionation section
        
        returns: first address after the off page call in the base section
        """
        self._sections[0][base_address] = 0x90
        self._set_word(0, base_address+1, page_address)
        self._sections[0][base_address+3] = 0x02
        self._set_word(0, base_address+4, stub_address)
        
        return base_address+6
    
    def apply_patches(self, code_dict, rst_dict):
        # read rst files
        maps = {}
        for section_index, filename in rst_dict.items():
            maps[section_index] = get_address_map(filename)
        
        # find free space in each section
        empty_start = []
        for section_index in xrange(17):
            empty_start.append(self.find_last_free_chunk(section_index))
        
        # embed code files
        for section_index, filename in code_dict.items():
            with open(filename, "rb") as code_file:
                code = bytearray(code_file.read())
            for i in xrange(len(code)):
                self._sections[section_index][empty_start[section_index]+i] = code[i]
            empty_start[section_index] += len(code)
        
        # find the off-page call stubs
        stubs = {}
        offset = 0
        for section_index in xrange(1, 17):
            res = self.find_pattern(Patterns.OFFPAGE_CALL, offset)
            if res is not None:
                stubs[section_index] = res[1]
                # move ahead so we can find the next stub
                offset = res[1] + len(Patterns.OFFPAGE_CALL)
        
        # hook into control request handling
        res = find_in_inner_dict(maps, "_HandleControlRequest")
        if res is not None:
            section_index, address = res
            
            res = self.find_pattern(Patterns.CONTROL_REQUEST_HANDLER)
            if res is not None:
                call_address = self._get_word(res[0], res[1]+1)
                self._set_word(res[0], call_address+1, address)
                if section_index != 0:
                    # not base
                    self._set_word(res[0], call_address+4, stubs[section_index])
        
        # replace the EP interrupt vector, handling all incoming and 
        # outgoing non-control data
        # we diverge from Psychson, since it would allow for multiple 
        # sections to contain endpoint interrupt handlers but that doesn't
        # seam to be useful
        res = find_in_inner_dict(maps, "_EndpointInterrupt")
        if res is not None:
            if res[0] != 0:
                self._logger.error("endpoint interupt not in base section")
            self._set_word(0, 0x0014, res[1])
        
        res = find_in_inner_dict(maps, "_HandleEndpointInterrupt")
        if res is not None:
            section_index, address = res
            
            res = self.find_pattern(Patterns.ENDPOINT_INTERRUPT_HANDLER)
            if res is not None:
                stub_address = address
                if section_index != 0:
                    # create off-page stub
                    stub_address = empty_start[0]
                    empty_start[0] = self._add_offpage_call(
                        empty_start[0], address, 
                        stubs[section_index])
                
                self._sections[res[0]][res[1]] = 0x60
                self._sections[res[0]][res[1]+1] = 0x0B
                self._sections[res[0]][res[1]+2] = 0x00
                self._set_word(res[0], res[1]+4, stub_address)
                for i in xrange(7):
                    self._sections[res[0]][res[1]+6+i] = 0x00
                
        # CDB handling code
        res = find_in_inner_dict(maps, "_HandleCDB")
        if res is not None:
            section_index, address = res
            
            res = self.find_pattern(Patterns.CDB_HANDLER)
            if res is not None:
                stub_address = address
                if section_index != 0:
                    # create off-page stub
                    stub_address = empty_start[0]
                    empty_start[0] = self._add_offpage_call(
                        empty_start[0], address, 
                        stubs[section_index])
                
                #TODO: do we assume, that res[0]==0?
                self._sections[0][res[1]] = 0x02
                self._set_word(0, res[1]+1, stub_address)
        
        # add own code to infinite loop
        res = find_in_inner_dict(maps, "_LoopDo")
        if res is not None:
            section_index, address = res
            
            res = self.find_pattern(Patterns.MAIN_LOOP)
            if res is not None:
                stub_address = address
                if section_index != 0:
                    # create off-page stub
                    stub_address = empty_start[0]
                    empty_start[0] = self._add_offpage_call(
                        empty_start[0], address, 
                        stubs[section_index])
                
                #TODO: do we assume, that res[0]==0?
                loop_do_start = empty_start[0]
                self._sections[res[0]][empty_start[0]] = 0x12
                self._set_word(res[0], empty_start[0]+1, stub_address)
                self._sections[res[0]][empty_start[0]+3] = 0x90
                self._sections[res[0]][empty_start[0]+4] = self._sections[res[0]][res[1]+1]
                self._sections[res[0]][empty_start[0]+5] = self._sections[res[0]][res[1]+2]
                self._sections[res[0]][empty_start[0]+6] = 0x22
                empty_start[0] += 7
                self._sections[res[0]][res[1]] = 0x12
                self._set_word(res[0], res[1]+1, loop_do_start)
        
        # apply password patch code
        res = find_in_inner_dict(maps, "_PasswordReceived")
        if res is not None:
            section_index, address = res
            
            res = self.find_pattern(Patterns.PASSWORD_HANDLER)
            if res is not None:
                stub_address = address
                if section_index != 0:
                    # create off-page stub
                    stub_address = empty_start[0]
                    empty_start[0] = self._add_offpage_call(
                        empty_start[0], address, 
                        stubs[section_index])
                        
                pa = res[1] + 0x24
                pass_recvd_start = empty_start[res[0]]
                if res[0] != 0:
                    pass_recvd_start += 0x5000
                self._sections[res[0]][empty_start[res[0]]] = 0x12
                self._sections[res[0]][empty_start[res[0]]+1] = self._sections[res[0]][pa]
                self._sections[res[0]][empty_start[res[0]]+2] = self._sections[res[0]][pa+1]
                self._sections[res[0]][empty_start[res[0]]+3] = 0x02
                self._set_word(res[0], empty_start[res[0]]+4, stub_address)
                empty_start[res[0]] += 6
                self._set_word(res[0], pa, pass_recvd_start)

def save_if_not_none(data, filename):
    if data is not None:
        with open(filename, "wb") as data_file:
            data_file.write(data)


def check_firmware_image(filename):
    md5 = hashlib.md5()
    with open(filename, "rb") as firmware_file:
        md5.update(firmware_file.read())
    return md5.hexdigest() in VERIFIED

def get_address_map(filename):
    regex = re.compile(
        r"^\s*(?P<address>[0-9a-fA-F]+)\s+(\S+\s+)*(?P<label>_\S*):$")
    address_map = {}
    with open(filename, "rb") as rst_file:
        for line in rst_file:
            res = regex.match(line)
            if res is not None:
                address_map[res.group("label")] = int(res.group("address"), 16)
    
    return address_map

# searches inner dictionaries that are value of an outer dictionary for a certain inner key
# and returns the outer key and the inner value for the or None
# e.g. d={0:{"a":23}, 4:{"b":24, "gwr":2}}
# find_key_in_dict_dict(d, "b") returns (4, 24)
def find_in_inner_dict(outer_dict, inner_key):
    for outer_key, inner_dict in outer_dict.items():
        if inner_key in inner_dict:
            return (outer_key, inner_dict[inner_key])
    
    return None
