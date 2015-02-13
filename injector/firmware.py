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
        self._sections.append(Section(BASE_LENGTH))
        self._logger = logging.getLogger("injector.firmware.Firmware")
        self._patch_dict = {}
        self._generate_patch_dict()
    
    def _reset(self):
        self._filename = None
        self._header = None
        # store base at 0, other sections at section number + 1
        # e.g. [base, section_0, section_1, section_2]
        self._sections = []
        self._footer = None
        self._offpage_stubs = {}
    
    def load_from_file(self, filename):
        self._reset()
        
        self._filename = filename
        filesize = os.path.getsize(filename)
        with open(filename, "rb") as firmware_file:
            # read header
            self._header = Section(HEADER_LENGTH, firmware_file)
            
            # read base
            self._sections.append(Section(BASE_LENGTH, firmware_file))
            
            # read sections
            while (filesize - firmware_file.tell()) > FOOTER_LENGTH:
                new_section = Section(SECTION_LENGTH, firmware_file)
                self._sections.append(new_section)
            
            # read footer
            if (filesize - firmware_file.tell()) == FOOTER_LENGTH:
                self._footer = Section(FOOTER_LENGTH, firmware_file)
            
            self._logger.info("%i bytes remain", 
                (filesize - firmware_file.tell()))
    
    def save(self, filename):
        with open(filename, "wb") as firmware_file:
            self._header.write_to_file(firmware_file)
            
            for section in self._sections:
                section.write_to_file(firmware_file)
            
            if self._footer is not None:
                self._footer.write_to_file(firmware_file)
    
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
            res = self._sections[index].search(regex, offset)
            if res is not None:
                return (index, res.start(0))
        
        return (None, None)
    
    def get_last_free_chunk(self, section_index):
        return self._sections[section_index].get_last_free()
    
    def save_last_free_chunk(self, section_index, filename):
        with open(filename, "wb") as chunk_file:
            chunk_file.write("0x%.4X" 
                % self.get_last_free_chunk(section_index))
    
    def get_section(self, section_index):
        try:
            return self._sections[section_index]
        except IndexError:
            return None
    
    # reads word (big endian)
    def _get_word(self, section_index, offset):
        return self._sections[section_index].get_word(offset)
    
    # writes word (big endian)
    def _set_word(self, section_index, offset, value):
        self._sections[section_index].set_word(offset, value)
    
    def generate_header_file(self, filename):
        with open(filename, "wb") as header_file:
            res = self.find_pattern(Patterns.BMREQUESTTYPE)
            if res[0] is not None:
                address = self._get_word(res[0], res[1]+5)
                header_file.write("__xdata __at 0x%.4X BYTE %s;\n"
                    % (address, "bmRequestType"))
                header_file.write("__xdata __at 0x%.4X BYTE %s;\n"
                    % (address+1, "bRequest"))
            
            res = self.find_pattern(Patterns.SCSI_CDB)
            if res[0] is not None:
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
                if res[0] is not None:
                    header_file.write("#define %s 0x%.4X\n"
                        % ("DEFAULT_CDB_HANDLER", res[1]))
            
            res = self.find_pattern(Patterns.SCSI_TAG)
            if res[0] is not None:
                address = self._get_word(res[0], res[1]+len(Patterns.SCSI_TAG))
                header_file.write("__xdata __at 0x%.4X BYTE %s[4];\n"
                    % (address-3, "scsi_tag"))
            
            res = self.find_pattern(Patterns.FW_EPIRQ)
            if res[0] is not None:
                address = self._get_word(res[0], res[1]+17)
                header_file.write("__xdata __at 0x%.4X BYTE %s;\n"
                    % (address, "FW_EPIRQ"))
            
            header_file.write("__xdata __at 0x%.4X BYTE %s[1024];\n" 
                % (0xB000, "EPBUF"))
    
    def _add_offpage_call(self, base_address, page_section, page_address):
        """
        Add an off-page call to base section
        
        base_address:    Address in base section where the off page call is added
        page_section: Index of the destination section.
        page_address:    Address in the destination section
        
        returns: first address after the off page call in the base section
        """
        self._sections[0][base_address] = 0x90
        self._set_word(0, base_address+1, page_address)
        self._sections[0][base_address+3] = 0x02
        self._set_word(0, base_address+4, self._offpage_stubs[page_section])
        
        return base_address+6
    
    # returns address of appended offpage call
    def _append_offpage_call(self, page_section, page_address):
        base = self._sections[0]
        call_address = base.get_last_free()
        
        base.append(0x90)
        base.append_word(page_address)
        base.append(0x02)
        base.append_word(self._offpage_stubs[page_section])
        
        return call_address
    
    def _find_offpage_call_stubs(self):
        # find the off-page call stubs
        offset = 0
        for section_index in xrange(1, 17):
            res = self.find_pattern(Patterns.OFFPAGE_CALL, offset)
            if res[0] is not None:
                self._offpage_stubs[section_index] = res[1]
                # move ahead so we can find the next stub
                offset = res[1] + len(Patterns.OFFPAGE_CALL)
        
    def _add_patch(self, name, function, pattern=None, create_stub=True):
        self._patch_dict[name] = {"function": function, "pattern": pattern,
            "create_stub":create_stub}
    
    def _generate_patch_dict(self):
        self._add_patch("_HandleControlRequest", 
            self._patch_HandleControlRequest, 
            Patterns.CONTROL_REQUEST_HANDLER, False)
        self._add_patch("_EndpointInterrupt",
            self._patch_EndpointInterrupt,
            None, False)
        self._add_patch("_HandleEndpointInterrupt",
            self._patch_HandleEndpointInterrupt,
            Patterns.ENDPOINT_INTERRUPT_HANDLER, True)
        self._add_patch("_HandleCDB",
            self._patch_HandleCDB,
            Patterns.CDB_HANDLER, True)
        self._add_patch("_LoopDo",
            self._patch_LoopDo,
            Patterns.MAIN_LOOP, True)
        self._add_patch("_PasswordReceived",
            self._patch_PasswordReceived,
            Patterns.PASSWORD_HANDLER, True)
    
    def _patch_HandleControlRequest(self, patch_section, patch_address,
            pattern_section, pattern_address):
        # hook into control request handling
        call_address = self._get_word(pattern_section, pattern_address+1)
        self._set_word(pattern_section, call_address+1, patch_address)
        if patch_section != 0:
            # not base
            self._set_word(pattern_section, call_address+4,
                self._offpage_stubs[patch_section])
    
    def _patch_EndpointInterrupt(self, patch_section, patch_address,
            pattern_section, pattern_address):
        # replace the EP interrupt vector, handling all incoming and 
        # outgoing non-control data
        # we diverge from Psychson, since it would allow for multiple 
        # sections to contain endpoint interrupt handlers but that doesn't
        # seem to be useful
        if patch_section != 0:
            self._logger.error("endpoint interupt not in base section")
            return
        self._set_word(0, 0x0014, patch_address)
    
    def _patch_HandleEndpointInterrupt(self, patch_section, patch_address,
            pattern_section, pattern_address):
        sect = self._sections[pattern_section]
        sect.set_sequence(pattern_address, (0x60, 0x0B, 0x00))
        sect.set_word(pattern_address+4, patch_address)
        sect.set_sequence(pattern_address+6, [0x00]*7)
    
    def _patch_HandleCDB(self, patch_section, patch_address,
            pattern_section, pattern_address):
        # CDB handling code
        #TODO: do we assume, that pattern_section==0?
        sect = self._sections[0]
        sect.set_byte(pattern_address, 0x02)
        sect.set_word(pattern_address+1, patch_address)
    
    def _patch_LoopDo(self, patch_section, patch_address,
            pattern_section, pattern_address):
        # add own code to infinite loop
        
        #TODO: do we assume, that pattern_section==0?
        # at this point Psychson uses pattern_section together with the 
        # last free chunk of Base; 
        # that implies that pattern_section is expected to be 0 (index of Base)
        sect = self._sections[pattern_section]
        loop_do_start = sect.get_last_free()
        sect.append(0x12)
        sect.append_word(patch_address)
        sect.append(0x90)
        sect.append_word(sect.get_word(pattern_address+1))
        sect.append(0x22)
        
        sect.set_byte(pattern_address, 0x12)
        sect.set_word(pattern_address+1, loop_do_start)
    
    def _patch_PasswordReceived(self, patch_section, patch_address,
            pattern_section, pattern_address):
        # apply password patch code
        sect = self._sections[pattern_section]
        pattern_address += 0x24
        
        pass_recvd_start = sect.get_last_free()
        if pattern_section != 0:
            # not base
            pass_recvd_start += 0x5000
        
        sect.append(0x12)
        sect.append_word(sect.get_word(pattern_address))
        sect.append(0x02)
        sect.append_word(patch_address)
        sect.set_word(pattern_address, pass_recvd_start)
        
    
    def apply_patches(self, code_dict, rst_dict):
        # read rst files
        maps = {}
        for section_index, filename in rst_dict.items():
            maps[section_index] = get_address_map(filename)
        
        # embed code files
        for section_index, filename in code_dict.items():
            with open(filename, "rb") as code_file:
                code = bytearray(code_file.read())
            self._sections[section_index].extend(code)
        
        # find the off-page call stubs
        self._find_offpage_call_stubs()
        
        for patch_name, patch_data in self._patch_dict.items():
            patch_section, patch_address = find_in_inner_dict(maps, patch_name)
            if patch_section is not None:
                pattern_section = None
                pattern_address = None
                
                if patch_data["pattern"] is not None:
                    pattern_section, pattern_address = self.find_pattern(
                        patch_data["pattern"])
                    if pattern_section is None:
                        continue
                
                if patch_data["create_stub"] and (patch_section != 0):
                    # create off-page stub
                    patch_address = self._append_offpage_call(patch_section,
                        patch_address)
                
                self._logger.info("Applying patch %s", patch_name)
                patch_data["function"](patch_section, patch_address,
                    pattern_section, pattern_address)
                    

class Section(object):
    def __init__(self, length, data_source=None):
        if data_source is None:
            self._data = bytearray(length)
            self._last_free = 0
        else:
            data = data_source.read(length)
            self._data = bytearray(data)
            
            if len(data) < length:
                raise IOError("expected %i bytes, but got only %i" % 
                    (length, len(data)))
            
            self._last_free = self._find_last_free_chunk()
    
    def _find_last_free_chunk(self):
        ret = -1
        
        repeating = self._data[-1]
        ret = len(self._data) - 2
        
        while self._data[ret] == repeating:
            ret -= 1
            if ret < 0:
                break
        
        return ret + 1
    
    def get_last_free(self):
        return self._last_free
    
    # update last free by passing (the highest) address written to
    def _update_last_free(self, written_to):
        if written_to >= self._last_free:
            self._last_free = written_to + 1
    
    # reads word (big endian)
    def get_word(self, offset):
        value = self._data[offset] << 8
        value += self._data[offset+1]
        return value
    
    def set_byte(self, offset, value):
        self._data[offset] = value
        self._update_last_free(offset)
    
    # writes word (big endian)
    def set_word(self, offset, value):
        self._data[offset] = (value >> 8) & 0xFF
        self._data[offset+1] = value & 0xFF
        self._update_last_free(offset+1)
    
    def set_sequence(self, offset, values):
        for i in xrange(len(values)):
            self._data[offset+i] = values[i]
        self._update_last_free(offset+len(values)-1)
        
    def append(self, value):
        self.set_byte(self._last_free, value)
    
    def extend(self, values):
        self.set_sequence(self._last_free, values)
    
    def append_word(self, value):
        self.set_word(self._last_free, value)
    
    def write_to_file(self, output_file):
        output_file.write(self._data)
    
    def search(self, regex, offset):
        return regex.search(self._data, offset)
    
    def get_all(self):
        return bytearray(self._data)
    
# only with sections
def save_if_not_none(sec, filename):
    if sec is not None:
        with open(filename, "wb") as data_file:
            sec.write_to_file(data_file)


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
    
    return (None, None)
