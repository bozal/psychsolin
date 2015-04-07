# -*- coding: utf-8 -*-

"""Provide objects and helper methods for handling firmware binaries."""

import patterns

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

class Firmware(object):
    """Represent complete firmware binary."""
    
    def __init__(self):
        self._reset()
        self._sections.append(Section(BASE_LENGTH))
        self._logger = logging.getLogger("injector.firmware.Firmware")
        self._patch_dict = {}
        self._generate_patch_dict()
    
    def _reset(self):
        """Clear all data structures."""
        self._filename = None
        self._header = None
        # store base at 0, other sections at section number + 1
        # e.g. [base, section_0, section_1, section_2]
        self._sections = []
        self._footer = None
        self._offpage_stubs = {}
    
    def load_from_file(self, filename):
        """Load firmware from file.
        
        The binary file is expected to have a header, followed by the different
        sections and and an optional footer.
        
        Args:
          filename: Name of the file containing the firmware.
        """
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
        """Save firmware to file.
        
        Args:
          filename: Name of the file.
        """
        with open(filename, "wb") as firmware_file:
            self._header.write_to_file(firmware_file)
            
            for section in self._sections:
                section.write_to_file(firmware_file)
            
            if self._footer is not None:
                self._footer.write_to_file(firmware_file)
    
    def save_separate(self, filename):
        """Save header, footer and every section to a different file.
        
        The passed file name is used as a base for the files.
        
        Args:
          filename: Name base for the created files.
        """
        
        # save header
        save_if_not_none(self._header, "%s.header.bin" % filename)
        
        # save sections
        save_if_not_none(self._sections[0], "%s.base.bin" % (filename,))
        for i in xrange(1, len(self._sections)):
            save_if_not_none(self._sections[i], "%s.%X.bin" % (filename, i-1))
        
        # save footer
        save_if_not_none(self._footer, "%s.footer.bin" % filename)
    
    def find_pattern(self, byte_pattern, offset=0):
        """Search for a byte pattern.
        
        The sections are seached in acending order of their section index,
        starting with base, followed by section 0.
        
        None is regarded as wildcard and matches every byte value.
        
        Args:
          byte_pattern: Sequence of byte values and None (wildcard).
          offset: Offset the search starts in each section.
              Default is 0.
        
        Returns:
          Returns a tuple (section index, match start) of the first found
          occurence of the byte pattern or (None, None) if the byte pattern 
          wasn't found.
        """
        
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
        """Get last free chunk of a section.
        
        Args:
          section_index: Index of the section.
        
        Returns:
          Offset of the first byte of the last free chunk.
        """
        return self._sections[section_index].get_last_free()
    
    def save_last_free_chunk(self, section_index, filename):
        """Write last free chunk of a section to a file.
        
        The offset of the first byte of the last fre chunk is written as 
        hex number in ASCII.
        
        Args:
          section_index: Index of the section.
          filename: Name of the file.
        """
        with open(filename, "wb") as chunk_file:
            chunk_file.write("0x%.4X" 
                % self.get_last_free_chunk(section_index))
    
    def get_section(self, section_index):
        """Get section.
        
        Args:
          section_index: Index of the section.
        
        Returns:
          Object representing the section.
        """
        try:
            return self._sections[section_index]
        except IndexError:
            return None
    
    def _get_word(self, section_index, offset):
        """Read word from binary.
        
        Reads word big endian.
        
        Args:
          section_index: Index of the section.
          offset: Offset in the section.
        
        Returns:
          Value of the word.
        """
        return self._sections[section_index].get_word(offset)
    
    # writes word (big endian)
    def _set_word(self, section_index, offset, value):
        """Write word to binary.
        
        Writes word big endian.
        
        Args:
          section_index: Index of the section.
          offset: Offset in the section.
          value: Value of the word.
        """
        self._sections[section_index].set_word(offset, value)
    
    def generate_header_file(self, filename):
        """Generate C header file corresponding to the binary.
        
        Args:
          filename: Name of the header file.
        """
        with open(filename, "wb") as header_file:
            pattern_section, pattern_address = self.find_pattern(
                patterns.BMREQUESTTYPE)
            if pattern_section is not None:
                address = self._get_word(pattern_section, pattern_address+5)
                header_file.write("__xdata __at 0x%.4X BYTE %s;\n"
                    % (address, "bmRequestType"))
                header_file.write("__xdata __at 0x%.4X BYTE %s;\n"
                    % (address+1, "bRequest"))
            
            pattern_section, pattern_address = self.find_pattern(
                patterns.SCSI_CDB)
            if pattern_section is not None:
                address = self._get_word(pattern_section, pattern_address+1)
                header_file.write("__xdata __at 0x%.4X BYTE %s[16];\n"
                    % (address, "scsi_cdb"))
                #TODO: sure that we can take the result? 
                # since it might be a swapped in section,
                # so address is result + 0x5000
                header_file.write("#define %s 0x%.4X\n"
                    % ("DEFAULT_READ_SECTOR_HANDLER", pattern_address+7))
                
                handler_pattern = (0x90, address>>8, address&0xFF, # mov DPTR, #scsi_tag
                    0xE0, 0x12) # mvox A, @DPTR \ lcall 0x????
                handler_section, handler_address = self.find_pattern(
                    handler_pattern, pattern_address)
                if handler_section is not None:
                    header_file.write("#define %s 0x%.4X\n"
                        % ("DEFAULT_CDB_HANDLER", handler_address))
            
            pattern_section, pattern_address = self.find_pattern(
                patterns.SCSI_TAG)
            if pattern_section is not None:
                address = self._get_word(pattern_section, 
                    pattern_address+len(patterns.SCSI_TAG))
                header_file.write("__xdata __at 0x%.4X BYTE %s[4];\n"
                    % (address-3, "scsi_tag"))
            
            pattern_section, pattern_address = self.find_pattern(
                patterns.FW_EPIRQ)
            if pattern_section is not None:
                address = self._get_word(pattern_section, pattern_address+17)
                header_file.write("__xdata __at 0x%.4X BYTE %s;\n"
                    % (address, "FW_EPIRQ"))
            
            header_file.write("__xdata __at 0x%.4X BYTE %s[1024];\n" 
                % (0xB000, "EPBUF"))
    
    def _append_offpage_call(self, page_section, page_address):
        """Append off page call to base section.
        
        Args:
          page_section: Index of the section containing the called code.
          page_address: Address of the called code in the section.
        
        Returns:
          Address of appended offpage call in the base section.
        """
        base = self._sections[0]
        call_address = base.get_last_free()
        
        base.append(0x90)
        base.append_word(page_address)
        base.append(0x02)
        base.append_word(self._offpage_stubs[page_section])
        
        return call_address
    
    def _find_offpage_call_stubs(self):
        """Initiate internal structure providing off page call stubs."""
        
        # find the off-page call stubs
        offset = 0
        for section_index in xrange(1, 17):
            call_section, call_address = self.find_pattern(
                patterns.OFFPAGE_CALL, offset)
            if call_section is not None:
                self._offpage_stubs[section_index] = call_address
                # move ahead so we can find the next stub
                offset = call_address + len(patterns.OFFPAGE_CALL)
        
    def _add_patch(self, name, function, pattern=None, create_stub=True):
        """Add patch to internal patch dictionary.
        
        Args:
          name: Name of the patch.
          function: Function that contains the code to apply the patch. Has to
              accept four parameters (patch_section, patch_address,
              pattern_section, pattern_address).
          pattern: If a byte pattern is provided, the patch is only applied  
              if the pattern is found.
              Default is None.
          create_stub: Flag to automatically create an off page call if 
              necessary.
              Default is True.
        """
        self._patch_dict[name] = {"function": function, "pattern": pattern,
            "create_stub":create_stub}
    
    def _generate_patch_dict(self):
        """Generate internal dictionary containing all available patches."""
        self._add_patch("_HandleControlRequest", 
            self._patch_HandleControlRequest, 
            patterns.CONTROL_REQUEST_HANDLER, False)
        self._add_patch("_EndpointInterrupt",
            self._patch_EndpointInterrupt,
            None, False)
        self._add_patch("_HandleEndpointInterrupt",
            self._patch_HandleEndpointInterrupt,
            patterns.ENDPOINT_INTERRUPT_HANDLER, True)
        self._add_patch("_HandleCDB",
            self._patch_HandleCDB,
            patterns.CDB_HANDLER, True)
        self._add_patch("_LoopDo",
            self._patch_LoopDo,
            patterns.MAIN_LOOP, True)
        self._add_patch("_PasswordReceived",
            self._patch_PasswordReceived,
            patterns.PASSWORD_HANDLER, True)
    
    def _patch_HandleControlRequest(self, patch_section, patch_address,
            pattern_section, pattern_address):
        """Patch to hook into control request handling.
        
        Args:
          patch_section: Index of the section that contains the patch code.
          patch_address: Address of the patch code in the section. Or address
              of the off page call in the base section, if an off page call was
              created.
          pattern_section: Index of the section, that contains the associated
              byte pattern. Or None if no byte pattern was provided.
          pattern_address: Address of the associated byte pattern in the 
              section. Or None if no byte pattern was provided.
        """
        call_address = self._get_word(pattern_section, pattern_address+1)
        self._set_word(pattern_section, call_address+1, patch_address)
        if patch_section != 0:
            # not base
            self._set_word(pattern_section, call_address+4,
                self._offpage_stubs[patch_section])
    
    def _patch_EndpointInterrupt(self, patch_section, patch_address,
            pattern_section, pattern_address):
        """Patch to replace the EP interrupt vector.
        
        The EP interrupt vector handles all incoming and outgoing non-control 
        data.
        
        Args:
          patch_section: Index of the section that contains the patch code.
          patch_address: Address of the patch code in the section. Or address
              of the off page call in the base section, if an off page call was
              created.
          pattern_section: Index of the section, that contains the associated
              byte pattern. Or None if no byte pattern was provided.
          pattern_address: Address of the associated byte pattern in the 
              section. Or None if no byte pattern was provided.
        """
        # we diverge from Psychson, since it would allow for multiple 
        # sections to contain endpoint interrupt handlers but that doesn't
        # seem to be useful
        if patch_section != 0:
            self._logger.error("endpoint interupt not in base section")
            return
        self._set_word(0, 0x0014, patch_address)
    
    def _patch_HandleEndpointInterrupt(self, patch_section, patch_address,
            pattern_section, pattern_address):
        """Patch the Endpoint Interrupt handler.
        
        Args:
          patch_section: Index of the section that contains the patch code.
          patch_address: Address of the patch code in the section. Or address
              of the off page call in the base section, if an off page call was
              created.
          pattern_section: Index of the section, that contains the associated
              byte pattern. Or None if no byte pattern was provided.
          pattern_address: Address of the associated byte pattern in the 
              section. Or None if no byte pattern was provided.
        """
        sect = self._sections[pattern_section]
        sect.set_sequence(pattern_address, (0x60, 0x0B, 0x00))
        sect.set_word(pattern_address+4, patch_address)
        sect.set_sequence(pattern_address+6, [0x00]*7)
    
    def _patch_HandleCDB(self, patch_section, patch_address,
            pattern_section, pattern_address):
        """Patch for the CDB handling code.
        
        Args:
          patch_section: Index of the section that contains the patch code.
          patch_address: Address of the patch code in the section. Or address
              of the off page call in the base section, if an off page call was
              created.
          pattern_section: Index of the section, that contains the associated
              byte pattern. Or None if no byte pattern was provided.
          pattern_address: Address of the associated byte pattern in the 
              section. Or None if no byte pattern was provided.
        """
        #TODO: do we assume, that pattern_section==0?
        sect = self._sections[0]
        sect.set_byte(pattern_address, 0x02)
        sect.set_word(pattern_address+1, patch_address)
    
    def _patch_LoopDo(self, patch_section, patch_address,
            pattern_section, pattern_address):
        """Add own code to infinite loop.
        
        Args:
          patch_section: Index of the section that contains the patch code.
          patch_address: Address of the patch code in the section. Or address
              of the off page call in the base section, if an off page call was
              created.
          pattern_section: Index of the section, that contains the associated
              byte pattern. Or None if no byte pattern was provided.
          pattern_address: Address of the associated byte pattern in the 
              section. Or None if no byte pattern was provided.
        """
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
        """Patch password handling code.
        
        Args:
          patch_section: Index of the section that contains the patch code.
          patch_address: Address of the patch code in the section. Or address
              of the off page call in the base section, if an off page call was
              created.
          pattern_section: Index of the section, that contains the associated
              byte pattern. Or None if no byte pattern was provided.
          pattern_address: Address of the associated byte pattern in the 
              section. Or None if no byte pattern was provided.
        """
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
        """Apply patches.
        
        Args:
          code_dict: Dictionary mapping the indices of sections to names of
              binary files containing code.
          rst_dict: Dictionary mapping the indices of sections to names of
              rst files containing the label and addresses of code.
        """
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
                        self._logger.error("Can't find pattern for %s. "
                            "Don't apply patch", patch_name)
                        continue
                
                if patch_data["create_stub"] and (patch_section != 0):
                    # create off-page stub
                    patch_address = self._append_offpage_call(patch_section,
                        patch_address)
                
                self._logger.info("Applying patch %s", patch_name)
                patch_data["function"](patch_section, patch_address,
                    pattern_section, pattern_address)
                    

class Section(object):
    """Represent one section of firmware binary."""
    
    def __init__(self, length, data_source=None):
        """Initiate section object.
        
        Args:
          length: Amount of data the section can store in bytes.
          data_source: Should provide a read function to read in the initial 
              data of the section.
              Default is None.
        
        Raises:
          IOError: If data_source was not able to provide the whole initial 
              data.
        """
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
        """Search for last free chunk.
        
        Last free chunk is expected to contain a repeating byte value 
        (not necessary 0x00).
        
        Returns:
          Address of the first byte of the last free chunk.
        """
        ret = -1
        
        repeating = self._data[-1]
        ret = len(self._data) - 2
        
        while self._data[ret] == repeating:
            ret -= 1
            if ret < 0:
                break
        
        return ret + 1
    
    def get_last_free(self):
        """Get last free chunk.
        
        Returns:
          Address of the first byte of the last free chunk.
        """
        return self._last_free
    
    def _update_last_free(self, written_to):
        """Update the last free chunk.
        
        Args:
          written_to: Highest address that was written.
        """
        if written_to >= self._last_free:
            self._last_free = written_to + 1
    
    def get_word(self, offset):
        """Read word big endian.
        
        Args:
          offset: Address of the word in the section.
        
        Returns:
          Value of the word.
        """
        value = self._data[offset] << 8
        value += self._data[offset+1]
        return value
    
    def set_byte(self, offset, value):
        """Write byte.
        
        Args:
          offset: Address of the byte in the section.
          value: Value of the byte
        """
        self._data[offset] = value
        self._update_last_free(offset)
    
    def set_word(self, offset, value):
        """Write word big endian.
        
        Args:
          offset: Address of the word in the section.
          value: Value of the word.
        """
        self._data[offset] = (value >> 8) & 0xFF
        self._data[offset+1] = value & 0xFF
        self._update_last_free(offset+1)
    
    def set_sequence(self, offset, values):
        """Write sequence of byte values.
        
        Args:
          offset: Address of the first byte.
          values: Sequence of byte values.
        """
        for i in xrange(len(values)):
            self._data[offset+i] = values[i]
        self._update_last_free(offset+len(values)-1)
        
    def append(self, value):
        """Append byte to the end.
        
        Args:
          value: Value of the byte.
        """
        self.set_byte(self._last_free, value)
    
    def extend(self, values):
        """Append sequence of bytes to the end.
        
        Args:
          values: Sequence of byte values.
        """
        self.set_sequence(self._last_free, values)
    
    def append_word(self, value):
        """Append word to the end.
        
        Args:
          value: Value of the word
        """
        self.set_word(self._last_free, value)
    
    def write_to_file(self, output_file):
        """Write section data to file object.
        
        Args:
          output_file: File object.
        """
        output_file.write(self._data)
    
    def search(self, regex, offset):
        """Search for a regular expression in the section data.
        
        Args:
          regex: Regular expression to be applied.
          offset: Start search at this offset.
        
        Returns:
          Result of search.
        """
        return regex.search(self._data, offset)
    
    def get_all(self):
        """Get copy of all data.
        
        Returns:
          Copy of the section data.
        """
        return bytearray(self._data)
    
def save_if_not_none(sec, filename):
    """Write section to file.
    
    Args:
      sec: Section object or None.
      filename: Name of the file.
    """
    if sec is not None:
        with open(filename, "wb") as data_file:
            sec.write_to_file(data_file)


def check_firmware_image(filename):
    """Check if a file contains a supported firmware image.
    
    Args:
      filename: File containing the firmware binary.
    
    Returns:
      True if the file contains a support firmware image, else False.
    """
    md5 = hashlib.md5()
    with open(filename, "rb") as firmware_file:
        md5.update(firmware_file.read())
    return md5.hexdigest() in VERIFIED

def get_address_map(filename):
    """Extract address map from rst file.
    
    Args:
      filename: Name of the rst file.
    
    Returns:
      Dictionary mapping code labels to addresses.
    """
    regex = re.compile(
        r"^\s*(?P<address>[0-9a-fA-F]+)\s+(\S+\s+)*(?P<label>_\S*):$")
    address_map = {}
    with open(filename, "rb") as rst_file:
        for line in rst_file:
            res = regex.match(line)
            if res is not None:
                address_map[res.group("label")] = int(res.group("address"), 16)
    
    return address_map

def find_in_inner_dict(outer_dict, inner_key):
    """Search dictionaries with dictionaries as values.
    
    Search inner dictionaries that are value of an outer dictionary for a 
    certain inner key and return the outer key and the inner value 
    for the match.
    
    E.g. 
    d={0:{"a":23}, 4:{"b":24, "gwr":2}}
    find_key_in_dict_dict(d, "b") returns (4, 24)
    
    Args:
      outer_dict: Dictionary with dictionaries as values.
      inner_key: Wanted key of the inner dictionaries.
    
    Returns:
      Tuple (outer key, inner value) if the inner key was found. 
      (None, None) if the inner key was no found.
    """
    for outer_key, inner_dict in outer_dict.items():
        if inner_key in inner_dict:
            return (outer_key, inner_dict[inner_key])
    
    return (None, None)
