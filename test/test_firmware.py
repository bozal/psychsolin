#!/usr/bin/env python
# -*- coding: utf-8 -*-


import unittest
import os
from injector.firmware import Firmware
from data import header, sections, footer, free_chunks, pattern_search

class TestFirmware(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # create firmware file
        filename = "tmpdeadbeaf.bin"
        cls._files = [filename]
        with open(filename, "wb") as firmware_file:
            firmware_file.write(header)
            for sec in sections:
                firmware_file.write(sec)
            firmware_file.write(footer)
    
    @classmethod
    def tearDownClass(cls):
        # delete firmware file
        for filename in cls._files:
            os.remove(filename)
    
    def setUp(self):
        # open firmware
        self._fw = Firmware()
        self._fw.load_from_file(self._files[0])
    
    def test_save(self):
        # save firmware
        filename = "tmpsave.bin"
        self._fw.save(filename)
        
        # compare files
        assertFileEqual(self, self._files[0], filename, 
            "saved firmware differs from loaded firmware")
        
        # delete saved file
        os.remove(filename)
        
    def test_get_section(self):
        for i in xrange(len(sections)):
            self.assertSequenceEqual(self._fw.get_section(i), 
                sections[i], 
                "%s returned incorrect" % section_index_to_name(i))
    
    def test_find_pattern(self):
        for pattern, offset, expected in pattern_search:
            res = self._fw.find_pattern(pattern, offset)
            self.assertEqual(res, expected, 
                "got %s, but expected %s" % (res, expected))
    
    def test_find_last_free_chunk(self):
        for i in xrange(len(sections)):
            self.assertEqual(self._fw.find_last_free_chunk(i),
                free_chunks[i],
                "free chunk wrong for %s" % section_index_to_name(i))
    
def section_index_to_name(section_index):
    if section_index == 0:
        return "base"
    else:
        return "section%X" % (section_index-1)

def assertFileEqual(assert_instance, filename1, filename2, msg=None):
    with open(filename1, "rb") as file1, open(filename2, "rb") as file2:
        content1 = file1.read()
        content2 = file2.read()
    assert_instance.assertMultiLineEqual(content1, content2, msg)
    
