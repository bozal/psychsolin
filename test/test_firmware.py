# -*- coding: utf-8 -*-

"""Provide unittests for firmware."""

import unittest
import os
from injector.firmware import Firmware
from data import header, sections, footer, free_chunks, pattern_search

class TestFirmware(unittest.TestCase):
    """Test cases for firmware."""
    
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
        """Test saving to file"""
        
        # save firmware
        filename = "tmpsave.bin"
        self._fw.save(filename)
        
        # compare files
        assertFileEqual(self, self._files[0], filename, 
            "saved firmware differs from loaded firmware")
        
        # delete saved file
        os.remove(filename)
        
    def test_get_section_data(self):
        """Test access to section data."""
        for i in xrange(len(sections)):
            self.assertSequenceEqual(self._fw.get_section(i).get_all(), 
                sections[i], 
                "%s returned incorrect" % section_index_to_name(i))
    
    def test_find_pattern(self):
        """Test pattern matching."""
        for pattern, offset, expected in pattern_search:
            res = self._fw.find_pattern(pattern, offset)
            self.assertEqual(res, expected, 
                "got %s, but expected %s" % (res, expected))
    
    def test_get_last_free_chunk(self):
        """Test computation of last free chunk."""
        for i in xrange(len(sections)):
            self.assertEqual(self._fw.get_last_free_chunk(i),
                free_chunks[i],
                "free chunk wrong for %s" % section_index_to_name(i))
    
def section_index_to_name(section_index):
    """Translate index of section to name of section.
    
    Args:
      section_index: Index of a section.
    
    Returns:
      String containing the name corresponding to the passed section index.
    """
    if section_index == 0:
        return "base"
    else:
        return "section%X" % (section_index-1)

def assertFileEqual(assert_instance, filename1, filename2, msg=None):
    """Assert that two files contain exactly the same data.
    
    Args:
      assert_instance: Object that provides standard assert functions.
          (e.g. an instance of unittest.TestCase)
      filename1: Name (including path) of the first file.
      filename2: Name (including path) of the second file.
      msg: Message to be presented if the assertion fails.
          Default is None.
    """
    with open(filename1, "rb") as file1, open(filename2, "rb") as file2:
        content1 = file1.read()
        content2 = file2.read()
    assert_instance.assertMultiLineEqual(content1, content2, msg)
    
