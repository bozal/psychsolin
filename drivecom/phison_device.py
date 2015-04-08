# -*- coding: utf-8 -*-

"""Provide code to interact with a Phison USB device."""

import time
import logging
from scsi_access import execute_scsi_command, verify_device_path
import scsi_commands

MODE_NAMES = ["BootMode", "Burner", "HardwareVerify", "Firmware"]
WAIT_TIME_MS = 2000


class PhisonDevice(object):
    """Represent a Phison USB device."""
    
    def __init__(self, device):
        """Initiate object representing a Phison USB device.
        
        Args:
          device: Path to the (Linux) device corresponding to the Phison USB
              device.
        
        Raises:
          PhisonDeviceException: The device is not a valid path to a Linux 
              device.
        """
        self._logger = logging.getLogger("drivecom.phison_device.PhisonDevice")
        if not verify_device_path(device):
            raise PhisonDeviceException("'%s' is not a valid device" % device)
        self._device = device
    
    def get_info(self):
        """Get information about the device.
        
        The information include chip type, chip id, firmware version and 
        actual mode.
        
        Returns:
          Dictionary containing the information about the device.
        """
        ret = {
			"chip_type": None, "chip_id":None, "firmware_version":None, 
			"mode":None
		}
        vendor_info = self.get_vendor_info()
        if((vendor_info[0x17A] == ord("V")) and 
			(vendor_info[0x17B] == ord("R"))):
            # chip type
            ret["chip_type"] = word_from_data(vendor_info, 0x17E)
        
        # mode
        ret["mode"] = mode_from_vendor_info(vendor_info)
        
        # firmware version
        ret["firmware_version"] = "%X.%.2X.%.2X" % (vendor_info[0x94], 
            vendor_info[0x95], vendor_info[0x96])
        
        # chip id
        chip_info = self._execute_phison_command(scsi_commands.GET_CHIP_ID)
        ret["chip_id"] = "".join(("%.2X"%i) for i in chip_info[:6])
        
        
        return ret
    
    def get_run_mode(self):
        """Get actual mode of the device.
        
        0 BootMode
        1 Burner
        2 HardwareVerify
        3 Firmware
        
        Returns:
          Integer indicating the run mode.
        """
        vendor_info = self.get_vendor_info()
        return mode_from_vendor_info(vendor_info)
    
    def get_vendor_info(self):
        """Get vendor information from the Phison device.
        
        Returns:
          Bytearray containing the vendor information.
        """
        return self._execute_phison_command(scsi_commands.GET_VENDOR_INFO)
    
    def _execute_phison_command(self, phison_cmd, data_out=None):
        """Execute single SCSI command on the Phison device.
        
        Args:
          phison_cmd: Tuple (command, expected response length)
          data_out: Data to be sent by SCSI command as sequence of byte values.
              None if no data is to be sent.
              Default is None.
        
        Returns:
          Bytearray  contianing the response data.
        """
        return execute_scsi_command(self._device, phison_cmd[0], 
            data_out, phison_cmd[1])
    
    def get_num_lbas(self):
        """Get LBA count.
        
        Returns:
          LBA count.
        """
        res = self._execute_phison_command(scsi_commands.GET_NUM_LBAS)
        ret = 0
        for i in res[:4]:
            ret = (ret << 8)|i
        
        return ret+1
    
    def jump_to_pram(self):
        """Jump to PRAM."""
        self._execute_phison_command(scsi_commands.JUMP_TO_PRAM)
    
    def jump_to_bootmode(self):
        """Jump into bootmode."""
        self._execute_phison_command(scsi_commands.JUMP_TO_BOOTMODE)
    
    def transfer_data(self, data, header=0x03, body=0x02):
        """Transfer data to the device.
        
        The data is expectes to contain a 512 byte header, the actual data and
        a 512 byte footer.
        
        Args:
          data: Sequence of bytes to be transfered.
          header: 
              Default is 3.
          body: 
              Default is 2.
        
        Raises:
          PhisonDeviceException: Error during data transfer.
        """
        #TODO: why 1024 (=2*0x200)
        # 512 for header, but what if we have no footer,
        # then we would skip 512 byte
        # so do we always expect a footer?
        data_size = len(data) - 1024
        
        # send header
        scsi_commands.LOAD_HEADER[0][2] = header
        self._execute_phison_command(scsi_commands.LOAD_HEADER, data[:0x200])
        
        # get response
        res = self._execute_phison_command(scsi_commands.GET_STATUS)
        if res[0] != 0x55:
            raise PhisonDeviceException("Header not accepted")
        
        # send body
        address = 0
        while data_size > 0:
            chunk_size = data_size
            if chunk_size > 0x8000:
                chunk_size = 0x8000
            
            # address and size in 512 blocks
            cmd_address = address >> 9
            cmd_chunk = chunk_size >> 9
            scsi_commands.LOAD_BODY[0][2] = body
            word_to_data(scsi_commands.LOAD_BODY[0], 3, cmd_address)
            word_to_data(scsi_commands.LOAD_BODY[0], 7, cmd_chunk)
            self._execute_phison_command(scsi_commands.LOAD_BODY,
				data[address+0x200:address+0x200+chunk_size])
            
            # get response
            res = self._execute_phison_command(scsi_commands.GET_STATUS)
            if res[0] != 0xA5:
                raise PhisonDeviceException("Body not accepted")
            
            address += chunk_size
            data_size -= chunk_size
    
    def dump_firmware(self, filename):
        """Dump current firmware.
        
        Args:
          filename: Name of the file the firmware is written to.
        """
        address = 0
        # TODO: why only 11 sections? this is specific for the firmware version!
        # header + base + 11 sections + footer
        # 0x200 + 0x6000 + 11*0x4000 +0x200
        data = bytearray(0x32400)
        header = (0x42, 0x74, 0x50, 0x72, 0x61, 0x6D, 0x43, 0x64, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x14, 0x10, 0x0B, 0x18)
        insert_data(data, 0, header)
        
        while address*0x200 < len(data):
            length = min(0x40*0x200, (len(data)-0x400)-(address*0x200))
            temp = length/0x200
            word_to_data(scsi_commands.READ_BODY[0], 3, address)
            word_to_data(scsi_commands.READ_BODY[0], 7, temp)
            scsi_commands.READ_BODY[1] = length
            self._logger.debug("%s" % scsi_commands.READ_BODY)
            res = self._execute_phison_command(scsi_commands.READ_BODY)
            insert_data(data, 0x200+address*0x200, res)
            address += 0x40
        
        footer = (0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 
            0x6D, 0x70, 0x20, 0x6D, 0x61, 0x72, 0x6B, 0x00, 
            0x03, 0x01, 0x00, 0x10, 0x01, 0x04, 0x10, 0x42)
        insert_data(data, len(data)-0x200, footer)
        
        with open(filename, "wb") as firmware_file:
            firmware_file.write(data)
    
    def execute_image(self, filename):
        """Transfer code to the device and execute it there.
        
        Args:
          filename: Name of the file that contains the firmware binary.
        """
        # read image
        with open(filename, "rb") as image_file:
            data = bytearray(image_file.read())
        
        # load image
        self.transfer_data(data)
        self.jump_to_pram()
        
        # wait
        time.sleep(WAIT_TIME_MS/1000.0)
    
    def send_password(self, password):
        """Send password to device.
        
        Args:
          password: String containing the password.
        """
        data = bytearray(0x200)
        pw_array = bytearray(password)
        insert_data(data, 0x10, pw_array)
        self._execute_phison_command(scsi_commands.SEND_PASSWORD, data)
    
    def send_firmware(self, firmware_filename, burner_filename=None):
        """Flash device with new firmware.
        
        Args:
          firmware_filename: File containing the firmware binary.
          burner_filename: File containing the burner binary.
              Default is None.
        
        Raises:
          PhisonDeviceException: Burner image needed but not provided.
        """
        mode = self.get_run_mode()
        if mode != 1:
            # not burner mode
            if burner_filename is None:
                raise PhisonDeviceException("Burner image needed.")
            if mode != 0:
                # not boot mode
                # -> switch to boot mode
                self._logger.info("Switching to boot mode...")
                self.jump_to_bootmode()
                time.sleep(WAIT_TIME_MS/1000.0)
            self.execute_image(burner_filename)
        
        self._run_firmware(firmware_filename)
    
    def _run_firmware(self, firmware_filename):
        """Write new firmware to device.
        
        Args:
          firmware_filename: File containing the firmware binary.
        """
        with open(firmware_filename, "rb") as firmware_file:
            data = bytearray(firmware_file.read())
        
        #TODO: Find out what this actually does...
        #self._logger.info("Sending scary B7 command (takes several seconds)")
        #self._execute_phison_command(scsi_commands.SCARY_B7)
        
        self._logger.info("Rebooting...")
        self.jump_to_bootmode()
        time.sleep(WAIT_TIME_MS/1000.0)
        
        self._logger.info("Sending firmware..")
        self.transfer_data(data, 0x01, 0x00)
        scsi_commands.FIRMWARE_UPDATE[0][2] = 0x01
        scsi_commands.FIRMWARE_UPDATE[0][3] = 0x00
        self._execute_phison_command(scsi_commands.FIRMWARE_UPDATE)
        time.sleep(WAIT_TIME_MS/1000.0)
        
        self.transfer_data(data, 0x03, 0x02)
        scsi_commands.FIRMWARE_UPDATE[0][2] = 0x01
        scsi_commands.FIRMWARE_UPDATE[0][3] = 0x01
        self._execute_phison_command(scsi_commands.FIRMWARE_UPDATE)
        time.sleep(WAIT_TIME_MS/1000.0)
        
        scsi_commands.FIRMWARE_UPDATE[0][2] = 0x00
        scsi_commands.FIRMWARE_UPDATE[0][3] = 0x00
        self._execute_phison_command(scsi_commands.FIRMWARE_UPDATE)
        time.sleep(WAIT_TIME_MS/1000.0)
        
        scsi_commands.FIRMWARE_UPDATE[0][2] = 0x00
        scsi_commands.FIRMWARE_UPDATE[0][3] = 0x01
        self._execute_phison_command(scsi_commands.FIRMWARE_UPDATE)
        time.sleep(WAIT_TIME_MS/1000.0)
        
        self._logger.info("Executing...")
        self.jump_to_pram()
        time.sleep(WAIT_TIME_MS/1000.0)
        
        self._logger.info("Mode: %s" % MODE_NAMES[self.get_run_mode()])
        
    def dump_xram(self):
        """Read XRAM.
        
        Returns:
          Bytearray containing XRAM content.
        """
        data = bytearray()
        for address in xrange(0xF000):
            word_to_data(scsi_commands.READ_XRAM[0], 2, address)
            self._logger.debug("read xram at %.4X" % address)
            res = self._execute_phison_command(scsi_commands.READ_XRAM)
            data.append(res[0])
        
        return data
    
    def read_nand(self, address, count):
        """Read NAND.
        
        Args:
          address: Address to be read.
          count: Number of 512 byte blocks to be read.
        
        Returns:
          Bytearray containing the NAND data.
        """
        word_to_data(scsi_commands.READ_BODY[0], 3, address)
        word_to_data(scsi_commands.READ_BODY[0], 7, count)
        scsi_commands.READ_BODY[1] = count*512
        self._logger.debug("%s" % scsi_commands.READ_BODY)
        res = self._execute_phison_command(scsi_commands.READ_BODY)
        return res
    
    def read_xram(self, address):
        """Read single byte from XRAM.
        
        Args:
          address: Address to be read.
        
        Returns:
          Byte value at address.
        """
        word_to_data(scsi_commands.READ_XRAM[0], 2, address)
        data = self._execute_phison_command(scsi_commands.READ_XRAM)
        return data[0]
    
    def write_xram(self, address, value):
        """Write single byte to XRAM.
        
        Args:
          address: Address to be written to.
          value: Value to be written.
        """
        word_to_data(scsi_commands.WRITE_XRAM[0], 2, address)
        scsi_commands.WRITE_XRAM[0][4] = value & 0xFF
        self._execute_phison_command(scsi_commands.WRITE_XRAM)
    
    def read_iram(self, address):
        """Read single byte from IRAM.
        
        Args:
          address: Address to be read.
        
        Returns:
          Byte value at address.
        """
        scsi_commands.READ_IRAM[0][2] = address & 0xFF
        data = self._execute_phison_command(scsi_commands.READ_IRAM)
        return data[0]
    
    def write_iram(self, address, value):
        """Write single byte to IRAM.
        
        Args:
          address: Address to be written to.
          value: Value to be written.
        """
        scsi_commands.WRITE_IRAM[0][2] = address & 0xFF
        scsi_commands.WRITE_IRAM[0][3] = value & 0xFF
        self._execute_phison_command(scsi_commands.WRITE_IRAM)
        

class PhisonDeviceException(Exception):
    """Error during interaction with a Phison USB device."""
    pass

def mode_from_vendor_info(vendor_info):
    """Extract actual mode from vendor info.
    
    0 BootMode
    1 Burner
    2 HardwareVerify
    3 Firmware
    
    Args:
      vendor_info: Sequence containing the vendor information.
    
    Returns:
      Actual mode as integer value.
    """
    mode = None
    if (vendor_info[0x17A] == ord("V")) and (vendor_info[0x17B] == ord("R")):
        #TODO: Fix this, this is a dumb way of detecting it
        mode_string = "".join(chr(i) for i in vendor_info[0xA0:0xA8])
        try:
            mode = (" PRAM   ", " FW BURN", 
                " HV TEST").index(mode_string)
        except ValueError:
            # "Firmware"
            mode = 3
    
    return mode

def word_from_data(data, offset):
    """Extract word from byte sequence (big endian).
    
    Args:
      data: Byte sequence.
      offset: Position of the word in the data.
    
    Returns:
      Word value.
    """
    ret = data[offset] << 8
    ret += data[offset+1]
    return ret

def word_to_data(data, offset, value):
    """Write word to mutable byte sequence (big endian).
    
    Args:
      data: Mutable byte sequence.
      offset: Position in data.
      value: Word value.
    """
    data[offset] = (value >> 8) & 0xFF
    data[offset+1] = value & 0xFF

def insert_data(data, offset, value_list):
    """Write seqqunce of bytes to mutable sequence of bytes.
    
    Args:
      data: Mutable sequqnce of bytes.
      offset: Position in data.
      value_list: Sequence of bytes to be written.
    """
    for i in xrange(len(value_list)):
        data[offset+i] = value_list[i]
