psychsolin
==========

Python/Linux port of [Psychson](https://github.com/adamcaudill/Psychson), a tool to modify firmware of Phison 2251-03 aka 2303 (BadUSB)


## Quick Start

- download and decompress psycholin
- download Psychson and copy all source files (\*.h and \*.c) in `patch/` and `firmware/` and the whole `templates/` directory
- install sdcc, sg3-utils and binutils
- use psychsolin like Psychson

## Dependencies

- python 2.7
- sdcc
- sg3-utils (sg_raw)
- binutils (objcopy)
- bash

## Differences from Psychson

- all names are lower case (e.g. `psychsolin/drivecom` equals `Psychson/DriveCom`)
- python modules are called directly (e.g. to call drivecom you call `python psychsolin/drivecom` instead of `tools/DriveCom.exe`)
- parameters are passed Linux style (e.g. `python psychsolin/drivecom --action=GetInfo` instead of `tools/DriveCom.exe /action=GetInfo`)
- tools not included (see Dependencies)

## Known Issues

- only 11 sections of the firmware are dumped by `drivecom --action=DumpFirmware`, so if the flashed firmware uses more than 11 of the 16 possible sections the dump is incomplete; it's unknown why Psychson does it that way, but psychsolin does it also that way in case it's to avoid bricking the device
- (i)peek and (i)poke in drivecom console mode don't work


