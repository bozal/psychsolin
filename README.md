psychsolin
==========

Python/Linux port of [Psychson](https://github.com/adamcaudill/Psychson), a tool to modify firmware of Phison 2251-03 aka 2303 (BadUSB)


## Quick Start

- download and decompress psycholin
- download Psychson and copy the `templates/` directory and all source (\*.h and \*.c) in `patch/` and `firmware/`
- install sdcc and binutils
- use psychsolin like Psychson

## Dependencies

- python 2.7
- sdcc
- binutils (objcopy)
- bash

## Differences from Psychson

- all names are lower case (e.g. `psychsolin/drivecom` equals `Psychson/DriveCom`)
- python modules are called directly (e.g. to call drivecom you call `python psychsolin/drivecom` instead of `tools/DriveCom.exe`)
- parameters are passed Linux style (e.g. `python psychsolin/drivecom --action=GetInfo` instead of `tools/DriveCom.exe /action=GetInfo`)
- tools not included (see Dependencies)
- `EmbedPayload` not included





