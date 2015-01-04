#!/bin/bash

#Set things up and create bin directory if necessary.
export BUILD_FILES=
if [ ! -e "bin" ]
then
	mkdir bin
fi

#Build each file in the list.
#NOTE: This needs to change if more code files or sections are added.
for SOURCEFILE in main timers usb control scsi
do
	echo "*** Building $SOURCEFILE.c..."
	sdcc --model-small -mmcs51 -pdefcpu -c -o"bin/$SOURCEFILE.rel" "$SOURCEFILE.c"
	export BUILD_FILES="bin/$SOURCEFILE.rel $BUILD_FILES"
done

#Build Intel Hex and BIN versions of combined file.
echo "*** Linking..."
sdcc --xram-loc 0x6000 -o bin/output.hex $BUILD_FILES
makebin -p bin/output.hex bin/output.bin

#Creating firmware and burner images from templates
echo "*** Creating firmware and burner images from templates..."
cp ../templates/FWdummy.bin bin/fw.bin
cp ../templates/BNdummy.bin bin/bn.bin
dd conv=notrunc if=bin/output.bin of=bin/fw.bin obs=512 seek=1 bs=512
dd conv=notrunc if=bin/output.bin of=bin/bn.bin obs=512 seek=1 bs=512

