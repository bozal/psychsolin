#!/bin/bash

#Set things up and create bin directory if necessary.
export BUILD_FILES=
if [ ! -e "bin" ]
then
	mkdir bin
fi

#Generate .h C file for compilation.
echo "*** Generating C .h file..."
python ../injector --action=GenerateHFile --firmware=fw.bin --output=equates.h

#Build each file in the list.
#NOTE: This needs to change if more code files or sections are added.
for SOURCEFILE in base
do
	echo "*** Building $SOURCEFILE.c..."
	sdcc --model-small -mmcs51 -pdefcpu -c -o"bin/$SOURCEFILE.rel" "$SOURCEFILE.c"
	export BUILD_FILES="bin/$SOURCEFILE.rel $BUILD_FILES"
done

#Retrieve free space for each section in the image.
echo "*** Retrieving free space in image..."
python ../injector --action=FindFreeBlock --firmware=fw.bin --section=Base --output=bin/free.txt
export BASE_FREE_ADDR=
for LINE in $(cat "bin/free.txt")
do
	export BASE_FREE_ADDR="$LINE $BASE_FREE_ADDR"
done
rm "bin/free.txt"

#Build Intel Hex and BIN versions of combined file.
echo "*** Linking..."
sdcc --model-small --code-loc $BASE_FREE_ADDR --xram-size 0x400 --xram-loc 0x7C00 -o bin/output.hex $BUILD_FILES
objcopy -I ihex -O binary bin/output.hex bin/output.bin

#Build patched image from assembled image.
#NOTE: This needs to change if more code files or sections are added.
echo "*** Injecting..."
python ../injector --action=ApplyPatches --firmware=fw.bin --basecode=bin/output.bin --baserst=bin/base.rst --output=bin/fw.bin




