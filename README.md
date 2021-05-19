# fileslack

## Description

A FAT 32 crawler displaying the hidden data of a sector for a given path in a given partition. This tool was part of a practical lab for the course [Digital Forensics INFO8012-1](https://www.programmes.uliege.be/cocoon/20202021/cours/INFO8012-1.html) of the university of Liège.

## File organization

The implementation of the tool is located in [fileslack.c](fileslack.c). A custom FAT 32 diagram can be found in [FAT32.png](FAT32.png).

## Requirements

We will need to have [gcc](https://gcc.gnu.org) installed before attempting anything with this tool.

## Installation and usage

1. Run this command to get an executable.
```bash
make fileslack
```
2. Run the tool as followed
```bash
./fileslack if=diskimage.img part=partition_number /path/to/the/file
```
Where `diskimage.img`is the disk image to analyze, `partition_number` the partition to analyze on that disk and `/path/to/the/file` the absolute path of the file in that partition.

## Contributor(s)

@AntoineBoonen and Florian Mataigne.
