#!/usr/bin/env python
# This idapython script is supposed to get the function boundaries in a binary

import idc
import idaapi
import idautils


func_boundaries = []
for func in idautils.Functions():
    if idaapi.segtype(idc.SegStart(func)) != idaapi.SEG_CODE:
        continue
    if "plt" in idc.SegName(func):
        continue
    func_start = idaapi.get_func(func).startEA
    func_end = idaapi.get_func(func).endEA
    func_boundaries.append((func_start, func_end))

base_addr = idaapi.get_imagebase()
to_write = "base_address: " + hex(base_addr) + "\n"
for start, end in func_boundaries:
    #boundaries = start + " " + end
    boundaries = hex(start) + " " + hex(end)
    print boundaries,
    to_write += boundaries + "\n"

if len(idc.ARGV) > 1:  # if its ran via the batch mode, it will have an argument
    output_file = idc.ARGV[1]
else:
    output_file = "/home/anonymous/per_func_symbex/per_func_symbex/ida_gui_func_boundaries.txt"
with open(output_file, "w") as f:

    f.write(to_write)
    f.close()

if len(idc.ARGV) > 1:  # if its ran via the batch mode, it will have an argument
    idc.Exit(0)
