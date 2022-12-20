import sys
import binascii
import logging
import cle
import struct

l = logging.getLogger(name="inputs")
l.setLevel(logging.DEBUG)


class Inputs:
    """
    This class analyzes values from memory and register read and write operations and tries to know their type and where they point to in memory if they are pointers.

    :param path_id: int: the unique identifier of the path object under consideration
    :param project: angr project object
    """

    def __init__(self, path_id,  project):
        self.path_id = path_id
        self.project = project

        self.global_var_segments = {}
        self.global_var_read = {}
        self.global_var_written = {}

        self.global_all_segments_read = {}
        self.global_all_segments_write = {}

        self.global_all_segments = {}

        self.all_objects = {}
        self.all_objects_read = {}
        self.all_objects_write = {}

        self.dynamic_mem_read = {}
        self.dynamic_mem_write = {}

        self.init_data_seg_tracking()

    def init_data_seg_tracking(self):
        """
        Sets up data structures to start tracking accesses to data sections
        """
        if isinstance(self.project.loader.main_object, cle.backends.elf.elf.ELF):
            # in ARM global variables could be stored in .text section. I observed this
            seg_of_interest = [".bss", ".data", ".rodata", ".text"]
            self.global_var_written = {".bss": [],
                                       ".data": [], ".rodata": [], ".text": []}
            self.global_var_read = {".bss": [],
                                    ".data": [], ".rodata": [], ".text": []}
        elif isinstance(self.project.loader.main_object, cle.backends.pe.pe.PE):
            seg_of_interest = [".textbss", ".data", ".rdata", ".text"]  # i
            self.global_var_written = {".textbss": [],
                                       ".data": [], ".rdata": [], ".text": []}
            self.global_var_read = {".textbss": [],
                                    ".data": [], ".rdata": [], ".text": []}
        else:
            l.error("bin_format unknown %s", str(
                type(self.project.loader.main_object)))
            raise NameError

        for seg in self.project.loader.main_object.sections_map:
            # seg = str(seg).replace("\x00","") #\x00 for PEs weirdness
            seg = str(seg)
            region = str(self.project.loader.main_object.sections_map[seg])
            seg = seg.replace("\x00", "")  # \x00 for PEs weirdness
            addr = long(region.split("vaddr")[1].split(",")[0], 16)
            addr_len = long(region.split("vaddr")[1].split(
                "size")[1].split(">")[0], 16)
            self.global_all_segments[seg] = {
                "start": addr, "end": addr + addr_len}
            self.global_all_segments_read[seg] = []
            self.global_all_segments_write[seg] = []
            if seg in seg_of_interest:
                self.global_var_segments[seg] = {
                    "start": addr, "end": addr + addr_len}
        # lets initialize the start:end of all loaded objects
        for obj_entry in self.project.loader.all_objects:
            obj = str(obj_entry).split(",")[0].split()[-1]
            start = long(str(obj_entry).split(":")[0].split("[")[-1], 16)
            end = long(str(obj_entry).split(":")[-1].split("]")[0], 16)
            self.all_objects[obj] = {"start": start, "end": end}
            self.all_objects_read[obj] = []
            self.all_objects_write[obj] = []

        # lets also add the stack, heap, and func argument key to this
        self.dynamic_mem_read["stack"] = []
        self.dynamic_mem_read["argument"] = []
        self.dynamic_mem_read["unknown"] = []
        self.dynamic_mem_write["stack"] = []
        self.dynamic_mem_write["argument"] = []
        self.dynamic_mem_write["unknown"] = []

    def nature_of_value(self, value, value_length, state):
        """
        Attemps to figure out the type of the data value being analyzed, and if its a pointer, where in memory it points to

        :param value: the data value being analyzed
        :param state: angr state object, the execution state where the value was recovered
        :param value_length: means how many bytes
        """
        state_addr = state.scratch.ins_addr
        int_size = 4  # Integers are 4 bytes
        byte_width = 8
        endness = state.arch.memory_endness
        to_return = ""
        if value_length*byte_width > state.arch.bits:  # check for string
            return self.get_str_from_int(value, str(endness))
        # not a pointer, assume its an integer, a float, or a string
        if value_length*byte_width == state.arch.sizeof['int']:
            # get the int and float value. Check for floating point registers
            int_spec = float_spec = ""
            if state.arch.name in ["AMD64", "X86"]:
                if "xmm" in str(self.project.factory.block(state_addr).capstone.insns[0].op_str):
                    my_float = str(struct.unpack(
                        "<f", struct.pack("<I", value))[0])
                    if "nan" not in my_float:
                        float_spec = "<float:" + my_float+">"
                else:
                    int_spec = "<int:" + str(value)+">"
            else:  # ARM
                my_float = str(struct.unpack(
                    "<f", struct.pack("<I", value))[0])
                if "nan" not in my_float:
                    float_spec = "<float:" + my_float+">"
                int_spec = "<int:" + str(value)+">"

            # attempt to get the string
            to_return += int_spec + float_spec + \
                self.get_str_from_int(value, str(endness))
        if value_length == 1:  # a char
            return self.get_str_from_int(value, str(endness))
        if value_length*8 != state.arch.bits:  # if not a pointer, attempt a string translation
            return to_return + self.get_str_from_int(value, str(endness))

        # lets check for  potential double or pointer
        resolv = self.could_be_a_pointer(value)
        if resolv:
            to_return += "<ptr:" + hexx(value) + ":" + resolv + ">"

        if state.arch.name in ["AMD64", "X86"]:
            if "xmm" in str(self.project.factory.block(state_addr).capstone.insns[0].op_str):
                to_return += "<double:" + \
                    str(struct.unpack("<d", struct.pack("<Q", value))[0]) + ">"
        else:  # ARM
            to_return += "<double:" + \
                str(struct.unpack("<d", struct.pack("<Q", value))[0]) + ">"

        # if nothing returned, it means that we are dealing with a pointer or a string
        # for string, i.e if the raw value read was a string by itself
        to_return += self.get_str_from_int(value, str(endness))

        # for pointer (to integer or string)
        # we want to see if the value to be written/read from mem_addr could specify a pointer to
        # .rodata, .data, .bss, .dynstr, .dynsym, and then read what value it points to
        for seg in self.global_all_segments:
            if seg in self.global_var_segments or seg in [".dynstr", ".dynsym"]:
                mem_start = self.global_all_segments[seg]['start']
                mem_end = self.global_all_segments[seg]['end']
                if value >= mem_start and value <= mem_end:
                    to_return += "points-to <seg:" + seg + ">"
                    # read the possible integer it is pointing to. 4 bytes
                    read_value_all_expr = state.memory.load(
                        value, int_size, endness=state.arch.memory_endness, disable_actions=True, inspect=False)

                    read_value_all = state.se.eval_upto(read_value_all_expr, 2)
                    if len(read_value_all) > 2:
                        pass
                        #min_value = state.se.min(read_value_all_expr)
                        #max_value = state.se.max(read_value_all_expr)
                        #to_return += ",value (first 4 bytes) is " + str(read_value_all_expr)+ " [" + str(min_value) + "," + str(max_value)+"]"
                    else:
                        # ok, so this value can either be an integer, a pointer (to what?), or a string.
                        #int_value = state.se.eval_one(read_value_all_expr)
                        # pointer_to = could_be_a_pointer(int_value)#I commented this out becos I am not trying to find a pointer to a pointer and besides I am only reading 4 bytes
                        # the value here is the one passed to this func because we wanna invesigate if thats a pointer to a string
                        string_of = self.extract_string(state, seg, value)
                        if string_of:
                            to_return += ", <str-p: " + string_of + ">"

                    return to_return
        # if nothing happens
        return to_return

    def could_be_a_pointer(self, value):
        """
        Checks to see if the value points to any valid memory of the execution
        """
        for seg in self.global_all_segments:
            mem_start = self.global_all_segments[seg]['start']
            mem_end = self.global_all_segments[seg]['end']
            if value >= mem_start and value <= mem_end:
                return seg
        # if it did not return
        for region in self.all_objects:
            mem_start = self.all_objects[region]['start']
            mem_end = self.all_objects[region]['end']
            if value >= mem_start and value <= mem_end:
                return region
        # if nothing, then indicate its not a pointer
        return ""

    # value here is the address we want to attempt the extraction from
    def extract_string(self, state, segment, value):
        """
        Attempts to extract an ascii string from the sequence of bytes
        """
        byte_width = 8
        extracted_string = ""
        #start = global_all_segments[segment]['start']
        end = self.global_all_segments[segment]['end']

        rem_size = end - value
        addr = value
        read_chunk = state.arch.bits/byte_width  # I will read 8 or 4 bytes at a time

        while True:
            div, rem = divmod(rem_size, read_chunk)
            if div > 0:
                pass  # np,
            elif rem == 0:  # if div is 0 and rem is 0, it means that rem_size is 0
                return ""
            else:  # div is 0, but there was one more little chunk to read
                read_chunk = rem
            # note we did not specify to be read in little endian, since string bytes are stored as big endian, I think. Perhaps I should explicitly demand big endian
            read_value = state.memory.load(
                addr, read_chunk, disable_actions=True, inspect=False)
            hex_form = hexx(state.se.eval(read_value)).replace(
                "0x", "").replace("L", "")
            # if hex_form is not up to read_chunk byte length, it means there is precedding zeros
            # for example, if read_value evaluated to int 6, then hex_form will be 0x0000....06, but will be simplified as 0x6, which will cause us to miss the null terminator byte of 000s
            if len(hex_form) < read_chunk * 2:  # its supposed to be 16, i.e 8 * 2, i.e a byte is 0xZZ
                for _ in xrange(len(hex_form), read_chunk * 2):
                    hex_form = "0" + hex_form  # prefix with zeros up to read_chunk *2

            status, result = self.hex_to_ascii(hex_form)
            if status:  # null terminator encountered
                return extracted_string + result
            elif not result:  # non-ascii encountered
                return ""
            else:  # not finished
                extracted_string += result

            addr += read_chunk
            rem_size -= read_chunk
        l.warn("**ANOMALY** code should never get here")
        return extracted_string

    @staticmethod
    def hex_to_ascii(hex_form):
        """
        Attempts to extract an ascii character from a byte
        """
        extracted_string = ""
        unreadable_chars = ["01", "02", "03", "04", "05", "06", "07", "08", "0e", "0f", "10",
                            "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1f", "7f"]
        for i in xrange(0, len(hex_form), 2):  # check each byte at a time
            one_hex = hex_form[i:i+2]
            char = binascii.unhexlify(one_hex)
            if char == "\x00" or one_hex == "00":  # null termination
                return True, extracted_string  # True means, I encountered a null terminator
            else:
                # encountered unreadable char
                if one_hex in unreadable_chars or int(one_hex, 16) > int("7f", 16):
                    # the second False means we saw a non-ascii character so this is not a str
                    return False, False
                else:
                    extracted_string += char
        return False, extracted_string  # False means I have not seen a null terminator yet

    # If no null terminator, then no output
    def get_str_from_int(self, int_value, endness):
        """
        Attempt to extract an Ascii string from an integer value
        """
        # NOTE. We reverse the byte. intended for integer read out of memory that is little endian
        # since we loaded the value as little endian, lets reverse it. since I think strings are read as big endian.
        if not int_value:  # if 0
            return ""
        str_spec = ""
        hex_val = format(int_value, 'x')
        if len(hex_val) % 2:  # if odd length, prefix with 0
            hex_val = str(0) + hex_val
        byte = bytearray.fromhex(hex_val)
        if "LE" in endness:
            byte.reverse()

        hex_form = binascii.hexlify(byte)
        status, result = self.hex_to_ascii(hex_form)
        if status and len(result) > 0:  # a string
            str_spec = "<str:" + result + ">"
        return str_spec


def hexx(value):
    return hex(value).replace("L", "")
