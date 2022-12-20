import subprocess
import os
import logging

l = logging.getLogger(name="sa_tool")
l.setLevel(logging.DEBUG)


class SaTools:
    """
    An Sa_tool object  extracts the function boundaries from the input binary using an external static analysis tool
    Right now, we only support idat and nucleus

    :param path_to_sa_tool: full path to where the static analysis tool reside in the system
    :param path_to_binary: full path to the input binary
    """

    def __init__(self, path_to_sa_tool, path_to_binary):
        self.path_to_sa_tool = path_to_sa_tool
        self.path_to_binary = path_to_binary
        self.path_to_binary_folder = path_to_binary[:path_to_binary.rfind("/")]

        # some checks
        # make sure the path_to_sa_tool is good
        get_path = subprocess.check_output(
            "which " + self.path_to_sa_tool, shell=True)
        if not os.path.isfile(get_path.split()[0]):
            l.error("%s does not exist ",  self.path_to_sa_tool)
            raise FileNotFoundError
        # making sure we can write to the path_to_binary_folder
        if not os.access(self.path_to_binary_folder, os.W_OK):
            l.error("Cannot write to %s. Make sure you have permission",
                    self.path_to_binary_folder)
            raise PermissionError

    def ida_get_func_boundaries(self):
        """
        Use ida pro to get the function boundaries
        """
        # clean up the ida temp dir that may cause trouble
        subprocess.call("rm -r /tmp/ida 2> /dev/null", shell=True)
        script_folder = os.path.dirname(os.path.realpath(__file__))
        ida_script = script_folder + "/ida_get_func_boundaries.py"
        output_file = self.path_to_binary_folder + "/ida_func_boundaries.txt"
        # remove old output file if exists
        subprocess.call("echo '' >  " + output_file +
                        " 2> /dev/null", shell=True)
        cmd = self.path_to_sa_tool + ' -B ' + self.path_to_binary
        cmd2 = self.path_to_sa_tool + ' -A -S"' + ida_script + \
            " " + output_file + '" ' + self.path_to_binary
        subprocess.call(cmd, shell=True)  # this creates the idb file
        subprocess.call(cmd2, shell=True)  # this runs the ida scripts
        # now read the file and return a dict
        base_addr = ""
        func_boundaries = []
        with open(output_file, 'r') as f:
            for line in f:
                if "base_address" in line:  # the first line is the base address
                    base_addr = long(line.split()[1], 16)
                    continue
                func_start = long(line.split()[0], 16)
                func_end = long(line.split()[1], 16)
                func_boundaries.append((func_start, func_end))
        return base_addr, func_boundaries

    def nucleus_get_func_boundaries(self):
        """
        Use nucleus to get the function boundaries
        """
        cmd = self.path_to_sa_tool + " -e " + self.path_to_binary + " -d linear"
        nucleus_output = subprocess.check_output(cmd, shell=True)
        func_boundaries = []
        highest_addr_in_bb = {}
        func_info = nucleus_output.split("function ")
        bb_info = nucleus_output.split("BB @")
        # nucleus does not have a nice way to the base address of its loaded binary
        # we need to load the binary with same base address in angr
        # lets try and obtain the base address. I have seen
        # 0x400000 for elf 64
        # 140000000 for PE 64
        # 0x0 for position independent code
        # this is very adhoc.
        base_addr = nucleus_output.split(
            " .text ")[1].split(" (size")[0].split("@")[1]
        base_addr = long(base_addr, 16)
        if abs(base_addr - 0x400000) < abs(base_addr - 0x140000000):
            start_base_to_use = 0x400000
        else:
            start_base_to_use = 0x140000000
        _, rem = divmod(base_addr, start_base_to_use)
        if rem > 0:
            base_addr = base_addr - rem
        else:
            base_addr = 0x0

        for bb_item in bb_info:
            if "score " not in bb_item:  # this should skip bb_info[0]
                continue
            bb_addr = long(bb_item.split()[0], 16)  # the first addr in the bb
            addr_max = 0
            for addr_entry in bb_item.split("\n"):
                if "--A" in addr_entry or "--T" in addr_entry or "function" in addr_entry:
                    break  # those indicators make the end of a bb in nucleus
                if "0x" not in addr_entry or "{" in addr_entry or "--" in addr_entry or ">" in addr_entry:
                    continue
                addr_temp = long(addr_entry.strip().split()[0], 16)
                if addr_temp > addr_max:
                    addr_max = addr_temp
            if not addr_max:
                l.error(
                    "No address was found in basic block %#x. This should not happen",  bb_addr)
                raise NameError
            highest_addr_in_bb[bb_addr] = addr_max

        for func_entry in func_info:
            if " entry@" not in func_entry:
                continue
            func_start = long(func_entry.split(" entry@")[1].split()[0], 16)
            # we are gonna iterate all the basic blocks in func_entry  and find the one with the largest address
            bb_max = 0
            for bb_entry in func_entry.split("\n"):
                if "BB@" not in bb_entry:
                    continue
                bb_addr = bb_entry.split("BB@")[1]
                if long(bb_addr, 16) > bb_max:
                    bb_max = long(bb_addr, 16)

            if not bb_max:
                l.error(
                    "NO Basic block was seen in the function %s. This should not happen unless Nucleus changed it output format",  func_start)
                raise NameError
            # now we are gonna iterate all addrs in bb @ bb_max and get the last instr addr
            if bb_max not in highest_addr_in_bb:
                l.error("The basic block addr %#x  found in func  %#x does not happen to be in the bb dict highest_addr_in_bb. This should not happen",  bb_max, func_start)
                raise NameError
            else:
                func_end = highest_addr_in_bb[bb_max]
                func_boundaries.append((func_start, func_end))
        return base_addr, func_boundaries

    def get_func_boundaries(self):
        if "nucleus" in self.path_to_sa_tool:
            return self.nucleus_get_func_boundaries()
        elif "idat" in self.path_to_sa_tool:
            return self.ida_get_func_boundaries()
        else:
            # unsupported sa tool
            l.error("Unsupported sa tool: %s",  self.path_to_sa_tool)
            raise NameError
