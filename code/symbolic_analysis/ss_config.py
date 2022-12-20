#!/usr/bin/env python


class Ss_config():

    def __init__(self, debug, force_branch, max_paths, max_steps, loop_analyses_only):
        self.debug = debug
        self.force_branch = force_branch
        self.max_paths = max_paths
        self.max_steps = max_steps
        self.loop_analyses_only = loop_analyses_only

    def add_configs(self, low_arch_regs, arg_register_list, arg_registers_low_high_map, bin_format, ARCH, ARCH_bytes_size):
        self.low_arch_regs = low_arch_regs
        self.arg_register_list = arg_register_list
        self.arg_registers_low_high_map = arg_registers_low_high_map
        self.bin_format = bin_format
        self.ARCH = ARCH
        self.ARCH_bytes_size = ARCH_bytes_size
