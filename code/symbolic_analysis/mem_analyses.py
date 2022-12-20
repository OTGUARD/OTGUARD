import IPython
import logging

l = logging.getLogger(name="mem_analyses")
l.setLevel(logging.DEBUG)


class MemAnalyses:
    """
    This class  performs some analysis on memory involved in a read/write operations during the execution of a basic block.

    :param path_id: int: the unique identifier of the path object under consideration
    :param input_analyzer: an Input object: performs analysis on the values found int the registers and try to identify the type
    :param config: a Config object: holds information about some properties of the binary such as the argument registers, etc
    :param func_start: the start address of the function being summarized
    :param project: angr project object
    """

    def __init__(self, path_id, input_analyzer, config, func_start, project):
        self.path_id = path_id
        self.project = project
        self.input_analyzer = input_analyzer
        self.config = config
        self.func_start = func_start

    def mem_read_analyses(self, state, dc_tracker, current_step):
        """
        Called everytime there is a memory read. Analyze the value and type of what is read. If the read is from a global data section like BSS, the memory data is made symbolic, since we don't know what value it should have.

        :param self: the path object being stepped
        :param dc_tracker: to track when the register write is a symbolic value
        :param current_step: the current step object along the path that is being explored
        """
        state_addr = state.scratch.ins_addr
        resolved = state.se.eval_upto(state.inspect.mem_read_address, 2)
        if len(resolved) > 1:
            #l.info("****An address to be read from has more than one resolution, so don't track" + hexx(state_addr) + str([hexx(addr) for addr in state.history.bbl_addrs.hardcopy]))
            dc_tracker[hexx(state_addr)] += 1
            return
        mem_addr = resolved[0]
        read_len = state.se.eval(state.inspect.mem_read_length)
        if read_len > 8:
            l.info("memory read length was more than 8 bytes: %d bytes ", read_len)

        # get read value
        read_value_all_expr = state.memory.load(
            mem_addr, read_len, endness=state.arch.memory_endness, disable_actions=True, inspect=False)

        read_value_all = state.solver.eval_upto(read_value_all_expr, 2)
        # if you comment this out, code breaks for some weird reason
        min_value = state.se.min(read_value_all_expr)

        if len(read_value_all) > 1:
            read_value = str(read_value_all_expr)
            #l.info("Value read from memory is not concrete " + read_value )
            #l.info("mem_read of " + read_value +  " from " + hexx(mem_addr) + "of bytes" + str( read_len)  +  hexx(state_addr) + " path " + str( self.path_id) + str([hexx(addr) for addr in  state.history.bbl_addrs.hardcopy]))
            extra_info = "sym"
            dc_tracker[hexx(state_addr)] += 1
        else:
            read_value = read_value_all[0]
            #l.info("mem_read of " + str( read_value) +  "or" + hexx(read_value) +  " from " + hexx(mem_addr) + " of bytes " + str( read_len) +  hexx(state_addr) +  " path "+ str( self.path_id) + str( [hexx(addr) for addr in  state.history.bbl_addrs.hardcopy]))
            # see if the value can be a pointer to the .rodata, .bss, .data, .dynstr, .dynsym,
            extra_info = self.input_analyzer.nature_of_value(
                read_value, read_len, state)

        # Some angr bug? I have to do this mem read to update the breakpoint inspect objects. This must be done.
        not_used = state.memory.load(
            mem_addr, read_len, endness=state.arch.memory_endness, disable_actions=True, inspect=False)

        tuple_to_write = (hexx(mem_addr), read_len, read_value,
                          current_step.step_id, self.path_id, extra_info)
        # get what segment it was read from
        for seg in self.input_analyzer.global_all_segments:
            mem_start = self.input_analyzer.global_all_segments[seg]['start']
            mem_end = self.input_analyzer.global_all_segments[seg]['end']
            if mem_addr >= mem_start and mem_addr < mem_end:
                #l.info("in "+seg)
                if tuple_to_write not in self.input_analyzer.global_all_segments_read[seg]:
                    # record it
                    self.input_analyzer.global_all_segments_read[seg].append(
                        tuple_to_write)
                if seg in self.input_analyzer.global_var_segments:
                    if tuple_to_write not in self.input_analyzer.global_var_read[seg]:
                        # record it
                        self.input_analyzer.global_var_read[seg].append(
                            tuple_to_write)

                    # Below here, the goal is to selectively make new global vars symbolic
                    # I don't believe global vars stored here are writable
                    if seg in [".rodata", ".rdata", ".text"]:
                        return
                    for (start, end, _, _, _, extra_info) in self.input_analyzer.global_var_written[seg]:
                        if mem_addr >= start and mem_addr <= end:
                            l.info("But, it was written to before, so ignoring")
                            return
                    for (start, end, _, _, _, extra_info) in self.input_analyzer.global_var_read[seg]:
                        if mem_addr >= start and mem_addr <= end:
                            l.info(
                                "But, it was read  before, which means I have done this before, so ignoring")
                            return
                    if len(read_value_all) > 1:  # read value was symbolic
                        # this check has to done before the read_value != 0 check, because the two possible types that read_value can take
                        #l.info("but its symbolic, so ignoring")
                        return
                    if ".bss" in seg or ".data" in seg:  # PE store __security_cookie in the .data section
                        # not zero means its prob some initialized c pointer/variable as discussed in wikipedia
                        if int(read_value) != 0:
                            #l.info( "but its not 0, so ignoring")
                            return
                    l.info("making " + hexx(mem_addr) + " of len " +
                           str(read_len) + " bytes symbolic " + hexx(state_addr))
                    label = str(seg)+"_"+hexx(self.func_start)+"_" + \
                        hexx(mem_addr)+"_"+str(current_step.step_id)
                    state.memory.store(mem_addr, state.se.BVS(
                        label, read_len * 8), disable_actions=True, inspect=False)  # store is in bits
                    return
                return  # if not in the global_var_segments
        # suppose the segment was not found, trying search all loaded objects
        for obj in self.input_analyzer.all_objects:
            mem_start = self.input_analyzer.all_objects[obj]['start']
            mem_end = self.input_analyzer.all_objects[obj]['end']

            if mem_addr >= mem_start and mem_addr <= mem_end:
                l.info("from obj %s", obj)
                if tuple_to_write not in self.input_analyzer.all_objects_read[obj]:
                    self.input_analyzer.all_objects_read[obj].append(
                        tuple_to_write)
                return

        # suppose it was not found in the loaded objects, trying searching if its around the stack, arguments, or heap
        current_SP = state.se.eval_one(self.get_stack_pointer(state))
        if mem_addr <= self.config.INIT_SP and mem_addr >= current_SP:
            # check that its not reading the return address. we do not care about that
            # I decided not to track this since I am tracking stack writes. No need to track stack reads, since before it can be read, it must have been written. But perhaps in the future there will be a need to track this
            if tuple_to_write not in self.input_analyzer.dynamic_mem_read["stack"]:
                self.input_analyzer.dynamic_mem_read["stack"].append(
                    tuple_to_write)
            return

        # perhaps anguments passed to the func
        elif mem_addr > self.config.INIT_SP and mem_addr <= self.config.CUSTOM_ARG_BOUND:
            if tuple_to_write not in self.input_analyzer.dynamic_mem_read["argument"]:
                self.input_analyzer.dynamic_mem_read["argument"].append(
                    tuple_to_write)
        else:  # perhaps, this is an read from the heap or unknown
            if tuple_to_write not in self.input_analyzer.dynamic_mem_read["unknown"]:
                self.input_analyzer.dynamic_mem_read["unknown"].append(
                    tuple_to_write)
                #l.info("read from unknown location "+ str(tuple_to_write))

    def mem_write_analyses(self, state, dc_tracker, current_step):
        """
        Called everytime there is a memory write. Analyze the value and type of what is written. If the write is to a global data section like BSS, we note that wrote to it, so we do not make it symbolic when it is read from during exploration.

        :param self: the path object being stepped
        :param dc_tracker: to track when the register write is a symbolic value
        :param current_step: the current step object along the path that is being explored
        """
        state_addr = state.scratch.ins_addr
        resolved = state.se.eval_upto(state.inspect.mem_write_address, 2)
        if len(resolved) > 1:
            l.info("****An address to be written to has more than one resolution, so don't track " +
                   hexx(state_addr) + str([hexx(addr) for addr in state.history.bbl_addrs.hardcopy]))
            return
        mem_addr = state.se.eval(state.inspect.mem_write_address)
        write_len = state.se.eval(state.inspect.mem_write_length)
        write_expr = state.inspect.mem_write_expr
        write_value_all = state.se.eval_upto(write_expr, 2)
        if len(write_value_all) > 1:
            min_value = state.se.min(write_expr)
            #l.info("**Value to be written have more than one value ")
            write_value = str(write_expr)
            #l.info("mem_write of " + str(write_value) + " to " + hexx(mem_addr)+ str(write_len) +  " bytes "+ hexx(state_addr)+ " path "+ str(self.path_id) + str([hexx(addr) for addr in state.history.bbl_addrs.hardcopy]))
            extra_info = "sym"
            value_written_is_concrete = False
            dc_tracker[hexx(state_addr)] += 1
        else:
            write_value = write_value_all[0]
            value_written_is_concrete = True
            #l.info("mem_write of " + str( write_value) + " or " +hexx(write_value) + " to "+ hexx(mem_addr) + " " + str( write_len) +  " bytes "+ hexx(state_addr)+ " path " + str(self.path_id) + str( [hexx(addr) for addr in state.history.bbl_addrs.hardcopy]))
            extra_info = self.input_analyzer.nature_of_value(
                write_value, write_len, state)

        tuple_to_write = (hexx(mem_addr), write_len, write_value,
                          current_step.step_id, self.path_id, extra_info)
        for seg in self.input_analyzer.global_all_segments:
            mem_start = self.input_analyzer.global_all_segments[seg]['start']
            mem_end = self.input_analyzer.global_all_segments[seg]['end']
            if mem_addr >= mem_start and mem_addr < mem_end:
                #l.info("in" + seg)
                if tuple_to_write not in self.input_analyzer.global_all_segments_write[seg]:
                    self.input_analyzer.global_all_segments_write[seg].append(
                        tuple_to_write)
                if seg not in self.input_analyzer.global_var_segments:
                    pass
                    #l.info("mem_write is not in the global_var_segments "+ seg)
                else:
                    if tuple_to_write not in self.input_analyzer.global_var_written[seg]:
                        self.input_analyzer.global_var_written[seg].append(
                            tuple_to_write)
                return

        # suppose the segment was not found, trying search all loaded objects
        for obj in self.input_analyzer.all_objects:
            mem_start = self.input_analyzer.all_objects[obj]['start']
            mem_end = self.input_analyzer.all_objects[obj]['end']
            if mem_addr >= mem_start and mem_addr <= mem_end:
                l.info("found a mem write by state at " + str(state_addr) + " " + write_expr + " " + str(
                    write_value) + " in " + hexx(mem_addr) + " of len " + str(write_len) + " bytes in " + obj)
                if tuple_to_write not in self.input_analyzer.all_objects_write:
                    self.input_analyzer.all_objects_write[obj].append(
                        tuple_to_write)
                return

        # suppose it was not found in the loaded objects, trying searching if its around the stack, arguments, or heap
        current_SP = state.se.eval_one(self.get_stack_pointer(state))
        if mem_addr <= self.config.INIT_SP and mem_addr >= current_SP:
            # lets check if this write is the return address being wrote before a function call, we are not interested in this type of write
            value_being_written = tuple_to_write[2]
            if value_written_is_concrete and value_being_written > state.addr and value_being_written <= state.addr + 16:  # 16 bytes from the the current IP
                # for some reason a mem read occurs when the state initially jumps to the called address after executing a call instr. not sure why but in angr's framework, this mem_read is  the return address, the same one the caller writes to the stack before jumping to the address
                return
            if tuple_to_write not in self.input_analyzer.dynamic_mem_write["stack"]:
                self.input_analyzer.dynamic_mem_write["stack"].append(
                    tuple_to_write)

        # I do not believe we can write back to the passed argument location, so delete this later`
        # perhaps anguments passed to the func
        elif mem_addr > self.config.INIT_SP and mem_addr <= self.config.CUSTOM_ARG_BOUND:
            if tuple_to_write not in self.input_analyzer.dynamic_mem_write["argument"]:
                self.input_analyzer.dynamic_mem_write["argument"].append(
                    tuple_to_write)
        else:  # perhaps, this is an write to the heap or unknown
            if tuple_to_write not in self.input_analyzer.dynamic_mem_write["unknown"]:
                self.input_analyzer.dynamic_mem_write["unknown"].append(
                    tuple_to_write)
                #l.info("write to unknow location "+ str(tuple_to_write))

    @staticmethod
    def get_stack_pointer(state):
        if state.arch.name == "AMD64":
            # return state.regs.rsp
            return state.registers.load("rsp", disable_actions=True, inspect=False)
        elif state.arch.name == "X86":
            # return state.regs.esp
            return state.registers.load("esp", disable_actions=True, inspect=False)
        elif state.arch.name == "ARMEL":
            return state.registers.load("sp", disable_actions=True, inspect=False)
            # return state.regs.sp
        elif state.arch.name == "AARCH64":
            return state.registers.load("sp", disable_actions=True, inspect=False)
            # return state.regs.sp
        else:
            l.error("unknown arch")
            raise NameError


def hexx(value):
    return hex(value).replace("L", "")
