import IPython
import logging

l = logging.getLogger(name="reg_analyses")
l.setLevel(logging.DEBUG)


class RegAnalyses:
    """
    This class  performs some analysis on registers involved in a read/write operations during the execution of a basic block.
    :param path_id: int: the unique identifier of the path object under consideration
    :param input_analyzer: an Input object: performs analysis on the values found int the registers and try to identify the type
    :param config: a Config object: holds information about some properties of the binary such as the argument registers, etc
    """

    def __init__(self, path_id,  input_analyzer, config, project):
        self.path_id = path_id
        self.config = config
        self.project = project
        self.input_analyzer = input_analyzer

    def reg_write_analyses(self, state, path_func_arg_track, dc_tracker, current_step, current_state):
        """
        Analyzes the register involved in a register write operation. Indicate that it has been written to.
        For now, we only track writes to known argument registers

        :param self: the path object being stepped
        :param path_func_arg_track: a dictionary that tracks if an argument register has been read before or written to
        :param dc_tracker: to track when the register write is a symbolic value
        :param current_step: the current step object along the path that is being explored
        :param current_state: the current state object along the path that is being explored
        """
        state_addr = state.scratch.ins_addr
        #reg_name = state.arch.translate_register_name(state.inspect.reg_write_offset, size=None)
        reg_name = state.arch.translate_register_name(
            state.inspect.reg_write_offset, size=state.inspect.reg_write_length)
        # so in angr, I see that the xmm0 registers are named ymm0. So let let me translate this if thats the case

        if "sp" in reg_name:
            self.update_stack_tracker(
                state, current_step.stack_tracker, current_state)

        if reg_name not in str(self.project.factory.block(state_addr).capstone.insns[0].op_str):
            # because I am using VEX op_level=0, other registers that I am not interested in gets tracked too
            # notice that I had to do this after the update_stack_tracker since sp can change due to some instructions where sp is not explicitly used
            if "ymm" in reg_name:
                # In the future, if ymm0 starts getting used in the disassenbked code, then I will start tracking it just as xmm0s
                reg_name = reg_name.replace("ymm", "xmm")
            if reg_name not in self.config.arg_registers_low_high_map and reg_name not in path_func_arg_track:
                # so that we can also track writes to 32bit registers (with respect to their 64bits equivalents)
                # I had to also check the arg_register_low_high_map since sometimes VEX reads the 64bit register and then slices down to the 32bit.
                return

        # update dc_tracker
        reg_write_expr = state.inspect.reg_write_expr
        if len(state.solver.eval_upto(reg_write_expr, 2)) > 1:
            dc_tracker[hexx(state_addr)] += 1

        # the goal here is to indicate that the registers of interest (i.e the one used to pass func arguments) has been written to
        # this way, we can track when the first read (reading passed arguments) is made
        # we only check the arg registers becos I assume those are the one that will be used to pass to another function to process, but not sure, TBD
        if reg_name in path_func_arg_track or reg_name in self.config.arg_registers_low_high_map:
            if reg_name in self.config.arg_registers_low_high_map:
                # map to the x64 regs, and use that as the name
                reg_name = self.config.arg_registers_low_high_map[reg_name]

            # the first entry is the indicator if the reg has been written before
            if path_func_arg_track[reg_name][0] is False:
                path_func_arg_track[reg_name][0] = True

            # For all those registers used in passing arguments to called functions
            # I want to track/record register writes that specify a pointer to global variables
            reg_write_value = state.se.eval_one(reg_write_expr)
            write_len = state.inspect.reg_write_length
            # this is for a register,so Im thinking the length should always be concrete
            write_len = state.se.eval_one(write_len)

            op_regs = str(self.project.factory.block(
                state_addr).capstone.insns[0].op_str).split(",")
            if len(op_regs) > 1:
                op_reg_written = op_regs[1].strip()
            else:
                op_reg_written = op_regs[0].strip()

            if op_reg_written in self.config.arg_registers_low_high_map:
                write_len = state.arch.registers[op_reg_written][1]

            # result will contain info about the global var segment
            result = self.input_analyzer.nature_of_value(
                reg_write_value, write_len, state)
            if len(result) > 3:  # if it returns any good info
                tuple_to_record = (reg_name, hexx(
                    reg_write_value), result, hexx(state_addr))
                current_step.path_reg_write_track.append(tuple_to_record)

    def reg_read_analyses(self, state, path_func_arg_track, dc_tracker, current_step):
        """
        the goal is to indicate that we have read a function argument if it has not been written to before

        :param self: the path object being stepped
        :param path_func_arg_track: a dictionary that tracks if an argument register has been read before or written to
        :param dc_tracker: to track when the register write is a symbolic value
        :param current_step: the current step object along the path that is being explored
        """
        state_addr = state.scratch.ins_addr
        reg_read = state.arch.translate_register_name(
            state.inspect.reg_read_offset, size=state.inspect.reg_read_length)
        # so in angr, I see that the xmm0 registers are named ymm0. So let let me translate this if thats the case

        if reg_read not in str(self.project.factory.block(state_addr).capstone.insns[0].op_str) and "ymm" not in reg_read:
            # because I am using VEX op_level=0, other registers that I am not interested in gets tracked too
            # also vex reads ymm0s eventhough the capstone disassembly is xmm0
            if reg_read not in self.config.arg_registers_low_high_map and reg_read not in path_func_arg_track:
                # so that we can also track writes to 32bit registers (with respect to their 64bits equivalents)
                # I had to also check the arg_register_low_high_map since sometimes VEX reads the 64bit register and then slices down to the 32bit.
                return
        # lets get the registers value
        reg_read_expr = state.inspect.reg_read_expr

        reg_read_values = state.solver.eval_upto(reg_read_expr, 2)
        if len(reg_read_values) > 1:
            dc_tracker[hexx(state_addr)] += 1
        else:
            reg_read_expr = reg_read_values[0]

        # vex uses ymm0 sometimes eventhough captone disassembly says xmm0
        if "ymm" in reg_read:
            # In the future, if ymm0 starts getting used in the disassenbked code, then I will start tracking it just as xmm0s
            reg_read = reg_read.replace("ymm", "xmm")
        # track function arguments
        if reg_read in self.config.arg_registers_low_high_map:
            # map to the x64 regs, and use that as the name
            reg_read = self.config.arg_registers_low_high_map[reg_read]

        if reg_read in path_func_arg_track:
            # the first entry is the indicator if the reg has been written before
            if path_func_arg_track[reg_read][0] is False:
                # we only report that an register-based argument was read, if the register has not been written
                # second entry means have not been read before, so the first time you read it, you are reading a passed function argument
                if path_func_arg_track[reg_read][1] is False:
                    path_func_arg_track[reg_read][1] = True
                    path_func_arg_track[reg_read][2] = reg_read_expr
                    path_func_arg_track[reg_read][3] = current_step.step_id
                    path_func_arg_track[reg_read][4] = hexx(
                        state.scratch.ins_addr)
                    # just for anomaly
                    values = state.solver.eval_upto(reg_read_expr, 2)
                    if len(values) < 2:
                        l.info("**ANOMALY** A register reported as a function argument has a concrete value " +
                               reg_read + " " + hex(state_addr) + " " + str(values))
                    else:
                        l.info("Passed argument read from " +
                               reg_read + " 2 possible values " + str(values))

    def update_stack_tracker(self, state, stack_tracker, current_state):
        """
        This tracks pushes to the stack, indicating arguments pushed to the stack before a function call. This helps us know how many arguments to pop from the stack when we avoid function calls
        """
        state_addr = state.scratch.ins_addr
        instr_pos = 0  # instruction position in the block. starts at 1
        # what was written to the stack pointer
        current_SP = state.se.eval_upto(state.inspect.reg_write_expr, 2)
        if len(current_SP) > 1:
            l.warn("STACK POINTER is symbolic ??")
        current_SP = current_SP[0]
        for instr_addr in self.project.factory.block(current_state.addr).capstone.insns:
            instr_pos += 1
            if instr_addr.address == state_addr:
                break
        stack_tracker[hexx(state_addr)] = current_SP


def hexx(value):
    return hex(value).replace("L", "")
