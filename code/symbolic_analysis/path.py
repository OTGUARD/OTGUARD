import copy
import IPython
import logging
import claripy
import angr
from step import Step
from mem_analyses import MemAnalyses
from reg_analyses import RegAnalyses
from inputs import Inputs
import path
import func_simulation
from termination import Termination
from loop_analyses import LoopAnalyses

l = logging.getLogger(name="path")
l.setLevel(logging.DEBUG)


class Path():
    """
    A path object. Created when the first path is initialized, and subsequently when a new path branches out a path

    :param path_id: int: a number starting from 0 (for path 0) that uniquely identifies each of the path objects
    :param state: angr state object: the state object at which the path was spawned
    :param step_created: a Step object: the step at which the path was spqwned
    :param parent_path: a path object: the path where the new path branched off
    """

    def __init__(self, path_id, state, step_created, parent_path):
        # self._registry.append(self)
        self.path_id = path_id
        self.current_state = state
        self.prev_state = state  # will be updated as path is stepped
        self.step_created = step_created
        self.current_step = step_created  # a step object
        if parent_path is None:  # if path 0
            self.parent_path = self  # just so I can avoid  checks for path 0 when using path.parent_path, but i will careful when using recursion of parents paths
            self.prev_step = step_created  # to be updated as path is stepped
        else:
            self.parent_path = parent_path
            self.prev_step = parent_path.prev_step  # to be updated as path is stepped

            self.explorer = parent_path.explorer
            self.explorer.paths.append(self)
            self.config = self.parent_path.config
            self.func_start = self.parent_path.func_start
            self.func_end = self.parent_path.func_end
            self.project = self.parent_path.project
            self.input_analyzer = Inputs(self.path_id,  self.project)
            self.reg_analyzer = RegAnalyses(
                self.path_id, self.input_analyzer, self.config, self.project)
            self.mem_analyzer = MemAnalyses(
                self.path_id, self.input_analyzer, self.config, self.func_start, self.project)

            # tracking arg regs that has been read/written into. each path keeps track of theirs
            self.path_func_arg_track = {}
            for reg in self.parent_path.config.arg_registers:
                # copy your parents current list
                self.path_func_arg_track[reg] = copy.copy(
                    self.parent_path.path_func_arg_track[reg])
        self.end_reason = ""
        self.steps = []  # store an ordered list of step objs
        self.reached_end = False
        self.TEMP_VAR = {}
        self.dc_tracker = {}
        self.termination = Termination()
        self.loop_analyses = LoopAnalyses(self.path_id)
        self.reg_to_symbolize = None  # used during force_branch

    def init_path_zero(self, config, func_start, func_end, project, explorer):
        """
        initiate the first path, i.e path 0
        """
        self.config = config
        self.func_start = func_start
        self.func_end = func_end
        self.project = project
        self.explorer = explorer  # the parent explorer object
        # initiate path_func_arg_track
        # tracking arg regs that has been read/written into. each path keeps track of theirs
        self.path_func_arg_track = {}
        for reg in self.config.arg_registers:
            self.path_func_arg_track[reg] = [False, False, "", "", ""]
            # [False, False, "", ""] = [has not been written to, has not been read from, read_expr, step when it was read, address it was read]
        for reg in self.config.fp_arg_registers:
            self.path_func_arg_track[reg] = [False, False, "", "", ""]

        self.input_analyzer = Inputs(self.path_id, self.project)
        self.reg_analyzer = RegAnalyses(
            self.path_id, self.input_analyzer, self.config, self.project)
        self.mem_analyzer = MemAnalyses(
            self.path_id, self.input_analyzer, self.config, self.func_start, self.project)

    def update_current_state(self, state):
        self.current_state = state

    def add_step(self):
        """
        adds a new Step object as a basic block is stepped
        returns the new Step object
        """
        new_step = Step(self.current_step.step_id + 1)
        self.steps.append(new_step)  # append a step object
        self.current_step = new_step

    def contextual_concretization_strategy(self, state):
        """
        use contextual information to approximate the address. so help me God
        if it involved x86 registers, then its 32 bits
        if it can be a pointer, so its either pointer to code, or data
        that way, we can further cut down the  possible number of solutions
        """
        pass

    def track_address_concretization(self, state):
        """
        TODO but not critical
        #state.inpspect.address_concretization_result = contextual_concretization_strategy
        """
        pass

    def step_path(self):
        """
        steps a path one basic block
        returns the path with its state advanced one basic block
        """
        self.prev_step = self.current_step
        self.add_step()  # this updates the current step
        self.prev_state = self.current_state.copy()
        return self.current_step.one_step(self)

    @staticmethod
    def constraint_contains(cons, cons_list):
        """
        used to see if constraints added during the execution of a basic block is part of an overall constraints of a path
        """
        for c in cons.split("###"):
            if c not in str(cons_list):
                return False
        return True

    # 1 means the first encountered
    def process_new_child_state(self, child_state, has_sibling=False, position=1, total_children=0, is_sym_call=False):
        """
        To process the new successor states after a basic block is stepped
        :param child_state: angr state object: the successor state after a basic block is stepped
        :param has_sibling: bool: indicates if there was more than one successor states
        :param position: int: if there was more than one successor, this specifies if its child 1 or child 2 or 3, etc
        :param total_children: int:
        :param is_sym_call: if the successor was as a result of a call to a symbolic address
        """
        p_path_id = self.path_id  # parent path_id
        path_being_analyzed = self  # may be updated if a branched path from the stepped path
        parent_path = self  # the stepped path
        if not has_sibling or position == 1:
            # continuation of the path that was stepped
            parent_path.current_state = child_state

        if has_sibling:
            if position == 1:
                # inherit the parents path id
                next_sib = len(parent_path.explorer.paths)
                path_being_analyzed.current_step.path_events.split += "t_fam:" + \
                    str(total_children)+",next_sib:"+str(next_sib)
            else:
                path_id = len(parent_path.explorer.paths)
                l.info("** New Path %d **", path_id)
                step_created = parent_path.current_step
                path_being_analyzed = path.Path(
                    path_id, child_state, step_created, parent_path)

                path_being_analyzed.current_step.path_events.split += "t_fam:" + \
                    str(total_children)+",f_sib:"+str(p_path_id)
                if position < total_children:  # you have a next sibling
                    next_sib = len(parent_path.explorer.paths)
                    path_being_analyzed.current_step.path_events.split += ",next_sib:" + \
                        str(next_sib)

                if "forced" in parent_path.TEMP_VAR:
                    if child_state.addr in parent_path.TEMP_VAR["forced"]:
                        path_being_analyzed.current_step.path_events.forced = "%#x" % (
                            child_state.addr)

            path_being_analyzed.current_step.path_events.events += "path_split, "
            # we specify the path split at the step after the split has happened
        # update the cumul_ratio and dc
        current_cumul_ratio = parent_path.prev_step.path_events.cumul_ratio
        sym_ops = 0.0
        all_ops = len(parent_path.dc_tracker)

        # check if we came here via a call, which will cause us later to make eax symbolic, hence creation of a symbolic var
        if child_state.history.jumpkind in ["Ijk_Call"]:
            parent_path.dc_tracker["%#x" % (parent_path.project.factory.block(
                parent_path.prev_state.addr).capstone.insns[-1].address)] += 1  # since we are symbolizing things

        if is_sym_call:  # after handling sym_call at step_state, lets make sure its dc is impacted
            parent_path.dc_tracker["%#x" % (parent_path.project.factory.block(
                parent_path.prev_state.addr).capstone.insns[-1].address)] += 1  # since we are symbolizing things

        for addr_entry in parent_path.dc_tracker:
            if parent_path.dc_tracker[addr_entry] != 0:
                sym_ops += 1
        computed_cumul_ratio = current_cumul_ratio + (sym_ops/all_ops)
        computed_dc = 1 - (computed_cumul_ratio /
                           parent_path.current_step.step_id)
        path_being_analyzed.current_step.path_events.cumul_ratio = computed_cumul_ratio
        path_being_analyzed.current_step.path_events.dc = computed_dc

        # tracking added constraints
        if parent_path.prev_step.step_id in parent_path.TEMP_VAR:
            # find out which of the cons in TEMP_VAR belongs to you
            for cons in parent_path.TEMP_VAR[parent_path.prev_step.step_id]["added_cons"]:
                # cons is in string form
                if parent_path.constraint_contains(cons, parent_path.current_state.se.constraints):
                    path_being_analyzed.current_step.path_events.events += parent_path.TEMP_VAR[
                        parent_path.prev_step.step_id]["events"] + ", "
                    path_being_analyzed.current_step.path_events.added_cons += cons.replace(
                        "###", "")

        # first make sure it did not call a function
        fxn_name = ""
        if child_state.history.jumpkind in ["Ijk_Call"]:
            fxn_name = func_simulation.handle_function_call(
                path_being_analyzed)
        elif is_sym_call:  # lets note that we encoutered a sym_call
            fxn_name = func_simulation.handle_function_sym_call(
                path_being_analyzed)

        # check for termination
        if "exit" in fxn_name:
            path_being_analyzed.termination.record_end(
                path_being_analyzed, "called_exit")
            return None

        reason = path_being_analyzed.termination.check_termination(
            path_being_analyzed)
        if reason:  # if you returned something
            path_being_analyzed.termination.record_end(
                path_being_analyzed, reason)
            return None
        else:
            reason_to_discard_path = path_being_analyzed.loop_analyses.check_for_loop(
                path_being_analyzed, has_sibling)
            if reason_to_discard_path:
                path_being_analyzed.termination.record_end(
                    child_state, reason_to_discard_path)
                return None
            return path_being_analyzed

    def symbolize_reg(self, state):  # the self here is the path object
        """
        makes the value in a register to be symbolic. Used to force both branches to be explored when the predicate is being considered to decide a branch
        """
        if len(self.reg_to_symbolize) == 0:
            return
        pred_reg = self.reg_to_symbolize['reg']
        reg_size = self.reg_to_symbolize['size']
        instr_addr = self.reg_to_symbolize['instr_addr']
        #setattr(state.regs, pred_reg, claripy.BVS(pred_reg, reg_size * 8))
        state.registers.store(pred_reg, claripy.BVS(
            pred_reg, reg_size * 8), disable_actions=True, inspect=False)
        l.info("hard force_split: breakpoint to symbolize %s at  %#x",
               pred_reg, instr_addr)
        self.reg_to_symbolize = {}  # empty it

    def symbolize_mem(self, state):  # the self here is the path object
        """
        makes the value in a memory to be symbolic. Used to force both branches to be explored when the predicate is being considered to decide a branch
        """
        # make sure its the right mem_read we want to symbolize: second to last instr before a jump, and with the cmp mnemonic
        state_addr = state.scratch.ins_addr
        instr_list = self.project.factory.block(state_addr).capstone.insns
        if len(instr_list) != 2 or str(instr_list[0].insn.mnemonic).strip() not in ["cmp", "test", "xor"]:
            return

        l.info(
            "hard force_split: breakpoint to symbolize memory at %#x triggered ", state_addr)
        mem_addrs = state.se.eval_upto(state.inspect.mem_read_address, 2)
        if len(mem_addrs) != 1:
            l.info(
                "but mem location to symbolize has more than one target, so ignoring")
            return

        mem_addr = mem_addrs[0]
        read_len = state.se.eval(state.inspect.mem_read_length)
        label = "split_%#x_%#x_%d" % (
            self.func_start, mem_addr, self.current_step.step_id)
        state.memory.store(mem_addr, state.se.BVS(
            label, read_len * 8), disable_actions=True, inspect=False)  # store is in bits

    def force_branch_split(self, mode="soft"):  # self here is the path object
        """
        force both direction of a branch to be explored by attemping to make the predicate symbolic
        "soft" mode means that after the predicate register has been identified, it will be made symbolic before the basic block is executed. This means that the branch is not always guaranteed suppose the predicate register is over-written just before the cmp instr happens. Also, soft mode only symbolizes registers. "hard" mode symbolizes both registers and memory just before the cmp instr happens. This guarantees that both brances will be taken. "soft" and "hard" mode is a trade-off between the integrity of data flow.
        """
        state = self.current_state
        self.reg_to_symbolize = {}  # empty it
        breakpoint_tuple = ()
        successors = ""
        # find out the predicate, and make them symbolic, then try one more time
        instr_list = self.project.factory.block(state.addr).capstone.insns
        instr_list.reverse()
        success = False
        ins_pos = -1
        for ins in instr_list:
            ins_pos += 1  # starts at 0
            # just saying that the cmp/test must be just before the jump instruction
            if str(ins.insn.mnemonic).strip() in ["cmp", "test", "xor"] and ins_pos == 1:
                operands = str(ins.insn.op_str).split(",")
                instr_addr = ins.insn.address
                for reg in operands:
                    pred_reg = reg.strip()
                    if pred_reg in state.arch.registers:
                        # in bytes
                        reg_size = state.arch.registers[pred_reg][1]
                        #old_value = getattr(state.regs, pred_reg)
                        old_value = state.registers.load(
                            pred_reg, disable_actions=True, inspect=False)
                        #reg_will_be_symbolized = True
                        if mode == "soft":
                            # make reg symbolic at the start of the BB
                            #setattr(state.regs, pred_reg, claripy.BVS(pred_reg, reg_size * 8))
                            state.registers.store(pred_reg, claripy.BVS(
                                pred_reg, reg_size * 8), disable_actions=True, inspect=False)
                            l.info(
                                "soft force_split: stepping state again after making %s symbolic",  pred_reg)
                        elif mode == "hard":
                            # put a breakpoint, to make reg symbolic before the "test" or "cmp" is done
                            self.reg_to_symbolize = {
                                'reg': pred_reg, 'size': reg_size, 'instr_addr': instr_addr}
                            breakp = state.inspect.b(
                                "instruction", when=angr.BP_BEFORE, instruction=instr_addr, action=self.symbolize_reg)
                            breakpoint_tuple = (breakp, "instruction")
                            l.info(
                                "hard force_split: stepping state again after making %s symbolic", pred_reg)
                        else:
                            l.info("invalid force_split mode %s", mode)
                            raise NameError
                        # step state again
                        successors = self.project.factory.successors(
                            state, opt_level=0)
                        # if symbolizing one of the operands helped
                        if len(successors.unsat_successors) == 0 or len(successors.flat_successors) > 1:
                            l.info("force branch worked !!")
                            success = True
                            break
                        else:
                            l.info("force branch did not work :(")
                            if mode == "hard":
                                # remove the breakpoint
                                state.inspect.remove_breakpoint(
                                    breakpoint_tuple[1], breakpoint_tuple[0])
                            # put back old value
                            #setattr(state.regs, pred_reg, old_value)
                            state.registers.store(
                                pred_reg, old_value, disable_actions=True, inspect=False)
                # if reg_will_be_symbolized:# reg was symbolized
                #    break
                if not success and mode == "hard":  # if it gets here it means there was no success at symbolizing reg
                    #mem_will_be_symbolized = True
                    instr_addr = ins.insn.address
                    breakp = state.inspect.b(
                        "mem_read", when=angr.BP_BEFORE, action=self.symbolize_mem)
                    breakpoint_tuple = (breakp, "mem_read")
                    l.info(
                        "hard force_split: stepping state again after setting a mem_read breakpoint incase it happens at %#x", instr_addr)
                    successors = self.project.factory.successors(
                        state, opt_level=0)
                    # if symbolizing one of the operands helped
                    if len(successors.unsat_successors) == 0 or len(successors.flat_successors) > 1:
                        l.info("force branch worked !!")
                        success = True
                        break
                    else:
                        l.info("force branch did not work :(")
                        # remove the breakpoint
                        state.inspect.remove_breakpoint(
                            breakpoint_tuple[1], breakpoint_tuple[0])
                        # no need to put the old back the old mem_value, because the successors will not be used following return to step_state
            if success:
                break
        # return the successors, and also the set breakpoints if any, so that they can be removed from the flat_successor's state
        return successors, success, breakpoint_tuple
