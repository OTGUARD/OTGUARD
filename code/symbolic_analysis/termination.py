import sys
import logging
l = logging.getLogger(name="termination")
l.setLevel(logging.DEBUG)


class Termination:
    """
    A termination object concludes a path when it ends, and records why it ended and other final attributes of the path.

    :param reason: reason why the path ended
    :param last_addr: the last address executed by the path
    :param path_bbs: the paths basic block history
    :param path_len: the path basic block or stepping length
    :param constraints: the final constraints on the path
    """

    def __init__(self, reason="", last_addr="", path_bbs="", path_len="", constraints=""):
        self.reason = reason
        # ["No_Flat_Succ", "Hit_Return_No_Flat_Succ", "Sym_IP", "Sym_IP_Return", Returned, Out_Of_Bounds, Loop, Sym_Call]: others "called_exit", "Uid_Clash", "Not Yet Ended.."
        self.last_addr = last_addr
        self.path_bbs = path_bbs
        self.path_len = path_len
        self.constraints = constraints

    @staticmethod
    def check_termination(path):
        """
        This checks if a path has terminated/ended
        """
        if "Ijk_Sig" in path.current_state.history.jumpkind:
            # this happens on few scenarios including  when an instruction is not valid
            return path.current_state.history.jumpkind
        # check for return
        if path.current_state.history.jumpkind in ["Ijk_Ret"]:
            return "Returned"  # this means that the function actually returned to a resolvable address within the set symbolic IP threshold
        # check for Out_Of_Bounds
        if path.current_state.addr < path.func_start or path.current_state.addr > path.func_end:
            return "Out_Of_Bounds"
        return False

    def record_end(self,  path, end_reason):
        """
        After a path has terminated, this gathers and records the final attributes of the path
        """
        path_bbs = [
            addr for addr in path.current_state.history.bbl_addrs.hardcopy]
        # state.solver.simplify()
        if end_reason in ["No_Flat_Succ", "Hit_Return_No_Flat_Succ", "Sym_IP", "Sym_Call", "Sym_IP_Return", "Angr_Crashed"]:
            # The above end_reasons are the ones that basically had no flat successors when stepped. We have to still account for the things they did prior to not having an eventual flat successor
            self.no_flat_succ_path_events_update(path)
            # since I know it tried to execute the last BB before saying it cant
            path_bbs.append(path.current_state.addr)

            # Sym_IP_Return means the state retuned successors within angr's threshold (i.e 256) via but after executing a return instr
            if end_reason in ["Hit_Return_No_Flat_Succ", "Sym_IP_Return"]:
                self.record_return_value(path)
        if end_reason == "Returned":  # returned and was concretized to a few address, so had flat succs
            self.record_return_value(path)
            self.last_addr = path.project.factory.block(
                path.prev_state.addr).capstone.insns[-1].insn.address
        else:
            self.last_addr = path.project.factory.block(
                path.current_state.addr).capstone.insns[-1].insn.address

        if end_reason in ["Out_Of_Bounds", "Returned"] or "Ijk_Sig" in end_reason:
            end_reason += "-"+hexx(path.current_state.addr)
        self.reason = end_reason
        self.path_bbs = path_bbs
        self.path_len = len(path_bbs)
        self.constraints = path.current_state.se.constraints
        path.reached_end = True

    def record_return_value(self, path):
        """
        try to get the return value, i.e eax
        we have to step it without executing the last instruction, i.e the return instruction
        """
        for ins in path.project.factory.block(path.current_state.addr).capstone.insns[0:-1]:  # skip one, i.e the last instruction
            # if "ret" in str(ins):#suppose ret was the first and only instruction in that BB
            if path.current_step.instr_is_a_return(ins, path):
                break
            child_state = path.project.factory.successors(
                path.current_state, num_inst=1).flat_successors[0]

        func_return_value = child_state.se.eval_upto(
            self.get_return_register(child_state), 2)
        # path.un_ignore_breakpoints(["all"])
        if len(func_return_value) == 1:
            path.current_step.path_events.events += "has_ret_value"
            path.current_step.path_events.ret_values += str(
                func_return_value[0]) + " "

    @staticmethod
    def no_flat_succ_path_events_update(path):
        """
        because the states here are the states that were stepped but had no successors, this means that we will use their previous step to access things
        """
        current_cumul_ratio = path.prev_step.path_events.cumul_ratio
        sym_ops = 0.0
        all_ops = len(path.dc_tracker)

        for addr_entry in path.dc_tracker:
            if path.dc_tracker[addr_entry] != 0:
                sym_ops += 1
        computed_cumul_ratio = current_cumul_ratio + (sym_ops/all_ops)
        computed_dc = 1 - (computed_cumul_ratio/path.current_step.step_id)
        path.current_step.path_events.cumul_ratio = computed_cumul_ratio
        path.current_step.path_events.dc = computed_dc

        if "added_cons" in path.TEMP_VAR:
            for cons in path.TEMP_VAR["added_cons"]:
                # cons is in string form
                if path.constraint_contains(cons, path.current_state.se.constraints):
                    path.current_step.path_events.events += path.TEMP_VAR["events"] + ", "
                    path.current_step.path_events.added_cons += cons.replace(
                        "###", "")

    @staticmethod
    def get_return_register(state):
        """
        return the value of the return register for the architecture under consideration
        """
        if state.arch.name == "AMD64":
            return state.registers.load("rax", disable_actions=True, inspect=False)
        elif state.arch.name == "X86":
            return state.registers.load("eax", disable_actions=True, inspect=False)
        elif state.arch.name == "ARMEL":
            return state.registers.load("r0", disable_actions=True, inspect=False)
        elif state.arch.name == "AARCH64":
            return state.registers.load("r0", disable_actions=True, inspect=False)
        else:
            l.error("unknown arch")
            raise NameError


def hexx(value):
    return hex(value).replace("L", "")
