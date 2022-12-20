import gc
import logging
import IPython
from angr import errors
import events

l = logging.getLogger(name="step")
l.setLevel(logging.DEBUG)


class Step:
    """
    A step object holds information about events that happened during the stepping or execution of a basic block
    :param step_id; int: a unique number (incrementing) to identify a step during the stepping of a path
    """

    def __init__(self, step_id):
        self.step_id = step_id
        # to track when the stack pointer changes, used in reg_write_analyses
        self.stack_tracker = {}
        # an append-only list just to note when inputs are written to any one of the argument registers
        self.path_reg_write_track = []
        self.path_events = events.Events()

    def one_step(self, path):
        """
        advance a path one step or one basic block
        returns a list of successor states
        """
        gc.collect()
        # used by track_added_constraints, and also to track paths that were forced splitted
        path.TEMP_VAR = {}
        successors_to_return = []
        l.info("stepping state %s path %d current step %d history %s", path.current_state, path.path_id,
               self.step_id,  str([hexx(a) for a in path.current_state.history.bbl_addrs.hardcopy]))

        path.dc_tracker = {}  # used to track SymOps and AllOps
        for ins in path.project.factory.block(path.current_state.addr).capstone.insns:
            # no SymOps to begin with in that instruction
            path.dc_tracker[hexx(ins.insn.address)] = 0

        try:
            successors = path.project.factory.successors(
                path.current_state, opt_level=0)
        except errors.AngrPathError as e:
            l.error("Angr crashed stepping state @ %#x,  path %d. See crash report \n %s",
                    path.current_state.addr, path.path_id, str(e))
            # raise
            path.termination.record_end(path, "Angr_Crashed")
            return []
        flat_succ = successors.flat_successors
        unsat_succ = successors.unsat_successors

        if path.config.force_branch and len(unsat_succ) > 0 and len(flat_succ) == 1:
            returned_successors, success, bp_tuple = path.force_branch_split(
                mode=path.config.force_branch)
            if success:
                leaves = returned_successors.flat_successors
                if path.config.force_branch == "hard":
                    for s in leaves:
                        s.inspect.remove_breakpoint(bp_tuple[1], bp_tuple[0])
                # ok, now we want to retain that one  previous flat_successor that succeeded before we try to force the second path
                # save flat_succ incase things mess up
                orig_flat_succ = [s for s in flat_succ]
                path.TEMP_VAR["forced"] = []
                for this_state in leaves:
                    # flat_succ[0] is the previously generated flat successors before the forcing
                    if this_state.addr != flat_succ[0].addr:
                        # retain the one we had before
                        flat_succ.append(this_state)
                        path.TEMP_VAR["forced"].append(this_state.addr)
                leaves = flat_succ
                # safety check incase things messed up
                if len(leaves) != 2:  # This can happen when the unsat_succ is the same as the flat_succ, e.g in conditional jump, both both target point to same address
                    if unsat_succ[0].addr != leaves[0].addr:
                        l.info("Inform Developer  Investigation 202 in func " + hexx(path.func_start) + " state at " + hexx(
                            path.current_state.addr) + " " + str(leaves) + " " + str(orig_flat_succ) + str(unsat_succ))
                    # I just when back to the original. Not sure why this could happen, but just for safety
                    leaves = orig_flat_succ
            else:  # not successful
                leaves = flat_succ  # the previous successors
        else:
            leaves = flat_succ

        if len(leaves) != len(successors.all_successors) or len(leaves) == 0:
            pass
            #l.info("Flat successors: " + str(len(leaves)) + " not same as All successors: " + str(len(successors.all_successors)))
            #l.info("unsat "+ str (len(successors.unsat_successors)))
            #l.info("uncon " +str(len(successors.unconstrained_successors)))

        if len(leaves) == 0:
            # many things can cause this, so lets proceed one by one
            # see if its because it made a call instruction, and to an address that is symblolic. i.e call edi and edi was unconstrained
            last_instr = path.project.factory.block(
                path.current_state.addr).capstone.insns[-1]
            # I used this to make sure its not something else (other than a sym_call) that caused it not to have a flat_successor. I observed that when all_successors is 0, something really bad happened such as an "Getting a unsat result". Not completely sure what this even means for now. Explore Zeus(client32.bin) func 0x411149
            if self.instr_is_a_call(last_instr, path) and len(successors.all_successors) != 0:
                path.project.hook(last_instr.insn.address,
                                  do_nothing, length=last_instr.insn.size)
                # the above hook will cause it not to execute the call instruction
                leaves = path.project.factory.successors(
                    path.current_state).flat_successors
                path.project.unhook(last_instr.insn.address)
                if len(leaves) != 1:
                    l.info(
                        "Symbolic Call handling did not work. resulted in %d successors", len(leaves))
                    path.termination.record_end(path, "Sym_Call")
                else:
                    # We will  set the IP to the next instruction after the "call" that we nopped
                    child_state_returned = path.process_new_child_state(
                        leaves[0], is_sym_call=True)  # only one child_state
                    if child_state_returned != None:
                        successors_to_return.append(child_state_returned)
            # lets see if this was because of a return
            elif self.instr_is_a_return(last_instr, path):
                path.termination.record_end(path, "Hit_Return_No_Flat_Succ")
            else:
                path.termination.record_end(path, "No_Flat_Succ")
        elif len(leaves) > 5:  # just my little threshold so I don't have many paths lying around
            # symbolic IP. Just happened to be with the angr threshold of 256
            last_instr = path.project.factory.block(
                path.current_state.addr).capstone.insns[-1]
            if self.instr_is_a_return(last_instr, path):
                path.termination.record_end(path, "Sym_IP_Return")
            else:
                path.termination.record_end(path, "Sym_IP")

        elif len(leaves) == 1:
            child_count = 0
            child_state_returned = path.process_new_child_state(
                leaves[0])  # only one child_state
            if child_state_returned != None:
                successors_to_return.append(child_state_returned)
        else:  # more then one flat successors. child state has a sibling
            child_count = 0
            for child_state in leaves:
                child_count += 1
                child_state_returned = path.process_new_child_state(
                    child_state, has_sibling=True, position=child_count, total_children=len(leaves))
                if child_state_returned != None:
                    successors_to_return.append(child_state_returned)
        return successors_to_return

    @staticmethod
    def instr_is_a_return(instr, path):
        """
        this uses known/adhoc heuristics to know it the last instruction is a function return or not
        returns a bool
       """
        if path.project.arch.name in ["AMD64", "X86"]:
            return "ret" in str(instr.mnemonic)
        elif path.project.arch.name in ["ARMEL", "AARCH64"]:
            if "pop" in str(instr.mnemonic) or "ldm" in str(instr.mnemonic):
                return "pc" in str(instr.op_str)
            else:
                return "bx" in str(instr.mnemonic) and "lr" in str(instr.op_str)
        else:
            l.info("unknown arch")
            raise NameError

    @staticmethod
    def instr_is_a_call(instr, path):
        """
        checks if an instruction is a call
        returns a bool
        """
        if path.project.arch.name in ["AMD64", "X86"]:
            return "call" in str(instr.mnemonic)
        elif path.project.arch.name in ["ARMEL", "AARCH64"]:
            return "bl" in str(instr.mnemonic)
        else:
            return False


def do_nothing(state):
    """
    used by an angr hook functionality
    """
    pass


def hexx(value):
    return hex(value).replace("L", "")
