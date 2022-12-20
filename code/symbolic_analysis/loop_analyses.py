import IPython
import logging

l = logging.getLogger(name="loop_analyses")
l.setLevel(logging.DEBUG)


class Loop():
    def __init__(self, loop_head, loop_tail, loop_body, count, steps):
        self.loop_head = loop_head
        self.loop_tail = loop_tail
        self.loop_body = loop_body
        self.count = count
        self.formula = []
        self.pred_var = []
        self.bound_var = []
        self.diff_func = []
        self.info = ""
        self.steps = steps  # step_ids this loop was encountered


class LoopAnalyses():
    def __init__(self, path_id):
        self.path_id = path_id
        self.loops = []  # a list of loop instances

    def initiate_loop(self, loop_tail, loop_body, step):
        loop_head = loop_body[0]
        loop_tail = loop_tail
        count = 1
        steps = [step]
        new_loop = Loop(loop_head, loop_tail, loop_body, count, steps)
        self.loops.append(new_loop)
        return new_loop

    # when bb is in its history, we want to see if it is part of a previously identified loop body
    def check_within_past_loop(self, path, bb_addr):  # addr in hex
        bb_pred_addr = path.current_state.history.bbl_addrs.hardcopy[-1]
        for loop_instance in self.loops:
            if bb_addr in loop_instance.loop_body:
                pos = loop_instance.loop_body.index(bb_addr)
                pred = loop_instance.loop_body[pos - 1]
                if pred == bb_pred_addr:
                    # that bb and its pred already exists in the loop addr chain
                    if bb_addr != loop_instance.loop_head:
                        return "within_past_loop", None  # is within past loop
                    else:
                        return "repeating_loop",  loop_instance
        return False, None

    def check_within_ancestral_past_loop(self, path, bb_addr):
        bb_pred_addr = path.current_state.history.bbl_addrs.hardcopy[-1]
        for ancestor_path in self.get_ancestors(path, path, []):
            for loop_instance in ancestor_path.loop_analyses.loops:
                if bb_addr in loop_instance.loop_body:
                    pos = loop_instance.loop_body.index(bb_addr)
                    pred = loop_instance.loop_body[pos - 1]
                    if pred == bb_pred_addr:
                        # that bb and its pred already exists in the loop addr chain
                        if bb_addr != loop_instance.loop_head:
                            return "within_past_loop", None  # is within past loop
                        else:
                            return "repeating_loop", loop_instance
        return False, None

    # get the count of a specific loop instances among ancestors. the cumulative used in checking if to breakout
    def get_ancestral_loop_count(self, path, loop_body):
        count = 0
        for ancestor_path in self.get_ancestors(path, path, []):
            for ancestor_loop in ancestor_path.loop_analyses.loops:
                if ancestor_loop.loop_body == loop_body:
                    # make sure your ancestors loop happened before you were created
                    for step in ancestor_loop.steps:
                        if step.step_id < path.step_created.step_id:
                            count += ancestor_loop.count
        #print "ancestor loop count returned " , count
        return count

    def update_loop(self, path, loop_tail, loop_body):
        # check if loop instance already exists
        for loop_instance in self.loops:
            if "".join(loop_instance.loop_body) == "".join(loop_body):
                loop_instance.count += 1
                l.info("repeating loop identified at " +
                       loop_instance.loop_head + " count:" + str(loop_instance.count))
                return loop_instance
        l.info("new loop identified at " + loop_body[0] + ". Times repeated in ancestor paths:" + str(
            self.get_ancestral_loop_count(path, loop_body)))
        return self.initiate_loop(loop_tail, loop_body, path.current_step)

    def check_for_loop(self, path, has_sibling, threshold=10):
        state_addr = path.current_state.addr
        if state_addr in path.current_state.history.bbl_addrs.hardcopy:
            addr = state_addr
            # check whether this is within a body of a loop already considered, hence no need to do any processing
            check, loop_instance = self.check_within_past_loop(path, addr)
            if check == "within_past_loop":
                return False
            elif check == "repeating_loop":
                self.update_loop(path, loop_instance.loop_tail,
                                 loop_instance.loop_body)
                return self.apply_loop_breakout_policy(path, loop_instance, threshold)

            check, loop_instance = self.check_within_ancestral_past_loop(
                path, addr)
            if check == "within_past_loop":
                return False
            elif check == "repeating_loop":
                self.update_loop(path, loop_instance.loop_tail,
                                 loop_instance.loop_body)
                return self.apply_loop_breakout_policy(path, loop_instance, threshold)

            # just record bb addresses involved in a loop in path_events
            path.current_step.path_events.loop = addr

            if "rep" in str(path.project.factory.block(state_addr).capstone.insns[0].mnemonic):
                # nothing much to do here
                # well "rep" only happens in x86 things
                if path.project.arch.name in ["AMD64", "X86"]:
                    counter_reg = path.current_state.registers.load(
                        "ecx", disable_actions=True, inspect=False)
                    if len(path.current_state.solver.eval_upto(counter_reg, 2)) == 1:  # concrete
                        counter_reg = path.current_state.solver.eval(
                            counter_reg)

                    #loop_bb_chain = addr+":"+addr
                    loop_body = [addr, addr]
                    loop_tail = addr
                    loop_instance = self.update_loop(
                        path, loop_tail, loop_body)
                    loop_instance.bound_var.append(counter_reg)
                    # if this loop has a sibling, it means the predicate is symbolic which means that every subsequent iteration introduces a new path. So lets breakout if it has a sibling, especialy since its a rep instruction
                    if has_sibling:
                        loop_instance.info += " rep_based_forced_breakout@" + \
                            str(path.current_step.step_id)
                        #l.info("made call to break loop at " + hex(state_addr))
                        return self.loop_breakout(path)
                l.error(
                    "rep instruction was encountered, but its not X86 or AMD64. This is an anomaly at %#x", state_addr)
                raise NameError

            else:
                # the goal here is to find the head and the tail
                # the head can either be here where the repetition occurred i.e state.addr or an address within the immediate preceeding bb (due to the fact that angr only keeps bb-based history)
                loop_head = loop_tail = preceeding_bb = ""
                last_occurence = path.current_state.history.bbl_addrs.hardcopy[::-1].index(
                    state_addr)
                stepped_bb = path.current_state.history.bbl_addrs.hardcopy[-1]
                # just to prevent list index overflow
                if last_occurence < len(path.current_state.history.bbl_addrs.hardcopy) - 1:
                    # preceeding bb to when state_addr occurred earlier before
                    preceeding_bb = path.current_state.history.bbl_addrs.hardcopy[
                        ::-1][last_occurence + 1]
                    instr_list = path.project.factory.block(
                        preceeding_bb).capstone.insns
                    if stepped_bb in [ins.insn.address for ins in instr_list if instr_list[0].insn.address != stepped_bb]:
                        # corner case loop_head
                        loop_head = stepped_bb
                    else:
                        loop_head = state_addr
                else:
                    loop_head = state_addr

                # lets get the loop_tail and loop_body
                # the tail is the last branched bb immediately before the head within the path
                vars_found = False
                last_to_now_len = last_occurence + 2
                for i in xrange(1, last_to_now_len):

                    # another stupid corner case within the first corner case:
                    # if the corner case bb has branch but is not looping on just itself, dont consider its branch as a legit tail
                    if i == 1 and loop_head != state_addr and len(path.current_state.history.bbl_addrs.hardcopy[::-1][0:last_occurence]) > 0:
                        continue
                    # index -1, -2, -3,
                    last_bb_addr = path.current_state.history.bbl_addrs.hardcopy[0-i]
                    # now lets find the tail
                    instr_list = path.project.factory.block(
                        last_bb_addr).capstone.insns
                    instr_list.reverse()
                    for instr in instr_list:
                        # make sure the bb ends with a jump instr
                        if str(instr.mnemonic).strip() in ["cmp", "test", "xor"] and "j" in instr_list[0].mnemonic:
                            # last_bb_addr is the loop_tail
                            loop_tail_index = path.current_state.history.bbl_addrs.hardcopy[::-1].index(
                                last_bb_addr)
                            #loop_body = path.current_state.history.bbl_addrs.hardcopy[::-1][0:loop_tail_index + 1]
                            loop_tail = last_bb_addr
                            loop_body = path.current_state.history.bbl_addrs.hardcopy[
                                ::-1][loop_tail_index:last_occurence + 1]
                            if state_addr != loop_head:
                                loop_body = loop_body + [loop_head]

                            loop_body.reverse()
                            # lets look forward and get the remainining body if applicable
                            rem = path.current_state.history.bbl_addrs.hardcopy[::-
                                                                                1][1:loop_tail_index]
                            rem.reverse()
                            loop_body.extend(rem)

                            loop_body = [a for a in loop_body]
                            pred_var, bound_var = self.get_loop_vars(
                                path, instr)

                            loop_instance = self.update_loop(
                                path, loop_tail, loop_body)
                            loop_instance.bound_var.append(bound_var)
                            loop_instance.pred_var.append(pred_var)
                            vars_found = True
                            break
                    if vars_found:
                        break
                if not vars_found:
                    l.error("loop vars not found")
                    loop_instance = self.update_loop(
                        path, state_addr, [state_addr, state_addr])
                    loop_instance.bound_var.append("X")
                    loop_instance.pred_var.append("X")

            return self.apply_loop_breakout_policy(path, loop_instance, threshold)
            #IPython.embed(banner1="end of loop things")
        return False  # false means do not discard path

    def apply_loop_breakout_policy(self, path, loop_instance, threshold):
        dc = path.current_step.path_events.dc

        # lets just iterate it for that much
        if loop_instance.count + self.get_ancestral_loop_count(path, loop_instance.loop_body) > (threshold * dc):
            loop_instance.info += " dc_based_forced_breakout@ step" + \
                str(path.current_step.step_id)
            l.info("made call to break loop at %#x",  path.current_state.addr)
            return self.loop_breakout(path)
        else:
            return False  # false means do not discard path

    @staticmethod
    def get_loop_vars(path, instr):
        # we try to use heuristics to find the bound and predicate variables. if not, we just pick them at random. bound is usually an immediate or memory
        var1 = str(instr.op_str.split(",")[0]).strip()
        var2 = str(instr.op_str.split(",")[1]).strip()
        var_list = []
        bound_var = ""
        # lets get their values if they are registers and concrete
        value = "X"
        for each_var in [var1, var2]:
            if each_var in path.current_state.arch.registers:
                reg_expr = path.current_state.registers.load(
                    each_var, disable_actions=True, inspect=False)
                if len(path.current_state.solver.eval_upto(reg_expr, 2)) == 1:
                    value = each_var + ":" + \
                        str(path.current_state.solver.eval(reg_expr))
                else:
                    value = each_var + ":" + str(reg_expr)
            elif "[" in each_var:
                value = "mem:" + each_var
                bound_var = value
            else:
                # immediate, but I could have further checked to see if it can be converted to an integer
                value = "imme:" + each_var
                bound_var = value
            var_list.append(value)

        # now lets figure which one is bound or predicate
        if bound_var:
            pred_var_index = (var_list.index(bound_var) + 1) % 2
            pred_var = var_list[pred_var_index]
            return pred_var, bound_var
        else:  # if they are both register, we can use the following heuristics: which operand was involved in a mathematical operation earlier, or eax was moved into following a call, or the register is eax and there was a preceeding call, then thats the pred. TODO when i find motivation for it
            # pick random
            return var_list[0], var_list[1]

    @staticmethod
    def loop_breakout(path):
        state_addr = path.current_state.addr
        # check if the rep instruction
        if "rep" in str(path.project.factory.block(state_addr).capstone.insns[0].mnemonic):
            size = path.project.factory.block(
                state_addr).capstone.insns[0].insn.size
            new_addr = state_addr + size
            old_addr = state_addr
            #path.current_state.regs.ip = new_addr
            path.current_state.registers.store(
                "ip", new_addr, disable_actions=True, inspect=False)
            l.info("loop breakout happened from %#x to %#x", state_addr, new_addr)
            return False  # means do not end path, since loop breakout worked
        # Else
        # Look for previous basic block in the history and know where to break out to. if breakout did not happen, move to next previous bb
        # last 3 previous basic blocks. Normally it should not go more that 2 times
        for i in xrange(1, 4):
            # index -1, -2, -3,
            last_bb_addr = path.current_state.history.bbl_addrs.hardcopy[0-i]
            last_instr = path.project.factory.block(
                last_bb_addr).capstone.insns[-1]

            size = last_instr.insn.size
            addr = last_instr.insn.address
            old_addr = state_addr
            new_addr = addr + size
            if new_addr == old_addr:  # breakout did not happen, go next previous bb
                continue
            path.current_state.registers.store(
                "ip", new_addr, disable_actions=True, inspect=False)
            l.info("loop breakout happened from %#x to %#x", state_addr, new_addr)
            return False

        # if execution gets here, it means breakout did not happen, which I don't expect this to happen
        l.warn("path %d loop DID NOT breakout @ %#x",
               path.path_id, path.current_state.addr)
        return "loop"

        # return an ordered list of ancestral paths

    def get_ancestors(self, path, orig_path, ancestor_list):
        if path.path_id != orig_path.path_id:
            ancestor_list.append(path)
        if path.path_id == 0:
            return ancestor_list
        else:
            return self.get_ancestors(path.parent_path, orig_path,  ancestor_list)
