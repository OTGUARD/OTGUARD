import sys
import claripy
import logging
import cle
l = logging.getLogger(name="func_simulation")
l.setLevel(logging.DEBUG)


def pop_args_from_stack(path):
    """
    heuristic technique
    all pushes to the stack immediately following the call, signifies argument push
    so say you have the following instructions:
    add 1, push 1, add 2, push 2, push 3, mov [stack] 4, call foo(). Only push 2, and push 3 are tracked as arguments
    basically, I assume that the pushes will all be together. I could be wrong, but on the lookout for counterexamples
    """
    # i honestly need to know the calling convention to correctly do this. becos there are other cc like fastcall
    if path.project.arch.name == "AMD86" and isinstance(path.project.loader.main_object, cle.backend.pe.pe.PE):
        how_many_to_pop = 0

        # lets get the last last_push position. i.e the instruction number of the last stack push. i.e the call instr will push the return address to stack before the func call
        last_push_pos = 0
        for instr_pos in path.current_step.stack_tracker:
            if instr_pos > last_push_pos:
                last_push_pos = instr_pos
        start_tracking = False
        pos_list = range(1, last_push_pos + 1)
        pos_list.reverse()
        for i in pos_list:
            if i == last_push_pos:  # we already popped the return address before pop_args_from_stack()
                continue
            if i in path.current_step.stack_tracker:
                how_many_to_pop += 1
                if not start_tracking:
                    start_tracking = True
            else:
                if start_tracking:
                    break

        l.info("poping %d arguments from the stack", how_many_to_pop)
        for i in xrange(0, how_many_to_pop):
            path.current_state.stack_pop()


def handle_function_sym_call(path):
    """
    Handle function calls When the call target is symbolic
    """
    # pop arguments pushed to the stack
    pop_args_from_stack(path)
    # set IP and return register
    last_instr = path.project.factory.block(
        path.prev_state.addr).capstone.insns[-1]
    ret_addr = last_instr.insn.address + last_instr.insn.size
    set_ip_and_ret_reg(path, ret_addr)

    path.current_step.path_events.calls += "sym_call, "
    return "sym_call"


def handle_function_call(path):
    """
    Handle function calling. Adjust the stack as appropriate, make the return register symbolic, and return
    """
    old_addr = path.current_state.addr
    ret_addr = path.current_state.callstack.top.ret_addr

    # pop arguments pushed to the stack
    pop_args_from_stack(path)

    # set IP and return register
    set_ip_and_ret_reg(path, ret_addr)
    # Now we have a new state

    # record that we saw a call on the path
    path.current_step.path_events.calls += "%#x" % (old_addr) + ", "
    fxn_name = ""
    try:
        if isinstance(path.project.loader.main_object, cle.backends.pe.pe.PE):
            ext_call = path.project.loader.find_symbol(
                old_addr).name  # may cause AttributeError Exception
        else:
            # this only works if the binary is elf
            ext_call = path.project.loader.main_object.reverse_plt[old_addr]
        fxn_name = str(ext_call)
        path.current_step.path_events.events += "e_call, "
        path.current_step.path_events.e_calls += "%#x" % (old_addr) + ", "
        path.current_step.path_events.e_calls += fxn_name + ", "
    except (KeyError, AttributeError):
        # internal function
        fxn_name = "%#x" % (old_addr)
        path.current_step.path_events.events += "i_call, "
        path.current_step.path_events.i_calls += fxn_name + ", "
    return fxn_name


def set_ip_and_ret_reg(path, ret_addr):
    """
    During function call simulation, make the return register symbolic
    Policy1: #make rax symbolic, and constrain it to current value, 1, or 0
    Policy2: Just make rax completely symbolic
    """
    policy = "policy2"  # chose policy2 for now
    if path.project.arch.name == "AMD64":
        path.current_state.registers.store(
            "rip", ret_addr,  disable_actions=True, inspect=False)
        reg_rax = path.current_state.registers.load(
            "rax", disable_actions=True, inspect=False)
        path.current_state.registers.store("rax", claripy.BVS(
            "rax", 64), disable_actions=True, inspect=False)
        if policy == "policy1":
            path.current_state.add_constraints(path.current_state.solver.Or(path.current_state.registers.load("rax", disable_actions=True, inspect=False) == 0, path.current_state.registers.load(
                "rax", disable_actions=True, inpsect=True) == 1, path.current_state.registers.load("rax", disable_actions=True, inspect=True) == reg_rax))
        # state.solver.simplify()
    elif path.project.arch.name == "X86":
        path.current_state.registers.store(
            "eip", ret_addr,  disable_actions=True, inspect=False)
        reg_eax = path.current_state.registers.load(
            "eax", disable_actions=True, inspect=False)
        path.current_state.registers.store("eax", claripy.BVS(
            "eax", 32), disable_actions=True, inspect=False)
        if policy == "policy1":
            path.current_state.add_constraints(path.current_state.solver.Or(path.current_state.registers.load("eax", disable_actions=True, inspect=False) == 0, path.current_state.registers.load(
                "eax", disable_actions=True, inpsect=True) == 1, path.current_state.registers.load("eax", disable_actions=True, inspect=True) == reg_eax))
    elif path.project.arch.name == "ARMEL":
        path.current_state.registers.store(
            "ip", ret_addr,  disable_actions=True, inspect=False)
        reg_r0 = path.current_state.registers.load(
            "r0", disable_actions=True, inspect=False)
        path.current_state.registers.store("r0", claripy.BVS(
            "r0", 32), disable_actions=True, inspect=False)
        if policy == "policy1":
            path.current_state.add_constraints(path.current_state.solver.Or(path.current_state.registers.load("r0", disable_actions=True, inspect=False) == 0, path.current_state.registers.load(
                "r0", disable_actions=True, inpsect=True) == 1, path.current_state.registers.load("r0", disable_actions=True, inspect=True) == reg_r0))
    elif path.project.arch.name == "AARCH64":
        path.current_state.registers.store(
            "ip", ret_addr,  disable_actions=True, inspect=False)
        reg_r0 = path.current_state.registers.load(
            "x0", disable_actions=True, inspect=False)
        path.current_state.registers.store("x0", claripy.BVS(
            "x0", 64), disable_actions=True, inspect=False)
        if policy == "policy1":
            path.current_state.add_constraints(path.current_state.solver.Or(path.current_state.registers.load("x0", disable_actions=True, inspect=False) == 0, path.current_state.registers.load(
                "x0", disable_actions=True, inpsect=True) == 1, path.current_state.registers.load("x0", disable_actions=True, inspect=True) == reg_r0))
    else:
        l.error("unknown arch")
        raise NameError
