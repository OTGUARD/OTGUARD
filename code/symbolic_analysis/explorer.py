import logging
import IPython
import angr
from path import Path
from step import Step


l = logging.getLogger(name="explorer")
l.setLevel(logging.DEBUG)

# This creates a per-function explorer object


class Explorer:
    """
    A class that manages the multi-path exploration. It steps each of the active paths at each breadth-first stepping

    :param func_boundary: tuple of start/end addresses for a function
    :param config: a config object that keeps information about the user-specified configuration for the exploration. e.g the max_paths and max_steps
    :param project: the angr Project object
    """

    def __init__(self, func_boundary, config, project):
        self.config = config
        self.project = project
        self.paths = []  # to hold all paths obj
        self.current_path = None
        self.input_paths = []
        self.active_paths = []
        self.func_start = func_boundary[0]
        self.func_end = func_boundary[1]
        self.current_step = 0

        self.breakpoint_dict = {}
        #self.output_dir = ""

    def set_func_base_and_stack(self, init_state):
        """
        Used to align the stack
        returns the initial state object
        """
        if init_state.arch.name == "AMD64":
            init_state.regs.rsp &= ~0xf
            init_state.regs.rsp -= 8
            init_state.regs.rbp = init_state.regs.rsp
            self.config.INIT_SP = init_state.se.eval_one(init_state.regs.rsp)
        elif init_state.arch.name == "X86":
            init_state.regs.esp &= ~0xf
            init_state.regs.esp -= 4
            init_state.regs.ebp = init_state.regs.esp
            self.config.INIT_SP = init_state.se.eval_one(init_state.regs.esp)
        elif init_state.arch.name == "ARMEL":
            init_state.regs.sp &= ~0xf
            init_state.regs.sp -= 4
            self.config.INIT_SP = init_state.se.eval_one(init_state.regs.sp)
        elif init_state.arch.name == "AARCH64":
            init_state.regs.sp &= ~0xf
            init_state.regs.sp -= 8
            self.config.INIT_SP = init_state.se.eval_one(init_state.regs.sp)
        else:
            l.error("unknown arch for input binary")
            raise NameError
        # Hardcoded assumptions - super-approximated to determine location bounds for STACK, ARGS, and unknown memory regions
        # 1. The stack will not grow more than 1000 x 8 bytes. i.e more than a 1000 things will not be pushed to a function's stack
        # 2. The number of arguments to a function will not be more than 100
        self.config.CUSTOM_SP_BOUND = self.config.INIT_SP - \
            (1000 * init_state.arch.bits *
             4)  # the stack will not grow more than this
        # arguments to the function will not be passed on the stack above this
        self.config.CUSTOM_ARG_BOUND = self.config.INIT_SP + \
            (100 * init_state.arch.bits * 4)
        # Idea: use ida to pre-determine/approx the size of a functions stack and number of arguments. Then use to set the above
        return init_state

    def set_breakpoints(self, init_path, b_list):
        """
        Set angr breakpoints, and action functions when breakpoints are triggered
        """

        if self.config.loop_analyses_only:
            return
        for breakpoint in b_list:
            if breakpoint == "constraints":
                bp = init_path.current_state.inspect.b(
                    breakpoint, when=angr.BP_AFTER, action=self.track_added_constraints)
            elif breakpoint == 'mem_read':
                bp = init_path.current_state.inspect.b(
                    breakpoint, when=angr.BP_BEFORE, action=self.track_mem_read)
            elif breakpoint == "mem_write":
                bp = init_path.current_state.inspect.b(
                    breakpoint, when=angr.BP_AFTER, action=self.track_mem_write)
            elif breakpoint == "reg_read":
                bp = init_path.current_state.inspect.b(
                    breakpoint, when=angr.BP_AFTER, action=self.track_reg_read)
            elif breakpoint == "reg_write":
                bp = init_path.current_state.inspect.b(
                    breakpoint, when=angr.BP_AFTER, action=self.track_reg_write)
            elif breakpoint == "address_concretization":
                pass
                #bp = state.inspect.b(breakpoint, when=angr.BP_AFTER, action=track_address_concretization)
            else:
                l.warn("unknown breakpoint set: %s ", breakpoint)
            self.breakpoint_dict[breakpoint] = bp

    def track_mem_read(self, state):
        """
        trigger function when a memory is read
        """
        self.current_path.mem_analyzer.mem_read_analyses(
            state, self.current_path.dc_tracker, self.current_path.current_step)

    def track_mem_write(self, state):
        """
        trigger function when a memory is written to
        """
        self.current_path.mem_analyzer.mem_write_analyses(
            state, self.current_path.dc_tracker, self.current_path.current_step)

    def track_reg_read(self, state):
        """
        trigger function when a register is read
        """
        self.current_path.reg_analyzer.reg_read_analyses(
            state, self.current_path.path_func_arg_track, self.current_path.dc_tracker, self.current_path.current_step)

    def track_reg_write(self, state):
        """
        trigger function when a register is written to
        """
        self.current_path.reg_analyzer.reg_write_analyses(
            state, self.current_path.path_func_arg_track, self.current_path.dc_tracker, self.current_path.current_step, self.current_path.current_state)

    def track_added_constraints(self, state):
        """
        trigger function when constraint is added to a path
        """
        # note that everal instructions in a block can trigger a breakpoint
        if self.current_path.prev_step.step_id not in self.current_path.TEMP_VAR:
            self.current_path.TEMP_VAR[self.current_path.prev_step.step_id] = {
            }
            self.current_path.TEMP_VAR[self.current_path.prev_step.step_id]["added_cons"] = [
            ]

        # i put an if statement below, becos I observed that ater a breakpoint is triggered and processed, execution starts at the breakpoint address again, which may trigger the breakpoint one more last time, so I just avoided the redundancy by using the if statement
        cons_to_add = ""
        cons = state.inspect.added_constraints
        for c in cons:
            # <Bool True ..> is used in angr constraints, but is not very useful to me, so I have to exclude it
            if "Bool True" in str(c):
                continue
            cons_to_add += str(c) + "###"

        if cons_to_add and cons_to_add not in self.current_path.TEMP_VAR[self.current_path.prev_step.step_id]["added_cons"]:
            self.current_path.TEMP_VAR[self.current_path.prev_step.step_id]["events"] = "cons_added"
            self.current_path.TEMP_VAR[self.current_path.prev_step.step_id]["added_cons"].append(
                cons_to_add)

    def initialize_path(self, state):
        """
        creating the first path object, path 0
        returns a path object
        """
        path_id = 0
        step_created = Step(0)
        parent_path = None  # will be updated at the constructor if path 0
        init_path = Path(path_id, state, step_created, parent_path)
        init_path.init_path_zero(
            self.config, self.func_start, self.func_end, self.project, self)

        self.paths.append(init_path)
        self.input_paths.append(init_path)
        return init_path

    def start_exploration(self):
        """
        steps each of the active paths until completion or max_paths or max_step is exceeded
        returns an explorer object
        """
        l.info("Processing func %#x ..", self.func_start)
        exploration_end_reason = "max steps " + \
            str(self.config.max_steps) + " exceeded"
        for _ in xrange(self.config.max_steps):
            if len(self.input_paths) < 1:
                l.info("No more paths to step")
                break
            if len(self.input_paths) >= self.config.max_paths:
                l.info("Max path limit of %d exceeded. #paths: %d",
                       self.config.max_paths, len(self.input_paths))
                exploration_end_reason = "max paths " + \
                    str(self.config.max_paths) + "  exceeded"
                break
            self.current_step += 1
            l.info("STEP * %d * steping %d paths",
                   self.current_step, len(self.input_paths))
            for path_entry in self.input_paths:
                path_entry.add_step()

            for path_entry in self.input_paths:
                self.current_path = path_entry
                successor_paths = path_entry.step_path()
                self.active_paths.extend(successor_paths)

            self.input_paths = self.active_paths
            self.active_paths = []

        # when max_paths or max_steps in exceed, wrap up
        for path_entry in self.paths:
            if not path_entry.reached_end:
                path_entry.termination.record_end(
                    path_entry, "Not yet Ended " + exploration_end_reason)
        return self
