#!/usr/bin/env python


class Events:
    """
    An Event object is a field of a Step object holds information that was gathered during when a state/basic block was stepped or executed
    """

    def __init__(self):
        self.added_cons = ""  # added constaints at a step
        self.calls = ""  # all calls
        self.i_calls = ""  # internal calls
        self.e_calls = ""  # external calls
        self.events = ""  # a string of events that happened at a step
        self.split = ""  # if that step caused a branching out  of new path
        # return values recovered if that last step contained a return instruction
        self.ret_values = ""
        self.cumul_ratio = 0.0  # the cumulative ratio of sym_ops to all_ops at that step
        self.dc = 0.0  # the degree of concreteness measure at that step
        self.loop = ""  # if a step is part of an identified loop
        self.forced = ""  # if a step was forced to happen i.e via force_branch
