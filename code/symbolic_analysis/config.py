#!/usr/bin/env python


class Config():
    """
    A config object holds information about the user-specified configuration of the summarization, and other information about the binary under investigation such as the registers
    """

    def __init__(self, debug, force_branch, max_paths, max_steps, loop_analyses_only):
        self.debug = debug
        self.force_branch = force_branch
        self.max_paths = max_paths
        self.max_steps = max_steps
        self.loop_analyses_only = loop_analyses_only
