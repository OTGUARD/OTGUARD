
import ss
import IPython

#output = ss.summarize("/home/anonymous/proof-of-concept/variability-matching/example111_arm32", "ida", "/home/anonymous/ida-7.0/idat64", addr_list=[0x8788, 0x86d4, 0x8458])


def stager_detonator(output, verbose=False):
    global_vars = {}  # addr: {read:[], written:[], "ref":[]}
    for addr in output:
        if verbose:
            print "\nfunc", addr, hex(addr)
        for path in output[addr]["paths"]:
            for step in output[addr]["paths"][path]["step"]:
                if "global_read" in output[addr]["paths"][path]["step"][step]:
                    for global_var_addr in output[addr]["paths"][path]["step"][step]["global_read"]:
                        if global_var_addr not in global_vars:
                            global_vars[global_var_addr] = {
                                "read": [], "written": [], "ref": []}  # initialize
                        # avoid duplicate
                        if hex(addr) not in global_vars[global_var_addr]["read"]:
                            global_vars[global_var_addr]["read"].append(
                                hex(addr))
                            if verbose:
                                print "reads", global_var_addr

                if "global_written" in output[addr]["paths"][path]["step"][step]:
                    for global_var_addr in output[addr]["paths"][path]["step"][step]["global_written"]:
                        if global_var_addr not in global_vars:
                            global_vars[global_var_addr] = {
                                "read": [], "written": [], "ref": []}
                        if hex(addr) not in global_vars[global_var_addr]["written"]:
                            global_vars[global_var_addr]["written"].append(
                                hex(addr))
                            if verbose:
                                print "writes", global_var_addr
                if "global_ptr_ref" in output[addr]["paths"][path]["step"][step]:
                    for global_var_addr in output[addr]["paths"][path]["step"][step]["global_ptr_ref"]:
                        if global_var_addr not in global_vars:
                            global_vars[global_var_addr] = {
                                "read": [], "written": [], "ref": []}
                        if hex(addr) not in global_vars[global_var_addr]["ref"]:
                            global_vars[global_var_addr]["ref"].append(
                                hex(addr))
                            if verbose:
                                print "refs", global_var_addr

    print "== Stager-Detonator Relationship =="
    for var in global_vars:
        item = global_vars[var]
        for tuples in [("read", "written"), ("read", "ref"), ("written", "ref")]:
            if len(item[tuples[0]]) > 0 and len(item[tuples[1]]) > 0 and item[tuples[0]] != item[tuples[1]]:
                print var
                print item
                continue


def brief(output):
    print len(output), "functions"
    for func_addr in output:
        func = hexx(func_addr)
        num_paths = len(output[func_addr]["paths"])
        size = output[func_addr]["func_end"] - func_addr
        time_to_explore = output[func_addr]["exploration_time"]
        # lets get the dc of last step of each of the paths
        cumul_dc = 0
        for path in output[func_addr]["paths"]:
            last_step_index = len(output[func_addr]["paths"][path]["step"])
            last_step_dc = output[func_addr]["paths"][path]["step"][last_step_index]["dc"]
            cumul_dc += last_step_dc * 1.0
        avg_dc = round(cumul_dc / num_paths, 3)
        print func, "num_paths:", str(num_paths) + ", size:", str(
            size) + ", time_to_explore:", str(time_to_explore)+"s,", "avg_dc:", avg_dc


def symbolic_profiler(output):
    pass


def hexx(addr):
    return hex(addr).replace("L", "")


def calls(output, per_path=False, func=None, path=None):
    if func != None:
        if func not in output:
            print "function", func, "not in output"
            return
        else:
            if path != None:
                if path not in output[func]["paths"]:
                    print "path", path, "not in function", func
                    return
                else:
                    call_list = []
                    for step in output[func]["paths"][path]["step"]:
                        if "calls" not in output[func]["paths"][path]["step"][step]:
                            continue
                        the_call = output[func]["paths"][path]["step"][step]["calls"].replace(
                            ",", "").strip()
                        # there should be only one call in angr's basic block stepping
                        if the_call:
                            call_list.append(the_call)
                    print "function", func, "path", path
                    print "\tcalls:", call_list
            else:  # user supplied func, but not path
                if per_path:
                    for path in output[func]["paths"]:
                        call_list = []
                        for step in output[func]["paths"][path]["step"]:
                            if "calls" not in output[func]["paths"][path]["step"][step]:
                                continue
                            #the_call = output[func]["paths"][path]["step"][step]["calls"].replace(",","").strip()
                            # just to separate them into i_calls/e_calls incase we are capturing the actual func names
                            if "i_calls" not in output[func]["paths"][path]["step"][step]:
                                the_call = output[func]["paths"][path]["step"][step]["i_calls"].replace(
                                    ",", "").strip()
                            else:
                                the_call = output[func]["paths"][path]["step"][step]["e_calls"].replace(
                                    ",", "").strip()
                                # there should be only one call in angr's basic block stepping
                            if the_call:
                                call_list.append(the_call)
                        print "function", func, "path", path
                        print "\tcalls:", call_list
                else:
                    print "function", func
                    if "calls" in output[func]["inputs"]:
                        print "calls:", output[func]["inputs"]["calls"]
                    return
    else:  # user did not specify a func, so we output for all func, and for all paths
        for func in output:
            print "function", func
            if per_path:
                for path in output[func]["paths"]:
                    call_list = []
                    for step in output[func]["paths"][path]["step"]:
                        if "calls" not in output[func]["paths"][path]["step"][step]:
                            continue
                        # just to separate them incase we are capturing the actual func names
                        if "i_calls" not in output[func]["paths"][path]["step"][step]:
                            the_call = output[func]["paths"][path]["step"][step]["i_calls"].replace(
                                ",", "").strip()
                        else:
                            the_call = output[func]["paths"][path]["step"][step]["e_calls"].replace(
                                ",", "").strip()
                        # there should be only one call in angr's basic block stepping
                        if len(the_call) > 1:
                            call_list.append(the_call)
                    if len(call_list) > 0:
                        print "\tpath", path
                        print "\t\tcalls:", call_list
            else:
                if "calls" in output[func]["inputs"]:
                    print "\tcalls:", output[func]["inputs"]["calls"]


def path_informer(output, input_addr, path=None):
    found_func = False
    found_bb = False
    input_path = path
    for func_addr in output:
        if input_addr >= func_addr and input_addr <= output[func_addr]["func_end"]:
            found_func = True
            print hexx(input_addr), "found in function", hexx(func_addr)
            # then the supplied address lies in this function
            for path in output[func_addr]["paths"]:
                if bool(input_path) and path != input_path:
                    continue
                bbs = output[func_addr]["paths"][path]["bb_addrs"]
                total_steps = len(bbs)
                last_addr_in_path = output[func_addr]["paths"][path]["last_addr_in_path"]
                for i in xrange(0, total_steps):
                    found_bb = False
                    if i == total_steps - 1:
                        if input_addr >= bbs[i] and input_addr <= last_addr_in_path:
                            # input_addr is in this path
                            found_bb = i + 1  # the step/bb it was found
                            dc = round(output[func_addr]["paths"]
                                       [path]["step"][found_bb]["dc"], 2)
                            bb = hexx(bbs[i])
                            print "*in path", str(path) + ", basic block", bb, "step:", i + \
                                1, "dc:", dc, "total_steps:", total_steps
                            break
                    elif (input_addr >= bbs[i] and input_addr < bbs[i+1]):
                        # input_addr is in this path
                        found_bb = i + 1  # the step/bb it was found
                        dc = round(output[func_addr]["paths"]
                                   [path]["step"][found_bb]["dc"], 2)
                        bb = hexx(bbs[i])
                        print "*in path", str(path) + ", basic block", bb, "step:", i + \
                            1, "dc:", dc, "total_steps:", total_steps
                        break
                if found_bb:
                    print "\tdc-spectrum:\n\t\t",
                    # how many points along the path states to display their dc for
                    spectrum_len = min(total_steps, 10)
                    spectrum_spacing = total_steps * 1.0/spectrum_len
                    cumulative = 0
                    for i in xrange(1, spectrum_len + 1):
                        cumulative += spectrum_spacing
                        index = int(round(cumulative))
                        print "step", str(
                            index)+":", round(output[func_addr]["paths"][path]["step"][index]["dc"], 2),

                    print "\n\tevents-before", bb, "bb\n\t\t",
                    for i in xrange(1, found_bb):
                        for field in output[func_addr]["paths"][path]["step"][i]:
                            if field in ["calls", "split", "loop", "added_cons"] and bool(output[func_addr]["paths"][path]["step"][i][field]):
                                print "step" + \
                                    str(i)+"("+field + \
                                    ":", output[func_addr]["paths"][path]["step"][i][field]+")",

                    print "\n\tevents-at", bb, "bb\n\t\t",
                    for field in output[func_addr]["paths"][path]["step"][found_bb]:
                        if field in ["calls", "split", "loop", "added_cons"] and bool(output[func_addr]["paths"][path]["step"][found_bb][field]):
                            print "step" + \
                                str(found_bb)+"("+field + \
                                ":", output[func_addr]["paths"][path]["step"][found_bb][field]+")",

                    print "\n\tevents-after", bb, "bb\n\t\t",
                    for i in xrange(found_bb+1, total_steps + 1):
                        for field in output[func_addr]["paths"][path]["step"][i]:
                            if field in ["calls", "split", "loop", "added_cons"] and bool(output[func_addr]["paths"][path]["step"][i][field]):
                                print "step" + \
                                    str(i)+"("+field + \
                                    ":", output[func_addr]["paths"][path]["step"][i][field]+")",
                    print
