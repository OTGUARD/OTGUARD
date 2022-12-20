#!/usr/bin/env python
# This orchestrates running the SCADA program, taking snapshots of the SCADA program, and then exploring the snaphsots. 
# NOTE: This code was sanitized to remove identification information and proprietary information. As a result may not successfully run as is. 

import subprocess, sys, os, time, copy, gc, datetime, socket, threading

otguard = ida_link = False #otguard is the ida GUI, ida_link is for the commandline IDA
stack_frame_no = myscada = ""

import idc
otguard = True
stack_frame_no = idc.ARGV[1]
myscada = idc.ARGV[2]
remote_vm_ip = sys.argv[3]
myscada_repo = sys.argv[4]

import angr, claripy, IPython, graphviz, matplotlib.pyplot


def sort_dumps():
    #sort the dumps by addresses, so we can load them in order
    print "Sorting", myscada, " dumps ...."
    file_dict = {}
    addr_set = set()
    for dump_file in os.listdir(local_dumps_folder):
        file_path = os.path.abspath(os.path.join(local_dumps_folder, dump_file))
        if os.path.isfile(file_path) and os.path.getsize(file_path) > 0 and ".dmp" in dump_file:
            start_addr = long(dump_file.split("-")[1], 16)
            file_dict[start_addr] = {}
            file_dict[start_addr]["path"] = file_path
            file_dict[start_addr]["size"] = os.path.getsize(file_path)
            file_dict[start_addr]["perm"] = dump_file.split("-")[4]
            addr_set.add(start_addr)
    addr_set = sorted(addr_set)
    return addr_set, file_dict

def angr_load_blobs(addr_set, file_dict):
    print "loading into angr ......"
    my_force_load_libs = []
    my_lib_opts = {}
    my_extra_info = {}
    seg_id = 0
    if BUI_arch == "64":
        arch = "amd64"
    elif BUI_arch == "32":
        arch = "x86"
    else:
        print "ERROR: Unknow Specified Architecture"

    for start_addr in addr_set:
        seg_id += 1
        file_path = file_dict[start_addr]['path']
        permission = file_dict[start_addr]["perm"]
        size = file_dict[start_addr]["size"]

        if "EXECUTE" in permission:
            x_segs.append({'start':start_addr, 'end':start_addr + size})

        my_force_load_libs.append(file_path)
        my_lib_opts[file_path] = {'backend': 'blob', 'custom_arch': arch, 'custom_base_addr': start_addr}
        my_extra_info[start_addr] = {'perm': permission, 'size': size, 'id' : seg_id}


    p = angr.Project(path_to_empty_file, main_opts={'backend':'blob', 'custom_arch':arch, 'custom_base_addr':0x0}, force_load_libs=my_force_load_libs, lib_opts=my_lib_opts )
    return p


check_arch = subprocess.check_output("file " + path_to_myscada, shell=True)
if "x86-64" in check_arch:
    print myscada + " is 64 bits"
    BUI_arch = "64"
    regs_map = {"ax":"rax", "bx":"rbx","cx":"rcx", "dx":"rdx", "si":"rsi","di":"rdi","sp":"rsp","ip":"rip","bp":"rbp","r":["r8","r9","r10","r11","r12","r13","r14","r15"]}

    #subprocess.call("cp " + path_to_myscada + " " + myscada_x64_folder + "/"+myscada, shell=True)
elif "80386" in check_arch:
    regs_map = {"ax":"eax", "bx":"ebx","cx":"ecx", "dx":"edx", "si":"esi","di":"edi","sp":"esp","ip":"eip","bp":"ebp","r":[]}
    print myscada + " is 32 bits"
    BUI_arch = "32"

    subprocess.call("mv " + path_to_myscada + " " + myscada_x86_folder + "/"+myscada, shell=True)
    print "Aborting 32 bits for now..."
    subprocess.call("touch " + vm_ready_pool + "/" + remote_vm_ip, shell=True) #release the vm
    sys.exit(1)

else:
    print check_arch
    print "**WARNING** Cannot determine ARCH of myscada", myscada, " Aborting ..."
    subprocess.call("mv " + path_to_myscada + " " + myscada_unknown_arch + "/"+myscada, shell=True)
    subprocess.call("touch " + vm_ready_pool + "/" + remote_vm_ip, shell=True) #release the vm
    sys.exit(1)


folder = myscada_ran_folder + "/" + BUI_arch
subprocess.call("mkdir -p "+folder +">/dev/null 2>&1",shell=True)

#if results exist, then don't run, because we already have results for that myscada
if os.path.isdir(results_folder):
    print myscada, "already has results. Aborting.."
    subprocess.call("mv " + path_to_myscada + " " + myscada_ran_folder + "/" + BUI_arch, shell=True)
    subprocess.call("touch " + vm_ready_pool + "/" + remote_vm_ip, shell=True) #release the vm
    sys.exit(0)



class mythread(threading.Thread):
    def __init__(self, var, thread_id):
        threading.Thread.__init__(self)
        self.var = var
        self.thread_id = thread_id
    def run(self):
        global thread_crashed
        if self.var == "run":
            remote_run_myscada()
            print "remote_run_myscada. DONE"
        elif self.var == "capture":
            #capture in 2 secs. Remember since we first check if the process is running before capturing, then the actual time of capture after execution should be more than 2 seconds
            remote_attempt_capture(2)
            #lets update an indicator that the myscada did not HIJACK the VM used
            global POSSIBLE_myscada_VM_HIJACK
            POSSIBLE_myscada_VM_HIJACK = False
            print "remote_attempt_capture(). DONE"
        elif self.var == "static_analysis":
            do_static_analysis()
            print "Static Analysis. DONE"
        elif self.var == "forensic_analysis":
            do_forensic_analysis()
            print "Forensic Analysis. DONE"
        else:
            print " INVALID ARGUMENT", self.var, "SHOULD NEVER HAPPEN PLEASEN CHECK"
            #subprocess.call("mv " + path_to_myscada + " " + myscada_crashed_folder + "/"+myscada, shell=True)
            otguard_exit(1)

        thread_crashed[self.thread_id] = False # let main thread know you did not crash



def remote_deliver_myscada():
    print "Delivering ", myscada, "to remote machine to execute ..."
    run_status = subprocess.call('scp   ' +path_to_myscada + " "+ remote_vm+":~ > /dev/null", shell=True)
    if str(run_status) != '0':
        print "[ERROR] subprocess call to deliver binary to remote machine had a problem, aborting .."
        otguard_exit(1)
    #make myscada binary executable
    subprocess.call('ssh '  + remote_vm +  ' " chmod ugo+x ' +myscada +'" ', shell=True)
    #shutdown network interface
    command_to_run = 'netsh interface set interface "Local Area Connection" admin=disable'
    print remote_command(command_to_run)

def remote_run_myscada():
    print "Executing ", myscada, "on remote machine to execute ..."

    run_status = ""
    if "crackme" in myscada: # for my test binary. if it does not get exactly one argument, it does not run
        run_status = subprocess.call('ssh '  + remote_vm +  ' " ./'+myscada + ' ARG1  " ', shell=True)
        if str(run_status) != '0':
            print "Deployed myscada execution", myscada, "had a problem"
    else:
        try:
            run_status = subprocess.check_output('ssh '  + remote_vm +  ' " ./'+myscada + ' ARG1 ARG2 ARG3 ARG4 AGR5 AGR6 > /dev/null "', shell=True)
        except Exception, e:
            print "An exception occurred during the execution of ", myscada, "on ", remote_vm, str(e)
        print "Deployed myscada execution finished: ", run_status

    #time.sleep(60)

def remote_attempt_capture(sleep_time):
    #time.sleep(1) #to ensure that the remote_run_myscada runs first. since we are uncertain how the threads will be scheduled


    #time.sleep(60)

    #check to see if the process is running first
    is_running = False
    for i in xrange(0,4): #lets wait for a maximum of 4 seconds
        if check_if_running(myscada.replace(".exe","")):
            is_running = True
            break
        print "not running after this one check"
        time.sleep(1)


    if is_running:
        print "Capturing ", myscada, "on remote machine after ", sleep_time, "secs ..."
        command_to_run= "./dump.sh " + myscada + " " + str(sleep_time)
        print remote_command(command_to_run) # this will execute on the remote machine and returns without waiting on windbg to finish
    else: #set something that will be checked by the person who is gonna call was_captured(), so they dont waste their time
        print "check_if_running() reported that myscada did not run"
        global myscada_did_not_run
        myscada_did_not_run = True

def check_if_running(process_name):
    try:
        print "checking if", process_name, "is running ..."
        output = subprocess.check_output('ssh '+remote_vm +' " echo get-process -name '+ process_name + ' | powershell -c -"', shell=True)
        #lets confirm, although if the process does not exist it will return error, which will make the subprocess call crash, leading to an exception
        print output
        if "Cannot find a process with the name" not in output:
            return True
    except Exception, e:
        pass
    return False

def was_captured(my_bool):
    #this function just check if a .dmp exists on the remote machine for the myscada under consideration
    if not my_bool:# I put my_bool incase I am reverting snapshot to an initial state, and I am  checking if dump already exist.
        #if this was the initial check in main, of course I know there is no dump, so just return False
        return False

    #lets check if the myscada was actually captured. check for dump output file
    command_to_run = "ls /cygdrive/c/Users/anonymous/Documents/from_windbg/"+myscada
    response = remote_command(command_to_run)


    if myscada + ".dmp" in response:
        return True
    else:
        print "Attempt to capture the process using Windbg had an exception which means that Windbg did not see the process. It is possible that the myscada has injected itself into another process, and has just exited since for program to get to this stage, we earlier detected that it was running"
        return False

def remote_command(command_to_run):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_para = (remote_vm_ip, 22222)
    s.connect(server_para)
    #command_to_run= "./dump.sh " + myscada + " " + str(sleep_time)
    s.send(command_to_run)
    response = s.recv(8192)
    s.close()
    return response

def remote_run_windbg():
    #make a remote call to run windbg script in the windows vm
    print "Remotely executing  windbg and associated scripts ..."

    if BUI_arch == "64":
        writer = "command_writer.ps1"
    elif BUI_arch == "32":
        writer = "command_writer_x86.ps1"
    else:
        print "ERROR: Unknown or Unspecified Architecture for BUI"
    run_status = subprocess.call('ssh '  + remote_vm +  ' " echo ./process_core.ps1 -myscada '+myscada+' -writer ' + writer + ' | powershell -file -"', shell=True)
    if str(run_status) != '0':
        print "[ERROR] subprocess call to run process_core had a problem, aborting .."
        otguard_exit(1)
    #time.sleep(1)

def remote_retrieve_output():
    #make a remote call to retrieve the output of windbg script run in the windows vm
    #remove my local store before
    if len(os.listdir(local_dumps_folder)) > 0:
        run_status = subprocess.call('rm ' + local_dumps_folder + "/*", shell=True)
        if str(run_status) != '0':
            print "[ERROR] subprocess call to remove local files  had a problem, aborting .."
            otguard_exit(1)

    print "Remotely retrieving output files ..."
    run_status = subprocess.call('scp -r  ' + remote_vm+':'+path_to_remote_dumps + " " +  workspace_folder + " > /dev/null", shell=True)
    if str(run_status) != '0':
        print "[ERROR] subprocess call to retrieve output had a problem, aborting .."
        otguard_exit(1)



def check_if_multi_threaded():

    threads = subprocess.check_output("grep '\<Id.*Teb\>:' " + local_dumps_folder + "/windbg.log", shell=True)
    num_threads = len(threads.splitlines())
    print "threads :", num_threads
    if num_threads > 2:
        print threads
        return True
    elif num_threads == 2 and "Id:" in threads:
        print "myscada", myscada, "is single threaded, yay !"
        return False
    else:
        print "We could not determine how many threads it has\n", threads
        return True

def initial_process_windbg_log():
    #retrieve register values from windbg.log
    regs_dict = {}
    print "\n ===== Processing the windbg output log====="
    print "\n==== REGISTERS ===="
    if BUI_arch == "64":
        regs = subprocess.check_output("grep '\<r.x\>=\|\<r.p\>=\|\<r.i\>=\|\<r[0-9][0-9]*\>=\|\<[cdefgs]s\>=\|\<[oditszapc]f\>=\|efl=\|iopl=' " + local_dumps_folder + "/windbg.log", shell=True)
    else:
        regs = subprocess.check_output("grep '\<e.x\>=\|\<e.p\>=\|\<e.i\>=\|\<[cdefgs]s\>=\|\<[oditszapc]f\>=\|efl=\|iopl=' " + local_dumps_folder + "/windbg.log", shell=True)

    print regs

    print "\n==== BACK TRACE ===="
    call_trace = subprocess.check_output("grep -i -A 50 '\<child.*retaddr\>' " + local_dumps_folder + "/windbg.log", shell=True)


    regs_array = regs.splitlines()
    for entry in regs_array:
        part = entry.split("=")
        regs_dict[part[0]] = part[1]
    return regs_dict

def analyze_loaded_symbols():
    global symbols_dict
    print "\n === Analyzing loaded modules and symbols =="
    sym = subprocess.check_output("grep ! " + local_dumps_folder + "/windbg.log", shell=True)
    sym_list = sym.splitlines()
    for entry in sym_list:
        addr = entry.split()[0]
        try: #to make sure the line is valid
            long_addr = long("0x" + addr.replace("`",""),16)
        except ValueError:
            continue
        symbol = entry.split()[1]
        symbols_dict[hex(long_addr)] = symbol

def structure_backtrace():
    global program_end_addrs
    backtrace = {}
    backtrace_lines = ""
    call_stack = subprocess.check_output("grep -i -A 50 '\<child.*retaddr\>' " + local_dumps_folder + "/windbg.log", shell=True)
    lines = call_stack.splitlines()
    last_frame = ""
    BUI_frame = "" #frame where BUI/myscada was last seen. To be used to calculate the call_trace_END_len (should be around 2 or 3 mostly)
    global BUI_bt_addrs, BUI_bt_addrs_frame_no #we will keep a track of the BUI ret addresses in the backtrace. The first one and last one in the list are more important

    #since the backtrace fields in windbg is different in 32 vs 64 bit. 32 shows EPB, 64 shows RSP
    if BUI_arch == "64":
        pointer_used = "sp"
    elif BUI_arch == "32":
        pointer_used = "bp"
    else:
        print "**ERROR** Cannot determine the BUI architecture. This is a problem"

    for frame_line in lines: #for each of the backtrace lines
        try: #to make sure the line is valid
            first_token = frame_line.split()[0]
            int(first_token,16) #make sure its makable into an int
            if len(first_token.strip()) != 2: #make sure the frame no is 2 digit as it always is unless windbg changed how they output stuff
                continue
        except ValueError:
            continue
        entries = frame_line.split()
        backtrace[hex(int(entries[0], 16))] = {'frame_no': hex(int(entries[0], 16)), pointer_used: hex(long("0x" + entries[1].replace("`",""),16)), 'ret_addr': hex(long("0x" + entries[2].replace("`",""),16)), 'call_site': entries[3]}
        #also remember that the ret addr and the pointer is used later in the symbolic exploration to check the correctness of the backtrace transition
        #lets get the BUI addr information, and then use in during the IDA loading to get the BUI segment start/end addr
        #print "callsite", entries[3:]
        if myscada.replace(".exe","") in str(entries[3:]):
            global BUI_bt_ret_addr, BUI_addr_prefix, bt_after_BUI_lib_func
            #lets record the libcall just on top of BUI in the backtrace
            if bt_after_BUI_lib_func == "":
                bt_after_BUI_lib_func = backtrace[hex(last_frame)]['call_site'].replace(":","")

            BUI_bt_ret_addr = backtrace[hex(last_frame)]['ret_addr'] #eventually, this will store the first BUI function that was called after START or wmain
            BUI_bt_addrs.append(BUI_bt_ret_addr)
            BUI_bt_addrs_frame_no[BUI_bt_ret_addr] = hex(int(entries[0],16))
            BUI_frame = int(entries[0],16)
        backtrace_lines += frame_line + "\n"
        last_frame = int(entries[0],16)
    #lets make sure BUI parameters was set, otherwise it means that the myscada did not show up in the backtrace
    if BUI_frame == "":
        global thread_reported_problem, thread_message
        thread_reported_problem = True
        thread_message += "\n***ERROR** It appears that BUI " + myscada + " did not appear in backtrace. Please investigate\n\n" + backtrace_lines + "\n\noriginal\n" + call_stack
        print thread_message
        otguard_exit(1)

    global call_trace_END_len #to be used to determine what len of the call_trace signifies the END
    call_trace_END_len = last_frame - BUI_frame
    #now lets generate the list of addresses that anytime execution IP finds itself here,  we know it  signifies the END
    for x in xrange(0,call_trace_END_len + 1):
        program_end_addrs.append(backtrace[hex(last_frame - x)]['ret_addr'])
    #program_end_addrs  = [backtrace[hex(last_frame)]['ret_addr'], backtrace[hex(last_frame-1)]['ret_addr'],backtrace[hex(last_frame -2)]['ret_addr']]
    return backtrace, backtrace_lines

#This function is not really implemented well to do what was originally planned
def determine_stack_frame_of_interest(do_it, given_value):
    if do_it == False:
        return given_value
    call_stack = subprocess.check_output("grep -i -A 1000 '\<child.*retaddr\>' " + local_dumps_folder + "/windbg.log", shell=True)
    frames = call_stack.splitlines()
    is_external = False
    frame_no = '0' #the default, the last function to be called in the backtrace
    for frame_line in frames: #for each of the backtrace lines
        try: #to make sure the line is valid
            int(frame_line.split()[0],16)
        except ValueError:
            continue
        for modules in known_external_libs:
            if modules in frame_line:
                is_external = True
                break
        if is_external:
            is_external = False
            continue
        frame_no = frame_line.split()[0]
        break
    return frame_no

def remote_windbg_run_frame_registers(frame_number):
    #make a remote call to run windbg script in the windows vm
    print "Remotely executing  windbg to get the frame registers of interest ..."


    run_status = subprocess.call('ssh '  + remote_vm +  ' " echo ./get_frame_registers.ps1 -frame_no ' +frame_number+ ' -myscada ' +myscada +' -arch '+BUI_arch + ' | powershell -file - " ', shell=True)
    if str(run_status) != '0':
        print "[ERROR] subprocess call to run process_core had a problem, aborting .."
        otguard_exit(1)
    #time.sleep(3)
    #make a remote call to retrieve the output of windbg script run in the windows vm
    print "Remotely retrieving output files for", myscada, "..."
    run_status = subprocess.call('scp  ' + remote_vm + ':'+path_to_remote_dumps+'/frame_registers-'+frame_number+"-"+myscada+'.log ' + local_dumps_folder + "/", shell=True)
    if str(run_status) != '0':
        print "[ERROR] subprocess call to retrieve output had a problem, aborting .."
        otguard_exit(1)

def process_frame_register_log(frame_no):
    print "\n ==== FRAME", frame_no, "REGISTERS ===="
    if BUI_arch == "64":
        #regs = subprocess.check_output("grep '\<r.x\>=\|\<r.p\>=\|\<.*r[0-9].*r[0-9][0-9]\>=\|iopl=\|efl=' " + local_dumps_folder + "/frame_registers-"+str(frame_no)+".log", shell=True)
        regs = subprocess.check_output("grep '\<r.x\>=\|\<r.i\>=\|\<r.p\>=\|\<.*r[0-9].*r[0-9][0-9]\>=\|iopl=\|efl=' " + local_dumps_folder + "/frame_registers-"+str(frame_no)+".log", shell=True)
        #reg_pos specifies what line and field to extract the non-volatile registers
        reg_pos = {'rbx': [0,1], 'rsi': [1,1], 'rdi': [1, 2], 'rip': [2, 0], 'rsp': [2, 1], 'rbp': [2, 2], 'r12': [4, 1], 'r13': [4, 2], 'r14': [5, 0], 'r15': [5, 1], 'fs':[7,4], 'gs':[7, 5]}
    elif BUI_arch == "32":
        regs = subprocess.check_output("grep '\<e.x\>=\|\<e.i\>=\|\<e.p\>=\|iopl=\|efl=' " + local_dumps_folder + "/frame_registers-"+str(frame_no)+".log", shell=True)
        reg_pos = {'ebx': [0,1], 'esi': [0,4], 'edi': [0, 5], 'eip': [1, 0], 'esp': [1, 1], 'ebp': [1, 2], 'fs':[2,4], 'gs':[2, 5]}
    else:
        print "**ERROR** Cannot determine the BUI architecture is 32 or 64 bit. This is a problem"
    print regs
    lines = regs.splitlines()
    #extracting all the Non volatile registers. And i know what line and field to extract each one based on the format windbg outputs them
    #global regs_dict
    regs_dict = {}
    for reg in reg_pos:
        line_index = reg_pos[reg][0]
        line_entry = reg_pos[reg][1]
        if reg not in lines[line_index]:
            print "ERROR: It looks like Windbg has changed the format they output the registers, so your register initialization will be wrong"
            return
        entry = lines[line_index].split()[line_entry]
        regs_dict[reg] = entry.split("=")[1]
    return regs_dict
def populate_registers_flags(state, regs_dict, only_non_volatile=bool):
    #the non volatile ones first
    for reg, val in regs_dict.iteritems(): #so angr only can set gs only, I think
        if reg[1] == "f" or reg in ["efl", "iopl", "cs", "ds", "ss", "es"]: #if its a flag or other unused registers
            continue
        setattr(state.regs, reg, long("0x" + val, 16))
    if only_non_volatile:
        return state

    eflags_index = {'cf': 1, 'pf': 2, 'af': 4, 'zf': 6, 'sf': 7, 'of': 11}
    for eflag in eflags_index:
        if regs_dict[eflag] == "1":
            state.regs.eflags = state.regs.eflags | (eflags_index[eflag] << 0)
        elif regs_dict[eflag] ==  "0":
            state.regs.eflags = state.regs.eflags & ~(eflags_index[eflag] << 0)
        else:
            print "[ERROR]", regs_dict[eflag], "does not have a proper value from Windbg, please check"
    #IF, TF, and DF are not emulated by ANGR or valgrind

    return state


def track_mem_write(state):
    steping[step_track['count']]['all_mem_write'] += 1
    if not state.inspect.mem_write_expr.concrete:
        steping[step_track['count']]['sym_mem_write'] += 1

def track_mem_read(state):
    steping[step_track['count']]['all_mem_read'] += 1
    if not state.inspect.mem_read_expr.concrete:
        steping[step_track['count']]['sym_mem_read'] += 1

def do_nothing(state):
    pass

def show_block(addr):
    p.factory.block(addr).pp()

def check_NX(addr):
    #check if these addresses are in the executable space, if not ALERT and prune
    for mapping in x_segs:
        if addr >= mapping['start'] and addr <= mapping['end']:
            return True
    return False

def end_of_BUI(addr):
    for address in p.factory.block(addr).instruction_addrs:
        if address in program_end_addrs:
            return True
    return False


#get the function call type, then determine calling convention
#so for x64, Windows uses a calling convention: Microsoft x64 calling convention
#is this instruction present in this block
def is_ins_present(mnemonic, operand,  addr):#input_str should be
    for ins in p.factory.block(addr).capstone.insns:
        if mnemonic in str(ins.mnemonic) and operand in str(ins.op_str):
            return True

    print "FXN prologue not present in", hex(addr)
    return False

def update_trace_and_check_symbolic_loop(state, uid, path_id, BUI_restrict, parent_states):
    global step_track, addrs_to_prune

    #just on the side check. incase you have one of those state split due to symbolic IP or something other than unconditional jumps
    parent_uid = step_track['prev_states'][uid]['parent']
    if state.history.jumpkind in ["Ijk_Call", "Ijk_Ret"] and len(parent_states[parent_uid]['children']) > 1:
        steping[step]['ps'] += len(parent_states[parent_uid]['children']) - 1
    #i.e, we were supposed to see it if we knew that IP was symbolic or other stuff like that
    
    steps = step_track['count']
    call_trace = step_track['prev_states'][uid]['call_trace']
    current_func_addr = ""
    for key in call_trace[-1]: #the last dictionary is the current info for the current function
        current_func_addr = key
    # call_trace = [{'addr':{'block_count:0'}}, {}, {}]
    if state.history.jumpkind in ["Ijk_Boring", "Ijk_Yield"]:
        call_trace[-1][current_func_addr]['block_count'] += 1
    elif state.history.jumpkind == "Ijk_Call":
        #track BUI functions called
        if  hex(state.addr)[0:BUI_prefix_len] in BUI_addr_prefix:
            global BUI_reached_funcs
            BUI_reached_funcs.add(hex(state.addr))


        #attemp to identify the function with flirt. This takes a long time
        if flirt_enabled:
            global BUI_reached
            if  hex(state.addr)[0:BUI_prefix_len]  in BUI_addr_prefix or BUI_reached:# Im saying, ones BUI has been reached, starting doing IDA flirt
                flirt(state.addr)
                #just to see if I can identify printf in crackme code
                BUI_reached = True #when we see that BUI_addr_prefix, BUI has been reached, and eventhough the code wanders off in lib code, we know BUI has been reached
                BUI_restrict = False


        #check if we just wanna stay within the BUI code, only if loop is not present, just to be safe

        if BUI_restrict and ida_get_cc(state.addr)[0] != "fastcall"  and (BUI_arch == "64" or is_ins_present("push", regs_map['bp'], state.addr)): # Normal function have "push ebp" in the first block. If it does not have it then do not skip beacause it may be doing things to stack
            #don't enter if you are a fastcall since fastcalls are inline
            #don't enter if you don't have the fxn prologue, but if you are x64 enter

            #see if a library call
            if  hex(state.addr)[0:BUI_prefix_len] not in BUI_addr_prefix:
                #lets determine if the caller is in BUI or not_BUI
                if hex(state.callstack.top.ret_addr)[0:BUI_prefix_len]  in BUI_addr_prefix:
                    BUI_caller = True
                else:
                    BUI_caller = False

                #note the function being called in the exploration graph
                address = hex(state.addr)
                sym = symbols_dict[address]
                #edit_graph_label(uid=uid, to_append="\n"+sym)
                paths_info['lib_calls'][path_id].append(sym)
                global lib_calls_seen
                #lib_calls_seen[hex(state.addr)] = sym
                lib_calls_seen[hex(state.addr)] = {}
                lib_calls_seen[hex(state.addr)]['name'] = sym

                #lets just store/print the cc for fun. Surroung with try/catch incase we do not have a ONE to one mapping, i.e dump_to_exe
                try:
                    if BUI_caller:
                        calling_c = "BUI_caller" # wil be replaced if everything goes well
                        called_from_addr_dump = p.factory.block(state.history.bbl_addrs[-1]).capstone.insns[-1].insn.address
                        called_from_addr = dump_to_exe(called_from_addr_dump)
                        for ref in ida2.link.idautils.XrefsFrom(called_from_addr):
                            func = ida2.link.idaapi.get_func(ref.to)
                            if not bool(func): #i know or think that in ida static things, the pointer to the lib call is in the plt, and will not be identified as a function
                                calling_c += str(ida2.link.idc.GetType(ref.to)) + ":" + str(ida2.link.idc.GuessType(ref.to))

                        lib_calls_seen[hex(state.addr)]['ida_cc'] = calling_c
                        if "std" in calling_c:
                            print "ida reported a std calling convention at static:", hex(called_from_addr), "dump:", hex(called_from_addr_dump)
                    else:
                        lib_calls_seen[hex(state.addr)]['ida_cc'] = "not_BUI_caller"
                #end
                except Exception, e:
                    print "Good one !. I caught an exception that could have happed because we dont have a ONE to ONE mapping", str(e)

                if "exit" in sym:
                    if BUI_caller: #if not BUI_caller, then we cannot really do the further processing below. I guess we can just exit but no, we want it to continue
                        print "we saw an exit @path", path_id, " @steps", steps
                        #get the exact caller addr
                        called_from_addr = p.factory.block(state.history.bbl_addrs[-1]).capstone.insns[-1].insn.address
                        for lib_plt_addr in BUI_exe_lib_funcs:
                            if hex(dump_to_exe(called_from_addr)) in BUI_exe_lib_funcs[lib_plt_addr]['call_sites']:
                                print "we found the caller address in the call_site, so perhaps this works: @path", path_id, "@steps", steps, " dump_to_exe", hex(dump_to_exe(called_from_addr))
                                if "exit" in BUI_exe_lib_funcs[lib_plt_addr]['name']:
                                    print "we now confirmed that the libs name is exit plt_addr:", lib_plt_addr, " lib_name:",  BUI_exe_lib_funcs[lib_plt_addr]['name']

                                    #print "* ALERT * path", path_id," has reached end via EXIT <", sym,">. size of call_trace:", len(call_trace), "@steps", steps
                                    #return False, "EXIT"
                    else:
                        print "we saw an exit, but it was not by a BUI_caller @path", path_id, "@steps", steps, "BUI_reached", BUI_reached
 
                #lets make sure this BUI_restrict thing is not causing looping due to us giving the possible return register i.e rax several values
                block_count = call_trace[-1][current_func_addr]['block_count']
                history = state.history.bbl_addrs.hardcopy
                #loop_count = history[len(history)-block_count:len(history)].count(state.addr)
                loop_count = history[len(history)-block_count:len(history)].count(state.callstack.top.ret_addr) # state.callstack.top.ret_addr is the addr we are about to return it to
                if loop_count > 1: #prune only when the loop has occurred twice
                    #print "possible looping count-", loop_count, "- due to the BUI_restrict thing @path", path_id, "@steps", steps

                    ax_val = getattr(state.regs, regs_map['ax'])
                    print " to be pruned. rax: ", state.se.eval_upto(ax_val, 10), "@path", path_id, "@", state.addr, "@step", steps, "loop_count:", loop_count
                    return True, "loop possibly caused by BUI_restrict"
                if loop_count == 1:
                    ax_val = getattr(state.regs, regs_map['ax'])
                    print "first loop seen", state.se.eval_upto(ax_val, 10), "@path", path_id, "@", hex(state.addr), "@step", steps, "loop_count:", loop_count

                ret_addr = state.callstack.top.ret_addr #this is ok since when the call was made, angr added stuff to the call stack top
                #print "**BUI restrict** @path",path_id, "@addr",hex(state.addr), "@steps", steps, "return to", hex(ret_addr)

                #we have to pop the return address of the stack, since it was put there by the caller.
                #We might also have to see if it is stdcall, and clean the pushed args, but now doing that now, so there could be errors
                ret_addr_another_way = state.se.eval(state.stack_pop())
                if ret_addr != ret_addr_another_way:
                    print "**FYI** the two ways of obtaining return address not same result", hex(ret_addr), hex(ret_addr_another_way)

                cc = args = size = ""
                if otguard: #make ida tell you the calling convenction
                    #dissassemble/analyze and comment that block first
                    do_ida_things(state.addr, state, step_track['prev_states'][uid]['bt_frame'], active_states, state.history.bbl_addrs.hardcopy[-1], step_track['prev_states'][uid]['parent_bt'], otguard=True, ida_link=False)
                    cc, args, size = ida_get_cc(state.addr)
                if ida_link: #make ida tell you the calling convenction
                    #dissassemble/analyze and comment that block first
                    do_ida_things(state.addr, state, step_track['prev_states'][uid]['bt_frame'], active_states, state.history.bbl_addrs.hardcopy[-1], step_track['prev_states'][uid]['parent_bt'], otguard=False, ida_link=True)
                    cc, args, size = ida_get_cc(state.addr)
                if otguard or ida_link:
                    if cc == "stdcall":
                        print "we encountered a",cc,", so need to pop the stack. #args", args, "adding", size, "to rsp after poping the return address"
                        if BUI_arch == "64":
                            state.regs.rsp = state.regs.rsp + size
                        else:
                            state.regs.esp = state.regs.esp + size

                    elif cc == "fastcall":
                        if BUI_arch == "64":
                            state.regs.rsp = state.regs.rsp + size
                        else:
                            state.regs.esp = state.regs.esp + size
                        if size > 0:
                            print "we encountered a",cc,", so need to pop the stack. #args", args, "adding", size, "to rsp after poping the return address"

                #point the IP to the return addr
                if BUI_arch == "64":
                    state.regs.rip = state.callstack.top.ret_addr
                else:
                    state.regs.eip = state.callstack.top.ret_addr

                #if True:
                if BUI_caller or (loop_count == 1 and not BUI_caller): 
                    reg_ax = regs_map['ax']

                    #rax_current_val = state.regs.rax
                    ax_old_val = getattr(state.regs,reg_ax)
                    #state.regs.rax = claripy.BVS("regs_rax",64)
                    setattr(state.regs,reg_ax, claripy.BVS("reg_ax",64))
                    ax_new_val = getattr(state.regs,reg_ax)

                    if BUI_arch == "64":
 
                        state.add_constraints(state.solver.Or(state.regs.rax == 0, state.regs.rax == 1, state.regs.rax == ax_old_val))
                    else:
                        state.add_constraints(state.solver.Or(state.regs.eax == 0, state.regs.eax == 1, state.regs.eax == ax_old_val))
                    #state.add_constraints(state.solver.Or(ax_new_val == 0, ax_new_val == 1, ax_new_val == ax_old_val))

                    ax_newest_val = getattr(state.regs,reg_ax)

                    state.solver.simplify()

                #since we will not be appending a new func to the call_trace
                call_trace[-1][current_func_addr]['block_count'] += 1


                #there should be no need to check for loops in this case, i hope, so just return
                return False, "new uid" #instruct caller function to make and continue things with new uid

            else:
                call_trace.append({hex(state.addr):{'block_count':1, 'ret_addr':hex(state.callstack.top.ret_addr)}})
                current_func_addr = hex(state.addr)
        else:
            call_trace.append({hex(state.addr):{'block_count':1, 'ret_addr':hex(state.callstack.top.ret_addr)}})
            current_func_addr = hex(state.addr)



    elif state.history.jumpkind == "Ijk_Ret":
        #print "path ", path_id, " poping..."
        #print "value of rax on return", state.regs.rax

        #check if we are returning at the right place. if not panic.
        if long(call_trace[-1][current_func_addr]['ret_addr'],16) != long(hex(state.addr),16):
            print "**PANIC** Return Addr Mismatch: from_bt:", call_trace[-1][current_func_addr]['ret_addr'], "retuned_here:", hex(state.addr), "path", path_id, "@step", steps

        call_trace.pop()
        if len(call_trace) <= call_trace_END_len:
            print "* ALERT * path", path_id," has reached end. size of call_trace:", len(call_trace), "@steps", steps
            return False, "END"
        for key in call_trace[-1]: #the last dictionary is the current info for the current function
            current_func_addr = key
        call_trace[-1][current_func_addr]['block_count'] += 1

        if step_track['prev_states'][uid]['min_bt_size_attained'] > len(call_trace):
            step_track['prev_states'][uid]['min_bt_size_attained'] = len(call_trace)

        #print "path ", path_id, "after popping", call_trace
    elif state.history.jumpkind == "Ijk_NoHook":# or state.history.jumpkind == "Ijk_Sys_syscall":
        return False, ""
    elif state.history.jumpkind == "Ijk_SigTRAP":
        return False, "" #This will be prunned off when the successor is stepped

    else:
        print "**FYI** JumpKind Encountered:", state.history.jumpkind, "by state ", state, "@path", path_id, "@step", steps


    block_count = call_trace[-1][current_func_addr]['block_count']
    history = state.history.bbl_addrs.hardcopy

    #ways to check for symbolic loops
    if state.addr in history[len(history)-block_count:len(history)]:#If I am looping within the same function

        cx = regs_map['cx']
        cx_reg = getattr(state.regs,cx)
        for ins in p.factory.block(state.addr).capstone.insns:
            #if 'rep' in ins.insn.mnemonic and len(state.se.eval_upto(state.regs.rcx,257))>256:
            if 'rep' in ins.insn.mnemonic and len(state.se.eval_upto(cx_reg,257))>256:
                return True, "rep, and",cx,"is symbolic"
            if 'dec' in ins.insn.mnemonic:
                if BUI_arch == "32":
                    #i think this is x86 specific stuff, not sure
                    if cx in str(ins.insn.op_str) and len(state.se.eval_upto(cx_reg,257))>256:
                        return True, "dec and", cx, "is symbolic on x86"
                else:
                    if 'r9' in str(ins.insn.op_str) and len(state.se.eval_upto(state.regs.r9,257))<256:
                        return True, "dec r9 and r9 is symbolic @ "+str(path_id)

    return False, ""

def initial_processing(state):
     global step_track, dot, addrs_to_prune
     successors_to_return = []
     uid, parent_uid = make_uid(state)

     steps = step_track['count']
     path_id = step_track['prev_states'][uid]['path_id']
     bt_frame = step_track['prev_states'][uid]['bt_frame']
     try:
         successors = p.factory.successors(state)
         leaves = successors.flat_successors

         #lets keep track of the branches not taken if any
         global BUI_branches_potentially_not_taken
         for s in successors.unsat_successors:
            if  hex(s.addr)[0:BUI_prefix_len] in BUI_addr_prefix: #make sure they are valid ones
                BUI_branches_potentially_not_taken.add(hex(s.addr))
         # == END of tracking == #

         if len(leaves) == 0:
            #maybe there are unconstrained sucessors. lets just FYI
            print "No flat successors for state", state, "@path", path_id, "@bt_frame", bt_frame, "@step", steps, "unconstrained states:", len(successors.unconstrained_successors), "unsat states:", len(successors.unsat_successors), "all:", len(successors.all_successors)
            p.factory.block(state.addr).pp()

            if hex(state.addr) not in addrs_to_prune:
                addrs_to_prune[hex(state.addr)] = {}
                addrs_to_prune[hex(state.addr)]['reason'] = "likely unconstrained successors"
                addrs_to_prune[hex(state.addr)]['count'] = 1
            else:
                addrs_to_prune[hex(state.addr)]['count'] += 1

            #lets also mark that state as pruned
            to_append = "No_Succ" + hex(state.addr) + "\n@step " +str(steps)
            do_prune_things(state, uid, to_append, path_id, "No_Succ")


         successors_to_return.extend(leaves)
     except Exception, e:
        #to avoid one error I encountered: angr.engines.vex.statements.dirty | Unsupported dirty helper amd64g_dirtyhelper_XSAVE_COMPONENT_0
        print "**WARNING** Exception in stepping state:",state, "@ path", path_id, "@step", steps,"Error:", str(e)
        p.factory.block(state.addr).pp()
        if hex(state.addr) not in addrs_to_prune:
            addrs_to_prune[hex(state.addr)] = {}
            addrs_to_prune[hex(state.addr)]['reason'] = str(e)
            addrs_to_prune[hex(state.addr)]['count'] = 1
        else:
            addrs_to_prune[hex(state.addr)]['count'] += 1

        #lets also mark that state as pruned
        to_append = "Exception" + hex(state.addr) + "\n@step " +str(steps)
        do_prune_things(state, uid, to_append, path_id, "Exception")

        return []



     step_track['prev_states'][uid]['graph_label']['child_list'] = []
     for child in leaves:
        step_track['prev_states'][uid]['graph_label']['child_list'].append(child.addr)

     if len(leaves) > 2: #if you have more than 2 children, it means the rip which was symbolic resulted in > 2 possibles addresses. I don't like that
        print "**FYI** state:",state, "@ path", path_id, "@step", steps,"has", len(leaves), "children"

     return successors_to_return

def do_prune_things(state,uid,to_append,path_id,reason):
    edit_graph_label(uid=uid, to_append=to_append, key='prune')
    paths_info['lib_calls'][path_id].append(" *"+reason+" PRUNED*")

def make_uid(state):
    build_uid = ""
    for bb in state.history.bbl_addrs.hardcopy:
        build_uid += str(bb)
    parent_uid = hash(build_uid)
    uid = hash(build_uid+str(state.addr))
    return uid, parent_uid


def initialize_state_properties(state, parent_states, stop_at_split, show_split, verbose_r):
            global step_track
            addr = state.addr
            to_return = False
            to_display = ""
            uid, parent_uid = make_uid(state)
            #print uid
            if uid in step_track['prev_states']:
                print "**NOT GOOD**, state uid is not unique and may be overwriting other states"
                print "this state", step_track['prev_states'][uid]['state'], "has same uid as this state", state

            step_track['prev_states'][uid] = {}
            step_track['prev_states'][uid]['parent'] = parent_uid
            step_track['prev_states'][uid]['addr'] = addr
            step_track['prev_states'][uid]['state'] = state
            #populate your call_trace with your parents
            step_track['prev_states'][uid]['call_trace'] = copy.deepcopy(parent_states[parent_uid]['call_trace'])
            frame_no = parent_states[parent_uid]['bt_frame']
            step_track['prev_states'][uid]["bt_frame"] = frame_no
            step_track['prev_states'][uid]['min_bt_size_attained'] = parent_states[parent_uid]['min_bt_size_attained']
            step_track['prev_states'][uid]["children"] = [] # we don't know its children yet
            path_id = parent_states[parent_uid]['path_id']
            step_track['prev_states'][uid]['path_id'] = path_id# inherit your parents path id
            parent_addr = state.history.bbl_addrs.hardcopy[-1]
            parent_path_id = path_id
            parent_bt = parent_states[parent_uid]['bt_frame']
            step_track['prev_states'][uid]["parent_bt"] = parent_bt
            parent_states[parent_uid]['children'].append(uid)


            if len(parent_states[parent_uid]['children']) > 1: # a branch is gonna happen. particularly important  to assigning next path_id
                step_track['max_path_id'] += 1
                path_id =  step_track['max_path_id']  #get the next path_id
                #path_inc +=  1
                step_track['prev_states'][uid]['path_id'] = path_id
                #inherit my parent paths_info
                paths_info['lib_calls'][path_id] = ["<path "+str(parent_path_id)+">"]
                #paths_info['lib_calls'][path_id].extend(paths_info['lib_calls'][parent_path_id])
                if not verbose_r:

                    to_display += "\n**NEW PATH**" +  hex(parent_addr)+" @frame "+parent_bt+" @path "+str(parent_path_id) +  "-->" + str([hex(step_track['prev_states'][u]['addr'])+" @path "+str(step_track['prev_states'][u]['path_id']) for u in parent_states[parent_uid]['children']])
                    to_display += "@ step "+str(step_track['count'])
                    if show_split:
                        to_display += str(state.se.constraints)
                        to_display += "\n== Parent ==\n"
                        to_display += str(p.factory.block(parent_addr).capstone)
                        count = 0
                        for u in parent_states[parent_uid]['children']:
                            #to_display += "\n== Child " + str(count) + " ==\n"
                            #to_display += str(p.factory.block(step_track['prev_states'][u]['addr']).capstone)
                            count += 1
                        #to_display += " * * *"
                    if stop_at_split:
                        to_return = True

            #graph stuff
            step_track['prev_states'][uid]['graph_label']={}
            graph_id = str(path_id) +"-"+ str(step_track['count'])
            #step_track['prev_states'][uid]['graph_label'] = copy.deepcopy(parent_states[parent_uid]['graph_label'])

            step_track['prev_states'][uid]['graph_label']['graph_id'] = graph_id


            #parent_graph_id need to be tracked incase you need to attach yourself to your parent, i.e when you are a split
            step_track['prev_states'][uid]['graph_label']['parent_graph_id'] = parent_states[parent_uid]['graph_label']['parent_graph_id']
            #parent_graph_label need to be tracked incase you want to edit this label, i.e when you are prunned
            step_track['prev_states'][uid]['graph_label']['label'] = parent_states[parent_uid]['graph_label']['label']
            if len(parent_states[parent_uid]['graph_label']['child_list']) > 1:
                #my parent said i have a sibling
                #attack myself to the graph

                #get the current function address
                cfa=""
                call_trace = len(step_track['prev_states'][uid]['call_trace'])
                for key in step_track['prev_states'][uid]['call_trace'][-1]:
                    cfa = key
                state.solver.simplify()
                label = graph_id + "\n"+hex(addr).replace("L","")+"\nf: "+cfa+"\ncall_stack: "+str(call_trace)+"\nframe:"+str(frame_no)[2:] + "\ncons:" + str(len(state.se.constraints))
                step_track['prev_states'][uid]['graph_label']['label'] = label
                attach_to_graph(uid)
                #since I am a split,I will be the parent for my next descendant that will come from a split
                step_track['prev_states'][uid]['graph_label']['parent_graph_id'] = graph_id


            return [path_id, parent_path_id, frame_no, parent_bt, addr, parent_addr, uid, parent_uid, to_display, to_return]
def check_backtrace_transition(frame_no, uid, path_id, parent_bt, addr, stop_at_backtrace_hit, verbose_r ):
            #check for backtrace stuff. We only update if it is a "progress" backtrace transition
            global step_track
            to_display = ""
            for num_frame in backtrace:
                ret_addr = long(backtrace[num_frame]['ret_addr'], 16)
                #if ret_addr in str(p.factory.block(long(addr, 16)).capstone):
                if ret_addr in p.factory.block(addr).instruction_addrs:
                    #lets make sure its the good transistion. from low to high, before we update it
                    if int(frame_no,16) < int(num_frame, 16)+1: #good
                        frame_no = hex(int(num_frame, 16)+1)
                        step_track['prev_states'][uid]["bt_frame"] = frame_no


                        #Correctness checking:
                        #lets make sure that this event is in line with the min_bt_size_attained property of the state
                        call_trace_len = len(step_track['prev_states'][uid]['call_trace'])
                        if len(backtrace) - int(frame_no,16) != call_trace_len:
                            print "**FYI** Logic Error: ", "bt transition occured, but frame_no =", frame_no, "and len(call_trace)=", call_trace_len, "path",path_id,"step", step_track['count'],"@", hex(addr)
                        #lets make sure it is also in line with the stack/base pointer of the frame, or did it return to previous previous callers
                        if BUI_arch == "64":
                            bt_sp = backtrace[frame_no]['sp'].replace("L","")
                            state_sp = str(step_track['prev_states'][uid]['state'].regs.rsp).split()[1].replace(">","")
                            if bt_sp != state_sp:
                                print "**FYI** Logic Error: ", "bt transition occured",parent_bt, "->",frame_no, "but state rsp =", state_sp, "and backtrace sp=", bt_sp, "path", path_id, "step", step_track['count'], "@", hex(addr)
                        else:
                            bt_bp = backtrace[frame_no]['bp'].replace("L","")
                            state_bp = str(step_track['prev_states'][uid]['state'].regs.ebp).split()[1].replace(">","")
                            if bt_bp != state_bp:
                                print "**FYI** Logic Error: ", "bt transition occured",parent_bt, "->",frame_no, "but state ebp =", state_bp, "and backtrace bp=", bt_bp, "path", path_id, "step", step_track['count'], "@", hex(addr)

                    if not verbose_r:
                        to_display +="\n** BACKTRACE HIT ** by state " + hex(addr) + "@path "+str(path_id)+" from frame "+ str(parent_bt) + " to: " + hex(int(num_frame,16)+1)
                       # print "Frame", hex(int(frame_no,16)+1),backtrace[hex(int(frame_no, 16) + 1)]
                    if stop_at_backtrace_hit:
                        return frame_no, True, to_display
            return frame_no, False, to_display


def check_stop_strings(stop_strings, state, path_id, stop_at_stop_strings):
            to_display= ""
            addr = state.addr
            to_return = False
            assembly = str(p.factory.block(addr).capstone)

            #check for some weird stuff I observed in net-traveller-myscada.exe
            if len(assembly) == 0:
                print "**FYI** NO BYTE @", hex(state.addr), " NOPPING.."
                nop_addr(state.addr, 1)
                return to_return, to_display


            for item in stop_strings:
                if item in assembly:
                    to_display +=  "\n** CUSTOM HIT ** ["+ item+ " ] by state "+hex(addr) + "@path "+str(path_id)
                    #p.factory.block(addr).pp()
                    if stop_at_stop_strings:
                        to_return = True
            if "syscall" in assembly:
                nop_syscalls(state)

            return to_return, to_display
def nop_addr(addr,size):
    global already_hooked_addrs
    if addr not in already_hooked_addrs:
        p.hook(addr, do_nothing, length=size)


def nop_syscalls(state):
    global p, syscalls, already_hooked_addrs
    addr = state.addr
    #NOP syscalls
    prev_ins = ""# to keep track of the instr b4 syscall, which is usually: mov eax <number>
    for ins in p.factory.block(addr).capstone.insns:
        if 'syscall' in ins.insn.mnemonic:
            #print "NOP-ing syscall.."
            if ins.insn.address not in already_hooked_addrs:
                p.hook(ins.insn.address, do_nothing, length=ins.insn.size)
                uid, parent_uid = make_uid(state)
                print "**FYI** syscall seen @", hex(ins.insn.address),  ", bt_frame", step_track['prev_states'][uid]['bt_frame'], ", prev instr:", prev_ins
                syscalls.append(hex(ins.insn.address)+":"+str(prev_ins)+":"+str(step_track['count']))
                already_hooked_addrs.append(ins.insn.address)
        else:
            prev_ins = hex(ins.insn.address)+":"+str(ins.insn.mnemonic)+" "+str(ins.insn.op_str)


def merge_states(rips, mode):
    total_merged = 0
    global active_states, step_track, merge_track
    steps = step_track['count']
    for rip in rips:
        if len(rips[rip]) == 1: #there were just one state with that rip
            continue
        #print "dict:", rips[rip]
        #print "lenght of ", rips[rip], "is ", len(rips[rip])
        #order of choosing which state you all states be merged to
        #bt_frame -> smaller_constraints -> smaller_call_trace -> arbitrary
        best_bt  = 0
        best_cons = best_ct = 99999999
        best_state = ""
        best_path = ""
        uid_list = copy.copy(rips[rip])
        for uid in rips[rip]:
            if len(uid_list) < 2: #checking because we may remove some elements below is not in active_states
                #this uid list will not be considered. There is another check after this loop
                continue

            #see if this uid points to a state that is actually in the active_states, because it could have been pruned before merge_state was called
            if step_track['prev_states'][uid]['state'] not in active_states:
                uid_list.remove(uid)
                if len(uid_list) == len(rips[rip]):
                    print "This is the error I am trying to avoid, please investigate in merge_states()"
                continue
                #check if it is less than 2 rips in rip, in which case nothing to be merged
                #if len(rips[rip]) < 2:
                 #   continue

            bt = int(step_track['prev_states'][uid]["bt_frame"],16)
            step_track['prev_states'][uid]["state"].solver.simplify()
            cons = len(step_track['prev_states'][uid]["state"].se.constraints)
            ct = len(step_track['prev_states'][uid]["call_trace"])
            if bt > best_bt:
                best_bt = bt
                best_cons = cons
                best_ct = ct
                #print "path", step_track['prev_states'][uid]['path_id'], "selected on bt"
                best_state = step_track['prev_states'][uid]['state']
                best_path = step_track['prev_states'][uid]['path_id']
            elif bt == best_bt and cons < best_cons:
                #print "path", step_track['prev_states'][uid]['path_id'], "selected on cons"
                best_bt = bt
                best_ct = ct
                best_cons = cons
                best_state = step_track['prev_states'][uid]['state']
                best_path = step_track['prev_states'][uid]['path_id']
            elif cons == best_cons and ct < best_ct:
                best_bt= bt
                best_cons = cons
                #print "path", step_track['prev_states'][uid]['path_id'], "selected on ct"
                best_ct = ct
                best_state = step_track['prev_states'][uid]['state']
                best_path = step_track['prev_states'][uid]['path_id']

            else:
                #features are same, so the first state in the list retains the best state
                pass

        if len(uid_list) < 2:
            print "**FYI** rip", rip, "no longer to be merged since some member(s) were already pruned"
            continue


        path_ids = []
        #merger_path = ""
        merger_path = str(best_path)
        merged_state = best_state
        best_state_uid = ""
        #print "best state has been selected", best_state
        #for uid in rips[rip]:#remove the other states from active states
        for uid in uid_list:#remove the other states from active states
            if step_track['prev_states'][uid]['state'] not in active_states:
                print "I don't see why this should happen, check later in merge_states()"
                continue
            state = step_track['prev_states'][uid]['state']
            path_id = step_track['prev_states'][uid]['path_id']
            path_ids.append(path_id)
            #print "path", path_id, "cons:", len(state.se.constraints), "bt:", step_track['prev_states'][uid]['bt_frame'], "ct:", len(step_track['prev_states'][uid]["call_trace"])
            #print path_ids
            if state != best_state:
                merged_state, merge_flag, is_merged = merged_state.merge(state)
                if not is_merged: #not sure why
                    print "***WARNING *** For some reason, states cannot be merged please investigate\n"
                    continue #don't remove the state from active_states
                to_append = "_m @"+str(steps)+"->"+merger_path
                edit_graph_label(uid=uid, to_append=to_append, key="merged")
            else:
                #merger_path = step_track['prev_states'][uid]['path_id']
                best_state_uid = uid
            if state in active_states:
                active_states.remove(state) #remove all states to be merged. the merged one will be appended in the end
            else:
                print "** WARNING Trying to remove a state from active_states, but the state is not there", state, "path", path_id, path_ids, "step", steps
        #print "Merged paths", path_ids, "into path", merger_path, "at Step", steps
        active_states.append(merged_state)
        merged_state_uid, parent_uid = make_uid(merged_state) #parent_uid not used here

        #let the merged state inherit all the best_state's properties. #most importantly its path ID, bt_frame, and call_trace
        if merged_state_uid in step_track['prev_states']:
            print "**WARNING  should never happen ** Merged State UID already exist, expect incorrect results"
        step_track['prev_states'][merged_state_uid] = {}

        #edit best_uid graph node, to indicate it is now a merger
        merged_state.solver.simplify()
        to_append = "_m @"+str(steps)+"\n"+str(path_ids)+"\ncons:"+str(len(merged_state.se.constraints))
        edit_graph_label(best_state_uid, to_append=to_append, key="merger")

        step_track['prev_states'][merged_state_uid] = step_track['prev_states'][best_state_uid]
        step_track['prev_states'].pop(best_state_uid)
        step_track['prev_states'][merged_state_uid]['state'] = merged_state
        step_no = steps
        if step_no in merge_track:
            merge_track[step_no][merger_path] = path_ids
        else:
            merge_track[step_no] = {}
            merge_track[step_no][merger_path] = path_ids
        total_merged += len(path_ids) -1 # -1 because we added a new merged state

    print "total states removed from merging", total_merged
    #print "length of active states", len(active_states)

def check_filter_by_bt(bt_frame_track):
    global active_states
        #for step in filter_by_bt:
         #   if step_track['count'] == step:
    temp = active_states
    active_states = []

    for uid in step_track['prev_states']:
        s = step_track['prev_states'][uid]['state']


        if s in temp:
        #trying to capture some error: if there are duplicate states in step_track['prev_states']
            if s in active_states: #this means it was appended before, which is weird
                print "**Duplicate Error**(during check_by_bt), temp_size", len(temp), "active_states_size", len(active_states), "prev_states_size", len(step_track['prev_states'])
                continue #no need to append twice

            frame_no = step_track['prev_states'][uid]['bt_frame']
            path_id = step_track['prev_states'][uid]['path_id']
            if int(frame_no,16) >= int(bt_frame_track, 16):
                active_states.append(s)
            else:
                #indicate their demise in the graph
                to_append = "bt_filter@" + str(step_track['count'])+"\n"+str(frame_no)[2:]+","+str(bt_frame_track)[2:]
                edit_graph_label(uid=uid,to_append=to_append, key="bt_filter")
    print "Guide by bt @ step", step_track['count'], "number of states changed from:", len(temp), "to",  len(active_states)



def step_and_show(times, stop_at_backtrace_hit=False, stop_at_split=False, show_split=False, stop_strings=[], stop_at_stop_strings=False, limit=10**4, BUI_restrict=False, filter_by_bt=[], state_merge=("soft",[]), enable_flirt=False, shake=[], verbose=False, verbose_r=False):
    start_time = int(round(time.time()))

    global step_track, active_states, min_bt_size_attained, bt_frame_track, addrs_to_prune, return_now, flirt_enabled, step_history
    step_history += ' '.join([str(times), str(BUI_restrict), str(filter_by_bt), str(state_merge), str(shake)]) + "\n"
    flirt_enabled = enable_flirt
    active_states = [state for state in active_states if state != ""] # clean it up, because I messed it up at after_stepping_ops() to make it indexable by path_id
    to_display=""
    #to track backtrace progress
    #bt_frame_track = stack_frame_no # this will be used to track what the current best bt frame is for all of the states
    for step_iteration in xrange(0, times):
        gc.collect()
        #let me stop when active state is more than some number during the iteration
        if len(active_states) > limit and step_iteration > 0:
            print "As requested, active_states is more than",limit," so returning control to you. Try doing a merge. step", step_track['count']
            break
        input_states = active_states
        active_states = []
        step_track['count'] += 1
        steps = step_track['count']

        #mem reads/writes is cumulative
        steping[steps] = {'cond_jmps':0, 'all_mem_write':steping[steps-1]['all_mem_write'], 'sym_mem_write':steping[steps-1]['sym_mem_write'], 'all_mem_read':steping[steps-1]['all_mem_read'], 'sym_mem_read':steping[steps-1]['sym_mem_read']}
        steping[steps]['BUI_reached_funcs'] = len(BUI_reached_funcs)

        for state in input_states:
            #if initial_processing(state): #includes getting info to help in tree construction and checking if rip is symbolic

            #STEP the states
            #before stepping lets add track when a symbolic write is made
            state.inspect.b('mem_write', when=angr.BP_AFTER, action=track_mem_write)
            state.inspect.b('mem_read', when=angr.BP_AFTER, action=track_mem_read)
            active_states.extend(initial_processing(state)) # steps the states and return sucessors

        #lets record ps and pe since at the point, we have the paths that will be stepped in the next round
        #steping[steps]['pe'] = len(step_track['prev_states']) # how many did we explore ? i.e the states that were input to initial_processing(), but also include those that were pruned/merged. all of which are in step_track['prevs_states']
        steping[steps]['pe'] = step_track['max_path_id'] + 1
        #ps is cumulative
        steping[steps]['ps'] = steping[steps - 1]['ps'] +  steping[steps -1]['cond_jmps'] #during analysis, steping[steps]['cond_jump'] is updated based on unconditional jumps encountered
        #the above is also being updated when we see that there was a split caused by something other than conditional jumps. like symbolic IP
        #because cond_jmps or ps is not tracking to see if other states have counted the basic blocks they are recording, this values may be more than what it really is


        parent_states = step_track['prev_states']
        #num_parents = len(parent_states)
        step_track['prev_states'] = {}
        #all_states = []
        #all_paths_ordered = {} # to store all paths ordered by path id
        states_to_prune = []
        rips = {}#to be used for merging.
        #use_these_states_only = []# to be used to only process the states that made progress: bactrace transitions
        #path_inc = 0
        to_return = False
        #for state in a:
        for state in active_states:
            #== INITIALIZE STATE PROPERTIES ==#
            [path_id, parent_path_id, frame_no, parent_bt, addr, parent_addr, uid, parent_uid, add_to_display, if_to_return] = initialize_state_properties(state, parent_states,stop_at_split, show_split, verbose_r)
            to_display += add_to_display
            to_return = to_return or if_to_return

            #track all explored blocks
            global BUI_explored_blocks
            BUI_explored_blocks.add(hex(state.addr))

            #check for unconditional jumps
            #p.factory.block(state.addr).pp()
            to_check = str(p.factory.block(state.addr).capstone)
            if "j"  in to_check and 'jmp' not in to_check:
                #global total_paths_seen
                #print "we seen it"
                steping[steps]['cond_jmps'] += 1
                #total_paths_seen += 1
            #== CHECK NX ==#
            if not check_NX(addr):
                print "**PRUNING** @path " + str(path_id) + " has address " + hex(addr) + " outside of executable space. Prunning @step", str(steps)
                states_to_prune.append(state)
                to_append = "NX: ip:" + hex(addr) + "\n@step " +str(steps)
                edit_graph_label(uid=uid, to_append=to_append, key='prune')
                paths_info['lib_calls'][path_id].append(" *NX PRUNED*")
                continue

            #== CALL TRACE and LOOP CHECK ==#
            result, msg  =  update_trace_and_check_symbolic_loop(state, uid, path_id,BUI_restrict, parent_states)
            if msg == "END":
                edit_graph_label(uid=uid,key="END")
                states_to_prune.append(state)
                #completed_paths.append(path_id)
                #don't do a continue so that we can do the check_backtrace_transition
                #continue
            elif msg == "new uid":
                new_uid, p_uid = make_uid(state)
                step_track['prev_states'][new_uid] = step_track['prev_states'][uid]
                step_track['prev_states'][new_uid]['addr'] = state.addr

                addr = state.addr  #use the new addr for the remainder of the loop
                step_track['prev_states'].pop(uid) #remove old uid from step_tract
                uid = new_uid# this func should now use the new 'uid' locally
            elif msg == "EXIT":
                edit_graph_label(uid=uid,key="EXIT")
                states_to_prune.append(state)

            if result:
                print "**PRUNING** path", path_id,  hex(state.addr), msg, "@ step", step_track['count'], "Prunning.."
                states_to_prune.append(state)
                #caller = state.history.bbl_addrs.hardcopy[-1]
                to_append = "SYMLOOP: ip:" + hex(addr) + "\n@step " +str(steps)
                edit_graph_label(uid=uid, to_append=to_append, key='prune')
                paths_info['lib_calls'][path_id].append(" *SYMLOOP PRUNED*")
                continue


            if verbose:
                print "\n=== PATH", path_id, "==="
                p.factory.block(addr).pp()


            #== CHECK/UPDATE FOR BACKTRACE TRANSITION ==#
            frame_no, if_to_return, add_to_display = check_backtrace_transition(frame_no, uid, path_id, parent_bt, addr, stop_at_backtrace_hit, verbose_r)
            to_return = to_return or if_to_return
            to_display += add_to_display
            #let each state indicate if they have a better bt transition
            if int(frame_no, 16) > int(bt_frame_track,16):
                print "**FYI** backtrace transition seen from", bt_frame_track, "to", frame_no, "@path", path_id, "@ step", step_track['count']
                bt_frame_track = frame_no

            #== DETERMINE STATES TO MERGE ==#
            if steps in state_merge[1]:
                mode = state_merge[0]
                if mode == "soft":
                    call_trace = step_track['prev_states'][uid]['call_trace']
                    cfa = ""
                    for key in call_trace[-1]:
                        cfa = key
                    key = "-".join([hex(addr),str(frame_no),str(len(call_trace)),cfa,str(state.regs.rsp)])
                    if key in rips:
                        rips[key].append(uid)
                    else:
                        rips[key] = []
                        rips[key].append(uid)
                elif mode == "mild":
                    call_trace = step_track['prev_states'][uid]['call_trace']
                    cfa = ""
                    for key in call_trace[-1]:
                        cfa = key
                    key = "-".join([hex(addr),str(frame_no),str(len(call_trace)),cfa])
                    if key in rips:
                        rips[key].append(uid)
                    else:
                        rips[key] = []
                        rips[key].append(uid)
                elif mode == "aggressive":
                    if hex(addr) in rips:
                        rips[hex(addr)].append(uid)
                    else:
                        rips[hex(addr)] = []
                        rips[hex(addr)].append(uid)
                else:
                    print "wrong mode for state_merger", state_merger[0]
                    state_merge[1] = []
            #== CHECK FOR STOP STRINGS, and NOP SYSCALLS ==#
            if_to_return, add_to_display = check_stop_strings(stop_strings, state, path_id, stop_at_stop_strings)
            to_return = to_return or if_to_return
            to_display += add_to_display


            #== END OF BUI CHECK==#
            if end_of_BUI(addr):
                to_return = True
                states_to_prune.append(state)
                print "* ALERT * path", path_id," has reached end. @steps", steps, "WEIRD place to happen though, becos the execution should progress via bt frames.  Unless the backtrace obtained from Windbg is incorrect"
                edit_graph_label(uid=uid,key="END")
                to_display += "** END OF BUI REACHED ** for path "+str(path_id)+ "@frame "+str(frame_no)
                continue

        if verbose:
            print "StepCount:", step_track['count'] , "(" + str(step_iteration+1) + ")"

        #== SHAKING BY BUI_restrict toggle ==#
        for num in shake:
            if steps%num == 0:
                BUI_restrict = not BUI_restrict
                break


        #=== PRUNNING ===#
        if len(states_to_prune) > 0:
             temp = len(active_states)
             #print "pruning", len(states_to_prune), "states"
             for this_state in states_to_prune:
                 active_states.remove(this_state)
             #print "active_states reduced by", temp - len(active_states)

        #=== MERGING ===#
        temp = len(active_states)
        if step_track['count'] in state_merge[1]:
            #print "attempting to merge", len(rips), "IPs"
            error =  merge_states(rips, state_merge[0]) #This will update active_states with the merged_state, and remove the states that were merged. Will also add to step_track['prev_states']
            if error:
                print "Investigate Error from state merging"
                break
            #print "active_states reduced by", temp - len(active_states)

        #=== GUIDE BY BT ===#
        temp = len(active_states)
        if step_track['count'] in filter_by_bt:
            check_filter_by_bt(bt_frame_track)

        if len(active_states) == 0: #no need to continue. no states to step
            break

        if to_return:
            break

    #AFTER the STEPPING times loop finishes
    #print "\n"+to_display
    active_states_count = after_stepping_ops(filter_by_bt, bt_frame_track)
    if active_states_count == 0:
        print "No more active states. I guess this is the END"
        subprocess.call("mkdir -p "+results_folder +">/dev/null 2>&1",shell=True)
        time_elapsed = int(round(time.time())) - start_time
        print "elapsed time: ", time_elapsed, "s"

        #get the total paths merged
        total_merged = 0
        for step_no in merge_track:
            total_merged += len(merge_track[step_no]) - 1 #because one path continued, i.e the merger path
        #get the list of library calls for each path
        path_calls = "\n*Post-capture Capabilities"
        for path in paths_info['lib_calls']:
            path_calls += "\n\n path " + str(path) + " " + str(paths_info['lib_calls'][path])

        #prepare to present the exploration graph
        #graph_filename = "/home/anonymous/otguard/"+myscada+str(datetime.datetime.now().strftime("-%d-%H-%M-%S"))+".gv"
        graph_filename = results_folder + "/"+myscada+".gv"
        add_to_label = "\n\n BUI_paths_not_explored: " + str(BUI_paths_not_explored_post_snapshot) + "\n\n ONE-TO-ONE Mapping Achieved: " + str(ONE_TO_ONE_MAPING_WORKED) + "\n\n Exploration Time: "+str(time_elapsed)+" s\npaths_seen: " + str(steping[step_track['count']]['ps']) + ", paths_explored: " + str(steping[step_track['count']]['pe']) + ", reached_end: " + str(len(completed_paths)) +", pruned: " + str(len(pruned_paths)) +  ", merged: "+ str(total_merged) + ", longest_path: "+ str(step_track['count'])
        dot.attr(label=dot_label + add_to_label, fontsize="20", labelloc="t")
        dot.render(graph_filename)
        dot.format = 'png' #also save in png
        dot.render(graph_filename)
        #subprocess.call("firefox " +graph_filename + ".pdf &", shell=True)

        #lets get the pre-capture calls from the backtrace
        pre_capture_calls = ""
        for i in xrange(0,len(backtrace)):
            pre_capture_calls +=  str(backtrace[hex(i)]['frame_no']) + ": "+  str(backtrace[hex(i)]['ret_addr']).replace("L","") + " "+ str(backtrace[hex(i)]['call_site']) + "\n"

        #prepare the pre-capture capabilities string to display
       

    if otguard:
        idc.Jump([state for state in active_states if state != ""][-1].addr)
    if ida_link:
        ida.link.idc.Jump([state for state in active_states if state != ""][-1].addr)

    print "elapsed time: ", int(round(time.time())) - start_time, "s"
    return True #true means that there are still active states

def write_to_file(my_str, filename):
    with open(filename, "w") as f:
            f.write(my_str)

def after_stepping_ops(filter_by_bt, bt_frame_track):
    filter_by_bt = False
   #lets generate an ordered state info to print, and also order the actives states by path_id
    global active_states
     #we also order active_states by path_id, just so i can be indexable by path_id
    temp = active_states
    ordered_paths = [""]*(step_track['max_path_id'] + 1)
    active_states = [""]*(step_track['max_path_id'] + 1)

    bt_present = {}

    for uid in step_track['prev_states']:
        s = step_track['prev_states'][uid]['state']
        if s in temp:
            if s in active_states:
                print "**Duplicate Error**(during after_stepping_ops), temp_size", len(temp), "active_states_size", len(active_states), "prev_states_size", len(step_track['prev_states'])
                continue
            frame_no = step_track['prev_states'][uid]['bt_frame']
            path_id = step_track['prev_states'][uid]['path_id']
            #lets know how many states are in which bt_frame
            if frame_no in bt_present:
                bt_present[frame_no] += 1
            else:
                bt_present[frame_no] = 1

            if filter_by_bt:
                if int(frame_no,16) >= int(bt_frame_track, 16):
                    active_states[int(path_id)] = s
                    ordered_paths[int(path_id)] = hex(s.addr) + "@path "+str(path_id)+" @frame "+str(frame_no)
            else:
                active_states[int(path_id)] = s
                ordered_paths[int(path_id)] = hex(s.addr) + "@path "+str(path_id)+" @frame "+str(frame_no)
    active_states_count = len([s for s in active_states if s != "" ])
    if filter_by_bt:
        print "No of paths b4 filter_by_bt:", len(temp)
    #print "\n #Paths:", active_states_count, "@bt_frame", bt_frame_track,"@step", step_track['count']
    print "\n #Paths:", active_states_count, "@bt_frames", bt_present,"completed:", completed_paths,"pruned:", pruned_paths,"@step", step_track['count']

    return active_states_count

def start_timer():
    global temp_start_time
    temp_start_time = int(round(time.time()))

def end_timer():
    return int(round(time.time())) - temp_start_time

def do_forensic_analysis():
    # ==== FORENSIC LOADING AND EXTRACTION ===#
    print "Forensic Loading and Extraction ..."
    global regs_dict, p, init_state, backtrace, backtrace_lines, stack_frame_no, min_bt_size_attained, bt_frame_track, ida
    #== REMOTE OP===#
    if not os.path.isfile(local_dumps_folder + "/windbg.log"): #check if dumps have already being extracted
        #open the win7 vm network interface. if dumps already exist then you did not shut it down in the first place
        command_to_run = 'netsh interface set interface "Local Area Connection" admin=enable'
        print remote_command(command_to_run)
        command_to_run = 'netsh interface ip set dns  "Local Area Connection" static 8.8.8.8'
        print remote_command(command_to_run)
        command_to_run = 'netsh interface ip set dns  "Local Area Connection 2" static 8.8.8.8'
        print remote_command(command_to_run)
        remote_run_windbg()
        remote_retrieve_output()
    else:
        print local_dumps_folder + "/windbg.log already exists"
    #====+++++======#
    addr_set, file_dict =  sort_dumps()
    regs_dict = initial_process_windbg_log()
    analyze_loaded_symbols()
    backtrace, backtrace_lines = structure_backtrace()

    if otguard:
        ida_load_segments(addr_set, file_dict, otguard=True, ida_link=False, ida=None)
    if ida_link:
        ida = idalink(path_to_empty_file, path_to_ida_executable)
        ida_load_segments(addr_set, file_dict, otguard=False,ida_link=True, ida=ida)

    p = angr_load_blobs(addr_set, file_dict)
    init_state = p.factory.blank_state()

    if len(stack_frame_no) > 0: #if I have initialized it to something via command line arguments
        pass
    else:
        stack_frame_no = determine_stack_frame_of_interest(False, "0") #False means just return what value I passed to it
    print "\nFrame of Interest:", stack_frame_no
    if int(stack_frame_no, 16) != 0:
        #== REMOTE OP ==#
        remote_windbg_run_frame_registers(stack_frame_no)
        #====+++++++====#
        regs_dict = {}
        regs_dict = process_frame_register_log(stack_frame_no)
        init_state =  populate_registers_flags(init_state, regs_dict, only_non_volatile=True)
    else:
        init_state =  populate_registers_flags(init_state, regs_dict, only_non_volatile=False)

    #based on size of backtrace and stack_frame_no, initalize reamining backtrace stack size
    min_bt_size_attained = len(backtrace) - int(stack_frame_no, 16)
    bt_frame_track = stack_frame_no #bt_frame_track is used to track the global current best bt as the states are stepping
    ## == END OF FORENSIC LOADING AND STUFF ====#


def remote_deliver_run_capture():
    #deliver myscada, execute, and attempt to capture
    remote_deliver_myscada()
    global thread_crashed
    thread_crashed["thread1"] = True # on completion, thread should set this to False
    t = mythread("run", "thread1")
    t.setDaemon(True) #this enables the thread to die when my program exits
    t.start()
    #remote_run_myscada()
    thread_crashed["thread2"] = True # on completion, thread should set this to False
    t2 = mythread("capture","thread2")
    t2.setDaemon(True) #this enables the thread to die when my program exits
    t2.start()



    time.sleep(10) #allowing Windbg time to inject itself and capture the process, before I check to see if a .dmp file is created. Also since the next step is to check 
    for my_thread in threading.enumerate():# this only enumerate thread that are still alive. still running the run() method
        if my_thread is not threading.current_thread():
            if my_thread.var == "run":
                #before we exit, lets give is a chance and poll of 50 seconds
                max_poll_time = 50 # secs.
                total_poll_time = 0
                poll_interval = 5 # secs
                while True:
                    if not my_thread.is_alive(): #to be set by remote_attempt_capture() after it completes
                        break


    for my_thread in threading.enumerate():
        if my_thread is not threading.current_thread():
            my_thread.join()

    if any_thread_crashed():
        print "It appears one of the thread run_myscada or capture_myscada crashed"
        #lets copy that sample into the crashed folder
        subprocess.call("mv " + path_to_myscada + " " + myscada_crashed_folder +"/"+myscada, shell=True)
        #revert snapshot of vm for next myscada
        otguard_exit(0)

    #lets check if the myscada even ran
    if myscada_did_not_run:
        print "It appears myscada", myscada, "did not run. Aborting ..."
        #lets copy that sample into the myscada_not_ran folder
        subprocess.call("mv " + path_to_myscada + " " + myscada_not_ran_folder +"/"+myscada, shell=True)
        #revert snapshot of vm for next myscada
        otguard_exit(0)

    if not was_captured(True):
        time.sleep(2)
        if not was_captured(True):
            time.sleep(2)
            if not was_captured(True):
                print "Attempt to capture myscada", myscada, "had a problem. Aborting ..."
                #lets copy that sample into the myscada_not_ran folder
                subprocess.call("mv " + path_to_myscada + " " + myscada_not_ran_folder +"/"+myscada, shell=True)
                #revert snapshot of vm for next myscada
                otguard_exit(0)


def any_thread_crashed():
    for t in thread_crashed:
        if thread_crashed[t]:
            print "Thread", t, "did not set its thread_crashed to False, hence it crashed"
            return True
    return False


def main():
    print "calling main()"
    global path_to_myscada, myscada_repo
    if not os.path.isfile(local_dumps_folder + "/windbg.log"): #if a local extracted dumps does not exists
        if not was_captured(False) : #this will check if a .dmp has already being captured so no need to rerun the myscada. False means we know, so just say its not captured.
            remote_deliver_run_capture()
        else:
            print ".dmp for ",myscada," already exists in remote machine"
        if thread_reported_problem:
            print "it appears a thread reported a problem: ", thread_message
            print "Aborting .."
            subprocess.call("mv " + path_to_myscada + " " + myscada_crashed_folder + "/"+myscada, shell=True)
            #revert snapshot of vm for next myscada
            otguard_exit(1)
    print "About to start the forensic and static analysis modules"
    global ss, regs_dict, p, init_state, step_track, backtrace, backtrace_lines, active_states, stack_frame_no, min_bt_size_attained, bt_frame_track, ida, ida2, BUI_total_funcs


    #do the static analysis and forensic analysis in multi-threaded way
    global thread_crashed
    thread_crashed["thread1"] = True # on completion, thread should set this to False
    t = mythread("static_analysis", "thread1") #do_static_analysis()
    t.setDaemon(True) #this enables the thread to die when my program exits
    t.start()
    thread_crashed["thread2"] = True # on completion, thread should set this to False
    t2 = mythread("forensic_analysis", "thread2") #do_forensic_analysis()
    t2.setDaemon(True) #this enables the thread to die when my program exits
    t2.start()
    for my_thread in threading.enumerate():
        if my_thread is not threading.current_thread():
            my_thread.join()

    #release the vm for next myscada
    release_vm()

    if any_thread_crashed():
        print "It appears one of the thread crashed during the static and forensic analysis stage, Aborting..."
        subprocess.call("mv " + path_to_myscada + " " + myscada_crashed_folder + "/"+myscada, shell=True)
        #IPython.embed()
        otguard_exit(0)

    if thread_reported_problem:
        print "it appears a thread reported a problem  during the static and forensic analysis stage:", thread_message
        print "Aborting .."
        subprocess.call("mv " + path_to_myscada + " " + myscada_crashed_folder + "/"+myscada, shell=True)
        otguard_exit(1)

    #IF IT MAKES IT PAST THIS POINT, the myscada should give us results. Move the myscada to the appropriate location and change the global variables of this location
    if check_if_multi_threaded():
        print "It appears the myscada is not single threaded, but i will only process thread 0"
        subprocess.call("mv " + path_to_myscada + " " + myscada_multi_threaded_folder + "/"+myscada, shell=True)
        myscada_repo = myscada_multi_threaded_folder
        path_to_myscada = myscada_multi_threaded_folder + "/" + myscada
        #otguard_exit(1)

    #=== Automated Disassembly ===#
    if otguard:
        ss = [init_state] #the ss is only used for the automated disassembly functionality
        analyzed = []
        steps = 5
        just_disassemble(steps, ss, analyzed)
    #== End of Automated Disassembly ==#

    ip = long("0x" + regs_dict[regs_map['ip']],16)

    #initialize the stepping data structure that tracks things like conditional jmps in the about-to-be-stepped block
    to_check = str(p.factory.block(init_state.addr).capstone)
    if "j"  in to_check and 'jmp' not in to_check:
        steping[0]['cond_jmps'] += 1

    active_states = [init_state]
    step_track = {'count': 0, 'prev_states':{}, 'max_path_id':0}
    state_info = {'addr':init_state.addr,'bt_frame': "0x" + stack_frame_no, 'path_id':0, 'min_bt_size_attained': min_bt_size_attained ,'parent': None, 'children':[], 'call_trace':[]}
    uid = hash(str(init_state.addr))
    step_track['prev_states'][uid] = state_info
    path_id = 0
    paths_info['lib_calls'][path_id] = []

    global BUI_reached_funcs

    if ONE_TO_ONE_MAPING_WORKED:
        for ret_addr in BUI_bt_addrs:
            #f_addr = ida2.link.idaapi.get_func(long(ret_addr,16) + BUI_offset_dump_to_exe).startEA
            f_addr = ida2.link.idaapi.get_func(dump_to_exe(long(ret_addr,16))).startEA
            BUI_reached_funcs.add(hex(f_addr)) # we know we will return to this func

    #lets construct the call_trace
    call_trace =[]
    call_len = len(backtrace)
    frame_to_start = int(stack_frame_no,16)
    call_trace.append({hex(ip):{'block_count':1, 'ret_addr':backtrace[hex(int(stack_frame_no,16))]['ret_addr']}}) #for the first frame
    #print frame_to_start, call_len
    for frame_no in xrange(frame_to_start + 1, call_len):
        #print "frame ", frame_no, " addr: ", backtrace[hex(frame_no)]['ret_addr']
        func_ret_addr = backtrace[hex(frame_no)]['ret_addr']
        addr_inside_func = backtrace[hex(frame_no - 1)]['ret_addr']#The previous fxn's ret addr: since we cannot really know the address that called the function(from this context), but we can know just one of the addresses inside the fxn i.e where control will return inside the fxn
        call_trace.insert(0,{addr_inside_func:{'block_count':1, 'ret_addr':func_ret_addr}})

    step_track['prev_states'][uid]['call_trace'] = call_trace# call_trace is a list of dict
    #graph things
    graph_id = "0-0"
    cfa = "" #current func addr
    for key in call_trace[-1]:
        cfa = key.replace("L","")
    label = "IP:"+hex(ip).replace("L","")+"\nframe:"+stack_frame_no+"\nf: "+cfa+"\ncall_stack: "+str(len(call_trace))
    step_track['prev_states'][uid]['graph_label'] = {'graph_id':graph_id, 'parent_graph_id':graph_id, 'label':label,'cs':0,'syscalls':0,'child_list':[], 'legit_loops':0, 'sym_loops':0, 'frame-tran':'','steps':0,'addr':hex(ip)}
    label = graph_id +"\n"+ step_track['prev_states'][uid]['graph_label']['label']

    init_dot_graph()
    dot.node(graph_id, label, shape='Mdiamond')

    if not otguard:
        #open myscada_run.conf and see if a run configuration exist for the myscada under consideration
        config_exists = False
        for filename in os.listdir("/home/anonymous/otguard/otguard/run_configs"):
            if filename == myscada + ".run.conf":
                start_time = int(round(time.time()))
                print myscada, "-> exploring via auto run config"
                config_exists = True
                with open('/home/anonymous/otguard/otguard/run_configs/' + myscada+".run.conf", 'r') as m_file:
                    for line in m_file:
                        print line
                        filter_by_bt = shake = []
                        state_merge = ("",[])
                        fields = line.split()
                        step_times = fields[0].split(":")[1]
                        if len(fields[1].split(":")[1]) > 1:
                            filter_by_bt = []
                            filter_by_bt_strings = fields[1].split(":")[1].split(",") #comma separated numbers
                            #make the list all integers
                            for item in filter_by_bt_strings:
                                filter_by_bt.append(int(item))
                        if len(fields[2].split(':')[1]) > 1:#if there is something at the other side of :, it means there is an entry
                            state_merge_type = fields[2].split(":")[1].split("#")[0]
                            state_merge_list_strings= fields[2].split(":")[1].split("#")[1].split(",") #comma separated numbers
                            state_merge_list = []
                            #make the list all integers
                            for item in state_merge_list_strings:
                                state_merge_list.append(int(item))
                            state_merge = (state_merge_type, state_merge_list)
                        if len(fields[3].split(":")[1]) > 1:
                            shake = []
                            shake_strings = fields[3].split(":")[1].split(",")
                            for item in shake_strings:
                                shake.append(int(item))
                        BUI_restrict = bool(int(fields[4].split(":")[1]))

                        print "times=",int(step_times),", BUI_restrict=",BUI_restrict,", filter_by_bt=",filter_by_bt,", state_merge=",state_merge, ", shake=",shake
                        if not step_and_show(int(step_times), BUI_restrict=BUI_restrict, filter_by_bt=filter_by_bt, state_merge=state_merge, enable_flirt=False, shake=shake):
                            #if a True is returned, it indicates its the end
                            break
                print "elapsed time to run config: ", int(round(time.time())) - start_time, "s"
                break
        if not config_exists and True:
            print myscada, "has no auto run config, running the default run: step_and_show(1000, BUI_restrict=True, limit=100)"
            step_and_show(5000, BUI_restrict=True, limit=500)

    else:
        idc.batch(0) #this allows the IDA GUI to function normally if it has been loaded with the -A switch

if __name__ == "__main__":
    try:
        main()
    except Exception, e:
        print "Exception wrapped aroung main(): ", str(e)
    otguard_exit(0)