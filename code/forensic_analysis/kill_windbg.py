#!/usr/bin/env python
import subprocess, socket



#see if my process is running
output = "No output"
try:
    output = subprocess.check_output('ssh anonymous@192.168.56.101 "echo get-process -name windbg | powershell -c -"', shell=True)
    #normally, if windbg is not running, an exception always happens
    print "This is the output\n", output
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_para = ('192.168.56.101', 22222)
    s.connect(server_para)
    command_to_run= "echo ./kill_windbg.ps1 | powershell -file -"
    s.send(command_to_run)
    print "response: ", s.recv(8192)
    s.close()
except Exception, e:
    print "looks like windbg is not running\n", str(e)
    print "response:", output

raw_input("press enter to exit")






