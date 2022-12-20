#!/usr/bin/python

import socket, sys, subprocess, threading

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#server_para = ("192.168.56.101",22222)
server_para = ("0.0.0.0",22222)
print 'starting up on %s port %s' % server_para
server.bind(server_para)
server.listen(500000)

while True:
    try:
        connection, client_address = server.accept()
        print "connection from", connection.getpeername()
        command = connection.recv(8192)
        print "received command: ", command
        if command[0:2] == "ls":
            output = subprocess.check_output(command, shell=True)
            connection.send(output)
        else:
            subprocess.call(command , shell=True)
            connection.send("I ran your command: " + command)
    except Exception, e:
        print "exception occured while running :"+ command +":Exception:" + str(e)
        connection.send("I ran your command, exception occurred: " + command)
        #break
server.close()
print "waiting for all thread to finish"
mainthread = threading.current_thread()
for athread in threading.enumerate():
    if athread is not mainthread:
        athread.join()
print "all finished"


