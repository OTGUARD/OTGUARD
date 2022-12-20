#!/usr/bin/env python
import os, subprocess, sys, threading, time

exe_path = "samples"
if len(sys.argv) == 2:
  exe_path = sys.argv[1]
elif len(sys.argv) > 2:
  print("Invalid arguments")
  sys.exit(1)
# in s
wait_time = 5
good_dir = os.path.join(exe_path, "good")
bad_dir = os.path.join(exe_path, "bad")
# this includes the main thread, the max number of spawned processes is max_threads - 1
max_threads = 256

def move_if_running(proc, file_name):
  # kills if still running and moves to good dir, else moves to bad dir
  old_path = os.path.join(exe_path, file_name)
  # if proc.poll() is None, this means it is still running
  if proc.poll() is None:
    proc.kill()
    os.rename(old_path, os.path.join(good_dir, file_name))
  else:
    os.rename(old_path, os.path.join(bad_dir, file_name))

if not os.path.exists(exe_path):
  print("folder " + exe_path + " does not exist")
  sys.exit(1)
if not os.path.exists(good_dir):
  os.makedirs(good_dir)
if not os.path.exists(bad_dir):
  os.makedirs(bad_dir)
# get all files, ignore directories
files = [f for f in os.listdir(exe_path) if os.path.isfile(os.path.join(exe_path, f))]
for f in files:
  # handle when the max thread count has been reached
  while threading.active_count() >= max_threads:
    try:
      # this won't necessarily get the oldest thread, but getting any thread is good enough
      threads = threading.enumerate()
      # wait until thread completes
      if threads[0] is not threading.current_thread():
        threads[0].join()
      else:
        threads[1].join()
    except IndexError:
      # may be a race condition if all threads are now complete
      pass
  # spawn a new process
  proc = subprocess.Popen(os.path.join(exe_path, f))
  # create the thread that checks on the process after a delay
  t = threading.Timer(wait_time, move_if_running, (proc, f))
  t.daemon = False
  t.start()
