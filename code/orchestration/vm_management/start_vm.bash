#!/bin/bash

vm_name=$1
vboxmanage startvm $vm_name --type headless

