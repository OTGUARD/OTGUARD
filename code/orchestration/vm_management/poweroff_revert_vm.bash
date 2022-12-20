#!/bin/bash

vm_name=$1
vboxmanage controlvm $vm_name poweroff
vboxmanage snapshot $vm_name restore ip_set

