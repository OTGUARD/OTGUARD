#!/bin/bash

vm_name=$1
vboxmanage snapshot $vm_name restore ip_set

