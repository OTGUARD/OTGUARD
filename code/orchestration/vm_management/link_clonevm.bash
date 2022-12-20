#!/bin/bash



for i in 1 3  6 7 10 11 12 13 14 15 16 17 18 19 ; 
#for i in  2 4 5 8 9 0; 
do
	
	echo "vboxmanage clonevm win7_c --mode machine --options link --name win7_c$i --register"
	vboxmanage clonevm win7_c --snapshot base --mode machine --options link --name win7_c$i --register
	sleep 2
done
	
