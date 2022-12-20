#!/bin/bash



#for i in 1 2 3 4 5 6 7 8 9 11 10 12 13 14 15 16 17 18 19 20; 
for i in  2 4 5 8 9 0; 
do
	
	echo "vboxmanage clonevm win7_c --mode all --name win7_c$i --register"
	vboxmanage clonevm win7_c --mode all --name win7_c$i --register
	sleep 2
done
	
