#!/bin/bash

if [ -z $1 ]; then
	echo "USAGE: bash multi_process_otguard.bash <path to samples folder>"
	exit
fi
if [ ! -d $1 ]; then
	echo "$1 does not exists as a directory"
	exit
fi



vm_ips=( "192.168.56.111" "192.168.56.112" "192.168.56.113" "192.168.56.114" "192.168.56.115" "192.168.56.116" "192.168.56.117" "192.168.56.118" "192.168.56.119" "192.168.56.110" "192.168.56.120" )
#vm_ips=( "192.168.56.112" "192.168.56.114" "192.168.56.115" "192.168.56.118" )
vm_names=( "win7_c1" "win7_c2" "win7_c3" "win7_c4" "win7_c5" "win7_c6" "win7_c7" "win7_c8" "win7_c9" "win7_c0" "win7_c10" )
#vm_names=( "win7_c2" "win7_c4"  "win7_c5" "win7_c8" )

#cannot parallel this since, you have to start them up completely first, before you revert
#attempt to start the vms



function revert_vms () {
	for vm in "${vm_names[@]}";
	do
		if [[ $(ssh anonymous@192.168.56.1 "vboxmanage list runningvms") = *"$vm"* ]];then
			#ssh anonymous@192.168.56.1 "vboxmanage controlvm $vm poweroff &"
			ssh anonymous@192.168.56.1 "bash /home/anonymous/otguard/poweroff_vm.bash $vm"
		fi
	done

	echo "reverting the vms to base state... "
	#lets revert the VM snapshots
	for vm in "${vm_names[@]}";
	do
		ssh anonymous@192.168.56.1 "bash /home/anonymous/otguard/revert_vm.bash $vm" &
	done
}

start_s=$(date +%s)
secs=0
mins=0
hrs=0
function elapsed_time () {
	let secs=($(date +%s) - $1) 
	if [[ $secs -gt 59 ]];then
		let mins=($secs / 60) 
		let secs=($secs % 60)
		if [[ $mins -gt 3599 ]]; then
			let hrs=($mins / 60) 
			let mins=($hrs % 60)
		else
			hrs=0
		fi
	else
		hrs=0
		mins=0
	fi
}


#No need for this, each otguard instance does this 
#revert_vms


#the otguard instances will start them up
#for vm in "${vm_names[@]}";
#do
#	ssh anonymous@192.168.56.1 "bash /home/anonymous/otguard/start_vm.bash $vm"
#done

#lets make sure we can ssh into these IPs without password
#No need for this if we make sure their base snapshot it ssh able
#for vm in "${vm_ips[@]}";
#do
#	ssh anonymous@$vm "ls otguard_server.py"
#done

#exit

samples_folder=$1
#just to check if there is a trailing slash /, and accomodate for that
i=$((${#samples_folder}-1))
if [[  "${samples_folder:$i:1}" = "/" ]];then
	:
else
	samples_folder=$samples_folder"/"
fi


multi_process_log=$samples_folder"run.log"

echo "Processing samples in $samples_folder" >> $multi_process_log
size=$(ls $1 | wc -l)
echo "Total samples: $size" >> $multi_process_log

mkdir -p /home/anonymous/otguard/run_outputs > /dev/null 2>&1
count=0

for myscada in $(ls $samples_folder); do

	#make sure it is an executable
	output=$(file $samples_folder""$myscada)
	#echo $output
	if [[ $output = *"executable"* ]]; then
		let count=$count+1
		poll_interval=5
		total_poll_time=0
		

		#make sure we have a free vm to use, if not, poll until vm becomes available
		echo "polling $myscada.."
		while true; 
			do
				ips_being_used=$(ps aux | grep python)
				ip_to_use=""
				ip_is_free=0
				for ip in "${vm_ips[@]}";
				do
					if [[ $ips_being_used = *"$ip"* ]];then
						:
					else
						echo "Total poll time: $total_poll_time secs"
						ip_to_use=$ip
						ip_is_free=1
						echo "Processing $myscada on $ip_to_use" >> $multi_process_log 
						break
					fi
				done
				if [[ $ip_is_free -eq 0 ]];then
					sleep $poll_interval
					let total_poll_time=$total_poll_time+$poll_interval
				else
					break #break from the polling while loop
				fi
			done
		python /home/anonymous/otguard/otguard/angry_ida.py 0 ida_link $myscada $ip_to_use $samples_folder  > /home/anonymous/otguard/run_outputs/$myscada".run" 2>&1 &
		#let secs=($(date +%s) - $start_s) 
		#let mins=($secs / 60) 
		#let hrs=($secs / 3600)
		elapsed_time $start_s 
		echo "fired up otguard for $myscada on $ip_to_use Total fired instances: $count/$size : Time elapsed: $hrs hrs, $mins mins, $secs secs"
		#sleep 15
		#lets remove the myscada sample from the win7 vm
		#ssh anonymous@192.168.56.101 "rm $myscada" 
	else
		echo "NON EXECUTABLE DETECTED: $myscada - $output" 
		echo "NON EXECUTABLE DETECTED: $myscada  $output" >> $multi_process_log 
	fi
done
echo "All myscada has been deployed. Waiting for all deployed otguard instances to finished .."
echo "All myscada has been deployed. Waiting for all deployed otguard instances to finished .." >> $multi_process_log

#lets determine when all the otguard instances are done
while true;
do
	ips_being_used=$(ps aux | grep python)
	i_see_one=0
	for ip in "${vm_ips[@]}";
	do
		#if you see one, sleep for next 10 seconds
		if [[ $ips_being_used = *"$ip"* ]];then
			i_see_one=1
			sleep 10
			break
		else
			:
		fi
	done
	if [[ $i_see_one -eq 0 ]];then
		echo "It seems like all otguard instances have finshed. DONE "		
		echo "It seems like all otguard instances have finshed. DONE " >> $multi_process_log
		break	
	fi
done

	
