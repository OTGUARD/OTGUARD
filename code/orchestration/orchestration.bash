#!/bin/bash

if [ -z $1 ]; then
	echo "USAGE: bash multi_process_otguard.bash <path to samples folder>"
	exit
fi
if [ ! -d $1 ]; then
	echo "$1 does not exists as a directory"
	exit
fi


max_process_file="/home/anonymous/otguard/otguard/max_process_file"
vm_ready_pool="/home/anonymous/otguard/otguard/vm_ready_pool"
vm_decom_list="/home/anonymous/otguard/otguard/vm_decom_list"
mkdir -p $vm_ready_pool > /dev/null 2>&1
mkdir -p $vm_decom_list > /dev/null 2>&1


vm_ips=( "192.168.56.111" "192.168.56.112" "192.168.56.113" "192.168.56.114" "192.168.56.115" "192.168.56.116" "192.168.56.117" "192.168.56.118" "192.168.56.119" "192.168.56.110" )
#vm_ips=( "192.168.56.112" "192.168.56.114" "192.168.56.115" "192.168.56.118" )
vm_names=( "win7_c1" "win7_c2" "win7_c3" "win7_c4" "win7_c5" "win7_c6" "win7_c7" "win7_c8" "win7_c9" "win7_c0" )
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


#initiate pool
for vm in "${vm_ips[@]}";
do
	touch $vm_ready_pool/$vm
done

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
		

		echo "polling $myscada for available process space .."
		while true; 
			do
				max=$(cat $max_process_file | head -n 1 | cut -f1 -d" ")
				let max=$max+0 
				current_size=$(ps aux | grep python | grep otguard | wc -l)
				let current_size=$current_size+0 
				if [[ $current_size -ge $max ]]; then
					sleep $poll_interval
					let total_poll_time=$total_poll_time+$poll_interval
				else
					echo $max $current_size
					echo "Total poll time: $total_poll_time secs"
					break
				fi
			done
		echo "polling $myscada for a ready VM .."
		while true; 
			do
				ip_to_use=$(ls -r $vm_ready_pool | head -n 1)
				for ip in $(ls -r  $vm_ready_pool);
					do
					not_matched=1
					for ip_decom in $(ls $vm_decom_list);
						do
						#if you enter here then, we know that ip_decom and vm_ready_pool are not empty
						ip_to_use=""
						if [[ $ip != $ip_decom ]];then
							not_matched=1
						else
							not_matched=0
							continue 2
						fi
						done
					if [[ $not_matched -eq 1 ]];then
						ip_to_use=$ip
						break
					fi
					done
				if [[ -z $ip_to_use ]];then
					sleep $poll_interval
					let total_poll_time=$total_poll_time+$poll_interval
				else
					echo "Total poll time: $total_poll_time secs"
					ip_to_use=$ip
					echo "Processing $myscada on $ip_to_use" >> $multi_process_log 
					#remove the file so we do not use it again
					rm $vm_ready_pool/$ip_to_use
					break
				fi
			done
		echo $ip $ip_decom $ip_to_use $not_matched
		python /home/anonymous/otguard/otguard/angry_ida.py 0 ida_link $myscada $ip_to_use $samples_folder  > /home/anonymous/otguard/run_outputs/$myscada".run" 2>&1 &
		elapsed_time $start_s 
		echo "fired up otguard for $myscada on $ip_to_use Total fired instances: $count/$size : Time elapsed: $hrs hrs, $mins mins, $secs secs"
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

	
