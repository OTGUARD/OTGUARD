if [[ -z $1 ]];then
	echo "specify an number"
	exit
fi

echo  $1 > /home/anonymous/otguard/otguard/max_process_file
