if [[ -z $1 ]];then
	echo "specify an IP address"
	exit
fi

rm /home/anonymous/otguard/otguard/vm_decom_list/$1
