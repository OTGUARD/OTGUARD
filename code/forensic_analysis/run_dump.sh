#usage ./run_dump program_name sec-b4_dumping
#this assumes that the malware takes no commandline argument

echo "Running" $1
./$1 &

echo "sleeping for $2 sec before dumping"
sleep $2
echo ./dumper.ps1 $1 | powershell -file -
echo "Done"
