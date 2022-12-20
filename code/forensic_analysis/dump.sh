#first argument is the myscada executable
#second argument is the time to sleep for
#this script was initially designed to be run immediately after the run_myscada.sh runs

echo "sleeping for $2 seconds before dumping.."
sleep $2

echo ./dumper.ps1 $1 | powershell -file -

echo "Done"
