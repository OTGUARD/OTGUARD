#usage: echo ./process_core.ps1 -myscada <myscada> -writer <cmd_writer_script> | powershell -file -

param(
    [Parameter(Mandatory=$true)][string]$myscada,
    [Parameter(Mandatory=$true)][string]$writer
)



$myscada_dir = "C:\Users\anonymous\Documents\from_windbg\$myscada"
$dumps_dir = $myscada_dir + "\dumps"
$dump_file = $myscada_dir + "\$myscada" + ".dmp"
$log_file = $dumps_dir + "\windbg.log"
$command_file = $myscada_dir + "\command.txt"

#check if previously created dumps already exist
if (Test-Path $dumps_dir) {
    Write-host "deleting existing $dumps_dir" 
    Remove-Item $dumps_dir -recurse
}

#create a directory to store the to-be-extracted dumps
New-Item $dumps_dir -type directory -force

#The command_writes the commands to command.txt in $myscada_dir
powershell -file ./$writer $myscada


#windbg -c $<C:\Users\anonymous\Documents\from_windbg\command.txt  -z C:\Users\anonymous\Documents\from_windbg\$args\$args.dmp -logo C:\Users\anonymous\Documents\from_windbg\$args\dumps\windbg.log

windbg -c $><$command_file  -z $dump_file -logo $log_file
