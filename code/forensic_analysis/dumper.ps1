
if ($args) {
    Write-Host "running dumper.ps1"
}else{
    Write-Host "no argument was given, exiting..."
    exit
}

$myscada_dir = "C:\Users\anonymous\Documents\from_windbg\$args"
$dump_file = "C:\Users\anonymous\Documents\from_windbg\$args\$args.dmp"
$log_file = "C:\Users\anonymous\Documents\from_windbg\$args\dump-$args.log"

#Delete the directory if it exists for a fresh start
if (Test-Path $myscada_dir) {
    Write-Host "deleting existing $myscada"
    Remove-Item $myscada_dir -recurse
}

New-Item $myscada_dir -type directory -force

windbg -c ".dump /ma $dump_file; q" -pn $args -logo $log_file
#windbg -c ".dump /ma C:\Users\anonymous\Documents\from_windbg\$args\$args.dmp; q" -pn $args -logo C:\Users\anonymous\Documents\from_windbg\$args\dump-$args.log
