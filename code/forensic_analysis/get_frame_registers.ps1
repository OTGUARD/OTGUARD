#Usage echo ./get_frame_registers -myscada <myscada.exe> -frame_no <frame_no_in_hex>  -arch <64|32>| powershell -file -

param(
    [Parameter(Mandatory=$true)][string]$frame_no,
    [Parameter(Mandatory=$true)][string]$myscada,
    [Parameter(Mandatory=$true)][string]$arch
)


$dump_file = "C:\Users\anonymous\Documents\from_windbg\$myscada\$myscada.dmp"
$log_file = "C:\Users\anonymous\Documents\from_windbg\$myscada\dumps\frame_registers-$frame_no-$myscada.log"

if ($arch.CompareTo("64")){ #if equal it returns a 0
    windbg -c " .effmach x86 ; ~0 s; .frame /c $frame_no; k; q" -z $dump_file -logo $log_file
}else{
    windbg -c "~0 s; .frame /c $frame_no; k; q" -z $dump_file -logo $log_file
}
