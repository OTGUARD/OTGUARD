
#This is the right way to run a PS script in cygwin
#echo ./test.ps1 -arg kk -arg2 2 | powershell -file -



param(
    [Parameter(Mandatory=$true)][string]$arg,
    [Parameter(Mandatory=$true)][string]$arg2
)

Write-Host "This is a test"
Write-Host $args
Write-Host $arg1

#Write-Host $args[0]
#Write-Host $args[1]
New-Item C:\Users\anonymous\Documents\from_windbg\test -type directory -force

#running the myscada 
#C:\Users\anonymous\Documents\myscada.exe jj
#    get-childitem
$program = $arg
Start-Job -scriptblock {
    param(
        $program
    )
    #C:\Users\anonymous\Documents\myscada.exe jj
    notepad.exe
    #$program
#    Start-Sleep -s 20
} - ArgumentList $program


$time = $arg2
#$time = $args[1]

Write-Host "I am sleeping for $time seconds"
Start-Sleep -s $time
Write-Host "I am done sleeping"
exit
