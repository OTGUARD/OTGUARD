#this script creates a command.txt for each of the myscada
#basically creates a command file in each of the myscada's directory

$command_file = "C:\Users\anonymous\Documents\from_windbg\$args\command.txt"

$writemem_cmd = ".writemem C:\\Users\\anonymous\\Documents\\from_windbg\\$args\\dumps\\core-%1-%4-%5-%6-%7.dmp %1 L%3"
$value = '!address -f:MEM_MAPPED,MEM_IMAGE,MEM_PRIVATE -c:"' + "$writemem_cmd" + '"'

#New-Item $command_file -type file -force -value '!address -f:MEM_MAPPED,MEM_IMAGE,MEM_PRIVATE -c:".writemem C:\\Users\\anonymous\\Documents\\from_windbg\\$args\\dumps\\core-%1-%4-%5-%6-%7.dmp %1 L%3"
New-Item $command_file -type file -force -value "$value
~0 s
~
r rax
r rbx
r rcx
r rdx
r rsi
r rdi
r rip
r rsp
r rbp
r r8
r r9
r r10
r r11
r r12
r r13
r r14
r r15
r iopl
r cs
r ss
r ds
r es
r fs
r gs
r of
r df
r if
r tf
r sf
r zf
r af
r pf
r cf
r efl
k
x /2 /f *!*
q"
