## Assumption  

1. '/etc/notes' is owned by 'root'.   
2. Program 'victim' is SETUID file and owned by 'root'.   

## Blueprint   
   
In victim.c line 25, there is strcpy function.   
So I will overwrite the return address of main()'s stack frame to the address of shellcode which executes /bin/bash.
To overwrite return address, I'll run another program 'exploit_victim' to execute 'victim' by calling system().    
I'll pass string like <figure 1> as the argument of system().    
Then shellcode will be in system()'s stack frame and    
return address of victim's main() stack will be overwritten to the address of somewhere in nop sled in system()'s stack frame.   

## Procedure   
1. 
