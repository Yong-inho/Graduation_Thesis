## Assumption  

1. '/etc/notes' is owned by 'root'.   
2. Program 'victim' is SETUID file and owned by 'root'.   

## Blueprint   
   
In victim.c line 25, there is strcpy function.   
So I will overwrite the return address of main()'s stack frame to the address of shellcode which executes /bin/bash.   
To overwrite return address, I'll run another program 'exploit_victim' to execute 'victim' by calling system().    
I'll pass a string like <figure 1> as the argument of system().    
![String](https://user-images.githubusercontent.com/62104730/79855029-58ef4480-8405-11ea-8251-e083a728ac04.JPG)   
\t\t\t\t\t\t\t<figure 1. char* command>    
Then shellcode will be in system()'s stack frame and    
return address of victim's main() stack will be overwritten to the address of somewhere in nop sled in system()'s stack frame.   

## Procedure   
1. 
