# Executing Shellcode Using Stack Overflow

## Assumption  

1. '/etc/notes' is owned by 'root'.   
2. Program 'victim' is SETUID file and owned by 'root'.   

## Blueprint   
   
In victim.c line 25, there is strcpy function.   
So I will overwrite the return address of main()'s stack frame to the address of shellcode which executes /bin/bash.   
To overwrite return address, I'll run another program 'exploit_victim' to execute 'victim' by calling system().    
I'll pass a string like below as the argument of system().    

>./victim 'nopsled + shellcode + address to return(somewhere in nopsled)'    

Then shellcode will be in system()'s stack frame and    
return address of victim's main() stack will be overwritten to the address of somewhere in nop sled in system()'s stack frame.   

## Procedure   

1. Finding somewhere in nopsled   
   Since system()'s stack frame will be on main()'s stack frame, varible 'i' in main(),      
   exploit_victim.c is defined as a frame of reference.   
   We can set variable 'offset' by passing argument when executing exploit_victim.   
   ```
   ~$:for i in $(0 30 3000)
     >do
     >echo Trying $i
     >./exploit_victim $i
     >done
   ```
   By executing above, we can find a offset which makes &i-offset == address of somewhere of nopsled 
   
2. Making string (in exploit_victim.c)
   Line 14 : char* command and char* buffer are declared.   
   Line 20 - 24 : Memory for 'command' is allocated, string "./victim '" is stored and    
   the address of 'buffer' is set to right after 'command'.   
   Line 28 ~ 29 : This will set memory with address of somewhere of nopsled (if 'i' is correct).   
   Line 31 : First 60 bytes of buffer will set to nop.   
   Line 32 : Shellcode will be located right after the nopsled.
   Line 33 : Makes The string for system()'s argument to end with '.

3. Executing 'victim'   
   Line 34 : system(command) is same to    
   ```
   ~$:./victim $('print "\x90" x 60 . "\x31\xc0.....\xcd\x80" . "ADDRESS" x 17')
   ```
   When strcpy in victim's main() is executed, return address in main()'s stack frame will be overwritten to "ADDRESS"   
   This cause shellcode to be run when victim's main() is end.
   
## Problem

Almost of modern processor use 64-bit address. So the "ADDRESS" includes null byte.   
This prevents argument for 'victim' being long enough to overwrite return address of victim's main() stack frame.
So this kind of attack is not practical today.
