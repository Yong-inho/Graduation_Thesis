# Adding Root User By Using Heap Overflow

## Assumption

1. '/etc/notes' is owned by 'root'.
2. Program 'victim' is SETUID file and owned by 'root'.

## Blueprint

In victim.c, memory for 'buffer' is allocated first and then memory for 'datafile' is allocated.   
Strcpy() is used for 'buffer' and this program can write something in files which is owned by root!   
So I'll create a root user by writing user info in '/etc/passwd'.   

## Procedure

1. User info format.
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
Real value of this field is H(password, salt) where H() is hash and salt is arbitrary two alphabets, and stored in shadow file.   
If the password of 'yong' is 123456 and salt is "XX", then x is H("123456","XX").  
