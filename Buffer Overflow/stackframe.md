```
/*
 * set breakpoint at if(check_authenticatioin(argv[1])) {
 */
(gdb)x/32xw $rsp
0x7fffffffdf50: .....
0x7fffffffdf60: .....
```

```
/*
 * set breakpoint at return auth_flag;
 */
(gdb)x/20xw $rsp
0x7fffffffdf10: 0xffffdf78  0x00007fff  0xffffe3a4  0x00007fff
0x7fffffffdf20: 0x41414141  0x41414141  0x41414141  0x41414141
0x7fffffffdf30: 0x41414141  0x41414141  0x41414141  0x00004141
0x7fffffffdf40: 0xffffdf60  0x00007fff  0x5555481e  0x00005555
0x7fffffffdf50: 0xffffe048  0x00007fff  0x00000000  0x00000002
```
As you can see, 0x7fffffffdf10 ~ 0x7fffffffdf40 is allocated after the function check_authentication() called.   
This is stackframe for check_authentication() in stack. We can separate this by 7 parts.

```
----------------------------------
0x7fffffffdf10: 0x00007fffffffdf78 -> Unknown(maybe padding)
----------------------------------
0x7fffffffdf18: 0x00007fffffffe3a4 -> Func argument (address of 'A' x 30)
----------------------------------
0x7fffffffdf20: 0x4141414141414141 -> local variable(password_buffer)
0x7fffffffdf28: 0x4141414141414141
----------------------------------
0x7fffffffdf30: 0x4141414141414141 -> Unknown(maybe padding)
0x7fffffffdf38: 0x41414141
----------------------------------
0x7fffffffdf3c: 0x00004141         -> Local variable(auth_flag)
----------------------------------
0x7fffffffdf40: 0x00007fffffffdf60 -> Saved frame pointer
----------------------------------
0x7fffffffdf48: 0x000055555555481e -> return address
----------------------------------
```

