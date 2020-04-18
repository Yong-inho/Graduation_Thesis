```c
/*
 * source code
 */
#include <stdio.h>

int main(void) {
  int i;
  for(i = 0; i < 10; i++)
    printf("Hello, world!");
  return 0;
}
```
```
/*
 * assembly code
 *    ~$ gdb -q ./a.out
 * (gdb) disassemble main
 */
push  rbp
mov   rbp,rsp
sub   rsp,0x10
mov   DWORD PTR [rbp-0x4], 0x0
jmp   0x65b <main+33>
lea   rdi,[rip+0xa2]
call  0x510 <puts@plt>
add   DWORD PTR [rbp-0x4],0x1
cmp   DWORD PTR [rbp-0x4],0x9
jle   0x64b <main+17>
mov   eax,0x0
leave
ret
```

First, set breakpoint at main

```
/*
 * (gdb) break main
 * (gdb) run
 */
Starting program: /home/yong/test

Breakpoint 1, main() at a.out:6
6         for(i = 0; i < 10; i++)
```

Let's show what is the next instruction

```
/*
 * (gdb) x/i $rip
 * register rip stores the address of next instruction
 */
=> 0x555555554642 <main+8>: mov   DWORD PTR [rbp-0x4],0x0
```

According to above, the instructions before <main+8> are not the parts of my source code
which is called function prologue and it's beyond this activity.   
   
Next, Let's show next 4 instructions

```
/*
 * (gdb) x/4i $rip
 */
=> 0x555555554642 <main+8>:   mov   DWORD PTR [rbp-0x4],0x0
   0x555555554649 <main+15>:  jmp   0x55555555464b <main+33>
   0x55555555464b <main+17>:  lea   rdi, [rip+0xa2]   # 0x5555555546f4
   0x555555554652 <main+24>:  call  0x555555554510 <puts@plt>
```

It's a just common routine for loop. Initializing variable 'i' in source code,
which is stored in momory located at [rbp-0x4],   
(jump to middle and test are not shown in this sequences)
and load effective address of [rip+0xa2] and call puts().

Here, I have two questions. 
First, why 'i' is not allocated in register, but memory?   
Second, is the string "Hello, world' stored in memory lacated at [rip+0xa2]? 

```
/*
 * $rip + 0xa2 = 0x555555554652 + 0xa2 = 0x5555555546f4
 * $rip != 0x555555554642 since curruntly I'm stopped at <main+8>
 * (gdb) x/s 0x5555555546f4
 */
0x5555555546f4: "hello, world!"
```
 
This answers to second question. 

```
/*
 * assembly code of a.out when compiled with -Og flag
 *
 */
push rbx
mov ebx,0x0
jmp 0x651 <main+23>
lea rdi,[rip+0x9b]
call 0x510 <puts@plt>
add ebx,0x1
cmp ebx,0x9
jle 0x642 <main+8>
mov eax,0x0
pop rbx
ret
```

Here, the variable 'i' is stored in register ebx.
So, 'i' is stored in memory because of compiler's optimization.
But I can't find the reason why this kind of optimization is done.

```
/*
 * result of executing next four instructions
 */
(gdb) nexti
0x555555554649      6         for(i = 0; i < 10; i++)
(gdb) nexti
0x55555555465b      6         for(i = 0; i < 10; i++)
(gdb) nexti
0x55555555465f      6         for(i = 0; i < 10; i++)
(gdb) nexti
8           puts("hello, world!");
```

Remain of execution is just looping.
