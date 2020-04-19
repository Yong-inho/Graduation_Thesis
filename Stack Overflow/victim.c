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
