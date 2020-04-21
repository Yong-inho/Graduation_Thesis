#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char* argv[]) {
  int fd;
  char* buffer, *datafile;
  
  buffer = (char*)malloc(100); // vulnerable point 1
  datafile = (char*)malloc(20); // vulnerable point 2
  strcpy(datafile, "/etc/notes");
  
  if(argc < 2)
    printf("Usage : %s <data to add to %s>\n", argv[0], datafile);
  
  strcpy(buffer, argv[1]); // vulnerable  point 3
  
  fd = open(datafile, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR);
  if(fd == -1)
    perror("in main() open()");
  
  if(write(fd, buffer, strlen(buffer)) == -1)
    perror("in main() write()");
  write(fd, "\n", 1);
  
  free(buffer);
  free(datafile);
  return 0;
}
