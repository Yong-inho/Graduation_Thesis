#include <stdio.h>
#include <stdlib.h>
#include <crypt.h>

int main(int argc, char* argv[]) {
  if(argc < 3)
  {
    printf("Usage : %s <password> <salt>\n", argv[0]);
    exit(0);
  }
  
  char* password = crypt(argv[1], argv[2]);
  
  printf("hash value for <%s,%s> is %s\n", argv[1], argv[2], password);
  
  return 0;
}
