#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#define BUFSIZE 64u
#define KEYSIZE 16u

char key[KEYSIZE+1];

typedef struct buf {
  char buf[64];
  char **foo;
} buf_t;

void seghandler(int signum)
{
  puts("SEGMENTATION FAULT");
  printf("Your key is %s\n", key);
  fflush(stdout);
  sleep(1);
  exit(0);
}

int main ()
{
  buf_t buf;
  buf.foo = &buf.buf;
  unsigned int len=0;
  int tmp;
  int keyfd = open("./key",O_RDONLY);
  struct sigaction sa;
  sa.sa_handler = seghandler;
  sigaction(SIGSEGV,&sa,NULL);

  len = read(keyfd,key,KEYSIZE);
  if(len == -1) exit(1);
  while(len<KEYSIZE)
  {
    tmp = read(keyfd,key,KEYSIZE-len);
    if (tmp != -1)
    {
      len+=tmp;
    }
  }
  close(keyfd);
  key[KEYSIZE] = '\0';


  printf("What is your name?\n");
  fflush(stdout);
  len = read(STDIN_FILENO,buf.buf,BUFSIZE+8);
  if (len == -1) exit(1);
  buf.buf[len] = '\0';
  for(tmp=0;tmp<BUFSIZE;tmp++)
  {
    char c = buf.buf[tmp];
    if((c<'A' || c>'z') && c!=' ')
    {
      printf("That does not look like a name to me!\n");
      fflush(stdout);
      exit(2);
    }
  }
  printf("Hello, %s\n",buf.buf);
  fflush(stdout);
  *buf.foo = NULL;
  exit(0);
}
  
