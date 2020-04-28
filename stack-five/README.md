# STACK FIVE

As opposed to executing an existing function in the binary, this time we’ll be introducing the concept of “shell code”, and being able to execute our own code.

**Hints**

- Don’t feel like you have to write your own shellcode just yet – there’s plenty on the internet.
- If you wish to debug your shellcode, be sure to make use of the [breakpoint](https://en.wikipedia.org/wiki/Breakpoint) instruction. On i386 / x86_64, that’s 0xcc, and will cause a SIGTRAP.
- Make sure you remove those breakpoints after you’re done.

```c
/*
 * phoenix/stack-five, by https://exploit.education
 *
 * Can you execve("/bin/sh", ...) ?
 *
 * What is green and goes to summer camp? A brussel scout.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

char *gets(char *);

void start_level() {
  char buffer[128];
  gets(buffer);
}

int main(int argc, char **argv) {
  printf("%s\n", BANNER);
  start_level();
}
```

