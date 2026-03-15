#include <stdio.h>
#include <stdlib.h>

void backdoor() {
    system("/bin/sh");
}

void main() {
    char buf[64];
    printf("Enter some text: ");
    gets(buf); // Vulnerable to buffer overflow
    printf("You entered: %s\n", buf);
}