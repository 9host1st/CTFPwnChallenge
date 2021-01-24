#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main() {
    char *str = "test423123123";
    char str2[100];
    printf("%d\n", read(0, str2, 100));
    printf("%d\n", strcmp(str, str2));
}

