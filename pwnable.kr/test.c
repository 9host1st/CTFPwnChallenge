#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int calcDecodeLength(char* a1) {
    int v2 = strlen(a1);
    int v3 = 0;
    if(*(v2 - 1 + a1) != 61 || *(v2 - 2 + a1) != 61) {
        if(*(v2 - 1 + a1) == 61)
            v3 = 1;
    } else {
        v3 = 2;
    }
    return (v2 * 0.75 - v3);
}
int main() {
    char s[100];
    scanf("%30s", s);
    printf("%d", calcDecodeLength(s));
}
