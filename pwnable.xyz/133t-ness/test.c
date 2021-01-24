#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main() {
    int a, b;
    scanf("%d %d", &a, &b);
    printf("%d %d\n", a, b);
    if(a > 1) printf("yes\n");
    if(b > 1337) printf("yes2\n");
    if(a*b == 1337) printf("ans\n");
}
