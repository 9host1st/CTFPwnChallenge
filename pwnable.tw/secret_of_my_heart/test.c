#include <stdio.h>
int main() {
	char buf[40];
	int len;
	len = read(0, buf, 32);
	printf("%d", len);
}
