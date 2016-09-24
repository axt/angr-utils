
#include <stdio.h>


int f0(int a) {
	if (a > 0) {
		a = 1;
	} else {
		a = 2;
	}
}
int main()
{
	int a;
	if(a > 0) {
		f0(a);
	} else {
		f0(0);
	}
}
