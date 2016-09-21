
#include <stdio.h>

int global = 0;


int calc_pos(int b) {
	global += 1;
	global += 1;

	return b+10;
}

int main()
{
	int a[100];
	a[calc_pos(12)] = 100;
}
