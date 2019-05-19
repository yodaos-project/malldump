#include "stringx.h"

void trim(char *str, char c)
{
	if (c == 0) c = ' ';

	char *t = str;
	while (*str == c) str++;
	if (*str) {
		char *t1 = str;
		while (*str) str++;
		str--;
		while (*str == c) str--;
		while (t1 <= str) *(t++) = *(t1++);
	}
	*t = 0;
}
