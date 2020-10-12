#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include "util.h"

static int log_mask = ERR | DBG1 | DBG2 | DBG3;
FILE *logout = NULL;

void logg(short lvl, const char *fmt, ...)
{
	time_t t;
	va_list args;
	struct tm *tm;

	if (!(lvl & log_mask))
		return;

	if (!logout)
		logout = stdout;

	va_start(args, fmt);

	time(&t);
	tm = localtime(&t);

	fprintf(logout, "%02d-%02d-%02d %02d:%02d:%02d ",
		tm->tm_year % 100, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour,
		tm->tm_min, tm->tm_sec);
	vfprintf(logout, fmt, args);
	va_end(args);
	fflush(logout);
}
