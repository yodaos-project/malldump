#include "extlog.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#ifdef _WIN32
#define CL_RESET ""
#define CL_NORMAL CL_RESET
#define CL_NONE  CL_RESET
#define CL_WHITE ""
#define CL_GRAY  ""
#define CL_RED  ""
#define CL_GREEN ""
#define CL_YELLOW ""
#define CL_BLUE  ""
#define CL_MAGENTA ""
#define CL_CYAN  ""
#else
#define CL_RESET "\033[0;0m"
#define CL_NORMAL CL_RESET
#define CL_NONE  CL_RESET
#define CL_WHITE "\033[1;29m"
#define CL_GRAY  "\033[1;30m"
#define CL_RED  "\033[1;31m"
#define CL_GREEN "\033[1;32m"
#define CL_YELLOW "\033[1;33m"
#define CL_BLUE  "\033[1;34m"
#define CL_MAGENTA "\033[1;35m"
#define CL_CYAN  "\033[1;36m"
#endif

static int limit = LOG_LV_INFO;

int log_set_level(int level)
{
	int previous = limit;
	limit = level;
	return previous;
}

static int __log_message(int level, const char *format, va_list ap)
{
	char prefix[40];

	switch (level) {
	case LOG_LV_NONE: // None
		strcpy(prefix, "");
		break;
	case LOG_LV_DEBUG: // Bright Cyan, important stuff!
		strcpy(prefix, CL_CYAN"[Debug]"CL_RESET": ");
		break;
	case LOG_LV_INFO: // Bright White (Variable information)
		strcpy(prefix, CL_WHITE"[Info]"CL_RESET": ");
		break;
	case LOG_LV_NOTICE: // Bright White (Less than a warning)
		strcpy(prefix, CL_WHITE"[Notice]"CL_RESET": ");
		break;
	case LOG_LV_WARN: // Bright Yellow
		strcpy(prefix, CL_YELLOW"[Warning]"CL_RESET": ");
		break;
	case LOG_LV_ERROR: // Bright Red (Regular errors)
		strcpy(prefix, CL_RED"[Error]"CL_RESET": ");
		break;
	case LOG_LV_FATAL: // Bright Red (Fatal errors, abort(); if possible)
		strcpy(prefix, CL_RED"[Fatal Error]"CL_RESET": ");
		break;
	default:
		printf("__log_message: Invalid level passed.\n");
		return 1;
	}

	printf("%s", prefix);
	vprintf(format, ap);
	fflush(stdout);

	return 0;
}

int log_message(int level, const char *format, ...)
{
	int rc;
	va_list ap;

	assert(format && *format != '\0');

	if (level < limit && level != LOG_LV_NONE)
		return 0;

	va_start(ap, format);
	rc = __log_message(level, format, ap);
	va_end(ap);

	return rc;
}
