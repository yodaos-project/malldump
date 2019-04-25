#include "unilog.h"
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
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

static int limit = UNILOG_INFO;

struct unilog_event {
	unilog_event_func_t fn;
	struct unilog_event *next;
};

static struct unilog_event before_head;
static struct unilog_event after_head;

int unilog_set_level(int level)
{
	int previous = limit;
	limit = level;
	return previous;
}

void unilog_watch_before_event(unilog_event_func_t fn)
{
	struct unilog_event *event = malloc(sizeof(*event));
	event->fn = fn;
	event->next = before_head.next;
	before_head.next = event;
}

void unilog_watch_after_event(unilog_event_func_t fn)
{
	struct unilog_event *event = malloc(sizeof(*event));
	event->fn = fn;
	event->next = after_head.next;
	after_head.next = event;
}

void unilog_unwatch_before_event(unilog_event_func_t fn)
{
	struct unilog_event *event = &before_head;

	do {
		if (event->next && event->next->fn == fn) {
			struct unilog_event *tmp = event->next;
			event->next = tmp->next;
			free(tmp);
			break;
		}
	} while ((event = event->next));
}

void unilog_unwatch_after_event(unilog_event_func_t fn)
{
	struct unilog_event *event = &after_head;

	do {
		if (event->next && event->next->fn == fn) {
			struct unilog_event *tmp = event->next;
			event->next = tmp->next;
			free(tmp);
			break;
		}
	} while ((event = event->next));
}

static int __unilog_message(int level, const char *format, va_list ap)
{
	char prefix[40];

	switch (level) {
	case UNILOG_NONE: // None
		strcpy(prefix, "");
		break;
	case UNILOG_DEBUG: // Bright Cyan, important stuff!
		strcpy(prefix, CL_CYAN"[Debug]"CL_RESET": ");
		break;
	case UNILOG_INFO: // Bright White (Variable information)
		strcpy(prefix, CL_WHITE"[Info]"CL_RESET": ");
		break;
	case UNILOG_NOTICE: // Bright White (Less than a warning)
		strcpy(prefix, CL_WHITE"[Notice]"CL_RESET": ");
		break;
	case UNILOG_WARN: // Bright Yellow
		strcpy(prefix, CL_YELLOW"[Warning]"CL_RESET": ");
		break;
	case UNILOG_ERROR: // Bright Red (Regular errors)
		strcpy(prefix, CL_RED"[Error]"CL_RESET": ");
		break;
	case UNILOG_FATAL: // Bright Red (Fatal errors, abort(); if possible)
		strcpy(prefix, CL_RED"[Fatal Error]"CL_RESET": ");
		break;
	default:
		printf("__unilog_message: Invalid level passed.\n");
		return 1;
	}

	printf("%s", prefix);
	vprintf(format, ap);
	fflush(stdout);

	return 0;
}

int unilog_message(int level, const char *module_path, const char *format, ...)
{
	int rc;
	va_list ap;
	struct unilog_event *event;

	assert(format && *format != '\0');

	if (level < limit && level != UNILOG_NONE) return 0;

	event = &before_head;
	while ((event = event->next)) {
		va_start(ap, format);
		event->fn(level, module_path, format, ap);
		va_end(ap);
	}

	va_start(ap, format);
	rc = __unilog_message(level, format, ap);
	va_end(ap);

	event = &after_head;
	while ((event = event->next)) {
		va_start(ap, format);
		event->fn(level,module_path, format, ap);
		va_end(ap);
	}

	return rc;
}
