#ifndef __LIB_UNILOG_H
#define __LIB_UNILOG_H

#include <stdarg.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#define __USE_GNU
#include <dlfcn.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum unilog_level {
	UNILOG_NONE = 0,
	UNILOG_DEBUG,
	UNILOG_INFO,
	UNILOG_NOTICE,
	UNILOG_WARN,
	UNILOG_ERROR,
	UNILOG_FATAL,
};

int unilog_set_level(int level);

typedef void (*unilog_event_func_t)(
	int level, const char *module_path, const char *format, va_list ap);

void unilog_watch_before_event(unilog_event_func_t fn);
void unilog_watch_after_event(unilog_event_func_t fn);
void unilog_unwatch_before_event(unilog_event_func_t fn);
void unilog_unwatch_after_event(unilog_event_func_t fn);

int unilog_message(int level, const char *module_path, const char *format, ...);

#ifdef _WIN32
#define LOG_XX(level, format, ...) \
do { \
	static char static_addr = 0; \
	HMODULE hModule; \
	GetModuleHandleEx( GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, \
		(LPCTSTR)(&static_addr), &hModule ); \
	char module_path[128] = {0}; \
	GetModuleFileNameA(hModule, module_path, 128); \
	unilog_message(level, module_path, format, ##__VA_ARGS__); \
} while(0)
#else
#define LOG_XX(level, format, ...)  \
do { \
	static char static_addr = 0; \
	Dl_info di; \
	memset(&di, 0, sizeof(di)); \
	if (dladdr(&static_addr, &di) == 0)  \
		unilog_message(level, "", format, ##__VA_ARGS__); \
	else  \
		unilog_message(level, di.dli_fname, format, ##__VA_ARGS__); \
} while(0)
#endif

#define LOG_NONE(format, ...) LOG_XX(UNILOG_NONE, format, ##__VA_ARGS__)
#define LOG_DEBUG(format, ...) LOG_XX(UNILOG_DEBUG, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) LOG_XX(UNILOG_INFO, format, ##__VA_ARGS__)
#define LOG_NOTICE(format, ...) LOG_XX(UNILOG_NOTICE, format, ##__VA_ARGS__)
#define LOG_WARN(format, ...) LOG_XX(UNILOG_WARN, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) LOG_XX(UNILOG_ERROR, format, ##__VA_ARGS__)
#define LOG_FATAL(format, ...) LOG_XX(UNILOG_FATAL, format, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif
