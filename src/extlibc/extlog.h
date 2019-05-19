#ifndef __EXT_LOG_H
#define __EXT_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

enum log_level {
	LOG_LV_NONE = 0,
	LOG_LV_DEBUG,
	LOG_LV_INFO, /* default */
	LOG_LV_NOTICE,
	LOG_LV_WARN,
	LOG_LV_ERROR,
	LOG_LV_FATAL,
};

/* Set log level and return former log level. */
int log_set_level(int level);

/* Log message to stdout */
int log_message(int level, const char *format, ...);

/* Marcos wrapping log_level for convenient usage of log_message */
#define LOG_NONE(format, ...) log_message(LOG_LV_NONE, format, ##__VA_ARGS__)
#define LOG_DEBUG(format, ...) log_message(LOG_LV_DEBUG, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) log_message(LOG_LV_INFO, format, ##__VA_ARGS__)
#define LOG_NOTICE(format, ...) log_message(LOG_LV_NOTICE, format, ##__VA_ARGS__)
#define LOG_WARN(format, ...) log_message(LOG_LV_WARN, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) log_message(LOG_LV_ERROR, format, ##__VA_ARGS__)
#define LOG_FATAL(format, ...) log_message(LOG_LV_FATAL, format, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif
