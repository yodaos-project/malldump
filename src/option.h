#ifndef __LIB_OPTION_H
#define __LIB_OPTION_H

#include <stdbool.h>

#define OPTERR_NONE 0
#define OPTERR_UNKNOW_OPTION 1
#define OPTERR_MISS_ARG 2
#define OPTERR_WRONG_VALUE 3
#define OPTERR_CONFIG_FILE_OPEN_FAILED 4

enum option_value_type {
	OPTVAL_NONE = 0,
	OPTVAL_STRING_STATIC,
	OPTVAL_STRING,
	OPTVAL_INTEGER,
	OPTVAL_BOOL,
};

struct option {
	char *optshort;
	char *key;
	union {
		char *s;
		int i;
		bool b;
	} value;
	enum option_value_type value_type;
	char *comment;
};

#define INIT_OPTION_STRING(optshort, key, val, desc) \
	{ optshort, key, .value.s = val, OPTVAL_STRING_STATIC, desc }
#define INIT_OPTION_INT(optshort, key, val, desc) \
	{ optshort, key, .value.i = val, OPTVAL_INTEGER, desc }
#define INIT_OPTION_BOOL(optshort, key, val, desc) \
	{ optshort, key, .value.b = val, OPTVAL_BOOL, desc }
#define INIT_OPTION_NONE() \
	{ NULL, NULL, .value.s = NULL, OPTVAL_NONE, NULL }

const char *option_errmsg();
struct option *find_option(const char *key, struct option * const opttab);
int option_init_from_arg(struct option * const opttab, int argc, char *argv[]);
int option_init_from_file(struct option * const opttab, const char *filename);
void option_fini(struct option * const opttab);

#endif
