#ifndef __EXT_OPT_H
#define __EXT_OPT_H

#include <assert.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OPTERR_NONE 0
#define OPTERR_UNKNOW_OPT 1
#define OPTERR_MISS_ARG 2
#define OPTERR_WRONG_VALUE 3
#define OPTERR_CONFIG_FILE_OPEN_FAILED 4

enum opt_type {
	OPT_NONE = 0,
	OPT_STRING_STATIC,
	OPT_STRING,
	OPT_INTEGER,
	OPT_BOOL,
};

struct opt {
	const char *optshort;
	const char *key;
	union {
		char *s;
		int i;
		bool b;
	} value;
	int type;
	const char *desc;
};

#define INIT_OPT_STRING(optshort, key, val, desc) \
	{ optshort, key, .value.s = val, OPT_STRING_STATIC, desc }
#define INIT_OPT_INT(optshort, key, val, desc) \
	{ optshort, key, .value.i = val, OPT_INTEGER, desc }
#define INIT_OPT_BOOL(optshort, key, val, desc) \
	{ optshort, key, .value.b = val, OPT_BOOL, desc }
#define INIT_OPT_NONE() \
	{ NULL, NULL, .value.s = NULL, OPT_NONE, NULL }

const char *opt_errmsg();
struct opt *find_opt(const char *key, struct opt * const opttab);

int opt_init_from_arg(struct opt * const opttab, int argc, char *argv[]);
int opt_init_from_file(struct opt * const opttab, const char *filename);
void opt_fini(struct opt * const opttab);
void opt_usage(struct opt * const opttab);

static inline const char *opt_string(struct opt *opt)
{
	assert(opt->type == OPT_STRING_STATIC || opt->type == OPT_STRING);
	return opt->value.s;
}

static inline int opt_int(struct opt *opt)
{
	assert(opt->type == OPT_INTEGER);
	return opt->value.i;
}

static inline bool opt_bool(struct opt *opt)
{
	assert(opt->type == OPT_BOOL);
	return opt->value.b;
}

#ifdef __cplusplus
}
#endif
#endif
