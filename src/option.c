#include "option.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ERRMSG_LEN 2048

static char errmsg[ERRMSG_LEN];

static bool convert_bool(const char *str)
{
	size_t len = strlen(str);

	if ((len == 2 && strcasecmp(str, "on") == 0) ||
	    (len == 3 && strcasecmp(str, "yes") == 0) ||
	    (len == 4 && strcasecmp(str, "true") == 0))
		return true;;

	if ((len == 3 && strcasecmp(str, "off") == 0) ||
	    (len == 2 && strcasecmp(str, "no") == 0) ||
	    (len == 5 && strcasecmp(str, "false") == 0))
		return false;

	return false;
}

static void option_parse_value(struct option *opt, const char *str)
{
	if (opt->value_type == OPTVAL_STRING_STATIC) {
		opt->value_type = OPTVAL_STRING;
		opt->value.s = malloc(strlen(str) + 1);
		strcpy(opt->value.s, str);
	} else if (opt->value_type == OPTVAL_STRING) {
		free(opt->value.s);
		opt->value.s = malloc(strlen(str) + 1);
		strcpy(opt->value.s, str);
	} else if (opt->value_type == OPTVAL_INTEGER) {
		opt->value.i = strtol(str, NULL, 0);
	} else if (opt->value_type == OPTVAL_BOOL) {
		opt->value.b = convert_bool(str);
	}
}

const char *option_errmsg()
{
	return errmsg;
}

static struct option *
__find_option(const char *optshort, struct option * const opttab)
{
	for (struct option *iter = opttab; iter->optshort != NULL; iter++) {
		if (strncmp(optshort, iter->optshort, strlen(optshort)) == 0)
			return iter;
	}

	return NULL;
}

struct option *find_option(const char *key, struct option * const opttab)
{
	for (struct option *iter = opttab; iter->optshort != NULL; iter++) {
		if (strcasecmp(key, iter->key) == 0)
			return iter;
	}

	return NULL;
}

int option_init_from_arg(struct option * const opttab, int argc, char *argv[])
{
	int index_args = 0;

	for (int i = 1; i < argc; i++) {
		char *z = argv[i];

		if (z[0] == '-') {
			struct option *tmp = __find_option(z, opttab);
			if (!tmp) {
				snprintf(errmsg, ERRMSG_LEN,
				         "unknown option %s", z);
				return OPTERR_UNKNOW_OPTION;
			}
			if (strchr(tmp->optshort, ':')) {
				i++;
				if (i == argc || argv[i][0] == '-') {
					snprintf(errmsg, ERRMSG_LEN,
					         "missing argument for %s", z);
					return OPTERR_MISS_ARG;
				}
				option_parse_value(tmp, argv[i]);
			} else {
				if (tmp->value_type != OPTVAL_BOOL) {
					snprintf(errmsg, ERRMSG_LEN,
					         "wrong value type of %s", z);
					return OPTERR_WRONG_VALUE;
				}
				tmp->value.b = true;
			}
		} else {
			char buffer[16];
			snprintf(buffer, sizeof(buffer), "%d", index_args++);
			struct option *tmp = __find_option(buffer, opttab);
			if (!tmp) {
				snprintf(errmsg, ERRMSG_LEN,
				         "unknown option %s", z);
				return OPTERR_UNKNOW_OPTION;
			}
			option_parse_value(tmp, z);
		}
	}

	return 0;
}

int option_init_from_file(struct option * const opttab, const char *filename)
{
	char line[1024], w1[1024], w2[1024];

	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		snprintf(errmsg, ERRMSG_LEN, "fopen: %s", strerror(errno));
		return OPTERR_CONFIG_FILE_OPEN_FAILED;
	}

	while (fgets(line, sizeof(line), file)) {
		if (line[0] == '#')
			continue;
		if (line[0] == '/' && line[1] == '/')
			continue;
		if (line[0] == '\n' && line[1] == '\0')
			continue;
		if (sscanf(line, "%1023[^:]: %1023[^\r\n[ #][ //]]", w1, w2) != 2)
			continue;

		struct option *tmp = find_option(w1, opttab);
		if (tmp) {
			option_parse_value(tmp, w2);
		} else {
			snprintf(errmsg, ERRMSG_LEN, "unknown option %s", w1);
			return OPTERR_UNKNOW_OPTION;
		}
	}

	fclose(file);
	return 0;
}

void option_fini(struct option * const opttab)
{
	for (struct option *iter = opttab; iter->optshort != NULL; iter++) {
		if (iter->value_type == OPTVAL_STRING) {
			assert(iter->value.s);
			free(iter->value.s);
			iter->value.s = NULL;
		}
	}
}
