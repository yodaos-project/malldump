#include "extopt.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stringx.h"

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

static void opt_parse_value(struct opt *opt, const char *str)
{
	if (opt->type == OPT_STRING_STATIC) {
		opt->type = OPT_STRING;
		opt->value.s = malloc(strlen(str) + 1);
		strcpy(opt->value.s, str);
		trim(opt->value.s, 0);
	} else if (opt->type == OPT_STRING) {
		free(opt->value.s);
		opt->value.s = malloc(strlen(str) + 1);
		strcpy(opt->value.s, str);
		trim(opt->value.s, 0);
	} else if (opt->type == OPT_INTEGER) {
		opt->value.i = strtol(str, NULL, 0);
	} else if (opt->type == OPT_BOOL) {
		opt->value.b = convert_bool(str);
	}
}

const char *opt_errmsg()
{
	return errmsg;
}

static struct opt *
__find_opt(const char *optshort, struct opt * const opttab)
{
	for (struct opt *iter = opttab; iter->optshort != NULL; iter++) {
		if (strncmp(optshort, iter->optshort, strlen(optshort)) == 0)
			return iter;
	}

	return NULL;
}

struct opt *find_opt(const char *key, struct opt * const opttab)
{
	for (struct opt *iter = opttab; iter->optshort != NULL; iter++) {
		if (strcasecmp(key, iter->key) == 0)
			return iter;
	}

	return NULL;
}

int opt_init_from_arg(struct opt * const opttab, int argc, char *argv[])
{
	int index_args = 0;

	for (int i = 1; i < argc; i++) {
		char *z = argv[i];

		if (z[0] == '-') {
			struct opt *tmp = __find_opt(z, opttab);
			if (!tmp) {
				snprintf(errmsg, ERRMSG_LEN,
				         "unknown opt %s", z);
				return OPTERR_UNKNOW_OPT;
			}
			if (strchr(tmp->optshort, ':')) {
				i++;
				if (i == argc || argv[i][0] == '-') {
					snprintf(errmsg, ERRMSG_LEN,
					         "missing argument for %s", z);
					return OPTERR_MISS_ARG;
				}
				opt_parse_value(tmp, argv[i]);
			} else {
				if (tmp->type != OPT_BOOL) {
					snprintf(errmsg, ERRMSG_LEN,
					         "wrong value type of %s", z);
					return OPTERR_WRONG_VALUE;
				}
				tmp->value.b = true;
			}
		} else {
			char buffer[16];
			snprintf(buffer, sizeof(buffer), "%d", index_args++);
			struct opt *tmp = __find_opt(buffer, opttab);
			if (!tmp) {
				snprintf(errmsg, ERRMSG_LEN,
				         "unknown opt %s", z);
				return OPTERR_UNKNOW_OPT;
			}
			opt_parse_value(tmp, z);
		}
	}

	return 0;
}

int opt_init_from_file(struct opt * const opttab, const char *filename)
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
		if (sscanf(line, "%1023[^:]: %1023[^\r\n]", w1, w2) != 2)
			continue;

		struct opt *tmp = find_opt(w1, opttab);
		if (tmp) {
			opt_parse_value(tmp, w2);
		} else {
			snprintf(errmsg, ERRMSG_LEN, "unknown opt %s", w1);
			return OPTERR_UNKNOW_OPT;
		}
	}

	fclose(file);
	return 0;
}

void opt_fini(struct opt * const opttab)
{
	for (struct opt *iter = opttab; iter->optshort != NULL; iter++) {
		if (iter->type == OPT_STRING) {
			assert(iter->value.s);
			free(iter->value.s);
			iter->value.s = NULL;
		}
	}
}

void opt_usage(struct opt * const opttab)
{
	char buf[16];

	fprintf(stderr, "Usage:\n");
	for (struct opt *iter = opttab; iter->optshort != NULL; iter++) {
		snprintf(buf, sizeof(buf), "%s", iter->optshort);
		if (iter->type != OPT_BOOL)
			snprintf(buf + 2, sizeof(buf) - 2, " %s", "<arg>");
		fprintf(stderr, "  %-12s %s\n", buf, iter->desc);
	}
}
