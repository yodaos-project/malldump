#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <extopt.h>
#include <extlog.h>
#include "sys.h"
#include "ptmalloc.h"

#define CONFIG_FILE "malldump.conf"

static struct opt opttab[] = {
	INIT_OPT_BOOL("-h", "help", false, "print this usage"),
	INIT_OPT_BOOL("-D", "debug", false, "debug mode [defaut: false]"),

	INIT_OPT_STRING("-t:", "type", "ptmalloc",
	                "type of malloc [default: ptmalloc]"),
	INIT_OPT_INT("-p:", "pid", 0, "pid of the target process"),

// http://gcc.gnu.org/onlinedocs/cpp/Stringification.html
#define MALLINFO_DESC(OFFSET) "offset of mallinfo [default: " #OFFSET "]"
#define MALLINFO_DESC2(OFFSET) MALLINFO_DESC(OFFSET)
	INIT_OPT_INT("-I:", "mallinfo_offset", 0,
	             MALLINFO_DESC2(MALLINFO_OFFSET)),
#define MP__DESC(OFFSET) "offset of mp_ [default: " #OFFSET "]"
#define MP__DESC2(OFFSET) MP__DESC(OFFSET)
	INIT_OPT_INT("-P:", "mp__offset", 0, MP__DESC2(MP__OFFSET)),
#define NARENAS_DESC(OFFSET) "offset of narenas [default: " #OFFSET "]"
#define NARENAS_DESC2(OFFSET) NARENAS_DESC(OFFSET)
	INIT_OPT_INT("-A:", "narenas_offset", 0, NARENAS_DESC2(NARENAS_OFFSET)),

	INIT_OPT_BOOL("-H", "human", false,
	              "display size of memory in"
	              " human mode [default: false]"),
	INIT_OPT_NONE(),
};

int main(int argc, char *argv[])
{
	if (is_file_exist(CONFIG_FILE))
		assert(opt_init_from_file(opttab, CONFIG_FILE) == 0);

	if (opt_init_from_arg(opttab, argc, argv)) {
		fprintf(stderr, "%s\n", opt_errmsg());
		exit(EXIT_FAILURE);
	}

	if (opt_bool(find_opt("help", opttab))) {
		opt_usage(opttab);
		exit(2);
	}

	if (opt_bool(find_opt("debug", opttab)))
		log_set_level(LOG_LV_DEBUG);
	else
		log_set_level(LOG_LV_INFO);

	int pid = opt_int(find_opt("pid", opttab));
	if (!is_process_exist(pid)) {
		fprintf(stderr, "Process(%d) not exist, exit ...\n", pid);
		exit(EXIT_FAILURE);
	}

	const char *type = opt_string(find_opt("type", opttab));
	if (strcasecmp(type, "ptmalloc")) {
		fprintf(stderr, "Unknown malloc implementation type: %s,"
		        " only support ptmalloc now\n", type);
		exit(1);
	}

	struct ptmalloc_offset offset;
	offset.mallinfo = opt_int(find_opt("mallinfo_offset", opttab));
	offset.mp_ = opt_int(find_opt("mp__offset", opttab));
	offset.narenas = opt_int(find_opt("narenas_offset", opttab));
	ptmalloc_injection(pid, &offset, opt_bool(find_opt("human", opttab)));

	opt_fini(opttab);
	return 0;
}
