#ifndef __STRINGX_H
#define __STRINGX_H

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Trim chars at head and tail
 *
 * @c: The char that should be trimmed, default to trim space if it is 0.
 */
void trim(char *str, char c);

#ifdef __cplusplus
}
#endif
#endif
