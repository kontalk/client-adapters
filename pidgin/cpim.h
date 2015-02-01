#ifndef _CPIM_H_
#define _CPIM_H_

#include <stddef.h>

typedef struct {
    char *from;
    char *to;
    char *timestamp;
    char *type;

    char *body;
} cpim_message;

void cpim_message_free(cpim_message *msg);

cpim_message *cpim_parse_message(const char *text, size_t len);

#endif  /* _CPIM_H_ */
