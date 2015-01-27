#ifndef _GPG_H_
#define _GPG_H_

#include <glib.h>

#define GPGME_REQUIRED_VERSION  "1.4.3"

gboolean gpg_init();
void gpg_free();

const char* gpg_import_key(void* keydata, size_t size);

#endif  /* _GPG_H_ */
