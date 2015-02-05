#ifndef _GPG_H_
#define _GPG_H_

#include <glib.h>
#include <gpgme.h>

#define GPGME_REQUIRED_VERSION  "1.4.3"

gboolean gpg_init();
void gpg_free();

char *gpg_decrypt(void *data, size_t size, size_t *out_size);

gpgme_error_t gpg_encrypt(const char *rcpt, const char *signer, char *data, size_t size, char **out, size_t *out_size);

void gpg_data_free(void *data);

const char *gpg_import_key(void *keydata, size_t size);

#endif  /* _GPG_H_ */
