
#include <string.h>

#include <gpgme.h>

#include <debug.h>

#include "gpg.h"
#include "kontalk.h"


static gpgme_ctx_t ctx;


gboolean
gpg_init()
{
    gboolean check = gpgme_check_version(GPGME_REQUIRED_VERSION) != NULL;
    if (check) {
        gpgme_error_t err = gpgme_new(&ctx);
        if (err) {
            purple_debug_fatal(PACKAGE_NAME, "cannot allocate GPGME context!\n");
            return FALSE;
        }
    }

    return check;
}

void
gpg_free()
{
    gpgme_release(ctx);
}

const char *
gpg_decrypt(void *data, size_t size, size_t *out_size)
{
    gpgme_data_t cipher, plain;
    gpgme_data_new_from_mem(&cipher, data, size, 0);
    gpgme_data_new(&plain);

    gpgme_error_t err = gpgme_op_decrypt_verify(ctx, cipher, plain);
    gpgme_data_release(cipher);
    if (err) {
        purple_debug_error(PACKAGE_NAME, "cannot decrypt data!\n");
        gpgme_data_release(plain);
        return NULL;
    }

    return gpgme_data_release_and_get_mem(plain, out_size);
}

const char *
gpg_import_key(void *keydata, size_t size)
{
    gpgme_data_t dh;
    gpgme_data_new_from_mem(&dh, keydata, size, 0);

    gpgme_error_t err = gpgme_op_import(ctx, dh);
    gpgme_data_release(dh);
    if (err) {
        purple_debug_error(PACKAGE_NAME, "cannot import key!\n");
        return NULL;
    }

    gpgme_import_result_t result = gpgme_op_import_result(ctx);
    if (result != NULL && (result->imported > 0 || result->unchanged > 0)) {
        return result->imports->fpr;
    }

    return NULL;
}
