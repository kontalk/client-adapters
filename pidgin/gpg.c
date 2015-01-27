
#include "gpg.h"

#include <string.h>

#include <gpgme.h>

#include <debug.h>


static gpgme_ctx_t ctx;


gboolean gpg_init()
{
    gboolean check = gpgme_check_version(GPGME_REQUIRED_VERSION) != NULL;
    if (check) {
        gpgme_error_t err = gpgme_new(&ctx);
        if (err) {
            purple_debug_fatal("kontalk", "cannot allocate GPGME context!\n");
            return FALSE;
        }
    }

    return check;
}

void gpg_free()
{
    gpgme_release(ctx);
}

const char* gpg_import_key(void* keydata, size_t size)
{
    gpgme_data_t dh;
    gpgme_data_new_from_mem(&dh, keydata, size, 0);

    gpgme_error_t err = gpgme_op_import(ctx, dh);
    if (err) {
        purple_debug_error("kontalk", "cannot import key!\n");
        goto end;
    }

    gpgme_import_result_t result = gpgme_op_import_result(ctx);
    if (result != NULL && result->imported > 0) {
        return result->imports->fpr;
    }

end:
    gpgme_data_release(dh);
    return NULL;
}
