
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

static gpgme_error_t
gpg_get_key(const char *pattern, gpgme_key_t *key, int secret_only)
{
    gpgme_error_t err;

    err = gpgme_op_keylist_start(ctx, pattern, secret_only);
    if (err)
        goto end;

    err = gpgme_op_keylist_next(ctx, key);
    if (err)
        goto end;

end:
    gpgme_op_keylist_end(ctx);
    return err;
}

// TODO this should return an error like gpg_encrypt
char *
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

void
gpg_data_free(void *data)
{
    if (data != NULL)
        gpgme_free(data);
}

gpgme_error_t
gpg_encrypt(const char *rcpt, const char *signer, char *data, size_t size, char **out, size_t *out_size)
{
    gpgme_key_t key_sign = NULL, key_encrypt = NULL;
    gpgme_data_t cipher = NULL, plain = NULL;
    gpgme_error_t err;

    // clear any previous signers
    gpgme_signers_clear(ctx);

    // find our signing key
    err = gpg_get_key(signer, &key_sign, 1);
    if (err) {
        purple_debug_warning(PACKAGE_NAME, "cannot find secret key!\n");
        goto end;
    }

    gpgme_signers_add(ctx, key_sign);

    // find encryption key
    err = gpg_get_key(rcpt, &key_encrypt, 0);
    if (err) {
        purple_debug_warning(PACKAGE_NAME, "cannot find encryption key!\n");
        goto end;
    }

    // prepare buffers
    gpgme_data_new_from_mem(&plain, data, size, 0);
    gpgme_data_new(&cipher);

    gpgme_key_t recp[] = { key_encrypt, NULL };
    // WARNING working around trust
    err = gpgme_op_encrypt_sign(ctx, recp, GPGME_ENCRYPT_ALWAYS_TRUST, plain, cipher);
    if (err) {
        gpgme_data_release(cipher);
        purple_debug_warning(PACKAGE_NAME, "encryption error!\n");
        goto end;
    }

    *out = gpgme_data_release_and_get_mem(cipher, out_size);
    return GPG_ERR_NO_ERROR;

end:
    if (plain != NULL)
        gpgme_data_release(plain);
    if (key_sign != NULL)
        gpgme_key_unref(key_sign);
    if (key_encrypt != NULL)
        gpgme_key_unref(key_encrypt);
    return err;
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
