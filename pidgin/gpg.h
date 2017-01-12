/*
 * Kontalk Pidgin plugin
 * Copyright (C) 2017 Kontalk Devteam <devteam@kontalk.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _GPG_H_
#define _GPG_H_

#include <glib.h>
#include <gpgme.h>

#define GPGME_REQUIRED_VERSION  "1.4.3"

gboolean gpg_init();
void gpg_free();

char *gpg_get_userid(const char *pattern, int secret_only);

char *gpg_decrypt(void *data, size_t size, size_t *out_size);

gpgme_error_t gpg_encrypt(const char *rcpt, const char *signer, char *data, size_t size, char **out, size_t *out_size);

void gpg_data_free(void *data);

const char *gpg_import_key(void *keydata, size_t size);

#endif  /* _GPG_H_ */
