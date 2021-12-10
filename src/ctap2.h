#ifndef CTAP2_H
#define CTAP_H

#include <fido.h>

void make_cred(fido_dev_t *dev, const char *pin, const char *rp_id, const unsigned char *user_id, void *cred_id, size_t *p_cred_id_len);
void get_assert(fido_dev_t *dev, const char *pin, const char *rp_id, void *cred_id, size_t cred_id_len, void *authdata, size_t *p_authdata_len);
int ctap2_authenticate(const char *username);

#endif
