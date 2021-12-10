#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "ctap2.h"

#define DEVICE_ATTEMPT_MAX 64
#define CLIENT_PIN_LENGTH_MAX 256

void print_fido_dev_info(const fido_dev_info_t *info) {
    printf("\tpath = [%s]\n", fido_dev_info_path(info));
    printf("\tmanufacturer: [%s]\n", fido_dev_info_manufacturer_string(info));
    printf("\tproduct     : [%s]\n", fido_dev_info_product_string(info));
    printf("\tVID = [0x%04X], PID = [0x%04X]\n", fido_dev_info_vendor(info), fido_dev_info_product(info));
}

int is_wisecure_fido_dev(const fido_dev_info_t *info) {
    if ( (uint16_t)fido_dev_info_vendor(info) == 0x3352 && (uint16_t)fido_dev_info_product(info) == 0xEA61) {
        return 1;
    } else {
        return 0;
    }
}

const fido_dev_info_t* get_available_dev(const fido_dev_info_t *devlist, size_t len) {
	const fido_dev_info_t *di;

    for (size_t i=0; i<len; i++) {
        di = fido_dev_info_ptr(devlist, i);
        if (is_wisecure_fido_dev(di)) {
            return di;
        }
    }
    return NULL;
}

void input(char *buf, size_t maxlen, const char *prompt) {
    printf("%s", prompt);
    fgets(buf, maxlen, stdin);
    buf[strcspn(buf, "\n")] = '\0';
}

int ctap2_authenticate(const char *username) {
    const unsigned char *user_id = (const unsigned char*)username;
    char client_pin[CLIENT_PIN_LENGTH_MAX];

	const fido_dev_info_t *di;
	fido_dev_info_t *devlist;
	fido_dev_t *dev;
	size_t ndevs;
	int state;

    char cred_id[256], authdata[256];
    size_t cred_id_len, authdata_len;

	//fido_init(FIDO_DEBUG);
	fido_init(FIDO_DISABLE_U2F_FALLBACK);

    devlist = fido_dev_info_new(DEVICE_ATTEMPT_MAX);
	if (devlist == NULL) {
		printf("Memory is not available for creating device info list.\n");
        return -1;
	}

    fido_dev_info_manifest(devlist, DEVICE_ATTEMPT_MAX, &ndevs);

    di = get_available_dev(devlist, ndevs);

    if (di) {
        dev = fido_dev_new();
        if (dev == NULL) {
            fprintf(stderr, "[%s:%d] fido_dev_new\n", __FUNCTION__, __LINE__);
            return 0;
        }
        state = fido_dev_open(dev, fido_dev_info_path(di));
        if (state != FIDO_OK) {
            fprintf(stderr, "[%s:%d] fido_dev_open: %s\n", __FUNCTION__, __LINE__, fido_strerr(state));
            fido_dev_free(&dev);
            return 0;
        }

        input(client_pin, CLIENT_PIN_LENGTH_MAX, "Enter PIN (will echo!): "); // FIXME

        make_cred(dev, client_pin, "localhost", user_id, cred_id, &cred_id_len);
        // TODO: RP must store the cred_id and its length
        get_assert(dev, client_pin, "localhost", cred_id, cred_id_len, authdata, &authdata_len);

        fido_dev_close(dev);
        fido_dev_free(&dev);
    }

	fido_dev_info_free(&devlist, ndevs);

    if (authdata_len > 0)
        return 0;
    else
        return -1;
}

void make_cred(fido_dev_t *dev, const char *pin, const char *rp_id, const unsigned char *user_id, void *cred_id, size_t *p_cred_id_len) {
    // set cred_id to the pointer to credential id, and set cred_id_len to the length

    const unsigned char clientDataHash[32] = {0};
    fido_cred_t *cred = fido_cred_new();
    int state = 0;

    assert(cred != NULL);

    state = fido_cred_set_type(cred, COSE_ES256);
    assert(state == FIDO_OK);

    state = fido_cred_set_clientdata_hash(cred, clientDataHash, sizeof(clientDataHash));
    assert(state == FIDO_OK);

    fido_cred_set_rp(cred, rp_id, "");
    fido_cred_set_user(cred, user_id, sizeof(user_id), NULL, NULL, NULL);
    fido_cred_set_extensions(cred, 0);
    fido_dev_make_cred(dev, cred, pin);

    *p_cred_id_len = fido_cred_id_len(cred);
    memcpy(cred_id, fido_cred_id_ptr(cred), *p_cred_id_len);

    fido_cred_free(&cred);
}

void get_assert(fido_dev_t *dev, const char *pin, const char *rp_id, void *cred_id, size_t cred_id_len, void *authdata, size_t *p_authdata_len) {
    // set authdata and authdata_len

    const unsigned char clientData[32] = {0};
    fido_assert_t *assert = fido_assert_new();

    fido_assert_allow_cred(assert, cred_id, cred_id_len);
    fido_assert_set_clientdata(assert, clientData, sizeof(clientData));
    fido_assert_set_rp(assert, rp_id);
    fido_dev_get_assert(dev, assert, pin);

    *p_authdata_len = fido_assert_authdata_len(assert, 0);
    memcpy(authdata, fido_assert_authdata_ptr(assert, 0), *p_authdata_len);

    fido_assert_free(&assert);
}

