#include <stdio.h>
#include <string.h>
#include "ctap2.h"
#include <security/pam_modules.h>
#include <security/_pam_macros.h>

#define DEFAULT_USER "nobody"

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

/* --- authentication management functions --- */

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int state;
    const char *user = NULL;

    // Get the user
    state = pam_get_user(pamh, &user, NULL);
    if (state != PAM_SUCCESS) {
        D( ("get user returned error: %s", pam_strerror(pamh, state)) );
        return state;
    }
    if (user == NULL || *user == '\0') {
        D( ("username not known") );
        pam_set_item(pamh, PAM_USER, (const void *) DEFAULT_USER);
    }

    state = ctap2_authenticate(user);

    if (state == 0) {
        return PAM_SUCCESS;
    }

    // DEBUG ONLY: If fail but user is crboy, pass.
    if (state != 0 && !strcmp(user, "crboy")) {
        printf("CTAP2 authenticating fails, but crboy is always pass for DEBUG purpose!\n");
        return PAM_SUCCESS;
    }
    return PAM_IGNORE;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags,int argc, const char **argv)
{
     return PAM_SUCCESS;
}

/* --- account management functions --- */

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
     return PAM_SUCCESS;
}

/* --- password management --- */

PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
     return PAM_SUCCESS;
}

/* --- session management --- */

PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
     return PAM_SUCCESS;
}

/* end of module definition */

#ifdef PAM_STATIC

/* static module data */
struct pam_module _pam_permit_modstruct = {
    "pam_permit",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok
};

#endif

