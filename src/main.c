#include <signal.h>
#include <sysrepo.h>
#include <unistd.h>

#include "plugin.h"
#include "plugin/common.h"

volatile int exit_application = 0;

static void sigint_handler(__attribute__((unused)) int signum);

int main(int argc, char *argv[])
{
    int error = SR_ERR_OK;
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    void *private_data = NULL;

    
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
                if (strcmp(argv[i + 1], "warn") == 0 || strcmp(argv[i + 1], "warning") == 0 || strcmp(argv[i + 1], "wrn") == 0) {
                    sr_log_stderr(SR_LL_WRN);
                    break;
                } else if (strcmp(argv[i + 1], "inf") == 0 || strcmp(argv[i + 1], "info") == 0 || strcmp(argv[i + 1], "information") == 0) {
                    sr_log_stderr(SR_LL_INF);
                    break;
                } else if (strcmp(argv[i + 1], "dbg") == 0 || strcmp(argv[i + 1], "debug") == 0 || strcmp(argv[i + 1], "debugging") == 0) {
                    sr_log_stderr(SR_LL_DBG);
                    break;
                }
            }
        }
    }
    else {
        sr_log_stderr(SR_LL_INF);
    }
    

    /* connect to sysrepo */
    error = sr_connect(SR_CONN_DEFAULT, &connection);
    if (error)
    {
        SRPLG_LOG_ERR(PLUGIN_NAME, "sr_connect error (%d): %s", error, sr_strerror(error));
        goto out;
    }

    error = sr_session_start(connection, SR_DS_RUNNING, &session);
    if (error)
    {
        SRPLG_LOG_ERR(PLUGIN_NAME, "sr_session_start error (%d): %s", error, sr_strerror(error));
        goto out;
    }

    error = sr_plugin_init_cb(session, &private_data);
    if (error)
    {
        SRPLG_LOG_ERR(PLUGIN_NAME, "sr_plugin_init_cb error");
        goto out;
    }

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application)
    {
        sleep(1);
    }

out:
    sr_plugin_cleanup_cb(session, private_data);
    sr_disconnect(connection);

    return error ? -1 : 0;
}

static void sigint_handler(__attribute__((unused)) int signum)
{
    SRPLG_LOG_WRN(PLUGIN_NAME, "Sigint called, exiting...");
    exit_application = 1;
}