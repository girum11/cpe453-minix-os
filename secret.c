#include <minix/drivers.h>
#include <minix/chardriver.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>
#include <sys/ucred.h>
#include <minix/const.h>
#include <minix/syslib.h>
#include "secret.h"


// TODO: Why aren't constants these being imported by <minix/const.h>?
#define O_WRONLY 2
#define O_RDONLY 4
#define O_RDWR 6

#define SECRET_SIZE 8192

/*
 * Function prototypes for the hello driver.
 */
static int hello_open(message *m);
static int hello_close(message *m);
static struct device * hello_prepare(dev_t device);
static int hello_transfer(endpoint_t endpt, int opcode, u64_t position,
        iovec_t *iov, unsigned int nr_req, endpoint_t user_endpt, unsigned int
        flags);

/* SEF functions and variables. */
static void sef_local_startup(void);
static int sef_cb_init(int type, sef_init_info_t *info);
static int sef_cb_lu_state_save(int);
static int lu_state_restore(void);

/* Entry points to the hello driver. */
static struct chardriver hello_tab =
{
    hello_open,
    hello_close,
    nop_ioctl,
    hello_prepare,
    hello_transfer,
    nop_cleanup,
    nop_alarm,
    nop_cancel,
    nop_select,
    NULL
};

typedef enum { false, true } bool;

/** Represents the /dev/hello device. */
static struct device hello_device;

static char the_secret[SECRET_SIZE];
static uid_t owner;
static int open_file_descriptors;
static bool secret_opened_for_reading;

/** State variable to count the number of times the device has been opened. */
static int open_counter;

static int hello_open(message *m)
{
    struct ucred new_owner;

    // Sanity check: Don't open in Read/Write mode.
    if (m->COUNT == O_RDWR) {
        fprintf(stderr, "open() was opened in READ_WRITE mode by UID: %d. Bouncing open() request.\n", new_owner.uid);
        return EACCES;
    }

    // Grab the credentials for the new owner.
    if (getnucred(m->USER_ENDPT, &new_owner) != 0) {
        fprintf(stderr, "getnucred failed\n");
        return errno;
    }

    // If empty...
    if (owner == -1) {

        switch (m->COUNT) {

        // WRITE_ONLY mode on an empty secret.
        case O_WRONLY:
            printf("Empty Secret opened in WRITE_ONLY mode by UID: %d\n", new_owner.uid);

            // Set the owner to be full
            owner = new_owner.uid;

            printf("Open file descriptors: %d\n", ++open_file_descriptors);
            
            return OK;

        // READ_ONLY mode on an empty Secret.
        case O_RDONLY:
            fprintf(stderr, "UID %d opened an Empty Secret in READ_ONLY mode.\n", new_owner.uid);

            printf("Open file descriptors: %d\n", ++open_file_descriptors);

            // do nothing.
            return OK;
        // Error state.
        default:
            fprintf(stderr, "unknown open() flags: %d", m->COUNT);
            return -1;
        }
    } 
    // If full...
    else {
        switch (m->COUNT) {

        // READ_ONLY mode on a full Secret.
        case O_RDONLY:
            

            // If the Secret is being read by the owner...
            if (owner == new_owner.uid) {
                printf("Full Secret opened in READ_ONLY mode by the owner: %d\n", new_owner.uid);

                // Set the Secret to be empty.
                owner = -1;

                // The Secret is now opened for reading
                secret_opened_for_reading = true;

                printf("Open file descriptors: %d\n", ++open_file_descriptors);

                return OK;
            }
            // If the Secret is being read by SOMEONE ELSE...
            else {
                printf("Can't read someone else's secret: Full Secret opened in READ_ONLY mode by %d, even though the owner was %d\n", new_owner.uid, owner);
                return -1;
            }

        // WRITE_ONLY mode on a full Secret.
        case O_WRONLY:
            fprintf(stderr, "No space left on device\n");
            return -1;

        // Error state.
        default:
            fprintf(stderr, "unknown open() flags: %d", m->COUNT);
            return -1;
        }
    }

    return OK;
}

static int hello_close(message *UNUSED(m))
{
    int i = 0;
    printf("hello_close()\n");

    printf("Open file descriptors: %d\n", --open_file_descriptors);

    // TODO: If you just closed the last open file descriptor, clear
    // out the Secret.
    if (open_file_descriptors == 0 && secret_opened_for_reading) {
        printf("Closed the last file descriptor; clearing the secret.\n");
        for (i = 0; i < SECRET_SIZE; i++) {
            the_secret[i] = '\0';
        }

        secret_opened_for_reading = false;
    }
        

    return OK;
}

static struct device *hello_prepare(dev_t UNUSED(dev))
{
    hello_device.dv_base = make64(0, 0);
    hello_device.dv_size = make64(strlen(HELLO_MESSAGE), 0);
    return &hello_device;
}

static int hello_transfer(endpoint_t endpt, int opcode, u64_t position,
    iovec_t *iov, unsigned nr_req, endpoint_t user_endpt,
    unsigned int UNUSED(flags))
{
    int bytes, ret;

    printf("hello_transfer()\n");

    if (nr_req != 1)
    {
        /* This should never trigger for character drivers at the moment. */
        printf("HELLO: vectored transfer request, using first element only\n");
    }

    bytes = strlen(HELLO_MESSAGE) - ex64lo(position) < iov->iov_size ?
            strlen(HELLO_MESSAGE) - ex64lo(position) : iov->iov_size;

    if (bytes <= 0)
    {
        return OK;
    }
    switch (opcode)
    {
        case DEV_SCATTER_S:

            printf("transfer() WRITE...\n");
            ret = sys_safecopyfrom(user_endpt, (cp_grant_id_t) iov->iov_addr, 0, (vir_bytes) (the_secret + ex64lo(position)), bytes);
            iov->iov_size += bytes;

            printf("the secret: %s\n", the_secret);

            break;
        case DEV_GATHER_S:

            printf("transfer() READ...\n");
            ret = sys_safecopyto(endpt, (cp_grant_id_t) iov->iov_addr, 0,
                                (vir_bytes) (the_secret + ex64lo(position)),
                                 bytes);
            iov->iov_size -= bytes;

            printf("the secret: %s\n", the_secret);

            break;

        default:
            return EINVAL;
    }
    return ret;
}

static int sef_cb_lu_state_save(int UNUSED(state)) {
/* Save the state. */
    ds_publish_u32("open_counter", open_counter, DSF_OVERWRITE);

    return OK;
}

static int lu_state_restore() {
/* Restore the state. */
    u32_t value;

    ds_retrieve_u32("open_counter", &value);
    ds_delete_u32("open_counter");
    open_counter = (int) value;

    return OK;
}

static void sef_local_startup()
{
    /*
     * Register init callbacks. Use the same function for all event types
     */
    sef_setcb_init_fresh(sef_cb_init);
    sef_setcb_init_lu(sef_cb_init);
    sef_setcb_init_restart(sef_cb_init);

    /*
     * Register live update callbacks.
     */
    /* - Agree to update immediately when LU is requested in a valid state. */
    sef_setcb_lu_prepare(sef_cb_lu_prepare_always_ready);
    /* - Support live update starting from any standard state. */
    sef_setcb_lu_state_isvalid(sef_cb_lu_state_isvalid_standard);
    /* - Register a custom routine to save the state. */
    sef_setcb_lu_state_save(sef_cb_lu_state_save);

    /* Let SEF perform startup. */
    sef_startup();
}

static int sef_cb_init(int type, sef_init_info_t *UNUSED(info))
{
/* Initialize the hello driver. */
    int do_announce_driver = TRUE;

    open_counter = 0;
    switch(type) {
        case SEF_INIT_FRESH:
            printf("%s", HELLO_MESSAGE);
        break;

        case SEF_INIT_LU:
            /* Restore the state. */
            lu_state_restore();
            do_announce_driver = FALSE;

            printf("%sHey, I'm a new version!\n", HELLO_MESSAGE);
        break;

        case SEF_INIT_RESTART:
            printf("%sHey, I've just been restarted!\n", HELLO_MESSAGE);
        break;
    }

    /* Announce we are up when necessary. */
    if (do_announce_driver) {
        chardriver_announce();
    }

    /* Initialization completed successfully. */
    return OK;
}

int main(void)
{
    int i = 0;
    owner = -1;
    open_file_descriptors = 0;
    secret_opened_for_reading = false;

    for (i = 0; i < SECRET_SIZE; i++) {
        the_secret[i] = '\0';
    }

    /*
     * Perform initialization.
     */
    sef_local_startup();

    /*
     * Run the main loop.
     */
    chardriver_task(&hello_tab, CHARDRIVER_SYNC);
    return OK;
}