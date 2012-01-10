#ifndef API_H
#define API_H

#include <sys/queue.h>
#include <sys/types.h>
#include <signal.h>

#include "buffer.h"
#include "cipher.h"
#include "key.h"
#include "kex.h"
#include "ssh.h"
#include "ssh2.h"
#include "packet.h"

struct kex_params {
	char *proposal[PROPOSAL_MAX];
};

/* API functions */
struct ssh *ssh_init(int is_server, struct kex_params *kex_params);
void ssh_free(struct ssh *);
int  ssh_add_hostkey(struct ssh* ssh, char *key);
int  ssh_packet_get(struct ssh* ssh);
void *ssh_packet_payload(struct ssh* ssh, u_int *len);
void ssh_packet_put(struct ssh* ssh, int type, const char *data, u_int len);
int  ssh_input_space(struct ssh* ssh, u_int len);
void ssh_input_append(struct ssh* ssh, const char *data, u_int len);
int  ssh_output_space(struct ssh* ssh, u_int len);
void *ssh_output_ptr(struct ssh* ssh, u_int *len);
void ssh_output_consume(struct ssh* ssh, u_int len);

#endif
