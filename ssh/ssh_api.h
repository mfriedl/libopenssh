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

/* TODO: Hier muessen spaeter die Werte fuer den Key-Exchange rein */
struct kex_params {
	char *proposal[PROPOSAL_MAX];
};

/* API functions */
struct session_state *ssh_init(int is_server, struct kex_params *kex_params);
int  ssh_add_hostkey(struct session_state* ssh, char *key);
int  ssh_packet_get(struct session_state* ssh);
void *ssh_packet_payload(struct session_state* ssh, u_int *len);
void ssh_packet_put(struct session_state* ssh, int type, const char *data, u_int len);
int  ssh_input_space(struct session_state* ssh, u_int len);
void ssh_input_append(struct session_state* ssh, const char *data, u_int len);
int  ssh_output_space(struct session_state* ssh, u_int len);
void *ssh_output_ptr(struct session_state* ssh, u_int *len);
void ssh_output_consume(struct session_state* ssh, u_int len);

#endif
