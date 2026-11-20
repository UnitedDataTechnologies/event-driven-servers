/*
   Copyright (C) 1999-2022 Marc Huber (Marc.Huber@web.de)
   All rights reserved.

   Redistribution and use in source and binary  forms,  with or without
   modification, are permitted provided  that  the following conditions
   are met:

   1. Redistributions of source code  must  retain the above copyright
      notice, this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions  and  the following disclaimer in
      the  documentation  and/or  other  materials  provided  with  the
      distribution.

   3. The end-user documentation  included with the redistribution,  if
      any, must include the following acknowledgment:

          This product includes software developed by Marc Huber
	  (Marc.Huber@web.de).

      Alternately,  this  acknowledgment  may  appear  in the software
      itself, if and wherever such third-party acknowledgments normally
      appear.

   THIS SOFTWARE IS  PROVIDED  ``AS IS''  AND  ANY EXPRESSED OR IMPLIED
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   IN NO EVENT SHALL  ITS  AUTHOR  BE  LIABLE FOR ANY DIRECT, INDIRECT,
   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
   BUT NOT LIMITED  TO,  PROCUREMENT OF  SUBSTITUTE  GOODS OR SERVICES;
   LOSS OF USE,  DATA,  OR PROFITS;  OR  BUSINESS INTERRUPTION) HOWEVER
   CAUSED AND ON ANY THEORY OF LIABILITY,  WHETHER IN CONTRACT,  STRICT
   LIABILITY,  OR TORT  (INCLUDING NEGLIGENCE OR OTHERWISE)  ARISING IN
   ANY WAY OUT OF THE  USE OF  THIS  SOFTWARE,  EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
 */

/*
   Copyright (c) 1995-1998 by Cisco systems, Inc.

   Permission to use, copy, modify, and distribute this software for
   any purpose and without fee is hereby granted, provided that this
   copyright and permission notice appear on all copies of the
   software and supporting documentation, the name of Cisco Systems,
   Inc. not be used in advertising or publicity pertaining to
   distribution of the program without specific prior permission, and
   notice be given in supporting documentation that modification,
   copying and distribution is by permission of Cisco Systems, Inc.

   Cisco Systems, Inc. makes no representations about the suitability
   of this software for any purpose.  THIS SOFTWARE IS PROVIDED ``AS
   IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
   WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
   FITNESS FOR A PARTICULAR PURPOSE.
*/

#ifndef __EAP_H_
#define __EAP_H_

#include <openssl/ssl.h>
#include "misc/str.h"

#define EAP_CODE_REQUEST    1
#define EAP_CODE_RESPONSE   2
#define EAP_CODE_SUCCESS    3
#define EAP_CODE_FAILURE    4

#define EAP_TYPE_IDENTITY   1
#define EAP_TYPE_NOTIFICATION 2
#define EAP_TYPE_NAK        3
#define EAP_TYPE_TLS        13
#define EAP_TYPE_TTLS       21

#define EAP_TLS_FLAG_L      0x80
#define EAP_TLS_FLAG_M      0x40
#define EAP_TLS_FLAG_S      0x20
#define EAP_TLS_FLAG_RESERVED 0x1f	/* Request; Response reserved is 0x3f */

/* EAP-TTLS (RFC 5281 3.1): same L/M/S bit values as EAP-TLS. The single
   Flags byte also carries the Version in its low three bits (TTLSv0 = 0);
   bits 0x18 are reserved. */
#define EAP_TTLS_FLAG_L     0x80
#define EAP_TTLS_FLAG_M     0x40
#define EAP_TTLS_FLAG_S     0x20
#define EAP_TTLS_FLAG_RESERVED 0x18
#define EAP_TTLS_VERSION_MASK 0x07
#define EAP_TTLS_VERSION    0

/* EAP-TTLS AVPs (RFC 5281 10.1): 4-octet code, flags, 3-octet length,
   optional Vendor-ID, data, zero padding to a 4-octet boundary. */
#define EAP_TTLS_AVP_USER_NAME     1
#define EAP_TTLS_AVP_USER_PASSWORD 2
#define EAP_TTLS_AVP_FLAG_V        0x80
#define EAP_TTLS_AVP_FLAG_M        0x40
#define EAP_TTLS_AVP_FLAG_RESERVED 0x3f
#define EAP_TTLS_AVP_HDR_LEN       8	/* code, flags and length */
#define EAP_TTLS_AVP_VENDOR_LEN    4	/* Vendor-ID when V is set */
#define EAP_TTLS_AVP_CODE_RADIUS_VENDOR_SPECIFIC 26

/* Inner PAP bounds: the RADIUS User-Name/User-Password value limits. */
#define EAP_TTLS_MAX_USER_NAME     255
#define EAP_TTLS_MAX_USER_PASSWORD 128

struct eap_ttls_avp {
    uint32_t code;		/* host byte order */
    u_char flags;		/* V/M, reserved bits cleared */
    uint32_t vendor_id;		/* host byte order; valid when V is set */
    const u_char *data;
    size_t data_len;
};

enum eap_ttls_avp_status {
    EAP_TTLS_AVP_MALFORMED = -1,
    EAP_TTLS_AVP_UNKNOWN_MANDATORY = -2,
    EAP_TTLS_AVP_END = 0,
    EAP_TTLS_AVP_OK = 1,
};

#define EAP_STATE_LEN       16
#define EAP_INVALID_LIMIT   5
#define EAP_DEFAULT_TIMEOUT 60
#define EAP_DEFAULT_MAX_MESSAGE 65535
#define EAP_DEFAULT_MAX_SESSIONS 4096
#define EAP_MAX_RADIUS_ATTR 253
#define EAP_MAX_FRAGMENT    3000
#define EAP_REPLY_CACHE_SIZE 4
#define EAP_COMPLETED_GRACE 30

enum eap_tls_state {
    EAP_TLS_NONE = 0,
    EAP_TLS_HANDSHAKE,
    EAP_TLS_FINAL_FLIGHT_SENDING,
    EAP_TLS_WAIT_FINAL_ACK,
    EAP_TLS_ALERT_SENT,
    EAP_TLS_DONE,
};

/* EAP-TTLS phase 1 is the TLS handshake; phase 2 is the inner method
   (AVPs) inside the established tunnel (RFC 5281 7.2). */
enum eap_ttls_phase {
    EAP_TTLS_PHASE1 = 0,
    EAP_TTLS_PHASE2,
};

struct eap_hdr {
    u_char code;
    u_char identifier;
    u_short length;
} __attribute__((__packed__));

struct eap_fragment {
    struct eap_fragment *next;
    size_t len;
    u_char data[1];
};

struct eap_cached_reply {
    u_char identifier;
    u_char code;
    u_char *eap;
    size_t eap_len;
    u_char *state;
    size_t state_len;
};

struct eap_session {
    u_char state[EAP_STATE_LEN];
    size_t state_len;
    tac_host *host;		/* RADIUS client this session belongs to */
    struct in6_addr peer_addr;	/* client address, host byte order */
    enum token transport;	/* S_radius_udp, S_radius_tcp, S_radius_tls, S_radius_dtls */
    time_t expires;
    time_t last_activity;
    u_char identifier;		/* last EAP identifier sent */
    u_char client_identifier;	/* last client EAP identifier seen */
    u_char success_identifier;	/* identifier for EAP-Success/Failure */
    int invalid;		/* invalid packets seen */
    int flags;
#define EAP_F_IDENTITY_SEEN 0x01
#define EAP_F_TLS_STARTED   0x02
#define EAP_F_HANDSHAKE_DONE 0x04
#define EAP_F_FAILED        0x08
#define EAP_F_FRAGMENT_ACK  0x10
#define EAP_F_COMPLETED     0x20
#define EAP_F_ALERT_SENT    0x40
#define EAP_F_IDENTITY_REQUESTED 0x80
#define EAP_F_TTLS_STARTED  0x100

    enum eap_tls_state tls_state;
    enum eap_ttls_phase ttls_phase;	/* EAP-TTLS only; PHASE2 after the handshake */
    u_char ttls_version;	/* negotiated EAP-TTLS version, 0 for TTLSv0 */
    str_t identity;		/* EAP-Response/Identity, unauthenticated */
    SSL *ssl;
    BIO *rbio;
    BIO *wbio;

    u_char *in;			/* EAP-Message reassembly buffer */
    size_t in_len;
    size_t in_max;

    u_char *tls_in;		/* EAP-TLS fragment reassembly buffer */
    size_t tls_len;
    size_t tls_max;
    size_t tls_total;		/* announced total, if L was set */

    u_char *avp_in;		/* EAP-TTLS phase-2 decrypted AVP buffer */
    size_t avp_len;
    size_t avp_max;

    struct eap_fragment *out;	/* pending EAP-TLS fragments */
    size_t out_offset;		/* offset of the next fragment */
    size_t out_total;

    struct eap_cached_reply reply_cache[EAP_REPLY_CACHE_SIZE];
    int reply_cache_next;

    u_char *profile_attrs;	/* profile/authorization AVPs for replay */
    size_t profile_attrs_len;

    u_char msk[64];
    u_char emsk[64];
};

int eap_has_message(rad_pak_hdr *pak);
void eap_radius_request(tac_session *session);
void eap_expire_sessions(tac_realm *r);
void eap_session_free(void *payload);
int eap_session_cmp(const void *a, const void *b);
SSL_CTX *eap_ssl_init(tac_realm *r);

#endif				/* __EAP_H_ */
