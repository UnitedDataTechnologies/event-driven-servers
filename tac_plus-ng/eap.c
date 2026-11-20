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

#include "headers.h"

#ifdef WITH_SSL

#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
/* OpenSSL 1.1 returns a referenced certificate under this older name. */
#define SSL_get1_peer_certificate SSL_get_peer_certificate
#endif

/*
 * Attribute walkers. The RADIUS packet has already passed rad_check_failed()
 * on the receive path, but the EAP code re-validates every attribute so a
 * malformed packet cannot make it read past the buffer.
 */
static int eap_pak_attr_bounds(rad_pak_hdr *pak, u_char **p, u_char **e)
{
    size_t len;

    if (!pak)
	return 0;
    len = ntohs(pak->length);
    if (len < RADIUS_HDR_SIZE)
	return 0;
    *p = RADIUS_DATA(pak);
    *e = *p + len - RADIUS_HDR_SIZE;
    return 1;
}

int eap_has_message(rad_pak_hdr *pak)
{
    u_char *p, *e;

    if (!eap_pak_attr_bounds(pak, &p, &e))
	return 0;

    while (p + 2 <= e) {
	size_t alen = p[1];
	if (alen < 2 || alen > (size_t) (e - p))
	    return 0;
	if (p[0] == RADIUS_A_EAP_MESSAGE)
	    return 1;
	p += alen;
    }
    return 0;
}

/*
 * Concatenate the EAP-Message (79) attribute values in packet order.
 * RFC 3579 3.1 requires them to be consecutive. An EAP-Message attribute
 * with a zero-length value is EAP-Start: success with *eap_len == 0.
 * On failure, *identifier carries the first two concatenated EAP octets'
 * Identifier when they were seen, so the caller can send an EAP-Failure
 * that names the client's identifier. The buffer comes from the
 * tac_session pool and is valid until the session is cleaned up.
 */
static int eap_collect(tac_session *session, u_char **eap, size_t *eap_len,
		       u_char *identifier)
    __attribute__((unused));

static int eap_collect(tac_session *session, u_char **eap, size_t *eap_len,
		       u_char *identifier)
{
    struct radius_data *rd;
    u_char *p, *e;
    size_t total = 0, max;

    *eap = NULL;
    *eap_len = 0;
    if (identifier)
	*identifier = 0;

    if (!session || !session->ctx || !session->ctx->realm ||
	!session->radius_data || !session->radius_data->pak_in)
	return 0;

    rd = session->radius_data;
    if (!eap_pak_attr_bounds(rd->pak_in, &p, &e))
	return 0;

    max = (size_t) session->ctx->realm->eap_max_message;

    int seen = 0, block_done = 0;
    u_char idbuf[2];
    size_t idlen = 0;
    while (p + 2 <= e) {
	size_t alen = p[1];
	if (alen < 2 || alen > (size_t) (e - p))
	    return 0;
	if (p[0] == RADIUS_A_EAP_MESSAGE) {
	    size_t vlen = alen - 2;
	    /*
	     * Keep the first two EAP octets even when the message is rejected
	     * below: Code and Identifier let an EAP-Failure name the client's
	     * identifier, as RFC 3748 requires.
	     */
	    if (identifier && idlen < sizeof(idbuf)) {
		size_t take = sizeof(idbuf) - idlen;
		if (take > vlen)
		    take = vlen;
		memcpy(idbuf + idlen, p + 2, take);
		idlen += take;
		if (idlen == sizeof(idbuf))
		    *identifier = idbuf[1];
	    }
	    if (block_done)
		return 0;	/* EAP-Message attributes must be consecutive */
	    seen = 1;
	    if (total + vlen > max)
		return 0;
	    total += vlen;
	} else if (seen)
	    block_done = 1;
	p += alen;
    }

    if (!seen)
	return 0;
    if (!total)
	return 1;		/* EAP-Start */

    *eap = mem_alloc(session->mem, total);
    if (!*eap)
	return 0;

    p = RADIUS_DATA(rd->pak_in);
    while (p + 2 <= e) {
	size_t alen = p[1];
	if (p[0] == RADIUS_A_EAP_MESSAGE) {
	    memcpy(*eap + *eap_len, p + 2, alen - 2);
	    *eap_len += alen - 2;
	}
	p += alen;
    }
    return 1;
}

/*
 * Return the first State (24) attribute. No State attribute is not an
 * error; zero-length State and State longer than EAP_STATE_LEN are.
 * The returned pointer refers to the RADIUS packet.
 */
static int eap_get_state(tac_session *session, const u_char **state, size_t *state_len)
    __attribute__((unused));

static int eap_get_state(tac_session *session, const u_char **state, size_t *state_len)
{
    struct radius_data *rd;
    u_char *p, *e;

    *state = NULL;
    *state_len = 0;

    if (!session || !session->radius_data || !session->radius_data->pak_in)
	return 0;

    rd = session->radius_data;
    if (!eap_pak_attr_bounds(rd->pak_in, &p, &e))
	return 0;

    while (p + 2 <= e) {
	size_t alen = p[1];
	if (alen < 2 || alen > (size_t) (e - p))
	    return 0;
	if (p[0] == RADIUS_A_STATE) {
	    size_t vlen = alen - 2;
	    if (!vlen || vlen > EAP_STATE_LEN)
		return 0;
	    *state = p + 2;
	    *state_len = vlen;
	    return 1;		/* first State attribute wins */
	}
	p += alen;
    }
    return 1;
}

struct eap_parsed {
    u_char code;
    u_char identifier;
    u_short length;		/* declared length, host byte order */
    u_char type;		/* Request/Response type; 0 for Success/Failure */
    u_char flags;		/* EAP-TLS/EAP-TTLS flags, reserved bits cleared */
    u_char version;		/* EAP-TTLS version; 0 otherwise */
    const u_char *data;
    size_t data_len;
};

/*
 * Validate the EAP header per RFC 3748, RFC 5216 3.1/3.2 and RFC 5281 3.1:
 * - at least the 4-byte header must be present;
 * - the declared length must be >= 4 and must not exceed the buffer;
 * - octets beyond the declared length are padding and are ignored;
 * - EAP-TLS has one flags byte; EAP-TTLS has one flags byte whose low
 *   three bits carry the Version, and L carries a 4-octet TLS Message
 *   Length;
 * - an S bit in an EAP-Response is rejected;
 * - reserved bits are ignored on receive (cleared in *out).
 */
static int eap_parse_hdr(const u_char *eap, size_t eap_len, struct eap_parsed *out)
    __attribute__((unused));

static int eap_parse_hdr(const u_char *eap, size_t eap_len, struct eap_parsed *out)
{
    struct eap_hdr hdr;
    size_t length, off;

    if (!eap || !out || eap_len < sizeof(hdr))
	return 0;

    memcpy(&hdr, eap, sizeof(hdr));
    length = ntohs(hdr.length);
    if (length < sizeof(hdr) || length > eap_len)
	return 0;

    memset(out, 0, sizeof(*out));
    out->code = hdr.code;
    out->identifier = hdr.identifier;
    out->length = (u_short) length;

    if (hdr.code != EAP_CODE_REQUEST && hdr.code != EAP_CODE_RESPONSE) {
	out->data = eap + sizeof(hdr);
	out->data_len = length - sizeof(hdr);
	return 1;
    }

    if (length < sizeof(hdr) + 1)
	return 0;
    out->type = eap[sizeof(hdr)];
    off = sizeof(hdr) + 1;

    if (out->type == EAP_TYPE_TLS) {
	if (length < off + 1)
	    return 0;
	out->flags = eap[off];
	if (hdr.code == EAP_CODE_RESPONSE && (out->flags & EAP_TLS_FLAG_S))
	    return 0;		/* RFC 5216 3.2 */
	out->flags &= EAP_TLS_FLAG_L | EAP_TLS_FLAG_M | EAP_TLS_FLAG_S;
	off++;
    } else if (out->type == EAP_TYPE_TTLS) {
	if (length < off + 1)
	    return 0;		/* flags byte, with Version in the low bits */
	out->flags = eap[off];
	if (hdr.code == EAP_CODE_RESPONSE && (out->flags & EAP_TTLS_FLAG_S))
	    return 0;		/* RFC 5281 3.1 */
	out->version = out->flags & EAP_TTLS_VERSION_MASK;
	out->flags &= EAP_TTLS_FLAG_L | EAP_TTLS_FLAG_M | EAP_TTLS_FLAG_S;
	off++;
	if ((out->flags & EAP_TTLS_FLAG_L) && length < off + 4)
	    return 0;		/* L carries a 4-octet TLS Message Length */
    }

    out->data = eap + off;
    out->data_len = length - off;
    return 1;
}

/*
 * EAP-TTLS AVP iterator (RFC 5281 10.1). One AVP is a 4-octet code, a flags
 * byte (V/M), a 3-octet length, an optional 4-octet Vendor-ID when V is set,
 * data, and zero padding to a 4-octet boundary. The length includes the
 * 8-octet header (12 with a Vendor-ID) but excludes padding.
 *
 * Returns EAP_TTLS_AVP_OK with *avp filled and *off advanced, END at the end
 * of the sequence, MALFORMED for a truncated AVP, a length below the header
 * size, a length over the buffer or max_message, impossible padding, or
 * RADIUS attribute 26 used as a code, and UNKNOWN_MANDATORY for an unknown
 * AVP with M set. Unknown AVPs with M clear are OK and ignored by the caller.
 *
 * Never log avp->data: it may carry a cleartext User-Password inside the TLS
 * tunnel.
 */
static int eap_ttls_avp_next(const u_char *buf, size_t len, size_t *off,
			     size_t max_message, struct eap_ttls_avp *avp);

static int eap_ttls_avp_next(const u_char *buf, size_t len, size_t *off,
			     size_t max_message, struct eap_ttls_avp *avp)
{
    size_t remaining, hdr, length, padded;
    uint32_t code;
    u_char flags;

    if (!buf || !off || !avp || *off > len)
	return EAP_TTLS_AVP_MALFORMED;
    if (*off == len)
	return EAP_TTLS_AVP_END;

    remaining = len - *off;
    if (remaining < EAP_TTLS_AVP_HDR_LEN)
	return EAP_TTLS_AVP_MALFORMED;

    memcpy(&code, buf + *off, sizeof(code));
    code = ntohl(code);
    flags = buf[*off + 4];
    length = ((size_t) buf[*off + 5] << 16) |
	     ((size_t) buf[*off + 6] << 8) | (size_t) buf[*off + 7];

    if (code == EAP_TTLS_AVP_CODE_RADIUS_VENDOR_SPECIFIC)
	return EAP_TTLS_AVP_MALFORMED;
    if (length > max_message)
	return EAP_TTLS_AVP_MALFORMED;

    hdr = EAP_TTLS_AVP_HDR_LEN;
    if (flags & EAP_TTLS_AVP_FLAG_V)
	hdr += EAP_TTLS_AVP_VENDOR_LEN;
    if (length < hdr)
	return EAP_TTLS_AVP_MALFORMED;
    if (length > remaining)
	return EAP_TTLS_AVP_MALFORMED;

    padded = (length + 3) & ~(size_t) 3;
    if (padded > remaining)
	return EAP_TTLS_AVP_MALFORMED;

    memset(avp, 0, sizeof(*avp));
    avp->code = code;
    avp->flags = flags & (EAP_TTLS_AVP_FLAG_V | EAP_TTLS_AVP_FLAG_M);
    if (flags & EAP_TTLS_AVP_FLAG_V) {
	uint32_t vendor;

	memcpy(&vendor, buf + *off + EAP_TTLS_AVP_HDR_LEN, sizeof(vendor));
	avp->vendor_id = ntohl(vendor);
    }
    avp->data = buf + *off + hdr;
    avp->data_len = length - hdr;

    if (code != EAP_TTLS_AVP_USER_NAME && code != EAP_TTLS_AVP_USER_PASSWORD &&
	(flags & EAP_TTLS_AVP_FLAG_M))
	return EAP_TTLS_AVP_UNKNOWN_MANDATORY;

    *off += padded;
    return EAP_TTLS_AVP_OK;
}

/*
 * Encode one EAP-TTLS AVP into buf. Returns the number of bytes written,
 * including zero padding, or 0 when the AVP is invalid or does not fit.
 * Reserved flag bits are cleared; RADIUS attribute 26 is not an AVP code.
 */
static size_t eap_ttls_avp_encode(u_char *buf, size_t buflen, uint32_t code,
				  u_char flags, uint32_t vendor_id,
				  const u_char *data, size_t data_len)
    __attribute__((unused));

static size_t eap_ttls_avp_encode(u_char *buf, size_t buflen, uint32_t code,
				  u_char flags, uint32_t vendor_id,
				  const u_char *data, size_t data_len)
{
    size_t hdr = EAP_TTLS_AVP_HDR_LEN, length, padded;
    uint32_t net;

    if (!buf || (!data && data_len))
	return 0;
    if (code == EAP_TTLS_AVP_CODE_RADIUS_VENDOR_SPECIFIC)
	return 0;

    flags &= EAP_TTLS_AVP_FLAG_V | EAP_TTLS_AVP_FLAG_M;
    if (flags & EAP_TTLS_AVP_FLAG_V)
	hdr += EAP_TTLS_AVP_VENDOR_LEN;
    if (data_len > 0xffffff - hdr)
	return 0;

    length = hdr + data_len;
    padded = (length + 3) & ~(size_t) 3;
    if (padded > buflen)
	return 0;

    net = htonl(code);
    memcpy(buf, &net, sizeof(net));
    buf[4] = flags;
    buf[5] = (u_char) (length >> 16);
    buf[6] = (u_char) (length >> 8);
    buf[7] = (u_char) length;
    if (flags & EAP_TTLS_AVP_FLAG_V) {
	uint32_t vendor = htonl(vendor_id);

	memcpy(buf + EAP_TTLS_AVP_HDR_LEN, &vendor, sizeof(vendor));
    }
    if (data_len)
	memcpy(buf + hdr, data, data_len);
    memset(buf + length, 0, padded - length);
    return padded;
}

/*
 * Validate a complete AVP sequence (zero or more AVPs). Returns 1 when every
 * AVP is well-formed (unknown optional AVPs are ignored), 0 for a malformed
 * AVP or a sequence over max_message, and -1 for an unknown mandatory AVP.
 */
static int eap_ttls_avp_validate(const u_char *buf, size_t len, size_t max_message);

static int eap_ttls_avp_validate(const u_char *buf, size_t len, size_t max_message)
{
    struct eap_ttls_avp avp;
    size_t off = 0;
    int status;

    if (len > max_message)
	return 0;

    while ((status = eap_ttls_avp_next(buf, len, &off, max_message, &avp)) ==
	   EAP_TTLS_AVP_OK)
	;

    if (status == EAP_TTLS_AVP_END)
	return 1;
    if (status == EAP_TTLS_AVP_UNKNOWN_MANDATORY)
	return -1;
    return 0;
}

/*
 * Classify a possibly incomplete phase-2 AVP sequence. Returns 1 when buf
 * ends on an AVP boundary and every AVP is structurally complete, 0 when the
 * trailing bytes may be the beginning of an AVP that continues in a later
 * EAP-TTLS packet, and -1 for a definitely malformed AVP (RADIUS attribute
 * 26, a length over max_message, or a length below its header size).
 * *complete_len is the length of the complete prefix.
 *
 * The AVP stream inside TLS is byte-oriented: a client may split a TLS record
 * or an AVP anywhere across EAP-TTLS packets, so truncation at the tail is
 * not an error until the conversation is abandoned.
 */
static int eap_ttls_avp_complete_len(const u_char *buf, size_t len,
				     size_t max_message, size_t *complete_len)
{
    size_t off = 0;

    *complete_len = 0;
    while (off < len) {
	size_t remaining = len - off, hdr, length, padded;
	uint32_t code;
	u_char flags;

	if (remaining < EAP_TTLS_AVP_HDR_LEN)
	    return 0;		/* header continues in the next packet */

	memcpy(&code, buf + off, sizeof(code));
	code = ntohl(code);
	flags = buf[off + 4];
	length = ((size_t) buf[off + 5] << 16) |
		 ((size_t) buf[off + 6] << 8) | (size_t) buf[off + 7];

	if (code == EAP_TTLS_AVP_CODE_RADIUS_VENDOR_SPECIFIC ||
	    length > max_message)
	    return -1;

	hdr = EAP_TTLS_AVP_HDR_LEN;
	if (flags & EAP_TTLS_AVP_FLAG_V)
	    hdr += EAP_TTLS_AVP_VENDOR_LEN;
	if (length < hdr)
	    return -1;
	if (remaining < hdr || length > remaining)
	    return 0;		/* AVP (or its Vendor-ID) continues */

	padded = (length + 3) & ~(size_t) 3;
	if (padded > remaining)
	    return 0;		/* padding continues */

	off += padded;
    }

    *complete_len = off;
    return 1;
}

/*
 * Append decrypted phase-2 bytes to the AVP buffer, growing it as needed.
 * The buffer is bounded by eap_max_message. It carries the cleartext inner
 * PAP password, so every caller cleanses it before freeing.
 */
static int eap_ttls_avp_append(struct eap_session *es, const u_char *data,
			       size_t len, size_t max)
{
    size_t need = es->avp_len + len;

    if (need > max)
	return 0;

    if (need > es->avp_max) {
	size_t grow = es->avp_max ? es->avp_max : 1024;
	u_char *p;

	while (grow < need)
	    grow <<= 1;
	if (grow > max)
	    grow = max;

	p = realloc(es->avp_in, grow);
	if (!p)
	    return 0;
	es->avp_in = p;
	es->avp_max = grow;
    }

    if (len)
	memcpy(es->avp_in + es->avp_len, data, len);
    es->avp_len = need;
    return 1;
}

/*
 * Cleanse and release the phase-2 AVP buffer. It may hold the cleartext
 * inner PAP password, so it must never be freed without cleansing.
 */
static void eap_ttls_avp_reset(struct eap_session *es)
{
    if (!es->avp_in)
	return;

    OPENSSL_cleanse(es->avp_in, es->avp_max);
    free(es->avp_in);
    es->avp_in = NULL;
    es->avp_len = 0;
    es->avp_max = 0;
}

static struct eap_session *eap_lookup(tac_session *session, const u_char *state, size_t state_len);
static struct eap_session *eap_new_session(tac_session *session);

/*
 * Remove an EAP session from its realm tree. Used when a session was created
 * but cannot be completed; eap_session_free() releases the payload.
 */
static void eap_drop_session(tac_realm *r, struct eap_session *es)
{
    struct eap_session key;

    if (!r->eap_sessions || !es)
	return;

    memset(&key, 0, sizeof(key));
    key.state_len = es->state_len;
    memcpy(key.state, es->state, es->state_len);
    RB_search_and_delete(r->eap_sessions, &key);
}

/*
 * Store the unauthenticated EAP-Response/Identity. eap_session_free() frees
 * identity.txt with free(), so it must not come from the tac_session pool.
 * Embedded NULs would make the stored length disagree with the C string.
 */
static int eap_store_identity(struct eap_session *es, const struct eap_parsed *parsed)
{
    char *identity;

    if (!parsed->data_len || parsed->data_len > 255)
	return 0;

    identity = malloc(parsed->data_len + 1);
    if (!identity)
	return 0;
    memcpy(identity, parsed->data, parsed->data_len);
    identity[parsed->data_len] = 0;

    if (strlen(identity) != parsed->data_len) {
	free(identity);
	return 0;
    }

    free(es->identity.txt);
    str_set(&es->identity, identity, parsed->data_len);
    return 1;
}

static int eap_nak_proposes(const struct eap_parsed *parsed, u_char type)
{
    size_t i;

    for (i = 0; i < parsed->data_len; i++)
	if (parsed->data[i] == type)
	    return 1;
    return 0;
}

/*
 * Reply cache. RFC 5216 2.1.5: retransmitted fragments keep the same EAP
 * Identifier. A ring of the last EAP_REPLY_CACHE_SIZE replies, keyed by the
 * identifier of the request being answered, lets a retransmitted
 * Access-Request (or fragment ACK) get the exact same reply without
 * advancing the state machine. The eap_session outlives the tac_session, so
 * the cached EAP and State bytes are malloc()ed copies.
 */
static void eap_cache_reply(struct eap_session *es, u_char identifier,
			    u_char code, const u_char *eap, size_t eap_len,
			    const u_char *state, size_t state_len)
{
    struct eap_cached_reply *slot;

    if (!es)
	return;

    slot = &es->reply_cache[es->reply_cache_next];
    free(slot->eap);
    free(slot->state);
    memset(slot, 0, sizeof(*slot));
    slot->identifier = identifier;
    slot->code = code;

    if (eap_len) {
	slot->eap = malloc(eap_len);
	if (slot->eap) {
	    memcpy(slot->eap, eap, eap_len);
	    slot->eap_len = eap_len;
	}
    }
    if (state_len) {
	slot->state = malloc(state_len);
	if (slot->state) {
	    memcpy(slot->state, state, state_len);
	    slot->state_len = state_len;
	}
    }

    /* Do not leave a partial entry behind: replaying an EAP reply without
       its State would break the conversation. */
    if ((eap_len && !slot->eap) || (state_len && !slot->state)) {
	free(slot->eap);
	free(slot->state);
	memset(slot, 0, sizeof(*slot));
	slot->identifier = identifier;
	slot->code = code;
    }

    es->reply_cache_next = (es->reply_cache_next + 1) % EAP_REPLY_CACHE_SIZE;
}

static struct eap_cached_reply *eap_reply_lookup(struct eap_session *es, u_char identifier)
{
    int i;

    if (!es)
	return NULL;

    for (i = 0; i < EAP_REPLY_CACHE_SIZE; i++) {
	struct eap_cached_reply *slot = &es->reply_cache[i];

	if (slot->eap_len && slot->identifier == identifier)
	    return slot;
    }
    return NULL;
}

/*
 * Send an EAP reply tied to an EAP session and cache it first.
 * rad_send_eap_reply() frees the tac_session, so the cache must hold its
 * own copies of the EAP and State bytes.
 */
static void eap_send_reply(tac_session *session, struct eap_session *es,
			   u_char identifier, u_char code,
			   const u_char *eap, size_t eap_len,
			   const u_char *state, size_t state_len)
{
    /*
     * rad_send_eap_reply() would downgrade an oversized Access-Accept (or
     * Access-Challenge) to EAP-Failure in a best-effort Access-Reject, but
     * the reply cache would still hold the Accept. Preflight the real reply
     * and cache the Failure that is actually sent instead. The EAP-Failure
     * carries the client's response identifier (RFC 5216 2.1.3).
     */
    if (!rad_eap_reply_fits(session, code, eap_len, state_len)) {
	u_char pkt[sizeof(struct eap_hdr)];
	struct eap_hdr hdr = {
	    EAP_CODE_FAILURE,
	    es ? es->client_identifier : identifier,
	    htons(sizeof(pkt))
	};

	memcpy(pkt, &hdr, sizeof(hdr));
	eap_cache_reply(es, identifier, RADIUS_CODE_ACCESS_REJECT, pkt, sizeof(pkt), NULL, 0);
	rad_send_eap_reply(session, RADIUS_CODE_ACCESS_REJECT, pkt, sizeof(pkt), NULL, 0);
	return;
    }

    eap_cache_reply(es, identifier, code, eap, eap_len, state, state_len);
    rad_send_eap_reply(session, code, eap, eap_len, state, state_len);
}

/* EAP-Failure (4-byte packet) in an Access-Reject. */
static void eap_send_failure(tac_session *session, struct eap_session *es, u_char identifier)
{
    u_char pkt[sizeof(struct eap_hdr)];
    struct eap_hdr hdr = { EAP_CODE_FAILURE, identifier, htons(sizeof(pkt)) };

    memcpy(pkt, &hdr, sizeof(hdr));
    eap_send_reply(session, es, identifier, RADIUS_CODE_ACCESS_REJECT, pkt, sizeof(pkt), NULL, 0);
}

/* EAP-Success (4-byte packet) in an Access-Accept. */
static void eap_send_success(tac_session *session, struct eap_session *es, u_char identifier)
{
    u_char pkt[sizeof(struct eap_hdr)];
    struct eap_hdr hdr = { EAP_CODE_SUCCESS, identifier, htons(sizeof(pkt)) };

    memcpy(pkt, &hdr, sizeof(hdr));
    eap_send_reply(session, es, identifier, RADIUS_CODE_ACCESS_ACCEPT, pkt, sizeof(pkt), NULL, 0);
}

/*
 * Copy an identity into a malloc()ed C string. Certificate-derived identities
 * are lowercased (ASCII only); the lab-only EAP-Response/Identity is used as
 * supplied. Reject empty values, embedded NULs and values over 255 bytes.
 */
static char *eap_copy_identity(const u_char *data, size_t len, int lowercase)
{
    char *identity;
    size_t i;

    if (!data || !len || len > 255 || memchr(data, 0, len))
	return NULL;

    identity = malloc(len + 1);
    if (!identity)
	return NULL;

    for (i = 0; i < len; i++) {
	u_char c = data[i];

	identity[i] = (char) (lowercase && c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
    }
    identity[len] = 0;
    return identity;
}

static char *eap_cert_cn(X509 *cert)
{
    X509_NAME *subject;
    X509_NAME_ENTRY *entry;
    ASN1_STRING *data;
    int idx;

    subject = X509_get_subject_name(cert);
    if (!subject)
	return NULL;

    idx = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
    if (idx < 0)
	return NULL;

    entry = X509_NAME_get_entry(subject, idx);
    if (!entry)
	return NULL;

    data = X509_NAME_ENTRY_get_data(entry);
    if (!data)
	return NULL;

    return eap_copy_identity(ASN1_STRING_get0_data(data),
			     (size_t) ASN1_STRING_length(data), 1);
}

/*
 * First GEN_DNS subjectAltName. *found distinguishes "no DNS SAN" (fall
 * back to CN) from "a DNS SAN exists but is unusable" (reject).
 */
static char *eap_cert_san(X509 *cert, int *found)
{
    GENERAL_NAMES *names;
    char *identity = NULL;
    int i;

    *found = 0;
    names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (!names)
	return NULL;

    for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
	GENERAL_NAME *gn = sk_GENERAL_NAME_value(names, i);

	if (gn->type != GEN_DNS)
	    continue;
	*found = 1;
	identity = eap_copy_identity(ASN1_STRING_get0_data(gn->d.dNSName),
				     (size_t) ASN1_STRING_length(gn->d.dNSName), 1);
	break;
    }

    GENERAL_NAMES_free(names);
    return identity;
}

static char *eap_extract_identity(tac_session *session, struct eap_session *es)
{
    tac_realm *r = session->ctx->realm;
    char *identity = NULL;

    switch (r->eap_identity_source) {
    case S_cert_cn:
    case S_cert_san:
	if (es->ssl) {
	    X509 *cert = SSL_get1_peer_certificate(es->ssl);

	    if (cert) {
		if (r->eap_identity_source == S_cert_cn)
		    identity = eap_cert_cn(cert);
		else {
		    int found = 0;

		    identity = eap_cert_san(cert, &found);
		    if (!found)
			identity = eap_cert_cn(cert);
		}
		X509_free(cert);
	    }
	}
	break;
    case S_eap_identity:
	identity = eap_copy_identity((const u_char *) es->identity.txt,
				     es->identity.len, 0);
	if (identity)
	    report(session, LOG_WARNING, ~0,
		   "EAP: using unauthenticated EAP-Response/Identity for authorization");
	break;
    default:
	break;
    }
    return identity;
}

/*
 * Add the default MS-MPPE-Encryption-Policy/Types and, once the TLS
 * handshake has completed, the MSK halves as MS-MPPE-Recv-Key/Send-Key
 * (RFC 5216 2.3, RFC 2548 2.4.2). rad_add_mppe_key() encrypts with this
 * request's Request Authenticator, so an Access-Accept retransmission
 * re-encrypts the retained MSK instead of replaying cached ciphertext.
 */
#ifdef WITH_CRYPTO
static int eap_add_mppe(tac_session *session, struct eap_session *es)
{
    struct radius_data *rd = session->radius_data;

    if (!(es->flags & EAP_F_HANDSHAKE_DONE) || !rd)
	return 0;

    /* No RADIUS secret means no keying material is requested. */
    if (!session->ctx->key)
	return 1;

    /* Policy/Types (2 * 12) plus two 58-byte key VSAs must fit together with
       the EAP-Message attribute header and its 4-byte EAP packet, the
       Message-Authenticator reservation, and whatever profile attributes
       survive rad_send_eap_reply()'s stripping. Counting data_len here would
       overcount attributes that are removed later (EAP-Message, State,
       Message-Authenticator, Reply-Message). */
    if (rad_eap_effective_payload_len(session, RADIUS_CODE_ACCESS_ACCEPT) +
	2 * 12 + 2 * 58 + 2 + 4 + RADIUS_MA_RESERVE > RADIUS_MAX_ATTRIBUTES)
	return 0;

    rad_add_mppe_policy(session);
    rad_add_mppe_key(session, es->msk, 32, RADIUS_A_MS_MPPE_RECV_KEY);
    rad_add_mppe_key(session, es->msk + 32, 32, RADIUS_A_MS_MPPE_SEND_KEY);
    return 1;
}
#endif

/*
 * Cache the profile/authorization AVPs from the reply buffer so an
 * Access-Accept/Access-Reject retransmission can replay them. The MS-MPPE
 * keys are deliberately not cached; they are re-encrypted per request.
 */
static void eap_cache_profile_attrs(struct eap_session *es, tac_session *session)
{
    struct radius_data *rd = session->radius_data;

    free(es->profile_attrs);
    es->profile_attrs = NULL;
    es->profile_attrs_len = 0;
    if (!rd || !rd->data_len)
	return;

    es->profile_attrs = malloc(rd->data_len);
    if (!es->profile_attrs)
	return;
    memcpy(es->profile_attrs, rd->data, rd->data_len);
    es->profile_attrs_len = rd->data_len;
}

/*
 * Map the completed handshake to a user and run the existing authorization
 * path. On success send EAP-Success in an Access-Accept; the profile
 * attributes are already in session->radius_data->data. On an identity
 * extraction failure or a denial send EAP-Failure in an Access-Reject.
 * rad_send_eap_reply() frees the tac_session, so do not touch it afterwards.
 */
static enum token eap_identity_authorize(tac_session *session, struct eap_session *es,
					 u_char identifier)
{
    enum hint_enum hint = hint_nosuchuser;
    enum token res;
    char *identity, *resp = NULL;

    identity = eap_extract_identity(session, es);
    if (!identity) {
	report(session, LOG_WARNING, ~0, "EAP: no usable client identity");
	es->flags |= EAP_F_FAILED;
	eap_send_failure(session, es, identifier);
	return S_deny;
    }

    str_set(&session->username, mem_strdup(session->mem, identity), 0);
    free(identity);
    if (!session->username.txt) {
	report(session, LOG_ERR, ~0, "EAP: out of memory storing client identity");
	es->flags |= EAP_F_FAILED;
	eap_send_failure(session, es, identifier);
	return S_deny;
    }

    res = eap_authorize(session, &resp, &hint);
    if (res == S_permit) {
	eap_cache_profile_attrs(es, session);
#ifdef WITH_CRYPTO
	if (!eap_add_mppe(session, es)) {
	    /* The profile AVPs must not ride on the Access-Reject: drop them
	       from both the reply buffer and the replay cache, and start the
	       failure reply from an empty attribute buffer. */
	    free(es->profile_attrs);
	    es->profile_attrs = NULL;
	    es->profile_attrs_len = 0;
	    if (session->radius_data)
		session->radius_data->data_len = 0;
	    es->flags |= EAP_F_FAILED;
	    eap_send_failure(session, es, identifier);
	    return S_deny;
	}
#endif
	eap_send_success(session, es, identifier);
	return res;
    }

    eap_cache_profile_attrs(es, session);
    es->flags |= EAP_F_FAILED;
    eap_send_failure(session, es, identifier);
    return res;
}

/* EAP-Response/Nak proposing the configured method, for RADIUS role reversal
   (RFC 3579 2.6.2). */
static void eap_send_nak(tac_session *session, struct eap_session *es, u_char identifier,
			 u_char type)
{
    u_char pkt[sizeof(struct eap_hdr) + 2];
    struct eap_hdr hdr = { EAP_CODE_RESPONSE, identifier, htons(sizeof(pkt)) };

    memcpy(pkt, &hdr, sizeof(hdr));
    pkt[4] = EAP_TYPE_NAK;
    pkt[5] = type;
    eap_send_reply(session, es, identifier, RADIUS_CODE_ACCESS_REJECT, pkt, sizeof(pkt), NULL, 0);
}

/*
 * Send an EAP-Request in an Access-Challenge with the session's State. The
 * server identifier is incremented for every new request and kept in
 * es->identifier (the last identifier sent). EAP-TLS carries a flags byte;
 * EAP-TTLS carries one flags byte that also holds the Version in its low
 * three bits (TTLSv0 only). Reserved bits are zero on send (RFC 5216 3.1,
 * RFC 5281 3.1). Replies to requests carrying State are cached (cache != 0)
 * under the identifier of the request being answered; replies to no-State
 * requests are not, because those create a new session and are never looked
 * up by identifier.
 */
static void eap_send_request(tac_session *session, struct eap_session *es,
			     u_char type, u_char flags, const u_char *data, size_t data_len,
			     int cache)
{
    size_t len = sizeof(struct eap_hdr) + 1 + data_len;
    u_char identifier = (u_char) (es->identifier + 1);
    u_char *pkt;
    size_t off;

    if (type == EAP_TYPE_TLS)
	len++;
    else if (type == EAP_TYPE_TTLS)
	len++;			/* flags byte, Version in the low bits */

    pkt = mem_alloc(session->mem, len);
    if (!pkt) {
	eap_send_failure(session, es, identifier);
	return;
    }

    struct eap_hdr hdr = { EAP_CODE_REQUEST, identifier, htons((u_short) len) };
    memcpy(pkt, &hdr, sizeof(hdr));

    off = sizeof(hdr);
    pkt[off++] = type;
    if (type == EAP_TYPE_TLS)
	pkt[off++] = flags & (EAP_TLS_FLAG_L | EAP_TLS_FLAG_M | EAP_TLS_FLAG_S);
    else if (type == EAP_TYPE_TTLS)
	pkt[off++] = (flags & (EAP_TTLS_FLAG_L | EAP_TTLS_FLAG_M | EAP_TTLS_FLAG_S)) |
		     (es->ttls_version & EAP_TTLS_VERSION_MASK);
    if (data_len)
	memcpy(pkt + off, data, data_len);

    es->identifier = identifier;
    if (cache)
	eap_send_reply(session, es, es->client_identifier, RADIUS_CODE_ACCESS_CHALLENGE,
		       pkt, len, es->state, es->state_len);
    else
	rad_send_eap_reply(session, RADIUS_CODE_ACCESS_CHALLENGE, pkt, len, es->state, es->state_len);
}

/* The configured EAP method as an EAP Request/Response type. */
static u_char eap_method_type(tac_realm *r)
{
    return r->eap_method == S_ttls ? EAP_TYPE_TTLS : EAP_TYPE_TLS;
}

/*
 * Send the configured method's Start request: EAP-Request/EAP-TLS Start
 * (RFC 5216 3.1) or EAP-Request/EAP-TTLS Start with Version 0 (RFC 5281
 * 3.1). Only the S bit is set; reserved bits are zero on send.
 */
static void eap_send_start(tac_session *session, struct eap_session *es, tac_realm *r, int cache)
{
    u_char type = eap_method_type(r);

    if (type == EAP_TYPE_TTLS) {
	es->ttls_version = EAP_TTLS_VERSION;
	es->flags |= EAP_F_TTLS_STARTED;
	eap_send_request(session, es, type, EAP_TTLS_FLAG_S, NULL, 0, cache);
    } else
	eap_send_request(session, es, type, EAP_TLS_FLAG_S, NULL, 0, cache);
}

/*
 * Lazily create the server SSL object for an EAP-TLS or EAP-TTLS session.
 * Both methods share the same TLS 1.2 server profile and SSL/BIO setup;
 * SSL_set_bio() hands the memory BIOs to the SSL object, and
 * eap_session_free() frees them with SSL_free().
 */
static int eap_tls_start(struct eap_session *es, tac_realm *r)
{
    if (es->ssl)
	return 1;
    if (!r->eap_tls)
	return 0;

    es->ssl = SSL_new(r->eap_tls);
    if (!es->ssl)
	return 0;

    SSL_set_accept_state(es->ssl);
    es->rbio = BIO_new(BIO_s_mem());
    es->wbio = BIO_new(BIO_s_mem());
    if (!es->rbio || !es->wbio) {
	if (es->rbio)
	    BIO_free(es->rbio);
	if (es->wbio)
	    BIO_free(es->wbio);
	SSL_free(es->ssl);
	es->ssl = NULL;
	es->rbio = es->wbio = NULL;
	return 0;
    }

    SSL_set_bio(es->ssl, es->rbio, es->wbio);
    SSL_set_app_data(es->ssl, es);
    es->tls_state = EAP_TLS_HANDSHAKE;
    return 1;
}

/*
 * Drain all pending TLS output into a malloc()ed buffer. A certificate
 * flight is several KB, so the buffer is sized from BIO_ctrl_pending(),
 * not a fixed EAP/RADIUS packet size. *buf is NULL and *len is 0 when
 * there is nothing to send.
 */
static int eap_tls_drain(struct eap_session *es, u_char **buf, size_t *len)
{
    size_t total, got = 0;

    *buf = NULL;
    *len = 0;

    total = (size_t) BIO_ctrl_pending(es->wbio);
    if (!total)
	return 1;

    *buf = malloc(total);
    if (!*buf)
	return 0;

    while (got < total) {
	int n = BIO_read(es->wbio, *buf + got, (int) (total - got));
	if (n <= 0)
	    break;
	got += (size_t) n;
    }

    if (got != total) {
	free(*buf);
	*buf = NULL;
	return 0;
    }

    *len = got;
    return 1;
}

/*
 * Queue drained TLS output for EAP-TLS fragmentation. es->out holds the
 * whole flight; out_offset is the number of bytes already sent and
 * out_total the full length. The first fragment carries L and the total
 * length; M is set on all but the last fragment (RFC 5216 2.1.5).
 */
static int eap_tls_queue(struct eap_session *es, const u_char *buf, size_t len)
{
    struct eap_fragment *f;

    while (es->out) {
	struct eap_fragment *next = es->out->next;
	free(es->out);
	es->out = next;
    }
    es->out_offset = 0;
    es->out_total = 0;

    if (!len)
	return 1;

    f = malloc(sizeof(*f) + len);
    if (!f)
	return 0;

    f->next = NULL;
    f->len = len;
    memcpy(f->data, buf, len);
    es->out = f;
    es->out_total = len;
    return 1;
}

/*
 * Send the next EAP-Request fragment of the queued flight in an
 * Access-Challenge with State. EAP-TLS uses type 13 and a flags byte;
 * EAP-TTLS uses type 21 and one flags byte that also holds the Version in
 * its low three bits (RFC 5216 3.1, RFC 5281 3.1). The EAP identifier is
 * incremented per fragment; reserved bits are zero. Returns 1 on success,
 * 0 when there is nothing to send, -1 after sending EAP-Failure (the
 * tac_session is gone).
 */
static int eap_tls_send_fragment(tac_session *session, struct eap_session *es)
{
    tac_realm *r = session->ctx->realm;
    u_char type = eap_method_type(r);
    size_t hdr = 2;		/* type + flags; TTLS Version is in flags */
    size_t remain, chunk, len, off;
    u_char flags = 0;
    u_char identifier;
    u_char *pkt;

    if (!es->out || es->out_offset >= es->out_total)
	return 0;

    remain = es->out_total - es->out_offset;
    chunk = remain > EAP_MAX_FRAGMENT ? EAP_MAX_FRAGMENT : remain;
    identifier = (u_char) (es->identifier + 1);

    len = sizeof(struct eap_hdr) + hdr + chunk;
    if (!es->out_offset)
	len += 4;		/* TLS Message Length */

    pkt = mem_alloc(session->mem, len);
    if (!pkt) {
	eap_send_failure(session, es, identifier);
	return -1;
    }

    struct eap_hdr eap_hdr = { EAP_CODE_REQUEST, identifier, htons((u_short) len) };
    memcpy(pkt, &eap_hdr, sizeof(eap_hdr));
    off = sizeof(eap_hdr);
    pkt[off++] = type;

    if (!es->out_offset)
	flags |= EAP_TLS_FLAG_L;
    if (es->out_offset + chunk < es->out_total)
	flags |= EAP_TLS_FLAG_M;
    pkt[off++] = flags;
    if (type == EAP_TYPE_TTLS)
	pkt[off - 1] |= es->ttls_version & EAP_TTLS_VERSION_MASK;

    if (!es->out_offset) {
	uint32_t total = htonl((uint32_t) es->out_total);

	memcpy(pkt + off, &total, sizeof(total));
	off += sizeof(total);
    }

    memcpy(pkt + off, es->out->data + es->out_offset, chunk);
    es->out_offset += chunk;
    es->identifier = identifier;

    eap_send_reply(session, es, es->client_identifier, RADIUS_CODE_ACCESS_CHALLENGE,
		   pkt, len, es->state, es->state_len);
    return 1;
}

/*
 * RFC 5216 2.1.3: a TLS alert produced by the server must be sent in an
 * EAP-Request/EAP-TLS before EAP-Failure. Walk the TLS records in the
 * drained output; anything else means OpenSSL did not produce an alert.
 */
static int eap_tls_has_alert(const u_char *buf, size_t len)
{
    size_t off = 0;

    while (off + 5 <= len) {
	size_t reclen = ((size_t) buf[off + 3] << 8) | buf[off + 4];

	if (buf[off] == SSL3_RT_ALERT)
	    return 1;
	off += 5 + reclen;
    }
    return 0;
}

/*
 * Handshake failure. Send the TLS alert, if OpenSSL produced one, in an
 * EAP-Request of the configured method (Access-Challenge) and wait for the
 * peer's response; otherwise send EAP-Failure directly. The EAP session
 * stays in the realm tree: the reply helper frees the tac_session, not the
 * eap_session.
 */
static void eap_tls_fail(tac_session *session, struct eap_session *es, const char *reason)
{
    tac_realm *r = session->ctx->realm;
    u_char type = eap_method_type(r);
    const char *method = type == EAP_TYPE_TTLS ? "EAP-TTLS" : "EAP-TLS";
    u_char *buf = NULL;
    size_t len = 0;
    unsigned long err = ERR_get_error();

    es->flags |= EAP_F_FAILED;
    if (err) {
	char ebuf[256];
	report(session, LOG_ERR, ~0, "%s handshake failed: %s: %s",
	       method, reason, ERR_error_string(err, ebuf));
    } else
	report(session, LOG_ERR, ~0, "%s handshake failed: %s", method, reason);

    if (eap_tls_drain(es, &buf, &len) && len && eap_tls_has_alert(buf, len)) {
	es->tls_state = EAP_TLS_ALERT_SENT;
	es->flags |= EAP_F_ALERT_SENT;
	eap_send_request(session, es, type, 0, buf, len, 1);
	free(buf);
	return;
    }

    free(buf);
    eap_send_failure(session, es, es->success_identifier);
}

/*
 * RFC 5216 2.3 / RFC 5281 7.1 / RFC 5705: export 128 bytes with the
 * method-specific label and an empty context. MSK = bytes 0..63, EMSK =
 * 64..127. EAP-TLS uses "client EAP encryption" (RFC 5216 2.3); EAP-TTLS
 * uses "ttls keying material" (RFC 5281 7.1). The temporary key material is
 * cleansed and never logged.
 */
static int eap_derive_keys(tac_session *session, struct eap_session *es)
{
    tac_realm *r = session->ctx->realm;
    const char *label;
    size_t label_len;
    u_char keymat[128];

    if (r->eap_method == S_ttls) {
	label = "ttls keying material";
	label_len = 20;
    } else {
	label = "client EAP encryption";
	label_len = 21;
    }

    if (SSL_export_keying_material(es->ssl, keymat, sizeof(keymat),
				   label, label_len, NULL, 0, 0) != 1) {
	OPENSSL_cleanse(keymat, sizeof(keymat));
	eap_tls_fail(session, es, "key export");
	return 0;
    }

    memcpy(es->msk, keymat, sizeof(es->msk));
    memcpy(es->emsk, keymat + sizeof(es->msk), sizeof(es->emsk));
    OPENSSL_cleanse(keymat, sizeof(keymat));
    return 1;
}

/*
 * Empty EAP-Response of the configured method with State: a fragment ACK or
 * the final handshake ACK (RFC 5216 2.1.5 / 2.1.3, RFC 5281 3.2). Fragment
 * ACKs move the queued server flight forward one fragment at a time. The
 * ACK for the last server fragment completes the TLS handshake: EAP-TLS
 * authorizes the certificate identity and sends EAP-Success; EAP-TTLS enters
 * phase 2 by starting it with an empty EAP-Request/TTLS (no AVPs, Version 0).
 */
static void eap_tls_ack(tac_session *session, struct eap_session *es,
			const struct eap_parsed *parsed)
{
    tac_realm *r = session->ctx->realm;
    int sent;

    switch (es->tls_state) {
    case EAP_TLS_FINAL_FLIGHT_SENDING:
	/* More final-flight fragments are queued: one fragment per ACK. */
	sent = eap_tls_send_fragment(session, es);
	if (sent < 0)
	    return;
	if (es->out_offset >= es->out_total)
	    es->tls_state = EAP_TLS_WAIT_FINAL_ACK;
	return;
    case EAP_TLS_HANDSHAKE:
	/* Fragment ACK for a non-final server flight. */
	sent = eap_tls_send_fragment(session, es);
	if (sent < 0)
	    return;
	if (!sent)
	    eap_send_failure(session, es, parsed->identifier);
	return;
    case EAP_TLS_WAIT_FINAL_ACK:
	if (parsed->identifier != es->identifier) {
	    eap_send_failure(session, es, parsed->identifier);
	    return;
	}
	es->tls_state = EAP_TLS_DONE;
	es->success_identifier = parsed->identifier;
	if (r->eap_method == S_ttls) {
	    /* RFC 5281 7.2: the server starts phase 2. This cut sends an
	       empty EAP-Request/TTLS (no AVPs, Version 0); Task 22 parses the
	       client's phase-2 AVPs. */
	    es->ttls_phase = EAP_TTLS_PHASE2;
	    es->expires = io_now.tv_sec + r->eap_timeout;
	    eap_send_request(session, es, EAP_TYPE_TTLS, 0, NULL, 0, 1);
	    return;
	}
	es->flags |= EAP_F_COMPLETED;
	es->expires = io_now.tv_sec + EAP_COMPLETED_GRACE;
	eap_identity_authorize(session, es, parsed->identifier);
	return;
    default:
	/* ALERT_SENT and FAILED are handled by the caller; an ACK in DONE or
	   before the handshake started is a protocol error. */
	eap_send_failure(session, es, parsed->identifier);
	return;
    }
}

/*
 * Append a fragment to the EAP-TLS reassembly buffer, growing it as needed.
 * Reassembly is capped at eap_max_message (RFC 5216 2.1.5).
 */
static int eap_tls_append(struct eap_session *es, const u_char *data, size_t len, size_t max)
{
    size_t need = es->tls_len + len;

    if (need > max)
	return 0;

    if (need > es->tls_max) {
	size_t grow = es->tls_max ? es->tls_max : 4096;
	u_char *p;

	while (grow < need)
	    grow <<= 1;
	if (grow > max)
	    grow = max;

	p = realloc(es->tls_in, grow);
	if (!p)
	    return 0;
	es->tls_in = p;
	es->tls_max = grow;
    }

    if (len)
	memcpy(es->tls_in + es->tls_len, data, len);
    es->tls_len = need;
    return 1;
}

/*
 * EAP-Response with State for the TLS tunnel (EAP-TLS or EAP-TTLS):
 * reassemble client fragments (RFC 5216 2.1.5, RFC 5281 3.2), feed the
 * complete TLS message to the shared server SSL object and send its output
 * as fragments of the configured method. The final TLS flight is followed
 * by a peer ACK: EAP-TLS then sends EAP-Success, EAP-TTLS starts phase 2.
 */
static void eap_tls_request(tac_session *session, struct eap_session *es,
			    const struct eap_parsed *parsed)
{
    tac_realm *r = session->ctx->realm;
    u_char type = eap_method_type(r);
    u_char flag_l = type == EAP_TYPE_TTLS ? EAP_TTLS_FLAG_L : EAP_TLS_FLAG_L;
    u_char flag_m = type == EAP_TYPE_TTLS ? EAP_TTLS_FLAG_M : EAP_TLS_FLAG_M;
    const u_char *tls_data = parsed->data;
    size_t tls_data_len = parsed->data_len;
    int reassembled = 0;
    u_char *buf = NULL;
    size_t len = 0;
    int ret, err;

    /* After an alert, RFC 5216 2.1.3 answers the peer's response with
       EAP-Failure. Restart-on-ClientHello is not implemented. */
    if (es->tls_state == EAP_TLS_ALERT_SENT || (es->flags & EAP_F_FAILED)) {
	eap_send_failure(session, es, parsed->identifier);
	return;
    }

    /* An empty EAP-Response is a fragment or completion ACK. */
    if (!parsed->data_len) {
	eap_tls_ack(session, es, parsed);
	return;
    }

    /* Non-empty TLS data is only valid while the handshake is running and
       all server fragments have been acknowledged. */
    if (es->tls_state == EAP_TLS_FINAL_FLIGHT_SENDING ||
	es->tls_state == EAP_TLS_WAIT_FINAL_ACK ||
	es->tls_state == EAP_TLS_DONE ||
	(es->out && es->out_offset < es->out_total)) {
	eap_send_failure(session, es, parsed->identifier);
	return;
    }

    /*
     * Client-to-server fragmentation (RFC 5216 2.1.5, RFC 5281 3.2). L is
     * only valid on the first fragment and carries the 4-octet TLS Message
     * Length; M is set on all but the last fragment. A response with neither
     * flag and no pending reassembly feeds parsed->data directly.
     */
    if (parsed->flags & (flag_l | flag_m) || es->tls_len || es->tls_total) {
	/* RFC 5216 2.1.5: L is set on the first fragment of a fragmented
	   TLS message. A first fragment with M but no L is malformed. */
	if (!es->tls_len && !es->tls_total &&
	    (parsed->flags & flag_m) && !(parsed->flags & flag_l)) {
	    eap_send_failure(session, es, parsed->identifier);
	    return;
	}
	if (parsed->flags & flag_l) {
	    uint32_t total;

	    if (es->tls_len || es->tls_total) {
		/* L on a non-first fragment. */
		eap_send_failure(session, es, parsed->identifier);
		return;
	    }
	    if (parsed->data_len < sizeof(total)) {
		eap_send_failure(session, es, parsed->identifier);
		return;
	    }
	    memcpy(&total, parsed->data, sizeof(total));
	    total = ntohl(total);
	    if (total < 1 || total > (uint32_t) r->eap_max_message) {
		eap_send_failure(session, es, parsed->identifier);
		return;
	    }
	    es->tls_total = (size_t) total;
	    tls_data = parsed->data + sizeof(total);
	    tls_data_len = parsed->data_len - sizeof(total);
	}

	if (!eap_tls_append(es, tls_data, tls_data_len, (size_t) r->eap_max_message)) {
	    /* The fragment would exceed eap_max_message. */
	    eap_send_failure(session, es, parsed->identifier);
	    return;
	}

	if (parsed->flags & flag_m) {
	    /* Fragment ACK: empty EAP-Request of the configured method. */
	    eap_send_request(session, es, type, 0, NULL, 0, 1);
	    return;
	}

	if (es->tls_total && es->tls_len != es->tls_total) {
	    /* Reassembled length does not match the announced total. */
	    eap_send_failure(session, es, parsed->identifier);
	    return;
	}

	tls_data = es->tls_in;
	tls_data_len = es->tls_len;
	reassembled = 1;
    }

    if (!eap_tls_start(es, r)) {
	eap_send_failure(session, es, parsed->identifier);
	return;
    }

    if (BIO_write(es->rbio, tls_data, (int) tls_data_len) != (int) tls_data_len) {
	eap_tls_fail(session, es, "BIO_write");
	if (reassembled) {
	    es->tls_len = 0;
	    es->tls_total = 0;
	}
	return;
    }

    if (reassembled) {
	es->tls_len = 0;
	es->tls_total = 0;
    }

    ret = SSL_do_handshake(es->ssl);
    if (ret == 1) {
	es->flags |= EAP_F_HANDSHAKE_DONE;
	if (r->eap_verify_client && SSL_get_verify_result(es->ssl) != X509_V_OK) {
	    eap_tls_fail(session, es, "client certificate verification");
	    return;
	}
	/* Export the method-specific keying material once the handshake is
	   complete (RFC 5216 2.3 for EAP-TLS, RFC 5281 7.1 for EAP-TTLS). A
	   key-export failure fails the conversation closed. */
	if (!eap_derive_keys(session, es))
	    return;
    } else {
	err = SSL_get_error(es->ssl, ret);
	if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
	    eap_tls_fail(session, es, "SSL_do_handshake");
	    return;
	}
    }

    if (!eap_tls_drain(es, &buf, &len)) {
	eap_tls_fail(session, es, "BIO_read");
	return;
    }

    if (!len) {
	free(buf);
	if (ret == 1) {
	    /* Defensive: the handshake completed with no server output left
	       to send, so there is no final flight to ACK. */
	    es->tls_state = EAP_TLS_DONE;
	    es->success_identifier = parsed->identifier;
	    if (type == EAP_TYPE_TTLS) {
		/* RFC 5281 7.2: start phase 2 with an empty
		   EAP-Request/TTLS (no AVPs, Version 0). */
		es->ttls_phase = EAP_TTLS_PHASE2;
		es->expires = io_now.tv_sec + r->eap_timeout;
		eap_send_request(session, es, EAP_TYPE_TTLS, 0, NULL, 0, 1);
		return;
	    }
	    es->flags |= EAP_F_COMPLETED;
	    es->expires = io_now.tv_sec + EAP_COMPLETED_GRACE;
	    eap_identity_authorize(session, es, parsed->identifier);
	}
	/* Otherwise: waiting for more client data. Never send an empty
	   EAP-Request. */
	return;
    }

    if (!eap_tls_queue(es, buf, len)) {
	free(buf);
	eap_tls_fail(session, es, "BIO_read");
	return;
    }
    free(buf);

    if (ret == 1) {
	/* Final TLS flight (CCS/Finished): fragment it and wait for the
	   peer's fragment ACKs and final empty ACK. EAP-TLS then authorizes
	   and sends EAP-Success; EAP-TTLS starts phase 2. */
	es->tls_state = EAP_TLS_FINAL_FLIGHT_SENDING;
    } else
	es->tls_state = EAP_TLS_HANDSHAKE;

    if (eap_tls_send_fragment(session, es) < 0)
	return;
    if (ret == 1 && es->out_offset >= es->out_total)
	es->tls_state = EAP_TLS_WAIT_FINAL_ACK;
}

/*
 * Fail the phase-2 conversation closed: log a non-sensitive reason, drop the
 * decrypted AVP buffer (which may contain the cleartext password), and send
 * EAP-Failure with the client's identifier.
 */
static void eap_ttls_phase2_fail(tac_session *session, struct eap_session *es,
				 u_char identifier, const char *reason)
{
    report(session, LOG_WARNING, ~0, "EAP-TTLS: %s", reason);
    es->flags |= EAP_F_FAILED;
    eap_ttls_avp_reset(es);
    eap_send_failure(session, es, identifier);
}

/*
 * EAP-TTLS phase 2 (RFC 5281 7.2): the client's EAP-Response/TTLS payload is
 * TLS application data. Feed it into the established tunnel, read the
 * decrypted AVP stream, and parse a sequence that may be split across TLS
 * records and EAP-TTLS packets.
 *
 * PAP requires User-Name and User-Password. The inner identity is authorized
 * through the local password path (eap_ttls_authorize()); a permit sends
 * EAP-Success with the profile AVPs. Never log AVP data: the User-Password is
 * cleartext inside TLS.
 */
static void eap_ttls_phase2_request(tac_session *session, struct eap_session *es,
				    const struct eap_parsed *parsed)
{
    tac_realm *r = session->ctx->realm;
    size_t max = (size_t) r->eap_max_message;
    const u_char *tls_data = parsed->data;
    size_t tls_data_len = parsed->data_len;
    u_char tmp[4096];
    int n, err;

    if (!(es->flags & EAP_F_HANDSHAKE_DONE)) {
	eap_ttls_phase2_fail(session, es, parsed->identifier,
			     "phase-2 response before the TLS handshake");
	return;
    }

    /*
     * RFC 5281 3.2: L is set on the first fragment and the four-octet TLS
     * Message Length precedes the TLS data. Validate the announced length
     * against max-message and skip it before feeding the tunnel.
     */
    if (parsed->flags & EAP_TTLS_FLAG_L) {
	uint32_t total;

	if (tls_data_len < sizeof(total)) {
	    eap_ttls_phase2_fail(session, es, parsed->identifier,
				 "phase-2 L flag without TLS Message Length");
	    return;
	}
	memcpy(&total, tls_data, sizeof(total));
	total = ntohl(total);
	if (total < 1 || total > (uint32_t) max) {
	    eap_ttls_phase2_fail(session, es, parsed->identifier,
				 "phase-2 TLS Message Length exceeds max-message");
	    return;
	}
	tls_data += sizeof(total);
	tls_data_len -= sizeof(total);
    }

    /* An empty response cannot carry AVPs. A fragment with M set is answered
       with an empty request below. */
    if (!tls_data_len && !(parsed->flags & EAP_TTLS_FLAG_M)) {
	eap_ttls_phase2_fail(session, es, parsed->identifier,
			     "empty phase-2 response");
	return;
    }

    if (tls_data_len &&
	BIO_write(es->rbio, tls_data, (int) tls_data_len) !=
	(int) tls_data_len) {
	eap_ttls_phase2_fail(session, es, parsed->identifier,
			     "phase-2 BIO_write failed");
	return;
    }

    /*
     * Drain every complete TLS record. SSL_read() returns SSL_ERROR_WANT_READ
     * when the current TLS record is split across EAP-TTLS packets; wait for
     * the next packet then. A clean TLS shutdown (SSL_ERROR_ZERO_RETURN) and
     * every other TLS error fail closed.
     */
    for (;;) {
	n = SSL_read(es->ssl, tmp, (int) sizeof(tmp));
	if (n > 0) {
	    if (!eap_ttls_avp_append(es, tmp, (size_t) n, max)) {
		OPENSSL_cleanse(tmp, sizeof(tmp));
		eap_ttls_phase2_fail(session, es, parsed->identifier,
				     "phase-2 data exceeds max-message");
		return;
	    }
	    continue;
	}
	err = SSL_get_error(es->ssl, n);
	if (err == SSL_ERROR_WANT_READ)
	    break;
	OPENSSL_cleanse(tmp, sizeof(tmp));
	report(session, LOG_WARNING, ~0,
	       "EAP-TTLS: phase-2 SSL_read failed (%d)", err);
	eap_ttls_phase2_fail(session, es, parsed->identifier,
			     "TLS tunnel read error");
	return;
    }
    OPENSSL_cleanse(tmp, sizeof(tmp));

    /* RFC 5281 3.2: a fragment with M set is acknowledged with an empty
       EAP-Request/TTLS before the next fragment. Do not parse a partial
       message. */
    if (parsed->flags & EAP_TTLS_FLAG_M) {
	eap_send_request(session, es, EAP_TYPE_TTLS, 0, NULL, 0, 1);
	return;
    }

    if (!es->avp_len) {
	/* The TLS record carried no application data yet (for example, only
	   part of a record). Prompt for the next client EAP packet. */
	eap_send_request(session, es, EAP_TYPE_TTLS, 0, NULL, 0, 1);
	return;
    }

    {
	size_t complete_len = 0;
	int complete = eap_ttls_avp_complete_len(es->avp_in, es->avp_len, max,
						 &complete_len);

	if (complete < 0) {
	    eap_ttls_phase2_fail(session, es, parsed->identifier,
				 "malformed phase-2 AVP");
	    return;
	}
	if (!complete) {
	    /* The trailing AVP continues in a later EAP-TTLS packet. */
	    eap_send_request(session, es, EAP_TYPE_TTLS, 0, NULL, 0, 1);
	    return;
	}
	if (eap_ttls_avp_validate(es->avp_in, es->avp_len, max) != 1) {
	    eap_ttls_phase2_fail(session, es, parsed->identifier,
				 "invalid phase-2 AVP sequence");
	    return;
	}
    }

    {
	struct eap_ttls_avp avp;
	const u_char *user_name = NULL, *user_password = NULL;
	size_t user_name_len = 0, user_password_len = 0, off = 0;
	int have_user_name = 0, have_user_password = 0;
	char username[EAP_TTLS_MAX_USER_NAME + 1];
	char password[EAP_TTLS_MAX_USER_PASSWORD + 1];
	enum hint_enum hint = hint_nosuchuser;
	char *resp = NULL;
	enum token res;

	while (eap_ttls_avp_next(es->avp_in, es->avp_len, &off, max, &avp) ==
	       EAP_TTLS_AVP_OK) {
	    if (avp.code == EAP_TTLS_AVP_USER_NAME && !have_user_name) {
		user_name = avp.data;
		user_name_len = avp.data_len;
		have_user_name = 1;
	    } else if (avp.code == EAP_TTLS_AVP_USER_PASSWORD && !have_user_password) {
		user_password = avp.data;
		user_password_len = avp.data_len;
		have_user_password = 1;
	    }
	}

	if (!have_user_name || !have_user_password) {
	    eap_ttls_phase2_fail(session, es, parsed->identifier,
				 "PAP requires User-Name and User-Password AVPs");
	    return;
	}
	if (!user_name_len || user_name_len > EAP_TTLS_MAX_USER_NAME ||
	    memchr(user_name, 0, user_name_len)) {
	    eap_ttls_phase2_fail(session, es, parsed->identifier,
				 "invalid inner User-Name");
	    return;
	}

	/* RFC 5281 7.3 / RFC 2865: the cleartext password may be null-padded
	   to a multiple of 16. Strip trailing NULs, reject embedded NULs and
	   bound the value before copying it into a C string. */
	while (user_password_len && user_password[user_password_len - 1] == 0)
	    user_password_len--;
	if (!user_password_len || user_password_len > EAP_TTLS_MAX_USER_PASSWORD ||
	    memchr(user_password, 0, user_password_len)) {
	    eap_ttls_phase2_fail(session, es, parsed->identifier,
				 "invalid inner User-Password");
	    return;
	}

	memcpy(username, user_name, user_name_len);
	username[user_name_len] = 0;
	memcpy(password, user_password, user_password_len);
	password[user_password_len] = 0;

	/* RFC 5281 7.3: the inner User-Name is authoritative; the outer
	   EAP-Response/Identity (typically "anonymous") is not used. */
	str_set(&session->username,
		mem_strndup(session->mem, (u_char *) username, user_name_len),
		user_name_len);
	if (!session->username.txt) {
	    OPENSSL_cleanse(username, sizeof(username));
	    OPENSSL_cleanse(password, sizeof(password));
	    eap_ttls_phase2_fail(session, es, parsed->identifier,
				 "out of memory storing inner User-Name");
	    return;
	}

	res = eap_ttls_authorize(session, username, password, &resp, &hint);
	OPENSSL_cleanse(username, sizeof(username));
	OPENSSL_cleanse(password, sizeof(password));
	if (res != S_permit) {
	    eap_ttls_phase2_fail(session, es, parsed->identifier,
				 "inner PAP authorization denied");
	    return;
	}
    }

    eap_cache_profile_attrs(es, session);
#ifdef WITH_CRYPTO
    if (!eap_add_mppe(session, es)) {
	/* Never send an Access-Accept without keys. The profile AVPs must not
	   ride on the Access-Reject: drop them from both the reply buffer and
	   the replay cache, and start the failure reply from an empty
	   attribute buffer. */
	free(es->profile_attrs);
	es->profile_attrs = NULL;
	es->profile_attrs_len = 0;
	if (session->radius_data)
	    session->radius_data->data_len = 0;
	es->flags |= EAP_F_FAILED;
	eap_ttls_avp_reset(es);
	eap_send_failure(session, es, parsed->identifier);
	return;
    }
#endif
    es->flags |= EAP_F_COMPLETED;
    es->expires = io_now.tv_sec + EAP_COMPLETED_GRACE;
    eap_ttls_avp_reset(es);
    eap_send_success(session, es, parsed->identifier);
}

/*
 * EAP-Response/EAP-TTLS. The packet layer accepts TTLSv0 only: a response
 * with another version fails the conversation. The S bit is already
 * rejected by eap_parse_hdr() for responses. Phase 1 (the TLS handshake) is
 * handled by the shared EAP-TLS tunnel code. Phase 2 starts with the empty
 * EAP-Request/TTLS sent by eap_tls_ack(); eap_ttls_phase2_request() reads the
 * decrypted AVPs, runs the PAP state machine and authorizes the inner user.
 */
static void eap_ttls_request(tac_session *session, struct eap_session *es,
			     const struct eap_parsed *parsed)
{
    if ((es->flags & EAP_F_FAILED) || !(es->flags & EAP_F_TTLS_STARTED)) {
	eap_send_failure(session, es, parsed->identifier);
	return;
    }

    if (parsed->version != EAP_TTLS_VERSION) {
	report(session, LOG_WARNING, ~0,
	       "EAP-TTLS: unsupported version %u (only version %d is supported)",
	       parsed->version, EAP_TTLS_VERSION);
	es->flags |= EAP_F_FAILED;
	eap_send_failure(session, es, parsed->identifier);
	return;
    }

    if (es->ttls_phase == EAP_TTLS_PHASE2) {
	eap_ttls_phase2_request(session, es, parsed);
	return;
    }

    eap_tls_request(session, es, parsed);
}

void eap_radius_request(tac_session *session)
{
    tac_realm *r = session->ctx->realm;
    u_char method = eap_method_type(r);
    struct eap_parsed parsed;
    struct eap_cached_reply *cached;
    struct eap_session *es;
    const u_char *state;
    u_char *eap;
    size_t eap_len, state_len;
    u_char identifier, collected_identifier;

    if (session->ctx->radius_1_1 == BISTATE_YES) {
	eap_send_failure(session, NULL, 0);
	return;
    }

    if (!eap_collect(session, &eap, &eap_len, &collected_identifier) ||
	!eap_get_state(session, &state, &state_len)) {
	eap_send_failure(session, NULL,
			 eap_len >= 2 ? eap[1] : collected_identifier);
	return;
    }

    /* A zero-length EAP-Message value is EAP-Start; it must not carry State. */
    if (!eap_len) {
	if (state_len) {
	    eap_send_failure(session, NULL, 0);
	    return;
	}
	es = eap_new_session(session);
	if (!es) {
	    eap_send_failure(session, NULL, 0);
	    return;
	}
	eap_send_request(session, es, EAP_TYPE_IDENTITY, 0, NULL, 0, 0);
	/* The client answers EAP-Request/Identity with the State we just sent;
	   accept that State-bearing response as the identity for TLS Start. */
	es->flags |= EAP_F_IDENTITY_REQUESTED;
	return;
    }

    if (!eap_parse_hdr(eap, eap_len, &parsed)) {
	eap_send_failure(session, NULL, eap_len >= 2 ? eap[1] : 0);
	return;
    }
    identifier = parsed.identifier;

    /* EAP is client-to-server here; anything else is RADIUS role reversal.
       Do not cache the Nak under the offending identifier: a later
       legitimate request could replay it. */
    if (parsed.code != EAP_CODE_RESPONSE) {
	eap_send_nak(session, NULL, identifier, method);
	return;
    }

    if (!state_len) {
	switch (parsed.type) {
	case EAP_TYPE_IDENTITY:
	    es = eap_new_session(session);
	    if (!es) {
		eap_send_failure(session, NULL, identifier);
		return;
	    }
	    if (!eap_store_identity(es, &parsed)) {
		eap_drop_session(r, es);
		eap_send_failure(session, NULL, identifier);
		return;
	    }
	    es->client_identifier = identifier;
	    es->success_identifier = identifier;
	    es->flags |= EAP_F_IDENTITY_SEEN;
	    eap_send_start(session, es, r, 0);
	    return;
	case EAP_TYPE_NAK:
	    if (!eap_nak_proposes(&parsed, method)) {
		eap_send_failure(session, NULL, identifier);
		return;
	    }
	    es = eap_new_session(session);
	    if (!es) {
		eap_send_failure(session, NULL, identifier);
		return;
	    }
	    es->client_identifier = identifier;
	    es->success_identifier = identifier;
	    eap_send_start(session, es, r, 0);
	    return;
	default:
	    eap_send_failure(session, NULL, identifier);
	    return;
	}
    }

    es = eap_lookup(session, state, state_len);
    if (!es || es->expires < io_now.tv_sec) {
	/* Unknown or expired State: reject instead of refreshing an expired
	   session. The periodic handler may not have purged it yet. */
	report(session, LOG_WARNING, ~0, "EAP: unknown or expired State from %s",
	       session->ctx->device_addr_ascii.txt);
	if (es)
	    eap_drop_session(r, es);
	eap_send_failure(session, NULL, identifier);
	return;
    }

    /*
     * RFC 5216 2.1.5: retransmitted fragments keep the same Identifier.
     * Replay the cached reply before dispatching, so neither a retransmitted
     * Access-Request nor a retransmitted final ACK after EAP-Success moves
     * the state machine forward.
     */
    cached = eap_reply_lookup(es, identifier);
    if (cached) {
	/* A valid retransmission: clear the invalid counter without
	   advancing the state machine. Do not extend expires: a cached
	   replay must not keep the session alive indefinitely. */
	es->invalid = 0;
	es->last_activity = io_now.tv_sec;
	/* Replay the profile/authorization AVPs from the original final reply.
	   Access-Challenge retransmissions must not acquire AVPs from a later
	   authorization. */
	if ((cached->code == RADIUS_CODE_ACCESS_ACCEPT ||
	     cached->code == RADIUS_CODE_ACCESS_REJECT) &&
	    es->profile_attrs_len && es->profile_attrs) {
	    struct radius_data *rd = session->radius_data;

	    if (rd->data_len + es->profile_attrs_len + RADIUS_HDR_SIZE + 18 <= sizeof(rd->data)) {
		memcpy(rd->data + rd->data_len, es->profile_attrs, es->profile_attrs_len);
		rd->data_len += es->profile_attrs_len;
	    }
	}
#ifdef WITH_CRYPTO
	/* The reply cache holds EAP/State only; the MSK is retained in the
	   completed eap_session and must be re-encrypted with the new
	   Request Authenticator (RFC 2548 2.4.2). */
	if (cached->code == RADIUS_CODE_ACCESS_ACCEPT && !eap_add_mppe(session, es)) {
	    /* Fail closed rather than send an Access-Accept without keys. */
	    es->flags |= EAP_F_FAILED;
	    eap_send_failure(session, NULL, identifier);
	    return;
	}
#endif
	rad_send_eap_reply(session, cached->code, cached->eap, cached->eap_len,
			   cached->state, cached->state_len);
	return;
    }

    if (identifier != es->identifier) {
	es->invalid++;
	if (es->invalid >= EAP_INVALID_LIMIT) {
	    report(session, LOG_WARNING, ~0,
		   "EAP: invalid identifier limit reached (%d)", es->invalid);
	    /* Drop the session so a client cannot keep it alive with bogus
	       identifiers. */
	    eap_drop_session(r, es);
	    eap_send_failure(session, NULL, identifier);
	    return;
	}
	/* Every Access-Request needs a reply, but do not cache a failure under
	   an identifier that is not part of the conversation. */
	eap_send_failure(session, NULL, identifier);
	return;
    }

    es->invalid = 0;
    es->client_identifier = identifier;
    es->success_identifier = identifier;
    es->expires = io_now.tv_sec + r->eap_timeout;
    es->last_activity = io_now.tv_sec;

    switch (parsed.type) {
    case EAP_TYPE_IDENTITY:
	/* EAP-Start sent EAP-Request/Identity with State; accept the client's
	   State-bearing Identity response and continue with TLS Start, like
	   the no-State Identity path above. Any other Identity with State is
	   still invalid. */
	if ((es->flags & EAP_F_IDENTITY_REQUESTED) && !(es->flags & EAP_F_IDENTITY_SEEN)) {
	    if (!eap_store_identity(es, &parsed)) {
		eap_drop_session(r, es);
		eap_send_failure(session, NULL, identifier);
		return;
	    }
	    es->client_identifier = identifier;
	    es->success_identifier = identifier;
	    es->flags |= EAP_F_IDENTITY_SEEN;
	    es->flags &= ~EAP_F_IDENTITY_REQUESTED;
	    eap_send_start(session, es, r, 0);
	    return;
	}
	eap_send_failure(session, es, identifier);
	return;
    case EAP_TYPE_TLS:
	if (r->eap_method != S_tls) {
	    eap_send_failure(session, es, identifier);
	    return;
	}
	eap_tls_request(session, es, &parsed);
	return;
    case EAP_TYPE_TTLS:
	if (r->eap_method != S_ttls) {
	    eap_send_failure(session, es, identifier);
	    return;
	}
	eap_ttls_request(session, es, &parsed);
	return;
    case EAP_TYPE_NAK:
	if (eap_nak_proposes(&parsed, method))
	    eap_send_start(session, es, r, 1);
	else
	    eap_send_failure(session, es, identifier);
	return;
    default:
	eap_send_failure(session, es, identifier);
	return;
    }
}

void eap_expire_sessions(tac_realm *r)
{
    if (r->eap_sessions) {
	rb_node_t *rbn, *next;
	for (rbn = RB_first(r->eap_sessions); rbn; rbn = next) {
	    struct eap_session *e = RB_payload(rbn, struct eap_session *);
	    next = RB_next(rbn);
	    if (e->expires < io_now.tv_sec)
		RB_delete(r->eap_sessions, rbn);
	}
    }
    if (r->realms) {
	rb_node_t *rbn;
	for (rbn = RB_first(r->realms); rbn; rbn = RB_next(rbn))
	    eap_expire_sessions(RB_payload(rbn, tac_realm *));
    }
}

void eap_session_free(void *payload)
{
    struct eap_session *e = payload;
    int i;

    if (!e)
	return;

    if (e->ssl)
	SSL_free(e->ssl);	/* frees rbio/wbio */
    free(e->in);
    free(e->tls_in);
    if (e->avp_in) {
	OPENSSL_cleanse(e->avp_in, e->avp_max);
	free(e->avp_in);
    }
    while (e->out) {
	struct eap_fragment *f = e->out;
	e->out = f->next;
	free(f);
    }
    for (i = 0; i < EAP_REPLY_CACHE_SIZE; i++) {
	free(e->reply_cache[i].eap);
	free(e->reply_cache[i].state);
    }
    free(e->identity.txt);
    free(e->profile_attrs);
    OPENSSL_cleanse(e->msk, sizeof(e->msk));
    OPENSSL_cleanse(e->emsk, sizeof(e->emsk));
    free(e);
}

int eap_session_cmp(const void *a, const void *b)
{
    const struct eap_session *x = a, *y = b;

    if (x->state_len != y->state_len)
	return (int) x->state_len - (int) y->state_len;
    return memcmp(x->state, y->state, x->state_len);
}

static struct eap_session *eap_lookup(tac_session *session, const u_char *state, size_t state_len)
{
    tac_realm *r = session->ctx->realm;
    struct eap_session key;
    struct eap_session *es;
    rb_node_t *rbn;

    if (!r->eap_sessions || state_len < 1 || state_len > EAP_STATE_LEN)
	return NULL;

    memset(&key, 0, sizeof(key));
    key.state_len = state_len;
    memcpy(key.state, state, state_len);

    rbn = RB_search(r->eap_sessions, &key);
    if (!rbn)
	return NULL;
    es = RB_payload(rbn, struct eap_session *);

    /* Bind the cached State to the RADIUS client that created it: another
       NAS, address or transport in the same realm must not receive the
       cached reply, profile AVPs and MS-MPPE keys (RFC 4962 3). */
    if (es->host != session->ctx->host ||
	es->transport != session->ctx->aaa_protocol ||
	memcmp(&es->peer_addr, &session->ctx->device_addr, sizeof(es->peer_addr)))
	return NULL;

    return es;
}

static struct eap_session *eap_new_session(tac_session *session) __attribute__((unused));

static struct eap_session *eap_new_session(tac_session *session)
{
    tac_realm *r = session->ctx->realm;
    struct eap_session *e = calloc(1, sizeof(*e));
    u_char state[EAP_STATE_LEN];
    size_t state_len;

    if (!e)
	return NULL;

    if (RAND_bytes(e->state, EAP_STATE_LEN) != 1) {
	free(e);
	return NULL;
    }
    e->state_len = EAP_STATE_LEN;
    e->host = session->ctx->host;
    e->peer_addr = session->ctx->device_addr;
    e->transport = session->ctx->aaa_protocol;
    e->identifier = 1;
    e->expires = io_now.tv_sec + r->eap_timeout;
    e->last_activity = io_now.tv_sec;

    if (!r->eap_sessions)
	r->eap_sessions = RB_tree_new(eap_session_cmp, eap_session_free);
    if (!r->eap_sessions) {
	free(e);
	return NULL;
    }

    if (RB_count(r->eap_sessions) >= r->eap_max_sessions) {
	/* Evict the session with the oldest last_activity; RB_first() would
	   return the lexicographically smallest State, not the oldest. */
	struct eap_session *oldest = NULL;
	rb_node_t *rbn;

	for (rbn = RB_first(r->eap_sessions); rbn; rbn = RB_next(rbn)) {
	    struct eap_session *candidate = RB_payload(rbn, struct eap_session *);
	    if (!oldest || candidate->last_activity < oldest->last_activity)
		oldest = candidate;
	}
	if (oldest) {
	    struct eap_session key;

	    memset(&key, 0, sizeof(key));
	    key.state_len = oldest->state_len;
	    memcpy(key.state, oldest->state, oldest->state_len);
	    RB_search_and_delete(r->eap_sessions, &key);
	}
    }

    state_len = e->state_len;
    memcpy(state, e->state, state_len);

    if (!RB_insert(r->eap_sessions, e)) {
	/* Duplicate key: RB_insert() freed the rbnode wrapper, not the
	   payload. Free the duplicate and return the existing session. */
	eap_session_free(e);
	return eap_lookup(session, state, state_len);
    }
    return e;
}

SSL_CTX *eap_ssl_init(tac_realm *r)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    if (!ctx)
	goto fail;

    /* TLS 1.2 only: TLS 1.0/1.1 are deprecated by RFC 8996 and disabled by
       modern OpenSSL security levels. This is a deliberate deviation from
       RFC 5216's TLS 1.0/3DES requirements. */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

    /* Deterministic server flight: no session tickets (the session cache
       switch does not disable TLS 1.2 tickets), no renegotiation, and no
       compression (RFC 5216 2.4). */
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION |
			     SSL_OP_NO_COMPRESSION);

    /* Require the clientAuth EKU on peer certificates. */
    SSL_CTX_set_purpose(ctx, X509_PURPOSE_SSL_CLIENT);

    if (r->eap_pass) {
	SSL_CTX_set_default_passwd_cb(ctx, ssl_pem_phrase_cb);
	SSL_CTX_set_default_passwd_cb_userdata(ctx, r->eap_pass);
    }

    if (!r->eap_cert || !SSL_CTX_use_certificate_chain_file(ctx, r->eap_cert))
	goto fail;
    if (!r->eap_key || !SSL_CTX_use_PrivateKey_file(ctx, r->eap_key, SSL_FILETYPE_PEM))
	goto fail;
    if (!SSL_CTX_check_private_key(ctx))
	goto fail;
    if (r->eap_cafile && !SSL_CTX_load_verify_locations(ctx, r->eap_cafile, NULL))
	goto fail;

    if (r->eap_verify_client)
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    else
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;

fail:
    {
	char ebuf[256];
	const char *terr = ERR_error_string(ERR_get_error(), ebuf);

	report(NULL, LOG_ERR, ~0,
	       "%s %d: realm %s: EAP TLS configuration failed%s%s",
	       __func__, __LINE__, r->name.txt, terr ? ": " : "", terr ? terr : "");
    }
    SSL_CTX_free(ctx);
    return NULL;
}

#endif				/* WITH_SSL */
