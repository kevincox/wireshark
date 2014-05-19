/* packet-ceph.c
 * Routines for Ceph dissection
 * Copyright 2014, Kevin Cox <kevincox@kevincox.ca>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR ADD PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/conversation.h>

#include "packet-tcp.h"

/* Forward declaration that is needed below if using the
 * proto_reg_handoff_ceph function as a callback for when protocol
 * preferences get changed. */
void proto_reg_handoff_ceph(void);
void proto_register_ceph(void);

/* Initialize the protocol and registered fields */
static int proto_ceph                            = -1;
static int hf_type                               = -1;
static int hf_version                            = -1;
static int hf_sockaddr_client                    = -1;
static int hf_sockaddr_server                    = -1;
static int hf_inet_family                        = -1;
static int hf_port                               = -1;
static int hf_addr_ipv4                          = -1;
static int hf_addr_ipv6                          = -1;
static int hf_connect                            = -1;
static int hf_connect_features                   = -1;
static int hf_connect_feat0_uid                  = -1;
static int hf_connect_feat0_nosrcaddr            = -1;
static int hf_connect_feat0_monclockcheck        = -1;
static int hf_connect_feat0_flock                = -1;
static int hf_connect_feat0_subscribe2           = -1;
static int hf_connect_feat0_monnames             = -1;
static int hf_connect_feat0_reconnect_seq        = -1;
static int hf_connect_feat0_dirlayouthash        = -1;
static int hf_connect_feat0_objectlocator        = -1;
static int hf_connect_feat0_pgid64               = -1;
static int hf_connect_feat0_incsubosdmap         = -1;
static int hf_connect_feat0_pgpool3              = -1;
static int hf_connect_feat0_osdreplymux          = -1;
static int hf_connect_feat0_osdenc               = -1;
static int hf_connect_feat0_omap                 = -1;
static int hf_connect_feat0_monenc               = -1;
static int hf_connect_feat0_query_t              = -1;
static int hf_connect_feat0_indep_pg_map         = -1;
static int hf_connect_feat0_crush_tunables       = -1;
static int hf_connect_feat0_chunky_scrub         = -1;
static int hf_connect_feat0_mon_nullroute        = -1;
static int hf_connect_feat0_mon_gv               = -1;
static int hf_connect_feat0_backfill_reservation = -1;
static int hf_connect_feat0_msg_auth             = -1;
static int hf_connect_feat0_recovery_reservation = -1;
static int hf_connect_feat0_crush_tunables2      = -1;
static int hf_connect_feat0_createpoolid         = -1;
static int hf_connect_feat0_reply_create_inode   = -1;
static int hf_connect_feat0_osd_hbmsgs           = -1;
static int hf_connect_feat0_mdsenc               = -1;
static int hf_connect_feat0_osdhashpspool        = -1;
static int hf_connect_feat0_mon_single_paxos     = -1;
static int hf_connect_feat1_osd_snapmapper       = -1;
static int hf_connect_feat1_mon_scrub            = -1;
static int hf_connect_feat1_osd_packed_recovery  = -1;
static int hf_connect_feat1_osd_cachepool        = -1;
static int hf_connect_feat1_crush_v2             = -1;
static int hf_connect_feat1_export_peer          = -1;
static int hf_connect_feat1_osd_erasure_codes    = -1;
static int hf_connect_feat1_osd_tmap2omap        = -1;
static int hf_connect_feat1_osdmap_enc           = -1;
static int hf_connect_feat1_mds_inline_data      = -1;
static int hf_connect_feat1_crush_tunables3      = -1;
static int hf_connect_feat1_osd_primary_affinity = -1;
static int hf_connect_feat1_msgr_keepalive2      = -1;
static int hf_connect_feat1_reserved             = -1;
static int hf_connect_host_type                  = -1;
static int hf_connect_seq_global                 = -1;
static int hf_connect_seq                        = -1;
static int hf_connect_proto_ver                  = -1;
static int hf_connect_auth_proto                 = -1;
static int hf_connect_auth_len                   = -1;
static int hf_connect_flags                      = -1;
static int hf_connect_flags_lossy                = -1;
static int hf_connect_reply                      = -1;

static guint gPORT_PREF = 6789;

#define C_NEW_FILESCOPE(klass) ((klass*)wmem_alloc(wmem_file_scope(), sizeof(klass)))

enum c_proto_data_keys {
	C_KEY_TREE
};

/* Initialize the subtree pointers */
static gint ett_ceph = -1;
static gint ett_sockaddr = -1;
static gint ett_connect = -1;
static gint ett_connect_reply = -1;

static const char *C_BANNER = "ceph";
enum c_banner {
	C_BANNER_LEN_MIN = 4,
	C_BANNER_LEN_MAX = 9
};

enum c_inet {
	C_IPv4 = 0x02,
	C_IPv6 = 0x0A
};

static const value_string c_inet_strings[] = {
	{ C_IPv4, "IPv4" },
	{ C_IPv6, "IPv6" },
	{ 0     ,  NULL  }
};

/***** Feature Flags *****/
/* Transmuted from ceph:/src/include/ceph_features.h */
enum c_features {
	C_FEATURE0_UID                  = 1 <<  0,
	C_FEATURE0_NOSRCADDR            = 1 <<  1,
	C_FEATURE0_MONCLOCKCHECK        = 1 <<  2,
	C_FEATURE0_FLOCK                = 1 <<  3,
	C_FEATURE0_SUBSCRIBE2           = 1 <<  4,
	C_FEATURE0_MONNAMES             = 1 <<  5,
	C_FEATURE0_RECONNECT_SEQ        = 1 <<  6,
	C_FEATURE0_DIRLAYOUTHASH        = 1 <<  7,
	C_FEATURE0_OBJECTLOCATOR        = 1 <<  8,
	C_FEATURE0_PGID64               = 1 <<  9,
	C_FEATURE0_INCSUBOSDMAP         = 1 << 10,
	C_FEATURE0_PGPOOL3              = 1 << 11,
	C_FEATURE0_OSDREPLYMUX          = 1 << 12,
	C_FEATURE0_OSDENC               = 1 << 13,
	C_FEATURE0_OMAP                 = 1 << 14,
	C_FEATURE0_MONENC               = 1 << 15,
	C_FEATURE0_QUERY_T              = 1 << 16,
	C_FEATURE0_INDEP_PG_MAP         = 1 << 17,
	C_FEATURE0_CRUSH_TUNABLES       = 1 << 18,
	C_FEATURE0_CHUNKY_SCRUB         = 1 << 19,
	C_FEATURE0_MON_NULLROUTE        = 1 << 20,
	C_FEATURE0_MON_GV               = 1 << 21,
	C_FEATURE0_BACKFILL_RESERVATION = 1 << 22,
	C_FEATURE0_MSG_AUTH             = 1 << 23,
	C_FEATURE0_RECOVERY_RESERVATION = 1 << 24,
	C_FEATURE0_CRUSH_TUNABLES2      = 1 << 25,
	C_FEATURE0_CREATEPOOLID         = 1 << 26,
	C_FEATURE0_REPLY_CREATE_INODE   = 1 << 27,
	C_FEATURE0_OSD_HBMSGS           = 1 << 28,
	C_FEATURE0_MDSENC               = 1 << 29,
	C_FEATURE0_OSDHASHPSPOOL        = 1 << 30,
	C_FEATURE0_MON_SINGLE_PAXOS     = 1 << 31,
	C_FEATURE1_OSD_SNAPMAPPER       = 1 <<  0,
	C_FEATURE1_MON_SCRUB            = 1 <<  1,
	C_FEATURE1_OSD_PACKED_RECOVERY  = 1 <<  2,
	C_FEATURE1_OSD_CACHEPOOL        = 1 <<  3,
	C_FEATURE1_CRUSH_V2             = 1 <<  4,
	C_FEATURE1_EXPORT_PEER          = 1 <<  5,
	C_FEATURE1_OSD_ERASURE_CODES    = 1 <<  6,
	C_FEATURE1_OSD_TMAP2OMAP        = 1 <<  6,
	C_FEATURE1_OSDMAP_ENC           = 1 <<  7,
	C_FEATURE1_MDS_INLINE_DATA      = 1 <<  8,
	C_FEATURE1_CRUSH_TUNABLES3      = 1 <<  9,
	C_FEATURE1_OSD_PRIMARY_AFFINITY = 1 <<  9,
	C_FEATURE1_MSGR_KEEPALIVE2      = 1 << 10,
	C_FEATURE1_RESERVED             = 1 << 31
};

/***** Connect Message Flags *****/
enum c_connect_flags {
	C_CONNECT_FLAG_LOSSY = 1 << 0,
};

enum c_sizes {
	C_SIZE_SOCKADDR_STORAGE = 128,
	C_SIZE_CONNECT = 33,
	C_SIZE_CONNECT_REPLY = 26,
	C_SIZE_HELLO_S = C_BANNER_LEN_MAX + 2*(8+C_SIZE_SOCKADDR_STORAGE) + C_SIZE_CONNECT_REPLY,
	C_SIZE_HELLO_C = C_BANNER_LEN_MAX + 8 + C_SIZE_SOCKADDR_STORAGE + C_SIZE_CONNECT
};

typedef enum _c_node_type {
	C_NODE_TYPE_UNKNOWN = 0x00,
	C_NODE_TYPE_MON     = 0x01,
	C_NODE_TYPE_MDS     = 0x02,
	C_NODE_TYPE_OSD     = 0x04,
	C_NODE_TYPE_CLIENT  = 0x08,
	C_NODE_TYPE_AUTH    = 0x20
} c_node_type;

static const value_string c_node_type_strings[] = {
	{ C_NODE_TYPE_UNKNOWN, "Unknown"               },
	{ C_NODE_TYPE_MON,     "Monitor"               },
	{ C_NODE_TYPE_MDS,     "Meta Data Server"      },
	{ C_NODE_TYPE_OSD,     "Object Storage Daemon" },
	{ C_NODE_TYPE_CLIENT,  "Client"                },
	{ C_NODE_TYPE_AUTH,    "Authentication Server" }
};

typedef enum _c_state {
	C_STATE_NEW,
	C_STATE_OPEN
} c_state;

typedef struct _c_node {
	c_node_type type;
	address addr;
	guint16 port;
	c_state state;
} c_node;

void c_node_init(c_node *n)
{
	n->type = C_NODE_TYPE_UNKNOWN;
	//n->addr;
	n->port = 0xFFFF;
	n->state = C_STATE_NEW;
}

typedef struct _c_conv_data {
	c_node client;
	c_node server;
} c_conv_data;

static void
c_conv_data_init(c_conv_data *d)
{
	c_node_init(&d->client);
	c_node_init(&d->server);
}

static c_conv_data*
c_conv_data_new(void)
{
	c_conv_data *r;
	r = C_NEW_FILESCOPE(c_conv_data);
	c_conv_data_init(r);
	return r;
}

typedef struct _c_pkt_data {
	conversation_t *conv;
	c_conv_data *convd;
	c_node *src;
	c_node *dst;
} c_pkt_data;

static void
c_pkt_data_init(c_pkt_data *d, packet_info *pinfo)
{
	d->conv = find_or_create_conversation(pinfo);
	g_assert(d->conv);
	d->convd = (c_conv_data*)conversation_get_proto_data(d->conv, proto_ceph);
	
	if (!d->convd) /* New conversation. */
	{
		d->convd = c_conv_data_new();
		
		/* Note: Server sends banner first. */
		
		copy_address(&d->convd->server.addr, &pinfo->src);
		d->convd->server.port = pinfo->srcport;
		copy_address(&d->convd->client.addr, &pinfo->dst);
		d->convd->client.port = pinfo->destport;
		conversation_add_proto_data(d->conv, proto_ceph, d->convd);
	}
	g_assert(d->convd);
	
	if (ADDRESSES_EQUAL(&d->convd->client.addr, &pinfo->src) &&
	    d->convd->client.port == pinfo->srcport)
	{
		d->src = &d->convd->client;
		d->dst = &d->convd->server;
	}
	else
	{
		d->src = &d->convd->server;
		d->dst = &d->convd->client;
	}
	g_assert(d->src);
	g_assert(d->dst);
}

guint c_header_len(c_pkt_data *d)
{
	if (d->src->state == C_STATE_NEW) return 0;
	else                              return 4;
}

static
gboolean c_from_client(c_pkt_data *d)
{
	return d->src == &d->convd->client;
}
static
gboolean c_from_server(c_pkt_data *d)
{
	return d->src == &d->convd->server;
}

/***** Ceph Data Tree *****/

#define C_NEW_TREESCOPE(klass) C_NEW_FILESCOPE(klass)

/* Helper to add items to the tree (or subtree).
 * 
 * This macro is very magic and expects the proper names.
 */
#define  ADD(hf, o, l) proto_tree_add_item(tree   , hf, tvb, o, l, ENC_LITTLE_ENDIAN)
#define ADDS(hf, o, l) proto_tree_add_item(subtree, hf, tvb, o, l, ENC_LITTLE_ENDIAN)

/* Helper macro to add item to (sub)tree if set.
 * 
 * Again, very magic.
 */
#define  ADD_IF_SET(o, hf, l) do{if((o) != C_TREE_UNSET)  ADD(hf, o, l);}while(0)
#define ADDS_IF_SET(o, hf, l) do{if((o) != C_TREE_UNSET) ADDS(hf, o, l);}while(0)

enum c_tree_constants {
	C_TREE_UNSET = (guint)-1
};

typedef struct _c_tree_sockaddr {
	guint start;
	guint family;
	guint port;
	guint addr_ipv4;
	guint addr_ipv6;
} c_tree_sockaddr;

static
c_tree_sockaddr *c_tree_sockaddr_new(void)
{
	c_tree_sockaddr *r;
	
	r = C_NEW_TREESCOPE(c_tree_sockaddr);
	
	r->start     = 0;
	r->family    = C_TREE_UNSET;
	r->port      = C_TREE_UNSET;
	r->addr_ipv4 = C_TREE_UNSET;
	r->addr_ipv6 = C_TREE_UNSET;
	
	return r;
}

static
void c_tree_sockaddr_render(proto_tree *root, int hf, tvbuff_t *tvb, c_tree_sockaddr *ct)
{
	proto_item *ti;
	proto_tree *tree;
	
	ti = proto_tree_add_item(root, hf, tvb,
	                         ct->start, C_SIZE_SOCKADDR_STORAGE,
	                         ENC_NA);
	tree = proto_item_add_subtree(ti, ett_sockaddr);
	
	if (ct->family != C_TREE_UNSET)
		proto_tree_add_item(tree, hf_inet_family, tvb, ct->family, 2, ENC_BIG_ENDIAN);
	if (ct->port != C_TREE_UNSET)
		proto_tree_add_item(tree, hf_port, tvb, ct->port, 2, ENC_BIG_ENDIAN);
	if (ct->addr_ipv4 != C_TREE_UNSET)
		proto_tree_add_item(tree, hf_addr_ipv4, tvb, ct->addr_ipv4, 4, ENC_BIG_ENDIAN);
	if (ct->addr_ipv6 != C_TREE_UNSET)
		proto_tree_add_item(tree, hf_addr_ipv6, tvb, ct->addr_ipv6, 16, ENC_BIG_ENDIAN);
}

typedef struct _c_tree_connect {
	guint start;
	
	guint features;
	guint host_type;
	guint seq_global;
	guint seq;
	guint proto_ver;
	guint auth_proto;
	guint auth_len;
	guint flags;
} c_tree_connect;

static
c_tree_connect *c_tree_connect_new(void)
{
	c_tree_connect *r;
	r = C_NEW_TREESCOPE(c_tree_connect);
	
	r->start = 0;
	
	r->features   = C_TREE_UNSET;
	r->host_type  = C_TREE_UNSET;
	r->seq_global = C_TREE_UNSET;
	r->seq        = C_TREE_UNSET;
	r->proto_ver  = C_TREE_UNSET;
	r->auth_proto = C_TREE_UNSET;
	r->auth_len   = C_TREE_UNSET;
	r->flags      = C_TREE_UNSET;
	
	return r;
}

static
void c_tree_connect_render(proto_tree *root,
                           tvbuff_t *tvb, c_tree_connect *ct)
{
	proto_item *ti;
	proto_tree *tree, *subtree;
	
	ti = proto_tree_add_item(root, hf_connect, tvb,
	                         ct->start, C_SIZE_CONNECT,
	                         ENC_NA);
	tree = proto_item_add_subtree(ti, ett_connect);
	
	
	if (ct->features != C_TREE_UNSET)
	{
		ti = ADD(hf_connect_features, ct->features, 8);
		subtree = proto_item_add_subtree(ti, hf_connect_features);
		
		/* Wireshark doesn't have support for 64 bit bitfields so dissect as
		   two 32 bit ones. */
		ADDS(hf_connect_feat0_uid,                  ct->features,   4);
		ADDS(hf_connect_feat0_nosrcaddr,            ct->features,   4);
		ADDS(hf_connect_feat0_monclockcheck,        ct->features,   4);
		ADDS(hf_connect_feat0_flock,                ct->features,   4);
		ADDS(hf_connect_feat0_subscribe2,           ct->features,   4);
		ADDS(hf_connect_feat0_monnames,             ct->features,   4);
		ADDS(hf_connect_feat0_reconnect_seq,        ct->features,   4);
		ADDS(hf_connect_feat0_dirlayouthash,        ct->features,   4);
		ADDS(hf_connect_feat0_objectlocator,        ct->features,   4);
		ADDS(hf_connect_feat0_pgid64,               ct->features,   4);
		ADDS(hf_connect_feat0_incsubosdmap,         ct->features,   4);
		ADDS(hf_connect_feat0_pgpool3,              ct->features,   4);
		ADDS(hf_connect_feat0_osdreplymux,          ct->features,   4);
		ADDS(hf_connect_feat0_osdenc,               ct->features,   4);
		ADDS(hf_connect_feat0_omap,                 ct->features,   4);
		ADDS(hf_connect_feat0_monenc,               ct->features,   4);
		ADDS(hf_connect_feat0_query_t,              ct->features,   4);
		ADDS(hf_connect_feat0_indep_pg_map,         ct->features,   4);
		ADDS(hf_connect_feat0_crush_tunables,       ct->features,   4);
		ADDS(hf_connect_feat0_chunky_scrub,         ct->features,   4);
		ADDS(hf_connect_feat0_mon_nullroute,        ct->features,   4);
		ADDS(hf_connect_feat0_mon_gv,               ct->features,   4);
		ADDS(hf_connect_feat0_backfill_reservation, ct->features,   4);
		ADDS(hf_connect_feat0_msg_auth,             ct->features,   4);
		ADDS(hf_connect_feat0_recovery_reservation, ct->features,   4);
		ADDS(hf_connect_feat0_crush_tunables2,      ct->features,   4);
		ADDS(hf_connect_feat0_createpoolid,         ct->features,   4);
		ADDS(hf_connect_feat0_reply_create_inode,   ct->features,   4);
		ADDS(hf_connect_feat0_osd_hbmsgs,           ct->features,   4);
		ADDS(hf_connect_feat0_mdsenc,               ct->features,   4);
		ADDS(hf_connect_feat0_osdhashpspool,        ct->features,   4);
		ADDS(hf_connect_feat0_mon_single_paxos,     ct->features,   4);
		ADDS(hf_connect_feat1_osd_snapmapper,       ct->features+4, 4);
		ADDS(hf_connect_feat1_mon_scrub,            ct->features+4, 4);
		ADDS(hf_connect_feat1_osd_packed_recovery,  ct->features+4, 4);
		ADDS(hf_connect_feat1_osd_cachepool,        ct->features+4, 4);
		ADDS(hf_connect_feat1_crush_v2,             ct->features+4, 4);
		ADDS(hf_connect_feat1_export_peer,          ct->features+4, 4);
		ADDS(hf_connect_feat1_osd_erasure_codes,    ct->features+4, 4);
		ADDS(hf_connect_feat1_osd_tmap2omap,        ct->features+4, 4);
		ADDS(hf_connect_feat1_osdmap_enc,           ct->features+4, 4);
		ADDS(hf_connect_feat1_mds_inline_data,      ct->features+4, 4);
		ADDS(hf_connect_feat1_crush_tunables3,      ct->features+4, 4);
		ADDS(hf_connect_feat1_osd_primary_affinity, ct->features+4, 4);
		ADDS(hf_connect_feat1_msgr_keepalive2,      ct->features+4, 4);
		ADDS(hf_connect_feat1_reserved,             ct->features+4, 4);
	}
	ADD_IF_SET(ct->host_type, hf_connect_host_type, 4);
	ADD_IF_SET(ct->seq_global, hf_connect_seq_global, 4);
	ADD_IF_SET(ct->seq, hf_connect_seq, 4);
	ADD_IF_SET(ct->proto_ver, hf_connect_proto_ver, 4);
	ADD_IF_SET(ct->auth_proto, hf_connect_auth_proto, 4);
	ADD_IF_SET(ct->auth_len, hf_connect_auth_len, 4);
	if (ct->flags != C_TREE_UNSET) {
		ti = ADD(hf_connect_flags, ct->flags, 1);
		subtree = proto_item_add_subtree(ti, hf_connect_flags);
		
		ADDS(hf_connect_flags_lossy, ct->flags, 1);
	}
}

typedef struct _c_tree_connect_reply {
	guint start;
	
	guint tag;
	guint features;
	guint seq_global;
	guint seq;
	guint proto_ver;
	guint auth_len;
	guint flags;
} c_tree_connect_reply;

static
c_tree_connect_reply *c_tree_connect_reply_new(void)
{
	c_tree_connect_reply *r;
	r = C_NEW_TREESCOPE(c_tree_connect_reply);
	
	r->start = 0;
	
	r->tag        = C_TREE_UNSET;
	r->features   = C_TREE_UNSET;
	r->seq_global = C_TREE_UNSET;
	r->seq        = C_TREE_UNSET;
	r->proto_ver  = C_TREE_UNSET;
	r->auth_len   = C_TREE_UNSET;
	r->flags      = C_TREE_UNSET;
	
	return r;
}

static
void c_tree_connect_reply_render(proto_tree *root,
                           tvbuff_t *tvb, c_tree_connect_reply *ct)
{
	proto_item *ti;
	proto_tree *tree, *subtree;
	
	ti = proto_tree_add_item(root, hf_connect_reply, tvb,
	                         ct->start, C_SIZE_CONNECT_REPLY,
	                         ENC_NA);
	tree = proto_item_add_subtree(ti, ett_connect_reply);
	
	
	if (ct->features != C_TREE_UNSET)
	{
		ti = ADD(hf_connect_features, ct->features, 8);
		subtree = proto_item_add_subtree(ti, hf_connect_features);
		
		/* Wireshark doesn't have support for 64 bit bitfields so dissect as
		   two 32 bit ones. */
		ADDS(hf_connect_feat0_uid,                  ct->features,   4);
		ADDS(hf_connect_feat0_nosrcaddr,            ct->features,   4);
		ADDS(hf_connect_feat0_monclockcheck,        ct->features,   4);
		ADDS(hf_connect_feat0_flock,                ct->features,   4);
		ADDS(hf_connect_feat0_subscribe2,           ct->features,   4);
		ADDS(hf_connect_feat0_monnames,             ct->features,   4);
		ADDS(hf_connect_feat0_reconnect_seq,        ct->features,   4);
		ADDS(hf_connect_feat0_dirlayouthash,        ct->features,   4);
		ADDS(hf_connect_feat0_objectlocator,        ct->features,   4);
		ADDS(hf_connect_feat0_pgid64,               ct->features,   4);
		ADDS(hf_connect_feat0_incsubosdmap,         ct->features,   4);
		ADDS(hf_connect_feat0_pgpool3,              ct->features,   4);
		ADDS(hf_connect_feat0_osdreplymux,          ct->features,   4);
		ADDS(hf_connect_feat0_osdenc,               ct->features,   4);
		ADDS(hf_connect_feat0_omap,                 ct->features,   4);
		ADDS(hf_connect_feat0_monenc,               ct->features,   4);
		ADDS(hf_connect_feat0_query_t,              ct->features,   4);
		ADDS(hf_connect_feat0_indep_pg_map,         ct->features,   4);
		ADDS(hf_connect_feat0_crush_tunables,       ct->features,   4);
		ADDS(hf_connect_feat0_chunky_scrub,         ct->features,   4);
		ADDS(hf_connect_feat0_mon_nullroute,        ct->features,   4);
		ADDS(hf_connect_feat0_mon_gv,               ct->features,   4);
		ADDS(hf_connect_feat0_backfill_reservation, ct->features,   4);
		ADDS(hf_connect_feat0_msg_auth,             ct->features,   4);
		ADDS(hf_connect_feat0_recovery_reservation, ct->features,   4);
		ADDS(hf_connect_feat0_crush_tunables2,      ct->features,   4);
		ADDS(hf_connect_feat0_createpoolid,         ct->features,   4);
		ADDS(hf_connect_feat0_reply_create_inode,   ct->features,   4);
		ADDS(hf_connect_feat0_osd_hbmsgs,           ct->features,   4);
		ADDS(hf_connect_feat0_mdsenc,               ct->features,   4);
		ADDS(hf_connect_feat0_osdhashpspool,        ct->features,   4);
		ADDS(hf_connect_feat0_mon_single_paxos,     ct->features,   4);
		ADDS(hf_connect_feat1_osd_snapmapper,       ct->features+4, 4);
		ADDS(hf_connect_feat1_mon_scrub,            ct->features+4, 4);
		ADDS(hf_connect_feat1_osd_packed_recovery,  ct->features+4, 4);
		ADDS(hf_connect_feat1_osd_cachepool,        ct->features+4, 4);
		ADDS(hf_connect_feat1_crush_v2,             ct->features+4, 4);
		ADDS(hf_connect_feat1_export_peer,          ct->features+4, 4);
		ADDS(hf_connect_feat1_osd_erasure_codes,    ct->features+4, 4);
		ADDS(hf_connect_feat1_osd_tmap2omap,        ct->features+4, 4);
		ADDS(hf_connect_feat1_osdmap_enc,           ct->features+4, 4);
		ADDS(hf_connect_feat1_mds_inline_data,      ct->features+4, 4);
		ADDS(hf_connect_feat1_crush_tunables3,      ct->features+4, 4);
		ADDS(hf_connect_feat1_osd_primary_affinity, ct->features+4, 4);
		ADDS(hf_connect_feat1_msgr_keepalive2,      ct->features+4, 4);
		ADDS(hf_connect_feat1_reserved,             ct->features+4, 4);
	}
	ADD_IF_SET(ct->seq_global, hf_connect_seq_global, 4);
	ADD_IF_SET(ct->seq, hf_connect_seq, 4);
	ADD_IF_SET(ct->proto_ver, hf_connect_proto_ver, 4);
	ADD_IF_SET(ct->auth_len, hf_connect_auth_len, 4);
	if (ct->flags != C_TREE_UNSET) {
		ti = ADD(hf_connect_flags, ct->flags, 1);
		subtree = proto_item_add_subtree(ti, hf_connect_flags);
		
		ADDS(hf_connect_flags_lossy, ct->flags, 1);
	}
}
typedef struct _c_tree {
	int size;
	const char *info;
	
	guint version;
	c_tree_sockaddr      *addr_client;
	c_tree_sockaddr      *addr_server;
	c_tree_connect       *connect;
	c_tree_connect_reply *connect_reply;
} c_tree;

static
c_tree *c_tree_new(void)
{
	c_tree *r;
	
	r = C_NEW_TREESCOPE(c_tree);
	
	r->size = 0;
	r->info = "";
	
	r->version = C_TREE_UNSET;
	r->addr_client = r->addr_server = NULL;
	r->connect = NULL;
	r->connect_reply = NULL;
	
	return r;
}

static
int c_tree_render(proto_tree *root, tvbuff_t *tvb, packet_info *pinfo, c_tree *ct)
{
	proto_item *ti;
	proto_tree *tree;
	
	ti = proto_tree_add_item(root, proto_ceph, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_ceph);
	
	if (ct->info)
		col_set_str(pinfo->cinfo, COL_INFO, ct->info);
	
	ADD_IF_SET(ct->version, hf_version, C_BANNER_LEN_MAX);
	if (ct->addr_client)
		c_tree_sockaddr_render(tree, hf_sockaddr_client, tvb, ct->addr_client);
	if (ct->addr_server)
		c_tree_sockaddr_render(tree, hf_sockaddr_server, tvb, ct->addr_server);
	if (ct->connect)
		c_tree_connect_render(tree, tvb, ct->connect);
	if (ct->connect_reply)
		c_tree_connect_reply_render(tree, tvb, ct->connect_reply);
	
	return ct->size;
}

#undef ADD

/***** Protocol Dissectors *****/
static
int c_dissect_sockaddr(c_tree_sockaddr *tree,
                       tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	guint16 af;
	
	/*
	struct sockaddr_storage {
		guint16 family;
		guint8  pad[???]; // Implementation defined.
	};
	struct sockaddr_in {
		guint16 family;
		guint16 port;
		guint32 addr;
		guint8  pad[8];
	};
	struct sockaddr_in6 {
		guint16 family;
		guint16 port;
		guint32 flow;
		guint8  addr[16];
		guint32 scope;
	};
	*/
	
	af = tvb_get_ntohs(tvb, off);
	tree->family = off;
	
	switch (af) {
	case C_IPv4:
		tree->port      = off+2;
		tree->addr_ipv4 = off+4;
		break;
	case C_IPv6: //@UNTESTED
		tree->port      = off+2;
		tree->addr_ipv6 = off+8;
		break;
	default:
		printf("UNKNOWN INET!\n");
	}
	off += C_SIZE_SOCKADDR_STORAGE; // Skip over sockaddr_storage.
	
	return off;
}

static
int c_dissect_connect(c_tree_connect *tree,
                      tvbuff_t *tvb _U_, guint off, c_pkt_data *data _U_)
{
	/* From ceph:/src/include/msgr.h
	struct ceph_msg_connect {
		__le64 features;
		__le32 host_type;
		__le32 global_seq;
		__le32 connect_seq;
		__le32 protocol_version;
		__le32 authorizer_protocol;
		__le32 authorizer_len;
		__u8  flags;
	} __attribute__(packed);
	*/
	
	tree->start = off;
	
	tree->features   = off; off += 8;
	tree->host_type  = off; off += 4;
	tree->seq_global = off; off += 4;
	tree->seq        = off; off += 4;
	tree->proto_ver  = off; off += 4;
	tree->auth_proto = off; off += 4;
	tree->auth_len   = off; off += 4;
	tree->flags      = off; off += 1;
	
	return off;
}

static
int c_dissect_connect_reply(c_tree_connect_reply *tree,
                            tvbuff_t *tvb _U_, guint off, c_pkt_data *data _U_)
{
	/* From ceph:/src/include/msgr.h
	struct ceph_msg_connect_reply {
		__u8 tag;
		__le64 features;
		__le32 global_seq;
		__le32 connect_seq;
		__le32 protocol_version;
		__le32 authorizer_len;
		__u8 flags;
	} __attribute__ ((packed));
	*/
	
	tree->start = off;
	
	tree->tag        = off; off += 1;
	tree->features   = off; off += 8;
	tree->seq_global = off; off += 4;
	tree->seq        = off; off += 4;
	tree->proto_ver  = off; off += 4;
	tree->auth_len   = off; off += 4;
	tree->flags      = off; off += 1;
	
	return off;
}

static
int c_dissect_new(c_tree *tree,
                  tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	if (tvb_memeql(tvb, 0, C_BANNER, C_BANNER_LEN_MIN) != 0)
		return 0; // Invalid banner.
	tree->version = 0;
	off += C_BANNER_LEN_MAX;
	
	tree->info = "Hello";
	
	if (c_from_server(data))
	{
		//@TODO: Why is there an 8-byte offset?
		off += 8;
		
		tree->addr_server = c_tree_sockaddr_new();
		off = c_dissect_sockaddr(tree->addr_server, tvb, off, data);
		
	}
	
	//@TODO: Why this offset?
	off += 8;
	
	tree->addr_client = c_tree_sockaddr_new();
	off = c_dissect_sockaddr(tree->addr_client, tvb, off, data);
	
	if (c_from_client(data))
	{
		tree->connect = c_tree_connect_new();
		off = c_dissect_connect(tree->connect, tvb, off, data);
	}
	else
	{
		tree->connect_reply = c_tree_connect_reply_new();
		off = c_dissect_connect_reply(tree->connect_reply, tvb, off, data);
	}
	
	data->src->state = C_STATE_OPEN;
	
	return off;
}

static int
dissect_ceph_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *vdata)
{
	c_pkt_data *data;
	c_tree *ctree;
	
	const char *buf _U_ = tvb_get_ptr(tvb, 0,0); //@TODO: Remove debug before release.
	
	data = (c_pkt_data*)vdata;
	
	ctree = (c_tree*)p_get_proto_data(wmem_file_scope(), pinfo, proto_ceph, C_KEY_TREE);
	if (!ctree)
	{
		ctree = c_tree_new();
		
		if (data->src->state == C_STATE_NEW)
			ctree->size = c_dissect_new(ctree, tvb, 0, data);
		else
			ctree->info = "Unknown Request";
		
		p_add_proto_data(wmem_file_scope(), pinfo, proto_ceph, C_KEY_TREE, ctree);
	}
	
	return c_tree_render(tree, tvb, pinfo, ctree);
}

static guint
dissect_ceph_len(packet_info *pinfo, tvbuff_t *tvb _U_, int offset _U_)
{
	c_tree *tree;
	c_pkt_data data;
	
	c_pkt_data_init(&data, pinfo);
	
	tree = (c_tree*)p_get_proto_data(wmem_file_scope(), pinfo, proto_ceph, C_KEY_TREE);
	if (tree)
		return tree->size;
	
	if (data.src->state == C_STATE_NEW)
		return c_from_server(&data)? C_SIZE_HELLO_S : C_SIZE_HELLO_C;
	else
		return 8;
}

static int
dissect_ceph(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *unused _U_)
{
	c_pkt_data data;
	
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ceph");
	col_clear(pinfo->cinfo, COL_INFO);
	
	c_pkt_data_init(&data, pinfo);
	
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
	                 dissect_ceph_len, dissect_ceph_message, (void*)&data);
	
	return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_ceph(void)
{
	module_t *ceph_module;
	//expert_module_t* expert_ceph;
	
	
	
	static hf_register_info hf[] = {
		{ &hf_type, {
			"Type", "ceph.type",
			FT_UINT8, BASE_HEX, NULL, 0,
			"The message type.", HFILL
		} },
		{ &hf_version, {
			"Version", "ceph.ver",
			FT_STRINGZ, BASE_NONE, NULL, 0,
			"The protocol version string.", HFILL
		} },
		{ &hf_sockaddr_server, {
			"Server's Network Address", "ceph.server.sockaddr",
			FT_NONE, BASE_NONE, NULL, 0,
			"The address of the server according to itself.", HFILL
		} },
		{ &hf_sockaddr_client, {
			"Client's Network Address", "ceph.client.sockaddr",
			FT_NONE, BASE_NONE, NULL, 0,
			"The address of the client as seen by the server.", HFILL
		} },
		{ &hf_inet_family, {
			"Address Family", "ceph.af",
			FT_UINT16, BASE_HEX, VALS(c_inet_strings), 0,
			"The address family of the client as seen by the server.", HFILL
		} },
		{ &hf_port, {
			"Port", "ceph.client.port",
			FT_UINT16, BASE_DEC, NULL, 0,
			"The port of the client as seen by the server.", HFILL
		} },
		{ &hf_addr_ipv4, {
			"IPv4 Address", "ceph.client.ip",
			FT_IPv4, BASE_NONE, NULL, 0,
			"The IP address of the client as seen by the server.", HFILL
		} },
		{ &hf_addr_ipv6, {
			"IPv6 Address", "ceph.client.ip",
			FT_IPv6, BASE_NONE, NULL, 0,
			"The IP address of the client as seen by the server.", HFILL
		} },
		{ &hf_connect, {
			"Connection Negotiation", "ceph.connect",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_connect_features, {
			"Features", "ceph.connect.features",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_uid, {
			"UID", "ceph.connect.features.uid",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_UID,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_nosrcaddr, {
			"NOSRCADDR", "ceph.connect.features.nosrcaddr",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_NOSRCADDR,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_monclockcheck, {
			"MONCLOCKCHECK", "ceph.connect.features.monclockcheck",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_MONCLOCKCHECK,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_flock, {
			"FLOCK", "ceph.connect.features.flock",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_FLOCK,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_subscribe2, {
			"SUBSCRIBE2", "ceph.connect.features.subscribe2",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_SUBSCRIBE2,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_monnames, {
			"MONNAMES", "ceph.connect.features.monnames",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_MONNAMES,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_reconnect_seq, {
			"RECONNECT_SEQ", "ceph.connect.features.reconnect_seq",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_RECONNECT_SEQ,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_dirlayouthash, {
			"DIRLAYOUTHASH", "ceph.connect.features.dirlayouthash",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_DIRLAYOUTHASH,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_objectlocator, {
			"OBJECTLOCATOR", "ceph.connect.features.objectlocator",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_OBJECTLOCATOR,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_pgid64, {
			"PGID64", "ceph.connect.features.pgid64",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_PGID64,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_incsubosdmap, {
			"INCSUBOSDMAP", "ceph.connect.features.incsubosdmap",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_INCSUBOSDMAP,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_pgpool3, {
			"PGPOOL3", "ceph.connect.features.pgpool3",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_PGPOOL3,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_osdreplymux, {
			"OSDREPLYMUX", "ceph.connect.features.osdreplymux",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_OSDREPLYMUX,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_osdenc, {
			"OSDENC", "ceph.connect.features.osdenc",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_OSDENC,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_omap, {
			"OMAP", "ceph.connect.features.omap",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_OMAP,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_monenc, {
			"MONENC", "ceph.connect.features.monenc",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_MONENC,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_query_t, {
			"QUERY_T", "ceph.connect.features.query_t",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_QUERY_T,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_indep_pg_map, {
			"INDEP_PG_MAP", "ceph.connect.features.indep_pg_map",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_INDEP_PG_MAP,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_crush_tunables, {
			"CRUSH_TUNABLES", "ceph.connect.features.crush_tunables",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_CRUSH_TUNABLES,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_chunky_scrub, {
			"CHUNKY_SCRUB", "ceph.connect.features.chunky_scrub",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_CHUNKY_SCRUB,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_mon_nullroute, {
			"MON_NULLROUTE", "ceph.connect.features.mon_nullroute",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_MON_NULLROUTE,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_mon_gv, {
			"MON_GV", "ceph.connect.features.mon_gv",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_MON_GV,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_backfill_reservation, {
			"BACKFILL_RESERVATION", "ceph.connect.features.backfill_reservation",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_BACKFILL_RESERVATION,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_msg_auth, {
			"MSG_AUTH", "ceph.connect.features.msg_auth",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_MSG_AUTH,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_recovery_reservation, {
			"RECOVERY_RESERVATION", "ceph.connect.features.recovery_reservation",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_RECOVERY_RESERVATION,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_crush_tunables2, {
			"CRUSH_TUNABLES2", "ceph.connect.features.crush_tunables2",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_CRUSH_TUNABLES2,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_createpoolid, {
			"CREATEPOOLID", "ceph.connect.features.createpoolid",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_CREATEPOOLID,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_reply_create_inode, {
			"REPLY_CREATE_INODE", "ceph.connect.features.reply_create_inode",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_REPLY_CREATE_INODE,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_osd_hbmsgs, {
			"OSD_HBMSGS", "ceph.connect.features.osd_hbmsgs",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_OSD_HBMSGS,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_mdsenc, {
			"MDSENC", "ceph.connect.features.mdsenc",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_MDSENC,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_osdhashpspool, {
			"OSDHASHPSPOOL", "ceph.connect.features.osdhashpspool",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_OSDHASHPSPOOL,
			NULL, HFILL
		} },
		{ &hf_connect_feat0_mon_single_paxos, {
			"MON_SINGLE_PAXOS", "ceph.connect.features.mon_single_paxos",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE0_MON_SINGLE_PAXOS,
			NULL, HFILL
		} },
		{ &hf_connect_feat1_osd_snapmapper, {
			"OSD_SNAPMAPPER", "ceph.connect.features.osd_snapmapper",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE1_OSD_SNAPMAPPER,
			NULL, HFILL
		} },
		{ &hf_connect_feat1_mon_scrub, {
			"MON_SCRUB", "ceph.connect.features.mon_scrub",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE1_MON_SCRUB,
			NULL, HFILL
		} },
		{ &hf_connect_feat1_osd_packed_recovery, {
			"OSD_PACKED_RECOVERY", "ceph.connect.features.osd_packed_recovery",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE1_OSD_PACKED_RECOVERY,
			NULL, HFILL
		} },
		{ &hf_connect_feat1_osd_cachepool, {
			"OSD_CACHEPOOL", "ceph.connect.features.osd_cachepool",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE1_OSD_CACHEPOOL,
			NULL, HFILL
		} },
		{ &hf_connect_feat1_crush_v2, {
			"CRUSH_V2", "ceph.connect.features.crush_v2",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE1_CRUSH_V2,
			NULL, HFILL
		} },
		{ &hf_connect_feat1_export_peer, {
			"EXPORT_PEER", "ceph.connect.features.export_peer",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE1_EXPORT_PEER,
			NULL, HFILL
		} },
		{ &hf_connect_feat1_osd_erasure_codes, {
			"OSD_ERASURE_CODES", "ceph.connect.features.osd_erasure_codes",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE1_OSD_ERASURE_CODES,
			NULL, HFILL
		} },
		{ &hf_connect_feat1_osd_tmap2omap, {
			"OSD_TMAP2OMAP", "ceph.connect.features.osd_tmap2omap",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE1_OSD_TMAP2OMAP,
			NULL, HFILL
		} },
		{ &hf_connect_feat1_osdmap_enc, {
			"OSDMAP_ENC", "ceph.connect.features.osdmap_enc",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE1_OSDMAP_ENC,
			NULL, HFILL
		} },
		{ &hf_connect_feat1_mds_inline_data, {
			"MDS_INLINE_DATA", "ceph.connect.features.mds_inline_data",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE1_MDS_INLINE_DATA,
			NULL, HFILL
		} },
		{ &hf_connect_feat1_crush_tunables3, {
			"CRUSH_TUNABLES3", "ceph.connect.features.crush_tunables3",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE1_CRUSH_TUNABLES3,
			NULL, HFILL
		} },
		{ &hf_connect_feat1_osd_primary_affinity, {
			"OSD_PRIMARY_AFFINITY", "ceph.connect.features.osd_primary_affinity",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE1_OSD_PRIMARY_AFFINITY,
			NULL, HFILL
		} },
		{ &hf_connect_feat1_msgr_keepalive2, {
			"MSGR_KEEPALIVE2", "ceph.connect.features.msgr_keepalive2",
			FT_BOOLEAN, 32, VALS(&tfs_supported_not_supported), C_FEATURE1_MSGR_KEEPALIVE2,
			NULL, HFILL
		} },
		{ &hf_connect_feat1_reserved, {
			"RESERVED", "ceph.connect.features.reserved",
			FT_BOOLEAN, 32, VALS(&tfs_set_notset), C_FEATURE1_RESERVED,
			NULL, HFILL
		} },
		{ &hf_connect_host_type, {
			"Host Type", "ceph.connect.host",
			FT_UINT32, BASE_HEX, VALS(&c_node_type_strings), 0,
			"The type of host.", HFILL
		} },
		{ &hf_connect_seq_global, {
			"Global Sequence Number", "ceph.connect.global_seq",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The number of connections initiated by this host.", HFILL
		} },
		{ &hf_connect_seq, {
			"Sequence Number", "ceph.connect.seq",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The number of connections initiated this session.", HFILL
		} },
		{ &hf_connect_proto_ver, {
			"Protocol Version", "ceph.connect.ver",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The protocol version to use.", HFILL
		} },
		{ &hf_connect_auth_proto, {
			"Authentication Protocol", "ceph.connect.auth.proto",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The authentication protocol to use.", HFILL
		} },
		{ &hf_connect_auth_len, {
			"Authentication Length", "ceph.connect.auth.length",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The length of the authentication.", HFILL
		} },
		{ &hf_connect_flags, {
			"Flags", "ceph.connect.flags",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_connect_flags_lossy, {
			"Lossy", "ceph.connect.flags.lossy",
			FT_BOOLEAN, 8, VALS(&tfs_enabled_disabled), C_CONNECT_FLAG_LOSSY,
			"Messages may be safely dropped.", HFILL
		} },
		{ &hf_connect_reply, {
			"Connection Negotiation Reply", "ceph.connect_reply",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
	};
	
	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ceph,
		&ett_sockaddr,
		&ett_connect,
		&ett_connect_reply,
	};
	
	/* Register the protocol name and description */
	proto_ceph = proto_register_protocol("Ceph", "Ceph", "ceph");
	
	/* Required function calls to register the header fields and subtrees */
	proto_register_field_array(proto_ceph, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	
	/*** Preferences ***/
	ceph_module = prefs_register_protocol(proto_ceph, proto_reg_handoff_ceph);
	
	prefs_register_uint_preference(ceph_module,
		"tcp.port", "Ceph TCP Port",
		" Ceph TCP port if other than the default",
		10, &gPORT_PREF
	);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * If this function is registered as a prefs callback (see
 * prefs_register_protocol above) this function is also called by Wireshark's
 * preferences manager whenever "Apply" or "OK" are pressed. In that case, it
 * should accommodate being called more than once by use of the static
 * 'initialized' variable included below.
 *
 * This form of the reg_handoff function is used if if you perform registration
 * functions which are dependent upon prefs. See below this function for a
 * simpler form which can be used if there are no prefs-dependent registration
 * functions.
 */
void
proto_reg_handoff_ceph(void)
{
	static gboolean initialized = FALSE;
	static dissector_handle_t ceph_handle;
	static int currentPort;
	
	if (!initialized) {
		/* Use new_create_dissector_handle() to indicate that
		 * dissect_ceph() returns the number of bytes it dissected (or 0
		 * if it thinks the packet does not belong to PROTONAME).
		 */
		ceph_handle = new_create_dissector_handle(dissect_ceph, proto_ceph);
		initialized = TRUE;
	
	} else {
		/* If you perform registration functions which are dependent upon
		 * prefs then you should de-register everything which was associated
		 * with the previous settings and re-register using the new prefs
		 * settings here. In general this means you need to keep track of
		 * the ceph_handle and the value the preference had at the time
		 * you registered.	The ceph_handle value and the value of the
		 * preference can be saved using local statics in this
		 * function (proto_reg_handoff).
		 */
		dissector_delete_uint("tcp.port", currentPort, ceph_handle);
	}
	
	currentPort = gPORT_PREF;
	dissector_add_uint("tcp.port", currentPort, ceph_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 noexpandtab:
 * :indentSize=4:tabSize=4:noTabs=false:
 */
