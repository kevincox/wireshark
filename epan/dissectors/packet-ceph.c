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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
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
static int proto_ceph         = -1;
static int hf_type            = -1;
static int hf_version         = -1;
static int hf_sockaddr_client = -1;
static int hf_sockaddr_server = -1;
static int hf_inet_family     = -1;
static int hf_port            = -1;
static int hf_addr_ipv4       = -1;
static int hf_addr_ipv6       = -1;

static guint gPORT_PREF = 6789;

enum c_proto_data_keys {
	C_KEY_TREE
};

/* Initialize the subtree pointers */
static gint ett_ceph = -1;
static gint ett_sockaddr = -1;

static const char *C_BANNER = "ceph";
enum c_banner {
	C_BANNER_LEN_MIN = 4,
	C_BANNER_LEN_MAX = 9 //@TODO: Technically 30 but can can't figure that out.
};

enum c_inet {
	C_IPv4 = 0x02,
	C_IPv6 = 0x0A
};

enum c_sizes {
	C_SIZE_SOCKADDR_STORAGE = 128,
	C_SIZE_HELLO_S = C_BANNER_LEN_MAX + 2*(8+C_SIZE_SOCKADDR_STORAGE),
	C_SIZE_HELLO_C = C_BANNER_LEN_MAX + 8 + C_SIZE_SOCKADDR_STORAGE
};

typedef enum _c_node_type {
	C_NODE_TYPE_UNKNOWN = 0x00,
	C_NODE_TYPE_MON     = 0x01,
	C_NODE_TYPE_MDS     = 0x02,
	C_NODE_TYPE_OSD     = 0x04,
	C_NODE_TYPE_CLIENT  = 0x08,
	C_NODE_TYPE_AUTH    = 0x20 //@TODO: Why not 0x10?
} c_node_type;

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
	r = (c_conv_data*)wmem_alloc(wmem_file_scope(), sizeof(c_conv_data));
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
	c_tree_sockaddr *r = (c_tree_sockaddr*)wmem_alloc(wmem_file_scope(), sizeof(c_tree_sockaddr));
	
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

typedef struct _c_tree {
	int size;
	const char *info;
	
	guint version;
	c_tree_sockaddr *addr_client;
	c_tree_sockaddr *addr_server;
} c_tree;

static
c_tree *c_tree_new(void)
{
	c_tree *r = (c_tree*)wmem_alloc(wmem_file_scope(), sizeof(c_tree));
	
	r->size = 0;
	r->info = "";
	
	r->version = C_TREE_UNSET;
	r->addr_client = r->addr_server = NULL;
	
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
	
	if (ct->version != C_TREE_UNSET)
		proto_tree_add_item(tree, hf_version, tvb, ct->version, C_BANNER_LEN_MAX, ENC_NA);
	if (ct->addr_client)
		c_tree_sockaddr_render(tree, hf_sockaddr_client, tvb, ct->addr_client);
	if (ct->addr_server)
		c_tree_sockaddr_render(tree, hf_sockaddr_server, tvb, ct->addr_server);
	
	return ct->size;
}

static int
c_dissect_sockaddr(c_tree_sockaddr *tree, tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	guint16 af;
	
	/*
	struct ceph_sockaddr_storage {
		guint16 family;
		guint8  pad[???]; // Implementation defined.
	};
	struct ceph_sockaddr_in {
		guint16 family;
		guint16 port;
		guint32 addr;
		guint8  pad[8];
	};
	struct ceph_sockaddr_in6 {
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

static int
c_dissect_new(c_tree *tree, tvbuff_t *tvb, packet_info *pinfo, c_pkt_data *data)
{
	gint off = 0;
	
	if (tvb_memeql(tvb, 0, C_BANNER, C_BANNER_LEN_MIN) != 0)
		return 0; // Invalid banner.
	tree->version = 0;
	off += C_BANNER_LEN_MAX;
	
	tree->info = "Hello";
	
	//@TODO: Why is there an 8-byte offset?
	off += 8;
	
	if (c_from_server(data))
	{
		tree->addr_server = c_tree_sockaddr_new();
		off = c_dissect_sockaddr(tree->addr_server, tvb, off, data);
		
		//@TODO: Why this offset?
		off += 8;
	}
	
	tree->addr_client = c_tree_sockaddr_new();
	off = c_dissect_sockaddr(tree->addr_client, tvb, off, data);
	
	data->src->state = C_STATE_OPEN;
	
	return off;
}

static int
dissect_ceph_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *vdata)
{
	c_pkt_data *data;
	c_tree *ctree;
	
	data = (c_pkt_data*)vdata;
	
	char *buf = tvb_get_ptr(tvb, 0,0); //@TODO: Remove debug before release.
	
	ctree = (c_tree*)p_get_proto_data(wmem_file_scope(), pinfo, proto_ceph, C_KEY_TREE);
	if (!ctree)
	{
		ctree = c_tree_new();
		
		if (data->src->state == C_STATE_NEW)
			ctree->size = c_dissect_new(ctree, tvb, pinfo, data);
		else
			ctree->info = "Unknown Request";
		
		p_add_proto_data(wmem_file_scope(), pinfo, proto_ceph, C_KEY_TREE, ctree);
	}
	
	return c_tree_render(tree, tvb, pinfo, ctree);
}

static guint
dissect_ceph_len(packet_info *pinfo, tvbuff_t *tvb, int offset)
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
	expert_module_t* expert_ceph;
	
	static const value_string strings_addr_fam[] = {
		{ C_IPv4, "IPv4" },
		{ C_IPv6, "IPv6" },
		{ 0     ,  NULL  }
	};
	
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
			FT_UINT16, BASE_HEX, VALS(strings_addr_fam), 0,
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
		} }
	};
	
	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ceph,
		&ett_sockaddr
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
		ceph_handle = new_create_dissector_handle(dissect_ceph,
				proto_ceph);
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
