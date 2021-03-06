/* conversations_table.c
 * conversations_table   2003 Ronnie Sahlberg
 * Helper routines common to all endpoint conversations tap.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>

#include "packet_info.h"
#include "proto.h"
#include "conversation_table.h"
#include "addr_resolv.h"
#include "emem.h"

#include "stat_cmd_args.h"

GList *cmd_string_list_ = NULL;

struct register_ct {
    gboolean hide_ports;       /* hide TCP / UDP port columns */
    int proto_id;              /* protocol id (0-indexed) */
    tap_packet_cb packet_func; /* function to be called for new incoming packets */
    conv_gui_init_cb gui_init_cb; /* GUI specific function to initialize conversation */
};

gboolean get_conversation_hide_ports(register_ct_t* ct)
{
    return ct->hide_ports;
}

int get_conversation_proto_id(register_ct_t* ct)
{
    if (!ct) {
        return -1;
    }
    return ct->proto_id;
}

tap_packet_cb get_conversation_packet_func(register_ct_t* ct)
{
    return ct->packet_func;
}

static GSList *registered_ct_tables = NULL;

void
dissector_conversation_init(const char *opt_arg, void* userdata)
{
    register_ct_t *table = (register_ct_t*)userdata;
    GString *cmd_str = g_string_new("conv,");
    const char *filter=NULL;

    g_string_append(cmd_str, proto_get_protocol_filter_name(table->proto_id));
    if(!strncmp(opt_arg, cmd_str->str, cmd_str->len)){
        filter = opt_arg + cmd_str->len;
    } else {
        filter = NULL;
    }
    g_string_free(cmd_str, TRUE);

    if (table->gui_init_cb)
        table->gui_init_cb(table, filter);
}

/** get conversation from protocol ID
 *
 * @param proto_id protocol ID
 * @return tap function handler of conversation
 */
register_ct_t* get_conversation_by_proto_id(int proto_id)
{
    GSList *ct;
    register_ct_t *table;

    for(ct = registered_ct_tables; ct != NULL; ct = g_slist_next(ct)){
        table = (register_ct_t*)ct->data;
        if ((table) && (table->proto_id == proto_id))
            return table;
    }

    return NULL;
}

static gint
insert_sorted_by_table_name(gconstpointer aparam, gconstpointer bparam)
{
    const register_ct_t *a = (register_ct_t *)aparam;
    const register_ct_t *b = (register_ct_t *)bparam;

    return g_ascii_strcasecmp(proto_get_protocol_short_name(find_protocol_by_id(a->proto_id)), proto_get_protocol_short_name(find_protocol_by_id(b->proto_id)));
}

void
register_conversation_table(const int proto_id, gboolean hide_ports, tap_packet_cb packet_func)
{
    register_ct_t *table;
    GString *cmd_str = g_string_new("conv,");

    table = g_new(register_ct_t,1);

    table->hide_ports   = hide_ports;
    table->proto_id     = proto_id;
    table->packet_func  = packet_func;
    table->gui_init_cb  = NULL;

    registered_ct_tables = g_slist_insert_sorted(registered_ct_tables, table, insert_sorted_by_table_name);

    g_string_append(cmd_str, proto_get_protocol_filter_name(table->proto_id));
    cmd_string_list_ = g_list_append(cmd_string_list_, cmd_str->str);
    register_stat_cmd_arg(cmd_str->str, dissector_conversation_init, table);
    g_string_free(cmd_str, FALSE);
}

/* Set GUI fields for register_ct list */
static void
set_gui_data(gpointer data, gpointer user_data)
{
    register_ct_t *table = (register_ct_t*)data;
    table->gui_init_cb = (conv_gui_init_cb)user_data;
}

void conversation_table_set_gui_info(conv_gui_init_cb init_cb)
{
    g_slist_foreach(registered_ct_tables, set_gui_data, init_cb);
}

void conversation_table_iterate_tables(GFunc func, gpointer user_data)
{
    g_slist_foreach(registered_ct_tables, func, user_data);
}

guint conversation_table_get_num(void)
{
    return g_slist_length(registered_ct_tables);
}


register_ct_t *get_conversation_table_by_num(guint table_num)
{
    return (register_ct_t *) g_slist_nth_data(registered_ct_tables, table_num);
}

/** Compute the hash value for two given address/port pairs.
 * (Parameter type is gconstpointer for GHashTable compatibility.)
 *
 * @param key Conversation. MUST point to a conv_key_t struct.
 * @return Computed key hash.
 */
static guint
conversation_hash(gconstpointer v)
{
    const conv_key_t *key = (const conv_key_t *)v;
    guint hash_val;

    hash_val = 0;
    ADD_ADDRESS_TO_HASH(hash_val, &key->addr1);
    hash_val += key->port1;
    ADD_ADDRESS_TO_HASH(hash_val, &key->addr2);
    hash_val += key->port2;
    hash_val ^= key->conv_id;

    return hash_val;
}

/** Compare two conversation keys for an exact match.
 * (Parameter types are gconstpointer for GHashTable compatibility.)
 *
 * @param key1 First conversation. MUST point to a conv_key_t struct.
 * @param key2 Second conversation. MUST point to a conv_key_t struct.
 * @return TRUE if conversations are equal, FALSE otherwise.
 */
static gboolean
conversation_equal(gconstpointer key1, gconstpointer key2)
{
    const conv_key_t *ck1 = (const conv_key_t *)key1;
    const conv_key_t *ck2 = (const conv_key_t *)key2;

    if (ck1->conv_id == ck2->conv_id)
    {
        if (ck1->port1 == ck2->port1 &&
            ck1->port2 == ck2->port2 &&
            ADDRESSES_EQUAL(&ck1->addr1, &ck2->addr1) &&
            ADDRESSES_EQUAL(&ck1->addr2, &ck2->addr2)) {
            return TRUE;
        }

        if (ck1->port2 == ck2->port1 &&
            ck1->port1 == ck2->port2 &&
            ADDRESSES_EQUAL(&ck1->addr2, &ck2->addr1) &&
            ADDRESSES_EQUAL(&ck1->addr1, &ck2->addr2)) {
            return TRUE;
        }
    }

    /*
     * The addresses, ports, or conversation IDs don't match.
     */
    return FALSE;
}

void
reset_conversation_table_data(conv_hash_t *ch)
{
    if (!ch) {
        return;
    }

    if (ch->conv_array != NULL) {
        guint i;
        for(i = 0; i < ch->conv_array->len; i++){
            conv_item_t *conv = &g_array_index(ch->conv_array, conv_item_t, i);
            g_free((gpointer)conv->src_address.data);
            g_free((gpointer)conv->dst_address.data);
        }

        g_array_free(ch->conv_array, TRUE);
    }

    if (ch->hashtable != NULL) {
        g_hash_table_destroy(ch->hashtable);
    }

    ch->conv_array=NULL;
    ch->hashtable=NULL;
}

const char *get_conversation_address(address *addr, gboolean resolve_names)
{
    if (resolve_names) {
        return ep_address_to_display(addr);
    } else {
        return ep_address_to_str(addr);
    }
}

const char *get_conversation_port(guint32 port, port_type ptype, gboolean resolve_names)
{

    if(!resolve_names) ptype = PT_NONE;

    switch(ptype) {
    case(PT_TCP):
        return ep_tcp_port_to_display(port);
    case(PT_UDP):
        return ep_udp_port_to_display(port);
    case(PT_SCTP):
        return ep_sctp_port_to_display(port);
    default:
        return ep_strdup_printf("%d", port);
    }
}

/* given an address (to distinguish between ipv4 and ipv6 for tcp/udp),
   a port_type and a name_type (FN_...)
   return a string for the filter name.

   Some addresses, like AT_ETHER may actually be any of multiple types
   of protocols,   either ethernet, tokenring, fddi, wlan etc so we must be
   more specific there;  that's why we need specific_addr_type.
*/
static const char *
conversation_get_filter_name(conv_item_t *conv_item, conv_filter_type_e filter_type)
{

    if ((conv_item == NULL) || (conv_item->dissector_info == NULL) || (conv_item->dissector_info->get_filter_type == NULL)) {
        return CONV_FILTER_INVALID;
    }

    return conv_item->dissector_info->get_filter_type(conv_item, filter_type);
}

/* Convert a port number into a string or NULL */
static char *
ct_port_to_str(port_type ptype, guint32 port)
{
    switch(ptype){
    case PT_TCP:
    case PT_UDP:
    case PT_SCTP:
    case PT_NCP:
        return g_strdup_printf("%d", port);
    default:
        break;
    }
    return NULL;
}

const char *get_conversation_filter(conv_item_t *conv_item, conv_direction_e direction)
{
    char *sport, *dport;
    const char *str = "INVALID";

    sport = ct_port_to_str(conv_item->ptype, conv_item->src_port);
    dport = ct_port_to_str(conv_item->ptype, conv_item->dst_port);

    switch(direction){
    case CONV_DIR_A_TO_FROM_B:
        /* A <-> B */
        str = ep_strdup_printf("%s==%s%s%s%s%s && %s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_ANY_ADDRESS),
                              ep_address_to_str(&conv_item->src_address),
                              sport?" && ":"",
                              sport?conversation_get_filter_name(conv_item,  CONV_FT_ANY_PORT):"",
                              sport?"==":"",
                              sport?sport:"",
                              conversation_get_filter_name(conv_item,  CONV_FT_ANY_ADDRESS),
                              ep_address_to_str(&conv_item->dst_address),
                              dport?" && ":"",
                              dport?conversation_get_filter_name(conv_item,  CONV_FT_ANY_PORT):"",
                              dport?"==":"",
                              dport?dport:""
            );
        break;
    case CONV_DIR_A_TO_B:
        /* A --> B */
        str = ep_strdup_printf("%s==%s%s%s%s%s && %s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_SRC_ADDRESS),
                              ep_address_to_str(&conv_item->src_address),
                              sport?" && ":"",
                              sport?conversation_get_filter_name(conv_item,  CONV_FT_SRC_PORT):"",
                              sport?"==":"",
                              sport?sport:"",
                              conversation_get_filter_name(conv_item,  CONV_FT_DST_ADDRESS),
                              ep_address_to_str(&conv_item->dst_address),
                              dport?" && ":"",
                              dport?conversation_get_filter_name(conv_item,  CONV_FT_DST_PORT):"",
                              dport?"==":"",
                              dport?dport:""
            );
        break;
    case CONV_DIR_A_FROM_B:
        /* A <-- B */
        str = ep_strdup_printf("%s==%s%s%s%s%s && %s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_DST_ADDRESS),
                              ep_address_to_str(&conv_item->src_address),
                              sport?" && ":"",
                              sport?conversation_get_filter_name(conv_item,  CONV_FT_DST_PORT):"",
                              sport?"==":"",
                              sport?sport:"",
                              conversation_get_filter_name(conv_item,  CONV_FT_SRC_ADDRESS),
                              ep_address_to_str(&conv_item->dst_address),
                              dport?" && ":"",
                              dport?conversation_get_filter_name(conv_item,  CONV_FT_SRC_PORT):"",
                              dport?"==":"",
                              dport?dport:""
            );
        break;
    case CONV_DIR_A_TO_FROM_ANY:
        /* A <-> ANY */
        str = ep_strdup_printf("%s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_ANY_ADDRESS),
                              ep_address_to_str(&conv_item->src_address),
                              sport?" && ":"",
                              sport?conversation_get_filter_name(conv_item,  CONV_FT_ANY_PORT):"",
                              sport?"==":"",
                              sport?sport:""
            );
        break;
    case CONV_DIR_A_TO_ANY:
        /* A --> ANY */
        str = ep_strdup_printf("%s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_SRC_ADDRESS),
                              ep_address_to_str(&conv_item->src_address),
                              sport?" && ":"",
                              sport?conversation_get_filter_name(conv_item,  CONV_FT_SRC_PORT):"",
                              sport?"==":"",
                              sport?sport:""
            );
        break;
    case CONV_DIR_A_FROM_ANY:
        /* A <-- ANY */
        str = ep_strdup_printf("%s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_DST_ADDRESS),
                              ep_address_to_str(&conv_item->src_address),
                              sport?" && ":"",
                              sport?conversation_get_filter_name(conv_item,  CONV_FT_DST_PORT):"",
                              sport?"==":"",
                              sport?sport:""
            );
        break;
    case CONV_DIR_ANY_TO_FROM_B:
        /* ANY <-> B */
        str = ep_strdup_printf("%s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_ANY_ADDRESS),
                              ep_address_to_str(&conv_item->dst_address),
                              dport?" && ":"",
                              dport?conversation_get_filter_name(conv_item,  CONV_FT_ANY_PORT):"",
                              dport?"==":"",
                              dport?dport:""
            );
        break;
    case CONV_DIR_ANY_FROM_B:
        /* ANY <-- B */
        str = ep_strdup_printf("%s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_SRC_ADDRESS),
                              ep_address_to_str(&conv_item->dst_address),
                              dport?" && ":"",
                              dport?conversation_get_filter_name(conv_item,  CONV_FT_SRC_PORT):"",
                              dport?"==":"",
                              dport?dport:""
            );
        break;
    case CONV_DIR_ANY_TO_B:
        /* ANY --> B */
        str = ep_strdup_printf("%s==%s%s%s%s%s",
                              conversation_get_filter_name(conv_item,  CONV_FT_DST_ADDRESS),
                              ep_address_to_str(&conv_item->dst_address),
                              dport?" && ":"",
                              dport?conversation_get_filter_name(conv_item,  CONV_FT_DST_PORT):"",
                              dport?"==":"",
                              dport?dport:""
            );
        break;
    default:
        break;
    }
    g_free(sport);
    g_free(dport);
    return str;
}

void
add_conversation_table_data(conv_hash_t *ch, const address *src, const address *dst, guint32 src_port, guint32 dst_port, int num_frames, int num_bytes,
        nstime_t *ts, nstime_t *abs_ts, ct_dissector_info_t *ct_info, port_type ptype)
{
    add_conversation_table_data_with_conv_id(ch, src, dst, src_port, dst_port, CONV_ID_UNSET, num_frames, num_bytes, ts, abs_ts, ct_info, ptype);
}

void
add_conversation_table_data_with_conv_id(
    conv_hash_t *ch,
    const address *src,
    const address *dst,
    guint32 src_port,
    guint32 dst_port,
    conv_id_t conv_id,
    int num_frames,
    int num_bytes,
    nstime_t *ts,
    nstime_t *abs_ts,
    ct_dissector_info_t *ct_info,
    port_type ptype)
{
    const address *addr1, *addr2;
    guint32 port1, port2;
    conv_item_t *conv_item = NULL;
    unsigned int conversation_idx = 0;

    if (src_port > dst_port) {
        addr1 = src;
        addr2 = dst;
        port1 = src_port;
        port2 = dst_port;
    } else if (src_port < dst_port) {
        addr2 = src;
        addr1 = dst;
        port2 = src_port;
        port1 = dst_port;
    } else if (CMP_ADDRESS(src, dst) < 0) {
        addr1 = src;
        addr2 = dst;
        port1 = src_port;
        port2 = dst_port;
    } else {
        addr2 = src;
        addr1 = dst;
        port2 = src_port;
        port1 = dst_port;
    }

    /* if we dont have any entries at all yet */
    if (ch->conv_array == NULL) {
        ch->conv_array = g_array_sized_new(FALSE, FALSE, sizeof(conv_item_t), 10000);

        ch->hashtable = g_hash_table_new_full(conversation_hash,
                                              conversation_equal, /* key_equal_func */
                                              g_free,             /* key_destroy_func */
                                              NULL);              /* value_destroy_func */

    } else {
        /* try to find it among the existing known conversations */
        conv_key_t existing_key;

        existing_key.addr1 = *addr1;
        existing_key.addr2 = *addr2;
        existing_key.port1 = port1;
        existing_key.port2 = port2;
        existing_key.conv_id = conv_id;
        if (g_hash_table_lookup_extended(ch->hashtable, &existing_key, NULL, (gpointer *) &conversation_idx)) {
            conv_item = &g_array_index(ch->conv_array, conv_item_t, conversation_idx);
        }
    }

    /* if we still dont know what conversation this is it has to be a new one
       and we have to allocate it and append it to the end of the list */
    if (conv_item == NULL) {
        conv_key_t *new_key;
        conv_item_t new_conv_item;

        COPY_ADDRESS(&new_conv_item.src_address, addr1);
        COPY_ADDRESS(&new_conv_item.dst_address, addr2);
        new_conv_item.dissector_info = ct_info;
        new_conv_item.ptype = ptype;
        new_conv_item.src_port = port1;
        new_conv_item.dst_port = port2;
        new_conv_item.conv_id = conv_id;
        new_conv_item.rx_frames = 0;
        new_conv_item.tx_frames = 0;
        new_conv_item.rx_bytes = 0;
        new_conv_item.tx_bytes = 0;
        new_conv_item.modified = TRUE;

        if (ts) {
            memcpy(&new_conv_item.start_time, ts, sizeof(new_conv_item.start_time));
            memcpy(&new_conv_item.stop_time, ts, sizeof(new_conv_item.stop_time));
            memcpy(&new_conv_item.start_abs_time, abs_ts, sizeof(new_conv_item.start_abs_time));
        } else {
            nstime_set_unset(&new_conv_item.start_abs_time);
            nstime_set_unset(&new_conv_item.start_time);
            nstime_set_unset(&new_conv_item.stop_time);
        }
        g_array_append_val(ch->conv_array, new_conv_item);
        conversation_idx = ch->conv_array->len - 1;
        conv_item = &g_array_index(ch->conv_array, conv_item_t, conversation_idx);

        /* ct->conversations address is not a constant but src/dst_address.data are */
        new_key = g_new(conv_key_t, 1);
        SET_ADDRESS(&new_key->addr1, conv_item->src_address.type, conv_item->src_address.len, conv_item->src_address.data);
        SET_ADDRESS(&new_key->addr2, conv_item->dst_address.type, conv_item->dst_address.len, conv_item->dst_address.data);
        new_key->port1 = port1;
        new_key->port2 = port2;
        new_key->conv_id = conv_id;
        g_hash_table_insert(ch->hashtable, new_key, GUINT_TO_POINTER(conversation_idx));
    }

    /* update the conversation struct */
    conv_item->modified = TRUE;
    if ( (!CMP_ADDRESS(src, addr1)) && (!CMP_ADDRESS(dst, addr2)) && (src_port==port1) && (dst_port==port2) ) {
        conv_item->tx_frames += num_frames;
        conv_item->tx_bytes += num_bytes;
    } else {
        conv_item->rx_frames += num_frames;
        conv_item->rx_bytes += num_bytes;
    }

    if (ts) {
        if (nstime_cmp(ts, &conv_item->stop_time) > 0) {
            memcpy(&conv_item->stop_time, ts, sizeof(conv_item->stop_time));
        } else if (nstime_cmp(ts, &conv_item->start_time) < 0) {
            memcpy(&conv_item->start_time, ts, sizeof(conv_item->start_time));
            memcpy(&conv_item->start_abs_time, abs_ts, sizeof(conv_item->start_abs_time));
        }
    }
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
