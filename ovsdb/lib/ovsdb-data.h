/* Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OVSDB_DATA_H
#define OVSDB_DATA_H 1

#include <stdlib.h>
#include "compiler.h"
#include "ovsdb-types.h"
#include "shash.h"

/* 错误码 */
#define OVSDB_OK                      (0)
#define OVSDB_ERR                     (0x00021000)             /* OVSDB错误的变量基准值, OVSDB内部统一分配 */
#define OVSDB_ERR_NULL_PTR            (OVSDB_ERR + 0x01)       /* 指针为空                                 */
#define OVSDB_ERR_INPUT_PARAM         (OVSDB_ERR + 0x02)       /* 输入参数错误                             */
#define OVSDB_ERR_EXISTED             (OVSDB_ERR + 0x03)       /* 已经存在                                 */
#define OVSDB_ERR_INDEX_FULL          (OVSDB_ERR + 0x04)       /* 资源分配完                               */

#define MAX_NETCONF_USERNAME_LEN      256
#define NETCONF_PORT                  22
#define MAX_IP_V4_LEN                 15
#define NETCONF_SEND_DATA_LEN         2601
#define MAX_VNI_ID                    32768
#define MIN_VNI_ID                    4096
#define MAX_VLAN_ID                   4063
#define MIN_VLAN_ID                   0
#define NETCONF_VLANBIT_LEN           512
#define NETCONF_VLANBIT_LEN_STR       1024
#define NETCONF_MAX_REPLY_LEN         20000
#define MAX_IFNAME_LEN                32
#define MAX_CE_MAC_LEN                15
#define MAX_OVSDB_MAC_LEN             17
#define MAX_BDID_LEN                  6
#define MAX_MAC_TYPE_LEN              10
#define MAX_SET_ID_LEN                20

#define OVSDB_NULL_RETURN(p) if(p == NULL){ return OVSDB_ERR;}

#define OVSDB_NULL_BREAK(p) if(p == NULL){ break;}

#define NETCONF_BIT_REVERSE(bitVlaue, bit)      \
    (((bitVlaue & (1<<bit)) >> bit) << (8 - bit - 1))

#define NETCONF_NUM_TO_STR(num, str)    \
if ((num >= 0) && (num <=9))            \
{                                       \
    str = num + '0';                    \
}                                       \
else if ((num >= 10) && (num <= 15))    \
{                                       \
    str = num + 'a' - 10;               \
}                                       \
else                                    \
{                                       \
    str = 0;                            \
}

struct ds;
struct ovsdb_symbol_table;
struct smap;

/* One value of an atomic type (given by enum ovs_atomic_type). */
union ovsdb_atom {
    int64_t integer;
    double real;
    bool boolean;
    char *string;
    struct uuid uuid;
};

void ovsdb_atom_init_default(union ovsdb_atom *, enum ovsdb_atomic_type);
const union ovsdb_atom *ovsdb_atom_default(enum ovsdb_atomic_type);
bool ovsdb_atom_is_default(const union ovsdb_atom *, enum ovsdb_atomic_type);
void ovsdb_atom_clone(union ovsdb_atom *, const union ovsdb_atom *,
                      enum ovsdb_atomic_type);
void ovsdb_atom_swap(union ovsdb_atom *, union ovsdb_atom *);

/* Returns false if ovsdb_atom_destroy() is a no-op when it is applied to an
 * initialized atom of the given 'type', true if ovsdb_atom_destroy() actually
 * does something.
 *
 * This can be used to avoid calling ovsdb_atom_destroy() for each element in
 * an array of homogeneous atoms.  (It's not worthwhile for a single atom.) */
static inline bool
ovsdb_atom_needs_destruction(enum ovsdb_atomic_type type)
{
    return type == OVSDB_TYPE_STRING;
}

/* Frees the contents of 'atom', which must have the specified 'type'.
 *
 * This does not actually call free(atom).  If necessary, the caller must be
 * responsible for that. */
static inline void
ovsdb_atom_destroy(union ovsdb_atom *atom, enum ovsdb_atomic_type type)
{
    if (type == OVSDB_TYPE_STRING) {
        free(atom->string);
    }
}

uint32_t ovsdb_atom_hash(const union ovsdb_atom *, enum ovsdb_atomic_type,
                         uint32_t basis);

int ovsdb_atom_compare_3way(const union ovsdb_atom *,
                            const union ovsdb_atom *,
                            enum ovsdb_atomic_type);

/* Returns true if 'a' and 'b', which are both of type 'type', has the same
 * contents, false if their contents differ.  */
static inline bool ovsdb_atom_equals(const union ovsdb_atom *a,
                                     const union ovsdb_atom *b,
                                     enum ovsdb_atomic_type type)
{
    return !ovsdb_atom_compare_3way(a, b, type);
}

struct ovsdb_error *ovsdb_atom_from_json(union ovsdb_atom *,
                                         const struct ovsdb_base_type *,
                                         const struct json *,
                                         struct ovsdb_symbol_table *)
    WARN_UNUSED_RESULT;
struct json *ovsdb_atom_to_json(const union ovsdb_atom *,
                                enum ovsdb_atomic_type);

char *ovsdb_atom_from_string(union ovsdb_atom *,
                             const struct ovsdb_base_type *, const char *,
                             struct ovsdb_symbol_table *)
    WARN_UNUSED_RESULT;
void ovsdb_atom_to_string(const union ovsdb_atom *, enum ovsdb_atomic_type,
                          struct ds *);
void ovsdb_atom_to_bare(const union ovsdb_atom *, enum ovsdb_atomic_type,
                        struct ds *);

struct ovsdb_error *ovsdb_atom_check_constraints(
    const union ovsdb_atom *, const struct ovsdb_base_type *)
    WARN_UNUSED_RESULT;

/* An instance of an OVSDB type (given by struct ovsdb_type).
 *
 * - The 'keys' must be unique and in sorted order.  Most functions that modify
 *   an ovsdb_datum maintain these invariants.  Functions that don't maintain
 *   the invariants have names that end in "_unsafe".  Use ovsdb_datum_sort()
 *   to check and restore these invariants.
 *
 * - 'n' is constrained by the ovsdb_type's 'n_min' and 'n_max'.
 *
 *   If 'n' is nonzero, then 'keys' points to an array of 'n' atoms of the type
 *   specified by the ovsdb_type's 'key_type'.  (Otherwise, 'keys' should be
 *   null.)
 *
 *   If 'n' is nonzero and the ovsdb_type's 'value_type' is not
 *   OVSDB_TYPE_VOID, then 'values' points to an array of 'n' atoms of the type
 *   specified by the 'value_type'.  (Otherwise, 'values' should be null.)
 *
 *   Thus, for 'n' > 0, 'keys' will always be nonnull and 'values' will be
 *   nonnull only for "map" types.
 */
struct ovsdb_datum {
    unsigned int n;             /* Number of 'keys' and 'values'. */
    union ovsdb_atom *keys;     /* Each of the ovsdb_type's 'key_type'. */
    union ovsdb_atom *values;   /* Each of the ovsdb_type's 'value_type'. */
};

/* Basics. */
void ovsdb_datum_init_empty(struct ovsdb_datum *);
void ovsdb_datum_init_default(struct ovsdb_datum *, const struct ovsdb_type *);
bool ovsdb_datum_is_default(const struct ovsdb_datum *,
                            const struct ovsdb_type *);
const struct ovsdb_datum *ovsdb_datum_default(const struct ovsdb_type *);
void ovsdb_datum_clone(struct ovsdb_datum *, const struct ovsdb_datum *,
                       const struct ovsdb_type *);
void ovsdb_datum_destroy(struct ovsdb_datum *, const struct ovsdb_type *);
void ovsdb_datum_swap(struct ovsdb_datum *, struct ovsdb_datum *);

/* Checking and maintaining invariants. */
struct ovsdb_error *ovsdb_datum_sort(struct ovsdb_datum *,
                                     enum ovsdb_atomic_type key_type)
    WARN_UNUSED_RESULT;

void ovsdb_datum_sort_assert(struct ovsdb_datum *,
                             enum ovsdb_atomic_type key_type);

size_t ovsdb_datum_sort_unique(struct ovsdb_datum *,
                               enum ovsdb_atomic_type key_type,
                               enum ovsdb_atomic_type value_type);

struct ovsdb_error *ovsdb_datum_check_constraints(
    const struct ovsdb_datum *, const struct ovsdb_type *)
    WARN_UNUSED_RESULT;

/* Type conversion. */
struct ovsdb_error *ovsdb_datum_from_json(struct ovsdb_datum *,
                                          const struct ovsdb_type *,
                                          const struct json *,
                                          struct ovsdb_symbol_table *)
    WARN_UNUSED_RESULT;
struct json *ovsdb_datum_to_json(const struct ovsdb_datum *,
                                 const struct ovsdb_type *);

char *ovsdb_datum_from_string(struct ovsdb_datum *,
                              const struct ovsdb_type *, const char *,
                              struct ovsdb_symbol_table *)
    WARN_UNUSED_RESULT;
void ovsdb_datum_to_string(const struct ovsdb_datum *,
                           const struct ovsdb_type *, struct ds *);
void ovsdb_datum_to_bare(const struct ovsdb_datum *,
                         const struct ovsdb_type *, struct ds *);

void ovsdb_datum_from_smap(struct ovsdb_datum *, struct smap *);

/* Comparison. */
uint32_t ovsdb_datum_hash(const struct ovsdb_datum *,
                          const struct ovsdb_type *, uint32_t basis);
int ovsdb_datum_compare_3way(const struct ovsdb_datum *,
                             const struct ovsdb_datum *,
                             const struct ovsdb_type *);
bool ovsdb_datum_equals(const struct ovsdb_datum *,
                        const struct ovsdb_datum *,
                        const struct ovsdb_type *);

/* Search. */
unsigned int ovsdb_datum_find_key(const struct ovsdb_datum *,
                                  const union ovsdb_atom *key,
                                  enum ovsdb_atomic_type key_type);
unsigned int ovsdb_datum_find_key_value(const struct ovsdb_datum *,
                                        const union ovsdb_atom *key,
                                        enum ovsdb_atomic_type key_type,
                                        const union ovsdb_atom *value,
                                        enum ovsdb_atomic_type value_type);

/* Set operations. */
bool ovsdb_datum_includes_all(const struct ovsdb_datum *,
                              const struct ovsdb_datum *,
                              const struct ovsdb_type *);
bool ovsdb_datum_excludes_all(const struct ovsdb_datum *,
                              const struct ovsdb_datum *,
                              const struct ovsdb_type *);
void ovsdb_datum_union(struct ovsdb_datum *,
                       const struct ovsdb_datum *,
                       const struct ovsdb_type *,
                       bool replace);
void ovsdb_datum_subtract(struct ovsdb_datum *a,
                          const struct ovsdb_type *a_type,
                          const struct ovsdb_datum *b,
                          const struct ovsdb_type *b_type);

/* Raw operations that may not maintain the invariants. */
void ovsdb_datum_remove_unsafe(struct ovsdb_datum *, size_t idx,
                               const struct ovsdb_type *);
void ovsdb_datum_add_unsafe(struct ovsdb_datum *,
                            const union ovsdb_atom *key,
                            const union ovsdb_atom *value,
                            const struct ovsdb_type *);

/* Type checking. */
static inline bool
ovsdb_datum_conforms_to_type(const struct ovsdb_datum *datum,
                             const struct ovsdb_type *type)
{
    return datum->n >= type->n_min && datum->n <= type->n_max;
}

/* A table mapping from names to data items.  Currently the data items are
 * always UUIDs; perhaps this will be expanded in the future. */

struct ovsdb_symbol_table {
    struct shash sh;            /* Maps from name to struct ovsdb_symbol *. */
};

struct ovsdb_symbol {
    struct uuid uuid;           /* The UUID that the symbol represents. */
    bool created;               /* Already used to create row? */
    bool strong_ref;            /* Parsed a strong reference to this row? */
    bool weak_ref;              /* Parsed a weak reference to this row? */
};

/*begin for ovsdb VTEP local DB data structre*/
/*begin for ovsdb VTEP local DB data structre*/
/*begin for ovsdb VTEP local DB data structre*/
/*begin for ovsdb VTEP local DB data structre*/
/*begin for ovsdb VTEP local DB data structre*/


/*修改原因:在内存中保存一份DB表,当DB发生变化时触发对应操作*/

enum ovsdb_vtep_encapsulation_type {
    ovsdb_vtep_vxlan_over_ipv4           /*vxlan_over_ipv4  */
};


struct ovsdb_vtep_vlan_binding{
    int vlan_id;    /*0-4095*/
    struct uuid uuid_logical_switch;
};

struct ovsdb_vtep_vlan_stats{
    int vlan_id;    /*0-4095*/
    struct uuid uuid_logical_binding_stats;
};

struct ovsdb_vtep_switch_binding{
    char* key;
    struct uuid uuid_logical_switch;
};

struct ovsdb_vtep_static_routes{
    char* key;
    char* value;
};

struct ovsdb_vtep_bfd{
    char* key;
    char* value;
};

struct ovsdb_vtep_bfd_status{
    char* key;
    char* value;
};

struct ovsdb_vtep_other_config{
    char* key;
    char* value;
};

struct ovsdb_vtep_status{
    char* key;
    char* value;
};





/*1 Global*/
#define GLOBAL_SWITCHES_NUM 10

typedef void (*global_switch_callback)(struct uuid* current, struct uuid* former, int atcion);
struct global_switches
{
    struct uuid switches[GLOBAL_SWITCHES_NUM];  /*uuid of Physical_Switch table*/
    global_switch_callback callback;
};
struct ovsdb_vtep_table_global{
    struct uuid uuid_self;
    struct uuid managers[10];  /*uuid of Manager table*/
    struct global_switches switches ;  /*uuid of Physical_Switch table*/
    int used_num_managers;
    int used_num_switches;
};

/*2 Physical_Switch*/
#define PHYSICAL_SWITCH_MANAGE_IP_NUM 10
#define PHYSICAL_SWITCH_PORT_NUM 100
#define PHYSICAL_SWITCH_TUNNEL_IP_NUM 10

struct ovsdb_vtep_table_physical_switch{
    struct uuid uuid_self;
    char* description;
    char* management_ips[PHYSICAL_SWITCH_MANAGE_IP_NUM];
    char* name;
    struct uuid ports[PHYSICAL_SWITCH_PORT_NUM]; /*uuid of Physical_Port*/
    char* tunnel_ips[PHYSICAL_SWITCH_TUNNEL_IP_NUM];
    int used_num_management_ips;
    int used_num_ports;
    int used_num_tunnel_ips;
};

/*3 Physical_Port*/
#define PORT_VLANBINDING_NUM 4096

typedef void (*port_vlanbindng_callback)(int vlan_id, struct uuid* logic_switch, int atcion);

struct port_vlanbingdings{
    struct ovsdb_vtep_vlan_binding vlan_bindings[PORT_VLANBINDING_NUM];
    port_vlanbindng_callback callback;  /*not used for the moment*/
};

struct ovsdb_vtep_table_physical_port{
    struct uuid uuid_self;
    char* name;
    char* description;
    struct port_vlanbingdings vlan_bindings;   /*vlan_bindings*/
    struct ovsdb_vtep_vlan_stats vlan_stats[10];    /*vlan_stats*/
    int used_num_vlan_bindings;
    int used_num_vlan_stats;
};

/*4 Logical_Binding_Stats*/
struct ovsdb_vtep_table_logical_binding_stats{
    struct uuid uuid_self;
    int bytes_from_local;
    int packets_from_local;
    int bytes_to_local;
    int packets_to_local;
};

/*5 Logical_Switch*/
struct ovsdb_vtep_table_logical_switch{
    struct uuid uuid_self;
    char* description;
    char* name;
    int tunnel_key;
};

/*6 Ucast_Macs_Local*/
struct ovsdb_vtep_table_ucast_macs_local{
    struct uuid uuid_self;
    char* MAC;
    struct uuid logical_switch;    /*uuid of Logical_Switch table*/
    struct uuid locator; /*uuid of Physical_Locator table*/
    char* ipaddr;
};

/*7 Ucast_Macs_Remote*/
struct ovsdb_vtep_table_ucast_macs_remote{
    struct uuid uuid_self;
    char* MAC;
    struct uuid logical_switch;    /*uuid of Logical_Switch table*/
    struct uuid locator; /*uuid of Physical_Locator table*/
    char* ipaddr;
};

/*8 Mcast_Macs_Local*/
struct ovsdb_vtep_table_mcast_macs_local{
    struct uuid uuid_self;
    char* MAC;
    struct uuid logical_switch;    /*uuid of Logical_Switch table*/
    struct uuid locator_set; /*uuid of Physical_Locator_Set table*/
    char* ipaddr;
};

/*9 Mcast_Macs_Remote*/
struct ovsdb_vtep_table_mcast_macs_remote{
    struct uuid uuid_self;
    char* MAC;
    struct uuid logical_switch;    /*uuid of Logical_Switch table*/
    struct uuid locator_set; /*uuid of Physical_Locator_Set table*/
    char* ipaddr;
};

/*10 Logical_Router*/
struct ovsdb_vtep_table_logical_route{
    struct uuid uuid_self;
    char* name;
    char* description;
    struct ovsdb_vtep_switch_binding switch_binding[10];
    struct ovsdb_vtep_static_routes static_routes[10];
    int used_num_switch_binding;
    int used_num_static_routes;
};

/*11 Physical_Locator_Set*/
#define LOCATOR_NUM_IN_LOCATION_SET 100

struct ovsdb_vtep_table_physical_locator_set{
    struct uuid uuid_self;
    struct uuid locators[LOCATOR_NUM_IN_LOCATION_SET]; /*one or more, uuid of Physical_Locator table*/
    int used_num_locators;
};

/*12 Physical_Locator*/
struct ovsdb_vtep_table_physical_locator{
    struct uuid uuid_self;
    struct ovsdb_vtep_bfd bfd[10];
    struct ovsdb_vtep_bfd_status bfd_status[10];
    char* dst_ip;
    enum ovsdb_vtep_encapsulation_type encapsulation_type;

    //int vni;    /*特意添加的一个属性，删除隧道时用*/

    int used_num_bfd;
    int used_num_bfd_status;
};

/*13 Manager*/
struct ovsdb_vtep_table_manager{
    struct uuid uuid_self;
    char* target;
    int max_backoff;    /*value >=1000*/
    int inactivity_probe;
    struct ovsdb_vtep_other_config other_config[10];
    bool is_connected;
    struct ovsdb_vtep_status status[10];
    int used_num_other_config;
    int used_num_status;
};

#define TABLE_PHYSICAL_SWITCH_NUM 10
#define TABLE_PHYSICAL_PORT_NUM 100
#define TABLE_LOGICAL_BINDING_STATS_NUM 100
#define TABLE_LOGICAL_SWITCH_NUM 1000
#define TABLE_UCAST_MACS_LOCAL_NUM 1000
#define TABLE_UCAST_MACS_REMOTE_NUM 1000
#define TABLE_MCAST_MACS_LOCAL_NUM 100
#define TABLE_MCAST_MACS_REMOTE_NUM 100
#define TABLE_LOGICAL_ROUTE_NUM 10
#define TABLE_PHYSICAL_LOCATOR_SET_NUM 100
#define TABLE_PHYSICAL_LOCATOR_NUM 1000
#define TABLE_MANAGER_NUM 100


/*The whole DB,including 13 tables above*/
struct ovsdb_vtep_db_tables{
    struct ovsdb_vtep_table_global table_global;    /*1 Global*/
    struct ovsdb_vtep_table_physical_switch table_physical_switch[TABLE_PHYSICAL_SWITCH_NUM];    /*2 Physical_Switch*/
    struct ovsdb_vtep_table_physical_port table_physical_port[TABLE_PHYSICAL_PORT_NUM];      /*3 Physical_Port*/
    struct ovsdb_vtep_table_logical_binding_stats table_logical_binding_stats[TABLE_LOGICAL_BINDING_STATS_NUM];      /*4 Logical_Binding_Stats*/
    struct ovsdb_vtep_table_logical_switch table_logical_switch[TABLE_LOGICAL_SWITCH_NUM];    /*5 Logical_Switch*/
    struct ovsdb_vtep_table_ucast_macs_local table_ucast_macs_local[TABLE_UCAST_MACS_LOCAL_NUM];       /*6 Ucast_Macs_Local*/
    struct ovsdb_vtep_table_ucast_macs_remote table_ucast_macs_remote[TABLE_UCAST_MACS_REMOTE_NUM];     /*7 Ucast_Macs_Remote*/
    struct ovsdb_vtep_table_mcast_macs_local table_mcast_macs_local[TABLE_MCAST_MACS_LOCAL_NUM];       /*8 Mcast_Macs_Local*/
    struct ovsdb_vtep_table_mcast_macs_remote table_mcast_macs_remote[TABLE_MCAST_MACS_REMOTE_NUM];     /*9 Mcast_Macs_Remote*/
    struct ovsdb_vtep_table_logical_route table_logical_route[TABLE_LOGICAL_ROUTE_NUM];      /*10 Logical_Router*/
    struct ovsdb_vtep_table_physical_locator_set table_physical_locator_set[TABLE_PHYSICAL_LOCATOR_SET_NUM];    /*11 Physical_Locator_Set*/
    struct ovsdb_vtep_table_physical_locator table_physical_locator[TABLE_PHYSICAL_LOCATOR_NUM];    /*12 Physical_Locator*/
    struct ovsdb_vtep_table_manager table_manager[TABLE_MANAGER_NUM];      /*13 Manager*/
    int used_num_table_global;
    int used_num_table_physical_switch;
    int used_num_table_physical_port;
    int used_num_table_logical_binding_stats;
    int used_num_table_logical_switch;
    int used_num_table_ucast_macs_local;
    int used_num_table_ucast_macs_remote;
    int used_num_table_mcast_macs_local;
    int used_num_table_mcast_macs_remote;
    int used_num_table_logical_route;
    int used_num_table_physical_locator_set;
    int used_num_table_physical_locator;
    int used_num_table_manager;
};


#define VXLAN_TUNNEL_NUM_MAX 4096
#define VXLAN_PORT_MAP_MAX 4094
#define VXLAN_TUNNEL_MAC_MAX 16384

#define SERVICE_NODE_MAX 10
#define HYPERVISOR_MAX 1024

#define IP_LENGTH_MAX 32


struct hw_vtep_vxlan_tunnel{
    int vni;
    char* source_ip;
    char* dst_ip;
    int used_bit;   /*是否使用的标志位*/
};

struct vxlan_tunnel_static_mac{
    int vni;
    char* source_ip;
    char* dst_ip;
    char* ce_mac;
    int used_bit;   /*是否使用的标志位*/
};

struct logical_switch_uuid_and_vni{
    struct uuid uuid_ls;
    int vni;
};

struct vlan_to_vni_map{
    int vni;
    int used_bit;   /*是否使用的标志位*/
};

struct port_vlan_to_vni_map{
    struct uuid port_uuid;
    struct vlan_to_vni_map vlan_vni_map[VXLAN_PORT_MAP_MAX];  /*下标表示vlanid,子接口为vlanid +1*/
};



#define GLOBAL_TABLE_NAME "Global"
#define PHYSICAL_SWITCH_TABLE_NAME "Physical_Switch"
#define LOGICAL_SWITCH_TABLE_NAME "Logical_Switch"
#define PHYSICAL_LOCATOR_SET_TABLE_NAME "Physical_Locator_Set"
#define PHYSICAL_LOCATOR_TABLE_NAME "Physical_Locator"
#define PHYSICAL_PORT_TABLE_NAME "Physical_Port"
#define UCAST_MACS_LOCAL_TABLE_NAME "Ucast_Macs_Local"
#define UCAST_MACS_REMOTE_TABLE_NAME "Ucast_Macs_Remote"
#define MCAST_MACS_LOCAL_TABLE_NAME "Mcast_Macs_Local"
#define MCAST_MACS_REMOTE_TABLE_NAME "Mcast_Macs_Remote"

#define LOGICAL_BINDING_STATS_TABLE_NAME "Logical_Binding_Stats"
#define LOGICAL_ROUTER_TABLE_NAME "Logical_Router"
#define MANAGER_TABLE_NAME "Manager"
#define ARP_SOURCES_LOCAL_TABLE_NAME "Arp_Sources_Local"
#define ARP_SOURCES_REMOTE_TABLE_NAME "Arp_Sources_Remote"

/*包含了Arp_Sources_Local和Arp_Sources_Remote*/
#define MAX_TABLE_ID 15

#if 0
enum table_list
{
    GLOBAL_TABLE,
    PHYSICAL_SWITCH_TABLE,
    LOGICAL_SWITCH_TABLE,
    PHYSICAL_LOCATOR_TABLE,
    PHYSICAL_LOCATOR_SET_TABLE,
    PHYSICAL_PORT_TABLE,
    UCAST_MACS_LOCAL_TABLE,
    UCAST_MACS_REMOTE_TABLE,
    MCAST_MACS_LOCAL_TABLE,
    MCAST_MACS_REMOTE_TABLE,
    MAX_TABLE_ID
};
#endif

enum table_action
{
    TABLE_INITIAL,
    TABLE_INSERT,
    TABLE_DELETE,
    TABLE_UPDATE,
    TABLE_INVALID_ACT
};

enum port_update_type
{
    ADD_VLAN_BINGDING,
    DELETE_VLAN_BINGDING,
    PORT_UPDATE_INVALID_TYPE
};


#define ACTION_TYPE(acion) ((action==TABLE_INITIAL)?"initial":((action==TABLE_INSERT)?"insert":((action==TABLE_DELETE)?"delete":"update")))

typedef void (*table_func)(struct jsonrpc*, struct json*, struct json*, char*, int);
void global_table_process(struct jsonrpc*,struct json*, struct json*, char*,int);
void physical_locator_table_process(struct jsonrpc*,struct json*, struct json*, char*,int);
void physical_port_table_process(struct jsonrpc*,struct json*, struct json*, char*, int );
void ucast_macs_local_table_process(struct jsonrpc*,struct json*, struct json*, char*, int );
void ucast_macs_remote_table_process(struct jsonrpc*,struct json*, struct json*, char*, int );
void mcast_macs_local_table_process(struct jsonrpc*,struct json*, struct json*, char*, int );
void mcast_macs_remote_table_process(struct jsonrpc*,struct json*, struct json*, char*, int );
void physical_switch_table_process(struct jsonrpc*,struct json*, struct json*, char*, int );
void logical_switch_table_process(struct jsonrpc*,struct json*, struct json*, char*, int );
void physical_locator_set_table_process(struct jsonrpc*,struct json*, struct json*, char*, int );

void logical_binding_stats_table_process(struct jsonrpc*,struct json*, struct json*, char*, int );
void logical_router_table_process(struct jsonrpc*,struct json*, struct json*, char*, int );
void manager_table_process(struct jsonrpc*,struct json*, struct json*, char*, int );
void arp_sources_local_table_process(struct jsonrpc*,struct json*, struct json*, char*, int );
void arp_sources_remote_table_process(struct jsonrpc*,struct json*, struct json*, char*, int );


void global_table_process_2(struct jsonrpc*,struct json*, struct json*, char*,int);
void physical_locator_table_process_2(struct jsonrpc*,struct json*, struct json*, char*,int);
void physical_port_table_process_2(struct jsonrpc*,struct json*, struct json*, char*, int );
void ucast_macs_local_table_process_2(struct jsonrpc*,struct json*, struct json*, char*, int );
void ucast_macs_remote_table_process_2(struct jsonrpc*,struct json*, struct json*, char*, int );
void mcast_macs_local_table_process_2(struct jsonrpc*,struct json*, struct json*, char*, int );
void mcast_macs_remote_table_process_2(struct jsonrpc*,struct json*, struct json*, char*, int );
void physical_switch_table_process_2(struct jsonrpc*,struct json*, struct json*, char*, int );
void logical_switch_table_process_2(struct jsonrpc*,struct json*, struct json*, char*, int );
void physical_locator_set_table_process_2(struct jsonrpc*,struct json*, struct json*, char*, int );

void logical_binding_stats_table_process_2(struct jsonrpc*,struct json*, struct json*, char*, int );
void logical_router_table_process_2(struct jsonrpc*,struct json*, struct json*, char*, int );
void manager_table_process_2(struct jsonrpc*,struct json*, struct json*, char*, int );
void arp_sources_local_table_process_2(struct jsonrpc*,struct json*, struct json*, char*, int );
void arp_sources_remote_table_process_2(struct jsonrpc*,struct json*, struct json*, char*, int );



int string_equals(char *stringA, char *stringB);
void mac_translate_ovsdb_to_ce(char*, char*);
void ce_config_bd(int vni);
void ce_undo_config_bd(int vni);

void ce_config_port(int vlan_id, int vni, char* port_name);
void ce_undo_config_port(int vlan_id, int vni, char* port_name);
void ce_config_vxlan_tunnel(int vni, char* source_ip, char* dst_ip);
void ce_undo_config_vxlan_tunnel(int vni, char* source_ip, char* dst_ip);

#define CE_MAC_FORM "1122-3344-5566"

void ce_config_nve1_source();
void ce_undo_config_nve1_source();
void ce_config_vxlan_tunnel_static_mac(char* ce_mac, char* source_ip, char* dst_ip, int vni);
void ce_undo_config_vxlan_tunnel_static_mac(char* ce_mac, char* source_ip, char* dst_ip, int vni);

void ovsdb_port_add_vlanbinding_process(struct json *new, struct json *old, char* node_name);
void ovsdb_port_update_vlanbinding_process(struct json *new, struct json *old, char* node_name, int* update_type);
void ovsdb_switch_update_management_ips_process(struct json *new, struct json *old, char* node_name);
void ovsdb_switch_update_tunnel_ips_process(struct json *new, struct json *old, char* node_name);
void ovsdb_physical_locator_process(struct uuid *uuid_pl, char *pl_dst_ip);
void  ovsdb_physical_locator_process_hypervisor_ip(struct uuid *uuid_pl, char *pl_dst_ip);
void  ovsdb_physical_locator_process_service_node_ip(struct uuid *uuid_pl, char *pl_dst_ip);
void ovsdb_physical_locator_process_config_vxlan_tunnel(int tunnel_key, char *pl_dst_ip);
void ovsdb_mcast_remote_update_locator_set_process(struct json *new, struct json *old, char* node_name);
void ovsdb_mcast_local_update_locator_set_process(struct json *new, struct json *old, char* node_name);

void ovsdb_query_port_and_mac(void *args);
void ovsdb_write_mcast_local(void *args);

struct ovsdb_write_mcast_local_args
{
    char *tunnel_ip;
    struct jsonrpc *rpc;
    struct uuid uuid_global;
};

//struct ovsdb_receive_mac_local_args
//{
//    char *tunnel_ip;
//    struct jsonrpc *rpc;
//};

struct table_callbacks
{
    const char* table_name;
    table_func callback;
};


#define ARGV_MAX 100
#define CE_6850HI_10GE_PORT_NUM 48
#define CE_6850HI_40GE_PORT_NUM 6

void main_vtep_ce_tor_cmd(int argc, char *argv[]);
void main_vtep_ce_tor_init(int argc, char *argv[]);

void do_transact_temp(struct jsonrpc *rpc, char *json_char);
void do_transact_temp_query_global(struct jsonrpc *rpc, int* global_uuid_num, struct uuid *uuid_global);
void do_transact_temp_query_logical_switch(struct jsonrpc *rpc, int* ls_num, struct logical_switch_uuid_and_vni *ls_info);
void do_transact_temp_query_locator_dstip(struct jsonrpc *rpc, char *json_char, int *pl_exist,  char* pl_dst_ip);
void do_transact_temp_query_locator_uuid(struct jsonrpc *rpc, char *json_char, struct uuid *locator_uuid);
void do_transact_temp_query_port_binding_logical_switch(struct jsonrpc *rpc, char *json_char ,int *ls_num, struct uuid *ls_uuids);
void do_transact_temp_query_logical_switch_tunnel_key(struct jsonrpc *rpc, char *json_char ,int *tunnel_key_exist, int *tunnel_key);
void do_transact_temp_query_physical_locator_dst_ip(struct jsonrpc *rpc, char *json_char ,char* dst_ip);
void do_transact_temp_query_mac_local_uuid(struct jsonrpc *rpc, char *json_char ,int *uuid_num, struct uuid *ucast_local_uuids);
int do_check_mac_info_from_fei(unsigned char *aucMacAddr, unsigned char *aucIfname, unsigned int add_or_delete_flag, unsigned int dyn_or_static_flag, unsigned int ulBDID);


void do_vtep(struct jsonrpc *rpc, const char *database, int argc , char *argv[] );
void do_vtep_transact(struct jsonrpc *rpc, const char *database, int argc , char *argv[] );
void do_vtep_monitor(struct jsonrpc *rpc, const char *database, int argc , char *argv[] );


/*below is socket related*/

#define MAX_BUF_LENGTH  196
#define TCP_TEST_PORT    5221

typedef struct MAC_INFO_SEND{
    unsigned char   aucMacAddr[32];
    unsigned char   aucIfname[16];
    unsigned int   add_or_delete_flag;  /*1表示新增，2表示删除*/
    unsigned int   dyn_or_static_flag;  /*1表示动态MAC，2表示静态MAC*/
    unsigned int   ulBDID;
}MAC_INFO_SEND_S;

#define MAC_ADD  1
#define MAC_DELETE  2

#define MAC_DYNAMIC  1
#define MAC_STATIC  2

#define FEI_MAC_CHECK_OK 0
#define FEI_MAC_CHECK_ERROR 1


/*end for ovsdb VTEP local DB data structre*/
/*end for ovsdb VTEP local DB data structre*/
/*end for ovsdb VTEP local DB data structre*/
/*end for ovsdb VTEP local DB data structre*/
/*end for ovsdb VTEP local DB data structre*/






struct ovsdb_symbol_table *ovsdb_symbol_table_create(void);
void ovsdb_symbol_table_destroy(struct ovsdb_symbol_table *);
struct ovsdb_symbol *ovsdb_symbol_table_get(const struct ovsdb_symbol_table *,
                                            const char *name);
struct ovsdb_symbol *ovsdb_symbol_table_put(struct ovsdb_symbol_table *,
                                            const char *name,
                                            const struct uuid *, bool used);
struct ovsdb_symbol *ovsdb_symbol_table_insert(struct ovsdb_symbol_table *,
                                               const char *name);

/* Tokenization
 *
 * Used by ovsdb_atom_from_string() and ovsdb_datum_from_string(). */

char *ovsdb_token_parse(const char **, char **outp) WARN_UNUSED_RESULT;
bool ovsdb_token_is_delim(unsigned char);

#endif /* ovsdb-data.h */
