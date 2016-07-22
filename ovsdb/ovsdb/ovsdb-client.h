
#ifndef OVSDB_CLIENT_H
#define OVSDB_CLIENT_H 1

#include "uthash.h"

#undef  OVSDB_DESC
#define OVSDB_DESC(name)              (1)

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

#define OVSDB_PRINTF_DEBUG_TRACE(szfmt, args...)\
do{\
    VLOG_DBG(\
        ">>>func: %s, line: %d. Debug: "szfmt"\r\n",\
        __FUNCTION__, __LINE__, ##args);\
}while(0)

#define OVSDB_PRINTF_DEBUG_WARN(szfmt, args...)\
do{\
    VLOG_WARN(\
        ">>>func: %s, line: %d. Warn: "szfmt"\r\n",\
        __FUNCTION__, __LINE__, ##args);\
}while(0)

#define OVSDB_PRINTF_DEBUG_ERROR(szfmt, args...)\
do{\
    VLOG_ERR(\
        ">>>func: %s, line: %d. Error: "szfmt"\r\n",\
        __FUNCTION__, __LINE__, ##args);\
}while(0)

#define OVSDB_CLIENT_GET_STRING_FROM_NCREPLY(str, str_len, left, right, start)  \
do{                                                                             \
    char * pLeft  = NULL;                                                       \
    char * pRight = NULL;                                                       \
    int i = 0;                                                                  \
    (void)memset(str, 0, str_len);                                              \
    pLeft = strstr(start, left);                                                \
    if (NULL == pLeft)                                                          \
    {                                                                           \
        start = NULL;                                                           \
        break;                                                                  \
    }                                                                           \
    pLeft = pLeft + strlen(left);                                               \
    pRight = strstr(pLeft, right);                                              \
    if (NULL == pLeft)                                                          \
    {                                                                           \
        start = NULL;                                                           \
        break;                                                                  \
    }                                                                           \
    while ((pLeft != pRight) && (i < str_len - 1))                              \
    {                                                                           \
        str[i] = *pLeft;                                                        \
        pLeft++;                                                                \
        i++;                                                                    \
    }                                                                           \
    str[i] = '\0';                                                              \
    start = pRight + strlen(right);                                             \
}while (0)

#define OVSDB_SUB_GET_TABLE(NAME)         (*(g_aucTBL[NAME].pstTbl))
#define OVSDB_SUB_GET_AGEINGTABLE(NAME)   (*(g_aucTBL[NAME].pstAgeingTbl))
#define OVSDB_SUB_GET_DATA_LENGTH(NAME)   ((g_aucTBL[NAME].iDataLength))
#define OVSDB_SUB_EXCHANGE_AGEINGTABLE(NAME)                    \
do{                                                             \
    struct ovsdb_sub_entry ** tmp;                              \
    tmp = g_aucTBL[NAME].pstTbl;                                \
    g_aucTBL[NAME].pstTbl = g_aucTBL[NAME].pstAgeingTbl;        \
    g_aucTBL[NAME].pstAgeingTbl = tmp;                          \
}while (0)

#define OVSDB_SUB_KEY_LEN        64

enum OVSDB_SUB_TABLE_NAME
{
    OVSDB_SUB_TABLE_MAC,
    OVSDB_SUB_TABLE_INTERFACE,
    OVSDB_SUB_TABLE_MAX,
};

struct ovsdb_sub_entry {
    char key[OVSDB_SUB_KEY_LEN]; /* key */
    void * pdata;                /* data */
    UT_hash_handle hh;           /* makes this structure hashable */
};

struct ovsdb_sub_table {
    char * name;
    struct ovsdb_sub_entry ** pstTbl;
    struct ovsdb_sub_entry ** pstAgeingTbl;
    struct ovsdb_sub_entry * pstTblA;
    struct ovsdb_sub_entry * pstTblB;
    int iDataLength;
};

#define OVSDB_SUB_BD_LEN         8
#define OVSDB_SUB_INTERFACE_LEN  64

struct ovsdb_sub_mac_key {
    union
    {
        char macAdd[18];
        char macAdd3[3][6];
        char macAdd6[6][3];
    }unMac;   //MAC存储格式:11:22:33:44:55:66
    char BD[OVSDB_SUB_BD_LEN];
#define macAdd   unMac.macAdd
#define macAdd3  unMac.macAdd3
#define macAdd6  unMac.macAdd6
};

struct ovsdb_sub_mac_data {
    char interface[OVSDB_SUB_INTERFACE_LEN];
    int  mac_type;
};

struct ovsdb_sub_port_key {
    char interface[OVSDB_SUB_INTERFACE_LEN];
};

enum OVSDB_CLIENT_CFG_TYPE
{
    OVSDB_CLIENT_CFG_LINKTYPE,
    OVSDB_CLIENT_CFG_CONTROLLERIP,
    OVSDB_CLIENT_CFG_CONTROLLERPORT,
    OVSDB_CLIENT_CFG_SWITCHNAME,
    OVSDB_CLIENT_CFG_DESCRIPTION,
    OVSDB_CLIENT_CFG_SWITCHMANAGEIP,
    OVSDB_CLIENT_CFG_TUNNERIP,
    OVSDB_CLIENT_CFG_NETCONFIP,
    OVSDB_CLIENT_CFG_NETCONFPORT,
    OVSDB_CLIENT_CFG_NETCONFUSER,
    OVSDB_CLIENT_CFG_NETCONFPW,
    OVSDB_CLIENT_CFG_MAX,   
};

struct ovsdb_client_cfg_map {
    char acType[32];
    char acAttribute[256];
    int (*pfnCheck)(void);
};

#define OVSDB_CLIENT_CFG_GET_STRING(TYPE) (gast_ovsdb_client_cfg_map[TYPE].acAttribute)

int ovsdb_sub_table_mac_add(char *mac, char *bd, char *interface, int mac_type);
int ovsdb_sub_table_mac_delete();
int ovsdb_sub_table_interface_add(char *interface);
int ovsdb_sub_table_interface_delete();

void ovsdb_add_port(char *interface);
void ovsdb_delete_port(char * interface);
int ovsdb_add_mac(char * mac, char * bd, char * interface, int mac_type);
void ovsdb_delete_mac(char * mac, char * bd, char * interface, int mac_type);

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



void mac_translate_ovsdb_to_ce(char*, char*);

#define CE_MAC_FORM "1122-3344-5566"

unsigned int netconf_ce_undo_config_vxlan_tunnel(unsigned int uiVni, char * paDstIp);

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

#endif /* ovsdb/ovsdb_client.h */

