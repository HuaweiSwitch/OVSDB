/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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

#include <config.h>

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#ifndef gettid
#define gettid() syscall(__NR_gettid)
#endif

#include "command-line.h"
#include "column.h"
#include "compiler.h"
#include "daemon.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "json.h"
#include "jsonrpc.h"
#include "lib/table.h"
#include <arpa/inet.h>
#include "ovsdb.h"
#include "ovsdb-data.h"
#include "ovsdb-error.h"
#include "poll-loop.h"
#include "sort.h"
#include "svec.h"
#include "stream.h"
#include "stream-ssl.h"
#include "table.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"
#include "netconf/libnetconf.h"
#include "netconf/libnetconf_ssh.h"
#include "ovsdb-client.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_client);
#if OVSDB_DEBUG
struct table_callbacks table_func_map[] = {
    {GLOBAL_TABLE_NAME, global_table_process},
    {PHYSICAL_SWITCH_TABLE_NAME, physical_switch_table_process},
    {LOGICAL_SWITCH_TABLE_NAME, logical_switch_table_process},
    {PHYSICAL_PORT_TABLE_NAME, physical_port_table_process},
    {UCAST_MACS_LOCAL_TABLE_NAME, ucast_macs_local_table_process},
    {UCAST_MACS_REMOTE_TABLE_NAME, ucast_macs_remote_table_process},
    {MCAST_MACS_LOCAL_TABLE_NAME, mcast_macs_local_table_process},
    {MCAST_MACS_REMOTE_TABLE_NAME, mcast_macs_remote_table_process},
    {PHYSICAL_LOCATOR_SET_TABLE_NAME, physical_locator_set_table_process},
    {PHYSICAL_LOCATOR_TABLE_NAME, physical_locator_table_process},
    {TUNNEL_TABLE_NAME, tunnel_table_process},
    /*below ones are not used*/
    {LOGICAL_BINDING_STATS_TABLE_NAME, logical_binding_stats_table_process},
    {LOGICAL_ROUTER_TABLE_NAME, logical_router_table_process},
    {MANAGER_TABLE_NAME, manager_table_process},
    {ARP_SOURCES_LOCAL_TABLE_NAME, arp_sources_local_table_process},
    {ARP_SOURCES_REMOTE_TABLE_NAME, arp_sources_remote_table_process},
};
#endif
#if 1
struct table_callbacks table_func_map[] = {
    {GLOBAL_TABLE_NAME, global_table_process},
    {PHYSICAL_SWITCH_TABLE_NAME, physical_switch_table_process},
    {LOGICAL_SWITCH_TABLE_NAME, logical_switch_table_process},
    {PHYSICAL_PORT_TABLE_NAME, physical_port_table_process},
    /* 顺序修改begin */
    {PHYSICAL_LOCATOR_TABLE_NAME, physical_locator_table_process},
    {PHYSICAL_LOCATOR_SET_TABLE_NAME, physical_locator_set_table_process},
    {UCAST_MACS_LOCAL_TABLE_NAME, ucast_macs_local_table_process},
    {UCAST_MACS_REMOTE_TABLE_NAME, ucast_macs_remote_table_process},
    {MCAST_MACS_LOCAL_TABLE_NAME, mcast_macs_local_table_process},
    {MCAST_MACS_REMOTE_TABLE_NAME, mcast_macs_remote_table_process},
    /* 顺序修改end */
    {TUNNEL_TABLE_NAME, tunnel_table_process},
    /*below ones are not used*/
    {LOGICAL_BINDING_STATS_TABLE_NAME, logical_binding_stats_table_process},
    {LOGICAL_ROUTER_TABLE_NAME, logical_router_table_process},
    {MANAGER_TABLE_NAME, manager_table_process},
    {ARP_SOURCES_LOCAL_TABLE_NAME, arp_sources_local_table_process},
    {ARP_SOURCES_REMOTE_TABLE_NAME, arp_sources_remote_table_process},
};
#endif

struct table_callbacks table_func_map_2[] = {
    {GLOBAL_TABLE_NAME, global_table_process_2},
    {PHYSICAL_SWITCH_TABLE_NAME, physical_switch_table_process_2},
    {LOGICAL_SWITCH_TABLE_NAME, logical_switch_table_process_2},
    {PHYSICAL_PORT_TABLE_NAME, physical_port_table_process_2},

    {PHYSICAL_LOCATOR_TABLE_NAME, physical_locator_table_process_2},

    {UCAST_MACS_LOCAL_TABLE_NAME, ucast_macs_local_table_process_2},
    {UCAST_MACS_REMOTE_TABLE_NAME, ucast_macs_remote_table_process_2},
    {MCAST_MACS_LOCAL_TABLE_NAME, mcast_macs_local_table_process_2},
    {MCAST_MACS_REMOTE_TABLE_NAME, mcast_macs_remote_table_process_2},
    {PHYSICAL_LOCATOR_SET_TABLE_NAME, physical_locator_set_table_process_2},
    //{PHYSICAL_LOCATOR_TABLE_NAME, physical_locator_table_process},
    /*below ones are not used*/
    {TUNNEL_TABLE_NAME, tunnel_table_process_2},
    {LOGICAL_BINDING_STATS_TABLE_NAME, logical_binding_stats_table_process_2},
    {LOGICAL_ROUTER_TABLE_NAME, logical_router_table_process_2},
    {MANAGER_TABLE_NAME, manager_table_process_2},
    {ARP_SOURCES_LOCAL_TABLE_NAME, arp_sources_local_table_process_2},
    {ARP_SOURCES_REMOTE_TABLE_NAME, arp_sources_remote_table_process_2},
};


/*global used for vtep monitor*/
struct ovsdb_vtep_db_tables ovsdb_vtep_db_table = {0};
/*switch_vxlan_tunnel全局变量在pyhsical_locator表的变化中操作*/
struct hw_vtep_vxlan_tunnel switch_vxlan_tunnel[VXLAN_TUNNEL_NUM_MAX] = {0};

struct hw_vtep_vxlan_tunnel service_node_vxlan_tunnel_to_be_created[SERVICE_NODE_MAX]= {0};
struct hw_vtep_vxlan_tunnel hypervisor_vxlan_tunnel_to_be_created[HYPERVISOR_MAX]= {0};
int vxlan_tunnel_to_be_create_flag = 0; /*是否有隧道需要创建的标识位，用于locator表处理一阶段与二阶段的联系*/

struct vxlan_tunnel_static_mac switch_vxlan_static_mac[VXLAN_TUNNEL_MAC_MAX] = {0};

#if OVSDB_DEBUG
/*global used for vtep transact*/
struct logical_switch_uuid_and_vni logical_switch_info[TABLE_LOGICAL_SWITCH_NUM] = {0};
#endif

/*MAC_ovsdb: 01:02:33:44:55:66  MAC_CE: 0102-3344-5566*/
/*调用者必须保证mac_ce申请的内存大小为strlen("0102-3344-5566")+1*/
/*用于配置vxlan静态mac的命令行暂时不支持，所以该函数暂时用不到*/
void mac_translate_ovsdb_to_ce(char* mac_ovsdb, char* mac_ce)
{
    if((NULL==mac_ovsdb) || (NULL==mac_ce))
    {
        OVSDB_PRINTF_DEBUG_ERROR("mac_ovsdb or mac_ce is null, return.");
        return;
    }

    /*根据vtep的dump,ovsdb的mac格式如上面那种格式*/
    if((strlen(mac_ovsdb))!=(strlen("11:22:33:44:55:66")))
    {
        OVSDB_PRINTF_DEBUG_ERROR("wrong ovsdb-mac format, return.");
        return;
    }

    /*转换*/
    mac_ce[0] = mac_ovsdb[0];
    mac_ce[1] = mac_ovsdb[1];
    mac_ce[2] = mac_ovsdb[3];
    mac_ce[3] = mac_ovsdb[4];
    mac_ce[4] = '-';
    mac_ce[5] = mac_ovsdb[6];
    mac_ce[6] = mac_ovsdb[7];
    mac_ce[7] = mac_ovsdb[9];
    mac_ce[8] = mac_ovsdb[10];
    mac_ce[9] = '-';
    mac_ce[10] = mac_ovsdb[12];
    mac_ce[11] = mac_ovsdb[13];
    mac_ce[12] = mac_ovsdb[15];
    mac_ce[13] = mac_ovsdb[16];
    mac_ce[14] = 0;

    return;
}

void mac_translate_ce_to_ovsdb(char* mac_ovsdb, char* mac_ce)
{
    if((NULL==mac_ovsdb) || (NULL==mac_ce))
    {
        OVSDB_PRINTF_DEBUG_ERROR("mac_ovsdb or mac_ce is null, return.");
        return;
    }

    /*根据vtep的dump,ovsdb的mac格式如上面那种格式*/
    if((strlen(mac_ce))!=(strlen("1111-2222-3333")))
    {
        OVSDB_PRINTF_DEBUG_ERROR("wrong ovsdb-mac format, return.");
        return;
    }

    /*转换*/
    mac_ovsdb[0]  = mac_ce[0];
    mac_ovsdb[1]  = mac_ce[1];
    mac_ovsdb[2]  = ':';
    mac_ovsdb[3]  = mac_ce[2];
    mac_ovsdb[4]  = mac_ce[3];
    mac_ovsdb[5]  = ':';
    mac_ovsdb[6]  = mac_ce[5];
    mac_ovsdb[7]  = mac_ce[6];
    mac_ovsdb[8]  = ':';
    mac_ovsdb[9]  = mac_ce[7];
    mac_ovsdb[10] = mac_ce[8];
    mac_ovsdb[11] = ':';
    mac_ovsdb[12] = mac_ce[10];
    mac_ovsdb[13] = mac_ce[11];
    mac_ovsdb[14] = ':';
    mac_ovsdb[15] = mac_ce[12];
    mac_ovsdb[16] = mac_ce[13];
    mac_ovsdb[17] = '\0';

    return;
}

int ip_translate_bfd_sessname(char* ip, char* name)
{
    unsigned int ip_value = 0;
    ip_value = inet_addr(ip);
    if (INADDR_NONE == ip_value) {
        return OVSDB_ERR;
    }
    (void)snprintf(name, BFD_SESSION_NAME_LEN,
                   "vxlan%08x", ip_value);

    return OVSDB_OK;
}

#if OVSDB_DESC("配置管理")

struct ovsdb_client_cfg_map gast_ovsdb_client_cfg_map[OVSDB_CLIENT_CFG_MAX] =
{
    {"Link type:",          {0}, NULL},
    {"Controller IP:",      {0}, NULL},
    {"Controller port:",    {0}, NULL},
    
    {"Switch name:",        {0}, NULL},
    {"Switch description:", {0}, NULL},
    {"Manage IP:",          {0}, NULL},
    {"Tunnel IP:",          {0}, NULL},
    {"BFD enabled:",        {0}, NULL},
    {"Netconf IP:",         {0}, NULL},
    {"Netconf port:",       {0}, NULL},
    {"Netconf user:",       {0}, NULL},
    {"Netconf password:",   {0}, NULL},
};

int ovsdb_client_init_cfg(void)
{
    FILE*   fpCfg;
    int     i;
    char    acTmp[512]      = {0};
    char    *pcHead, *pcEnd;

    fpCfg = fopen("/etc/openvswitch/ovsdb-client.cfg", "rb");
    if (NULL == fpCfg) {
        printf("\r\n[ERROR]Open ovsdb-client.cfg failed.");
        return -1;
    }
    
    while (!feof(fpCfg)) {
        (void)fgets(acTmp, 512, fpCfg);

        for (i = 0; i < OVSDB_CLIENT_CFG_MAX; i++) {
            pcHead = strstr(acTmp, gast_ovsdb_client_cfg_map[i].acType);
            if (NULL == pcHead){
                continue;
            }
        
            pcHead += strlen(gast_ovsdb_client_cfg_map[i].acType);
            pcEnd = pcHead;
        
            while ((*pcEnd != '\0') && (*pcEnd != '\n') && (*pcEnd != '\r'))
                pcEnd++;
        
            while ((*pcHead == ' ') && (pcHead != pcEnd))
                pcHead++;
        
            if ((pcHead >= pcEnd) ||
                (sizeof(gast_ovsdb_client_cfg_map[i].acAttribute) <= (pcEnd - pcHead))) {
                continue;
            }
        
            memcpy(gast_ovsdb_client_cfg_map[i].acAttribute, pcHead, (pcEnd - pcHead));
        }
    }
    
    fclose(fpCfg);
    
    for(i = 0; i < OVSDB_CLIENT_CFG_MAX; i++) {
        if (0 == strlen(gast_ovsdb_client_cfg_map[i].acAttribute)) {
            printf("\r\n[ERROR]Cann't find \"%s\" selection.", 
                gast_ovsdb_client_cfg_map[i].acType);
            return -1;
        }
    }
    
    return 0;
}

char g_aucBFD_local_mac[MAX_OVSDB_MAC_LEN] = {0};
unsigned int netconf_ce_query_ethernet_mac(char * pcMAC);

int ovsdb_client_init_system_mac(void)
{
    unsigned int uiRet = OVSDB_OK;
    char aucMAC[MAX_CE_MAC_LEN];

    (void)memset(aucMAC, 0, MAX_CE_MAC_LEN);

    uiRet = netconf_ce_query_ethernet_mac(aucMAC);
    if (uiRet != OVSDB_OK)
        return -1;

    if (strlen("1111-2222-3333") != strlen(aucMAC)) {
        OVSDB_PRINTF_DEBUG_ERROR("Get system mac failed.");
        return -1;
    }

    mac_translate_ce_to_ovsdb(g_aucBFD_local_mac, aucMAC);
    
    return 0;
}

int ovsdb_bfd_dstIPtoName(struct ovsdb_vtep_table_tunnel * entry)
{
    unsigned int ip = inet_addr(entry->bfd_config_remote.bfd_ip);

    if (ip == 0xffffffff) {
        OVSDB_PRINTF_DEBUG_ERROR("bfd tranlate name error, uuid: "UUID_FMT,
            UUID_ARGS(&entry->uuid_self1));
        return OVSDB_ERR;
    }

    (void)snprintf(entry->name, BFD_SESSION_NAME_LEN, "vxlan%x", ip);

    return OVSDB_OK;
}

#endif

#if OVSDB_DESC("netconf")
/*netconf session id*/
struct ovsdb_nc_sess {
    pid_t tid;
    struct nc_session * pst_netconf_session;
    struct nc_cpblts  * pst_cpblts;
};
struct ovsdb_nc_sess gst_nc_sess[2] = {0};

#define NETCONF_GET_MY_TID_SESSION(session) \
do { \
    pid_t my_tid = gettid(); \ 
    int i; \
    for (i = 0; i < 2; i++) { \
        if (gst_nc_sess[i].tid == my_tid) { \
            session = gst_nc_sess + i; \
            break; \
        } \
    } \
}while(0)

int netconf_msg_list_config_bd(unsigned int uiVniId);
int netconf_msg_list_undo_config_bd(unsigned int uiVniId);
int netconf_msg_list_config_vxlan_tunnel(unsigned int uiVni, char * paDstIp);
int netconf_msg_list_undo_config_vxlan_tunnel(unsigned int uiVni, char * paDstIp);
int netconf_msg_list_config_port(unsigned int uiVlanId, unsigned int uiVniId, char* paIfname);
int netconf_msg_list_undo_config_port(unsigned int uiVlanId, char* paIfname);
int netconf_msg_list_config_vxlan_tunnel_static_mac(char* paStaticMac, char* paSourceIp, char* paDstIp, unsigned int uiVniId);
int netconf_msg_list_undo_config_vxlan_tunnel_static_mac(char* paStaticMac, char* paSourceIp, char* paDstIp, unsigned int uiVniId);

unsigned int netconf_ce_undo_config_vxlan_tunnel(unsigned int uiVni, char * paDstIp);

char * netconf_ce_config_password(const char * username, const char * hostname)
{
    char * pcPW = xmalloc(256);
    
    if (NULL == pcPW)
        return NULL;
    
    memcpy(pcPW, OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_NETCONFPW), 256);
    
    return pcPW;
}

int netconf_ce_ssh_hostkey_check_default (const char* hostname, ssh_session session)
{
    char* hexa;
    int c, state, ret;
    ssh_key srv_pubkey;
    unsigned char *hash_sha1 = NULL;
    size_t hlen;
    enum ssh_keytypes_e srv_pubkey_type;

    state = ssh_is_server_known(session);
    
    ret = ssh_get_publickey(session, &srv_pubkey);
    if (ret < 0){
        OVSDB_PRINTF_DEBUG_ERROR("Unable to get server public key. ret = %d.", ret);
        return -1;
    }
            
    srv_pubkey_type = ssh_key_type(srv_pubkey);
    ret = ssh_get_publickey_hash(srv_pubkey, SSH_PUBLICKEY_HASH_SHA1, &hash_sha1, &hlen);
    ssh_key_free(srv_pubkey);
    if (ret < 0) {
        OVSDB_PRINTF_DEBUG_ERROR("Failed to calculate SHA1 hash of server public key. ret = %d.", ret);
        return -1;
    }
    
    hexa = ssh_get_hexa(hash_sha1, hlen);
    
    switch (state) {
    case SSH_SERVER_KNOWN_OK:
        break; /* ok */
    
    case SSH_SERVER_KNOWN_CHANGED:
        OVSDB_PRINTF_DEBUG_ERROR("Remote host key changed, the connection will be terminated!");
        goto fail;
    
    case SSH_SERVER_FOUND_OTHER:
        OVSDB_PRINTF_DEBUG_ERROR("The remote host key was not found but another type of key was, the connection will be terminated.");
        goto fail;
    
    case SSH_SERVER_FILE_NOT_FOUND:
        OVSDB_PRINTF_DEBUG_ERROR("Could not find the known hosts file.");
        /* fallback to SSH_SERVER_NOT_KNOWN behavior */
        
    case SSH_SERVER_NOT_KNOWN:
        /* store the key into the host file */
        ret = ssh_write_knownhost(session);
        if (ret < 0) {
            OVSDB_PRINTF_DEBUG_ERROR("Adding the known host %s failed (%s).", hostname, strerror(errno));
        }
        
        break;
    
    case SSH_SERVER_ERROR:
        ssh_clean_pubkey_hash(&hash_sha1);
        //fprintf(stderr,"%s",ssh_get_error(session));
        return -1;
    }
    
    ssh_clean_pubkey_hash(&hash_sha1);
    ssh_string_free_char(hexa);
    return 0;
    
fail:
    ssh_clean_pubkey_hash(&hash_sha1);
    ssh_string_free_char(hexa);
    return -1;
}

int netconf_ce_config_init(struct ovsdb_nc_sess * pst_nc_sess)
{
    int i = 0;
    int port = 0;

    port = atoi(OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_NETCONFPORT));
    
    if (port <= 0 || port >= 65535)
    {
        return -1;
    }
    
    pst_nc_sess->pst_cpblts = nc_cpblts_new(NULL);
    if (pst_nc_sess->pst_cpblts == NULL)
    {
        return -1;
    }

    nc_cpblts_add(pst_nc_sess->pst_cpblts, "urn:ietf:params:netconf:base:1.0");
    nc_cpblts_add(pst_nc_sess->pst_cpblts, "urn:ietf:params:netconf:capability:writable-running:1.0");
    nc_cpblts_add(pst_nc_sess->pst_cpblts, "urn:ietf:params:netconf:capability:candidate:1.0");
    nc_cpblts_add(pst_nc_sess->pst_cpblts, "urn:ietf:params:netconf:capability:confirmed-commit:1.0");
    nc_cpblts_add(pst_nc_sess->pst_cpblts, "http://www.huawei.com/netconf/capability/discard-commit/1.0");

    nc_cpblts_add(pst_nc_sess->pst_cpblts, "urn:ietf:params:netconf:capability:startup:1.0");
    nc_cpblts_add(pst_nc_sess->pst_cpblts, "urn:ietf:params:netconf:capability:rollback-on-error:1.0");
    nc_cpblts_add(pst_nc_sess->pst_cpblts, "http://www.huawei.com/netconf/capability/sync/1.1");
    nc_cpblts_add(pst_nc_sess->pst_cpblts, "http://www.huawei.com/netconf/capability/sync/1.0");
    nc_cpblts_add(pst_nc_sess->pst_cpblts, "http://www.huawei.com/netconf/capability/exchange/1.0");

    nc_cpblts_add(pst_nc_sess->pst_cpblts, "http://www.huawei.com/netconf/capability/active/1.0");
    nc_cpblts_add(pst_nc_sess->pst_cpblts, "http://www.huawei.com/netconf/capability/action/1.0");
    nc_cpblts_add(pst_nc_sess->pst_cpblts, "http://www.huawei.com/netconf/capability/execute-cli/1.0");
    nc_cpblts_add(pst_nc_sess->pst_cpblts, "http://www.huawei.com/netconf/capability/update/1.0");
    nc_cpblts_add(pst_nc_sess->pst_cpblts, "http://www.huawei.com/netconf/capability/commit-description/1.0");

    nc_cpblts_add(pst_nc_sess->pst_cpblts, "urn:ietf:params:netconf:capability:notification:1.0");
    nc_cpblts_add(pst_nc_sess->pst_cpblts, "urn:ietf:params:netconf:capability:interleave:1.0");

    nc_callback_ssh_host_authenticity_check(netconf_ce_ssh_hostkey_check_default);
    nc_callback_sshauth_password(netconf_ce_config_password);
    
    pst_nc_sess->pst_netconf_session = nc_session_connect(OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_NETCONFIP),
                                             (unsigned short)port,
                                             OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_NETCONFUSER),
                                             pst_nc_sess->pst_cpblts);
    if (NULL == pst_nc_sess->pst_netconf_session)
    {
        nc_cpblts_free(pst_nc_sess->pst_cpblts);
        pst_nc_sess->pst_cpblts = NULL;
        printf("\r\n[ERROR]Session connect failed when trying to connect to netconf.");
        return -1;
    }

    return 0;
}

void netconf_ce_config_destory(struct ovsdb_nc_sess * pst_nc_sess)
{
    if (NULL != pst_nc_sess->pst_netconf_session)
    {
        nc_session_free(pst_nc_sess->pst_netconf_session);
        pst_nc_sess->pst_netconf_session = NULL;
    }

    if (NULL != pst_nc_sess->pst_cpblts)
    {
        nc_cpblts_free(pst_nc_sess->pst_cpblts);
        pst_nc_sess->pst_cpblts = NULL;
    }

    return;
}

void netconf_vlanbit2netvlanbit(unsigned int uiVlanId, unsigned char aucNetVlanBitStr[])
{
    unsigned int uiLoopi     = 0;
    unsigned int uiLoopj     = 0;
    unsigned int uiLoopk     = 0;
    unsigned int ucVlanValue = 0;
    unsigned char vlanBit[NETCONF_VLANBIT_LEN] = {0};

    vlanBit[(uiVlanId >> 3)] |= (1 << (uiVlanId & 0x07));

    for (uiLoopi = 0; (uiLoopi < NETCONF_VLANBIT_LEN) && (uiLoopk < NETCONF_VLANBIT_LEN_STR); uiLoopi++)
    {
        ucVlanValue = 0;
        for (uiLoopj = 0; uiLoopj < 8; uiLoopj++)
        {
            ucVlanValue += NETCONF_BIT_REVERSE(vlanBit[uiLoopi], uiLoopj);
        }

        NETCONF_NUM_TO_STR((ucVlanValue & 0xf), aucNetVlanBitStr[uiLoopk+1]);
        NETCONF_NUM_TO_STR(((ucVlanValue & 0xf0)>>4), aucNetVlanBitStr[uiLoopk]);
        uiLoopk += 2;
    }

    return;
}


unsigned int netconf_ce_set_config(char* send_data)
{
    unsigned int    uiRet  = 0;
    nc_rpc          *rpc   = NULL;
    nc_reply        *reply = NULL;
    NC_MSG_TYPE     sessionRet = NC_MSG_REPLY;
    unsigned int    uiTry  = 0;

    OVSDB_NULL_RETURN(send_data);

    struct ovsdb_nc_sess * pst_session = NULL;
    NETCONF_GET_MY_TID_SESSION(pst_session);
    if (NULL == pst_session) {
        OVSDB_PRINTF_DEBUG_ERROR("Can't find netconf session, my tid = %d.", gettid());
        return OVSDB_ERR;
    }

RETRY:
    rpc = nc_rpc_generic(send_data);

    if (NULL == rpc) {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to rpc generic.");
        return OVSDB_ERR;
    }

    /* netconf下发配置*/
    sessionRet = nc_session_send_recv(pst_session->pst_netconf_session, rpc, &reply);

    nc_rpc_free(rpc);
    rpc = NULL;

    if (sessionRet != NC_MSG_REPLY){
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to set configuration, error message is %s.",
            nc_reply_get_errormsg(reply));
        nc_reply_free(reply);
        if (3 <= uiTry) {
            return OVSDB_ERR;
        }
        // 链接断开重连
        netconf_ce_config_destory(pst_session);
        (void)netconf_ce_config_init(pst_session);
        uiTry++;
        goto RETRY;
    }

    uiRet = nc_reply_get_type(reply);
    if (uiRet != NC_REPLY_OK) {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to set vxlan configuration, error message is %s",
                           nc_reply_get_errormsg(reply));
        nc_reply_free(reply);
        return OVSDB_ERR;
    }

    nc_reply_free(reply);
    return OVSDB_OK;
}

unsigned int netconf_ce_query_config_data(char* send_data, char ** ppcReplyData)
{
    NC_MSG_TYPE     sessionRet   = NC_MSG_REPLY;
    NC_REPLY_TYPE   replyRet     = NC_REPLY_DATA;
    unsigned int    uiTry        = 0;
    nc_rpc          *rpc         = NULL;
    nc_reply        *reply       = NULL;

    OVSDB_NULL_RETURN(send_data);

    struct ovsdb_nc_sess * pst_session = NULL;
    NETCONF_GET_MY_TID_SESSION(pst_session);
    if (NULL == pst_session) {
        OVSDB_PRINTF_DEBUG_ERROR("Can't find netconf session, my tid = %d.", gettid());
        return OVSDB_ERR;
    }

RETRY:
    rpc = nc_rpc_generic(send_data);

    if (NULL == rpc) {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to rpc generic.");
        return OVSDB_ERR;
    }

    /* netconf下发配置*/
    sessionRet = nc_session_send_recv(pst_session->pst_netconf_session, rpc, &reply);

    nc_rpc_free(rpc);
    rpc = NULL;

    if (sessionRet != NC_MSG_REPLY){
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to query configuration, error message is %s.",
            nc_reply_get_errormsg(reply));
        nc_reply_free(reply);
        if (3 <= uiTry) {
            return OVSDB_ERR;
        }
        // 链接断开重连
        netconf_ce_config_destory(pst_session);
        (void)netconf_ce_config_init(pst_session);
        uiTry++;
        goto RETRY;
    }

    replyRet = nc_reply_get_type(reply);
    if (replyRet != NC_REPLY_DATA)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to get reply configuration, error message is %s.",
            nc_reply_get_errormsg(reply));
        nc_reply_free(reply);
        return OVSDB_ERR;
    }

    /* 获取reply中的数据部分 */
    *ppcReplyData = nc_reply_get_data(reply);
    if (NULL == *ppcReplyData)
    {
        nc_reply_free(reply);
        return OVSDB_ERR;
    }

    nc_reply_free(reply);
    return OVSDB_OK;
}

unsigned int netconf_ce_query_config_all(char* send_data, char ** ppcReplyData)
{
    NC_MSG_TYPE     sessionRet   = NC_MSG_REPLY;
    NC_REPLY_TYPE   replyRet     = NC_REPLY_DATA;
    unsigned int    uiTry        = 0;
    nc_rpc          *rpc         = NULL;
    nc_reply        *reply       = NULL;

    OVSDB_NULL_RETURN(send_data);

    struct ovsdb_nc_sess * pst_session = NULL;
    NETCONF_GET_MY_TID_SESSION(pst_session);
    if (NULL == pst_session) {
        OVSDB_PRINTF_DEBUG_ERROR("Can't find netconf session, my tid = %d.", gettid());
        return OVSDB_ERR;
    }

RETRY:
    rpc = nc_rpc_generic(send_data);

    if (NULL == rpc) {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to rpc generic.");
        return OVSDB_ERR;
    }

    /* netconf下发配置*/
    sessionRet = nc_session_send_recv(pst_session->pst_netconf_session, rpc, &reply);

    nc_rpc_free(rpc);
    rpc = NULL;

    if (sessionRet != NC_MSG_REPLY){
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to query configuration, error message is %s.",
            nc_reply_get_errormsg(reply));
        nc_reply_free(reply);
        if (3 <= uiTry) {
            return OVSDB_ERR;
        }
        // 链接断开重连
        netconf_ce_config_destory(pst_session);
        (void)netconf_ce_config_init(pst_session);
        uiTry++;
        goto RETRY;
    }

    replyRet = nc_reply_get_type(reply);
    if (replyRet != NC_REPLY_DATA)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to get reply configuration, error message is %s.",
            nc_reply_get_errormsg(reply));
        nc_reply_free(reply);
        return OVSDB_ERR;
    }

    /* 获取reply的所有数据 */
    *ppcReplyData = nc_reply_dump(reply);
    if (NULL == *ppcReplyData)
    {
        nc_reply_free(reply);
        return OVSDB_ERR;
    }

    nc_reply_free(reply);
    return OVSDB_OK;
}

unsigned int netconf_ce_config_bd(unsigned int uiVniId)
{
    OVSDB_PRINTF_DEBUG_TRACE("********************netconf_ce_config_bd********************");
    unsigned int    uiRet                             = 0;
    char            send_data[NETCONF_SEND_DATA_LEN]  = {0};

    if (uiVniId > MAX_VNI_ID || uiVniId < MIN_VNI_ID)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]The VNI id %d is illegal.", uiVniId);
        return OVSDB_ERR;
    }

    /* 1.config [bridge-domain uiBdId] */
    snprintf(send_data, sizeof(send_data),
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
            "<evc xmlns=\"http://www.huawei.com/netconf/vrp\" format-version=\"1.0\" content-version=\"1.0\">"\
              "<bds>"\
                "<bd operation=\"create\">"\
                  "<bdId>%d</bdId>"\
                "</bd>"\
              "</bds>"\
            "</evc>"\
          "</config>"\
        "</edit-config>", uiVniId);

    uiRet = netconf_ce_set_config(send_data);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [bridge-domain %d]", uiVniId);
        //return OVSDB_ERR;
    }

    /* 2.config [vxlan vni uiVniId] */
    snprintf(send_data, sizeof(send_data),
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
            "<nvo3 xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<nvo3Vni2Bds>"\
                "<nvo3Vni2Bd operation=\"create\">"\
                  "<vniId>%d</vniId>"\
                  "<bdId>%d</bdId>"\
                "</nvo3Vni2Bd>"\
              "</nvo3Vni2Bds>"\
            "</nvo3>"\
          "</config>"\
        "</edit-config>", uiVniId, uiVniId);

    uiRet = netconf_ce_set_config(send_data);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [vxlan vni %d]", uiVniId);
        return OVSDB_ERR;
    }

    return OVSDB_OK;
}

/*
   undo bridge-domain xxxx
*/
unsigned int netconf_ce_undo_config_bd(unsigned int uiVniId)
{
    OVSDB_PRINTF_DEBUG_TRACE("********************netconf_ce_undo_config_bd********************");
    unsigned int    uiRet                             = 0;
    char            send_data[NETCONF_SEND_DATA_LEN]  = {0};
    char            *paReplyData                      = NULL;

    if (uiVniId > MAX_VNI_ID || uiVniId < MIN_VNI_ID)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]The VNI id %d is illegal.", uiVniId);
        return OVSDB_ERR;
    }

    /* 1.check before config [bridge-domain uiBdId] */
    snprintf(send_data, sizeof(send_data),
        "<get>"\
          "<filter type=\"subtree\">"\
            "<evc xmlns=\"http://www.huawei.com/netconf/vrp\" format-version=\"1.0\" content-version=\"1.0\">"\
              "<bds>"\
                "<bd>"\
                  "<bdId></bdId>"\
                "</bd>"\
              "</bds>"\
            "</evc>"\
          "</filter>"\
        "</get>");

    uiRet = netconf_ce_query_config_data(send_data, &paReplyData);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to query VNI before config [undo bridge-domain %d].", uiVniId);
        return OVSDB_ERR;
    }

    if ('\0' == paReplyData[0])
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR][bridge-domain %d] doesn't exist.", uiVniId);
        free(paReplyData);
        paReplyData = NULL;
        return OVSDB_ERR;
    }

    free(paReplyData);
    paReplyData = NULL;

    /* 1.1 删除此VNI对应的隧道列表 */
    (void)netconf_ce_undo_config_vxlan_tunnel(uiVniId, NULL);

    /* 2.config [undo bridge-domain uiVniId] */
    snprintf(send_data, sizeof(send_data),
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
            "<evc xmlns=\"http://www.huawei.com/netconf/vrp\" format-version=\"1.0\" content-version=\"1.0\">"\
              "<bds>"\
                "<bd operation=\"delete\">"\
                  "<bdId>%d</bdId>"\
                "</bd>"\
              "</bds>"\
            "</evc>"\
          "</config>"\
        "</edit-config>", uiVniId);

    uiRet = netconf_ce_set_config(send_data);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [undo bridge-domain %d].", uiVniId);
    }

    return uiRet;
}

unsigned int netconf_ce_query_nve_port(char* pcNveName, unsigned int * puiExist)
{
    unsigned int uiRet                             = 0;
    char         send_data[NETCONF_SEND_DATA_LEN]  = {0};
    char         *paReplyData                      = NULL;

    snprintf(send_data, sizeof(send_data),
        "<get>"\
          "<filter type=\"subtree\">"\
            "<ifm xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<interfaces>"\
                "<interface>"\
                  "<ifName>%s</ifName>"\
                "</interface>"\
              "</interfaces>"\
            "</ifm>"\
          "</filter>"\
        "</get>", pcNveName);

    uiRet = netconf_ce_query_config_data(send_data, &paReplyData);
    if (OVSDB_OK != uiRet) {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to query nve port before config [interface %s].", pcNveName);
        return OVSDB_ERR;
    }

    *puiExist = ('\0' == paReplyData[0]) ? 0 : 1;

    free(paReplyData);
    paReplyData = NULL;

    return OVSDB_OK;
}

unsigned int netconf_ce_config_nve1_source(char* paVtepIp)
{
    OVSDB_PRINTF_DEBUG_TRACE("********************netconf_ce_config_nve1_source********************");
    unsigned int uiRet                             = 0;
    unsigned int uiExist                           = 0;
    char         send_data[NETCONF_SEND_DATA_LEN]  = {0};

    /* 2.查询interface nve 1 是否存在*/
    uiRet = netconf_ce_query_nve_port("Nve1", &uiExist);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to query nve1 before config [interface nve 1].");
        return OVSDB_ERR;
    }

    if (0 == uiExist)
    {
        /* 3.配置interface nve 1 */
        snprintf(send_data, sizeof(send_data),
            "<edit-config>"\
              "<target><running/></target>"\
              "<default-operation>merge</default-operation>"\
              "<error-option>rollback-on-error</error-option>"\
              "<config>"\
                "<ifm xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
                  "<interfaces>"\
                    "<interface operation=\"create\">"\
                      "<ifName>Nve1</ifName>"\
                    "</interface>"\
                  "</interfaces>"\
                "</ifm>"\
              "</config>"\
            "</edit-config>");

        uiRet = netconf_ce_set_config(send_data);
        if (OVSDB_OK != uiRet)
        {
            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [interface Nve1].");
            return OVSDB_ERR;
        }
    }

    /* 4.配置source 1.1.1.1 */
    //如果已经存在隧道，并且隧道已经配置了远端的静态MAC，删除vtep IP会造成远端MAC配置连带删除
    /* 4.1先删除source配置
    snprintf(send_data, sizeof(send_data),
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
            "<nvo3 xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<nvo3Nves>"\
                "<nvo3Nve operation=\"merge\">"\
                  "<ifName>Nve1</ifName>"\
                  "<srcAddr>0.0.0.0</srcAddr>"\
                "</nvo3Nve>"\
              "</nvo3Nves>"\
            "</nvo3>"\
          "</config>"\
        "</edit-config>");

    uiRet = netconf_ce_set_config(send_data);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [undo source].");
        return OVSDB_ERR;
    } */

    /* 4.2再配置source 1.1.1.1 */
    snprintf(send_data, sizeof(send_data),
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
            "<nvo3 xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<nvo3Nves>"\
                "<nvo3Nve operation=\"merge\">"\
                  "<ifName>Nve1</ifName>"\
                  "<srcAddr>%s</srcAddr>"\
                "</nvo3Nve>"\
              "</nvo3Nves>"\
            "</nvo3>"\
          "</config>"\
        "</edit-config>", paVtepIp);

    uiRet = netconf_ce_set_config(send_data);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [source %s].", paVtepIp);
        return OVSDB_ERR;
    }

    return OVSDB_OK;
}

unsigned int netconf_ce_undo_config_nve1_source(char* paVtepIp)
{
    OVSDB_PRINTF_DEBUG_TRACE("********************netconf_ce_undo_config_nve1_source********************");
    unsigned int uiRet                             = 0;
    unsigned int uiExist                           = 0;
    char         send_data[NETCONF_SEND_DATA_LEN]  = {0};

    /* 2.查询interface nve 1 是否存在*/
    uiRet = netconf_ce_query_nve_port("Nve1", &uiExist);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to query nve1 before config [undo interface nve 1].");
        return OVSDB_ERR;
    }

    if (0 != uiExist)
    {
        /* 3.删除interface nve 1 */
        snprintf(send_data, sizeof(send_data),
            "<edit-config>"\
              "<target><running/></target>"\
              "<default-operation>merge</default-operation>"\
              "<error-option>rollback-on-error</error-option>"\
              "<config>"\
                "<ifm xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
                  "<interfaces>"\
                    "<interface operation=\"delete\">"\
                      "<ifName>Nve1</ifName>"\
                    "</interface>"\
                  "</interfaces>"\
                "</ifm>"\
              "</config>"\
            "</edit-config>");

        uiRet = netconf_ce_set_config(send_data);
        if (OVSDB_OK != uiRet)
        {
            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [undo interface Nve1].");
            return OVSDB_ERR;
        }
    }
    else
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR][interface Nve 1] doesn't exist.");
        return OVSDB_ERR;
    }

    return OVSDB_OK;
}

unsigned int netconf_ce_undo_config_port(unsigned int uiVlanId, char* paIfname)
{
    OVSDB_PRINTF_DEBUG_TRACE("********************netconf_ce_undo_config_port********************");
    unsigned int  uiRet                                   = 0;
    unsigned int  uiSubInterNum                           = 0;
    char          send_data[NETCONF_SEND_DATA_LEN]        = {0};
    char          *paReplyData                            = NULL;

    if((uiVlanId > MAX_VLAN_ID)||(uiVlanId < MIN_VLAN_ID))
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Vlan id %d id invalid", uiVlanId);
        return OVSDB_ERR;
    }

    if(!paIfname)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Port ifname name %s is NULL", paIfname);
        return OVSDB_ERR;
    }

    OVSDB_PRINTF_DEBUG_TRACE("[Info]Vlan id = %d", uiVlanId);
    OVSDB_PRINTF_DEBUG_TRACE("[Info]Port name = %s", paIfname);

    /* 为子接口号赋值 */
    uiSubInterNum = uiVlanId + 1;

    /* 查询interface paIfname.uiSubInterNum mode l2是否存在 */
    snprintf(send_data, sizeof(send_data),
        "<get>"\
          "<filter type=\"subtree\">"\
            "<ifm xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<interfaces>"\
                "<interface>"\
                  "<ifName>%s.%d</ifName>"\
                  "<l2SubIfFlag>true</l2SubIfFlag>"\
                "</interface>"\
              "</interfaces>"\
            "</ifm>"\
          "</filter>"\
        "</get>", paIfname, uiSubInterNum);

    uiRet = netconf_ce_query_config_data(send_data, &paReplyData);
    //printf("data out is %s\n", aReplyData);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to query %s.%d before config [interface %s.%d mode l2]",
            paIfname, uiSubInterNum, paIfname, uiSubInterNum);
        return OVSDB_ERR;
    }

    if ('\0' == paReplyData[0])
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Interface %s.%d doesn't exist", paIfname, uiSubInterNum);
        free(paReplyData);
        paReplyData = NULL;
        return OVSDB_ERR;
    }

    free(paReplyData);
    paReplyData = NULL;

    /* 删除interface paIfname.uiSubInterNum mode l2 */
    snprintf(send_data, sizeof(send_data),
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
            "<ifm xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<interfaces>"\
                "<interface operation=\"delete\">"\
                  "<ifName>%s.%d</ifName>"\
                  "<l2SubIfFlag>true</l2SubIfFlag>"\
                "</interface>"\
              "</interfaces>"\
            "</ifm>"\
          "</config>"\
        "</edit-config>", paIfname, uiSubInterNum);

    uiRet = netconf_ce_set_config(send_data);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [undo interface %s.%d mode l2]", paIfname, uiSubInterNum);
        return OVSDB_ERR;
    }

    return OVSDB_OK;
}

unsigned int netconf_ce_config_port(unsigned int uiVlanId, unsigned int uiVniId, char* paIfname)
{
    OVSDB_PRINTF_DEBUG_TRACE("********************netconf_ce_config_port********************");
    unsigned int  uiRet                                   = 0;
    unsigned int  uiSubInterNum                           = 0;
    char          send_data[NETCONF_SEND_DATA_LEN]        = {0};
    unsigned char netconfBit[NETCONF_VLANBIT_LEN_STR + 1] = {0};
    char          *paReplyData                            = NULL;

    if((uiVlanId > MAX_VLAN_ID)||(uiVlanId < MIN_VLAN_ID))
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Vlan id %d id invalid", uiVlanId);
        return OVSDB_ERR;
    }

    if((uiVniId > MAX_VNI_ID)||(uiVniId < MIN_VNI_ID))
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Vni %d is invalid", uiVniId);
        return OVSDB_ERR;
    }

    if(!paIfname)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Port ifname name %s is NULL", paIfname);
        return;
    }

    OVSDB_PRINTF_DEBUG_TRACE("[Info]Vlan id = %d, Vni = %d", uiVlanId, uiVniId );
    OVSDB_PRINTF_DEBUG_TRACE("[Info]Port name = %s", paIfname);

    /* 为子接口号赋值 */
    uiSubInterNum = uiVlanId + 1;

    /* 查询interface paIfname.uiSubInterNum mode l2是否存在 */
    snprintf(send_data, sizeof(send_data),
    "<get>"\
      "<filter type=\"subtree\">"\
        "<ifm xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
          "<interfaces>"\
            "<interface>"\
              "<ifName>%s.%d</ifName>"\
              "<l2SubIfFlag>true</l2SubIfFlag>"\
            "</interface>"\
          "</interfaces>"\
        "</ifm>"\
      "</filter>"\
    "</get>", paIfname, uiSubInterNum);

    uiRet = netconf_ce_query_config_data(send_data, &paReplyData);
    //printf("data out is %s\n", aReplyData);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to query %s.%d before config [interface %s.%d mode l2]",
            paIfname, uiSubInterNum, paIfname, uiSubInterNum);
        return OVSDB_ERR;
    }

    if ('\0' != paReplyData[0])
    {
        OVSDB_PRINTF_DEBUG_WARN("[ERROR]Interface %s.%d has existed", paIfname, uiSubInterNum);
        (void)netconf_ce_undo_config_port(uiVlanId, paIfname);
    }

    free(paReplyData);
    paReplyData = NULL;

    /* 配置interface paIfname.uiSubInterNum mode l2 */
    snprintf(send_data, sizeof(send_data),
    "<edit-config>"\
      "<target><running/></target>"\
      "<default-operation>merge</default-operation>"\
      "<error-option>rollback-on-error</error-option>"\
      "<config>"\
        "<ifm xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
          "<interfaces>"\
            "<interface operation=\"create\">"\
              "<ifName>%s.%d</ifName>"\
              "<l2SubIfFlag>true</l2SubIfFlag>"\
            "</interface>"\
          "</interfaces>"\
        "</ifm>"\
      "</config>"\
    "</edit-config>", paIfname, uiSubInterNum);

    uiRet = netconf_ce_set_config(send_data);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [interface %s.%d mode l2]",
            paIfname, uiSubInterNum);
        return OVSDB_ERR;
    }

    /* 配置bridge-domain uiVniId */
    snprintf(send_data, sizeof(send_data),
    "<edit-config>"\
      "<target><running/></target>"\
      "<default-operation>merge</default-operation>"\
      "<error-option>rollback-on-error</error-option>"\
      "<config>"\
        "<evc xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
          "<bds>"\
            "<bd operation=\"merge\">"\
              "<bdId>%d</bdId>"\
                "<servicePoints>"\
                  "<servicePoint operation=\"create\">"\
                    "<ifName>%s.%d</ifName>"\
                  "</servicePoint>"\
              "</servicePoints>"\
            "</bd>"\
          "</bds>"\
        "</evc>"\
      "</config>"\
    "</edit-config>", uiVniId, paIfname, uiSubInterNum);

    uiRet = netconf_ce_set_config(send_data);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [bridge-domain %d]", uiVniId);
        return OVSDB_ERR;
    }

    if(0 == uiVlanId)
    {
        /* 配置encapsulation untag */
        snprintf(send_data, sizeof(send_data),
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
            "<ethernet xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<servicePoints>"\
                "<servicePoint operation=\"merge\">"\
                  "<ifName>%s.%d</ifName>"\
                  "<flowType>untag</flowType>"\
                "</servicePoint>"\
              "</servicePoints>"\
            "</ethernet>"\
          "</config>"\
        "</edit-config>", paIfname, uiSubInterNum);

        uiRet = netconf_ce_set_config(send_data);
        if (OVSDB_OK != uiRet)
        {
            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [encapsulation untag]");
            return OVSDB_ERR;
        }
    }
    else
    {
        netconf_vlanbit2netvlanbit(uiVlanId, netconfBit);

        /* 配置encapsulation dot1q vid uiVlanId */
        snprintf(send_data, sizeof(send_data),
            "<edit-config>"\
              "<target><running/></target>"\
              "<default-operation>merge</default-operation>"\
              "<error-option>rollback-on-error</error-option>"\
              "<config>"\
                "<ethernet xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
                  "<servicePoints>"\
                    "<servicePoint operation=\"merge\">"\
                      "<ifName>%s.%d</ifName>"\
                      "<flowType>dot1q</flowType>"\
                      "<flowDot1qs>"\
                        "<dot1qVids>%s:%s</dot1qVids>"\
                      "</flowDot1qs>"\
                    "</servicePoint>"\
                  "</servicePoints>"\
                "</ethernet>"\
              "</config>"\
            "</edit-config>",
            paIfname, uiSubInterNum, netconfBit, netconfBit);

        uiRet = netconf_ce_set_config(send_data);
        if (OVSDB_OK != uiRet)
        {
            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [encapsulation vlan %d]", uiVlanId);
            return OVSDB_ERR;
        }
    }

    return OVSDB_OK;
}

unsigned int netconf_ce_config_vxlan_tunnel(unsigned int uiVni, char * paDstIp)
{
    OVSDB_PRINTF_DEBUG_TRACE("********************netconf_ce_config_vxlan_tunnel********************");
    unsigned int uiLoop                           = 0;
    unsigned int uiRet                            = 0;
    char         send_data[NETCONF_SEND_DATA_LEN] = {0};

    OVSDB_PRINTF_DEBUG_TRACE("[Info]ce_config_vxlan_tunnel_netconf");
    OVSDB_PRINTF_DEBUG_TRACE("[Info]vni=%d, dst ip=%s", uiVni, paDstIp);

    /* 1.判断VNI是否合法 */
    if((uiVni > MAX_VNI_ID)||(uiVni < MIN_VNI_ID))
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Vni %d is not valid.", uiVni);
        return OVSDB_ERR;
    }

    /* 2.判断dst_ip是否为空 */
    if(!paDstIp)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Dst_ip is NULL.");
        return OVSDB_ERR;
    }

    /* 3.检查是否有隧道ip */
    if(!ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0])
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]TOR does not have a tunnel ip address.");
        return OVSDB_ERR;
    }
    
    /*3.1 确保Nve 1已经配置*/
    uiRet = netconf_ce_config_nve1_source(ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0]);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_WARN("Failed to config Nve 1 source before config VXLAN tunnel.");
    }

    /* 4.配置vni uiVni head-end peer-list paDstIp */
    snprintf(send_data, sizeof(send_data),
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
            "<nvo3 xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<nvo3Nves>"\
                "<nvo3Nve operation=\"merge\">"\
                  "<ifName>nve1</ifName>"\
                  "<vniMembers>"\
                    "<vniMember operation=\"merge\">"\
                      "<vniId>%d</vniId>"\
                      "<nvo3VniPeers>"\
                        "<nvo3VniPeer operation=\"merge\">"\
                          "<peerAddr>%s</peerAddr>"\
                        "</nvo3VniPeer>"\
                      "</nvo3VniPeers>"\
                    "</vniMember>"\
                  "</vniMembers>"\
                "</nvo3Nve>"\
              "</nvo3Nves>"\
            "</nvo3>"\
          "</config>"\
        "</edit-config>", uiVni, paDstIp);

    uiRet = netconf_ce_set_config(send_data);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [vni %d head-end peer-list %s]", uiVni, paDstIp);
        return OVSDB_ERR;
    }

    return OVSDB_OK;
}

unsigned int netconf_ce_undo_config_vxlan_tunnel(unsigned int uiVni, char * paDstIp)
{
    OVSDB_PRINTF_DEBUG_TRACE("********************netconf_ce_undo_config_vxlan_tunnel********************");
    unsigned int uiRet                            = 0;
    char         send_data[NETCONF_SEND_DATA_LEN] = {0};

    OVSDB_PRINTF_DEBUG_TRACE("[Info]ce_config_vxlan_tunnel_netconf.");

    /* 1.判断VNI是否合法 */
    if((uiVni > MAX_VNI_ID)||(uiVni < MIN_VNI_ID))
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Vni %d is not valid.", uiVni);
        return OVSDB_ERR;
    }

    /* 3.检查是否有隧道ip */
    if(!ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0])
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]TOR does not have a tunnel ip address.");
        return OVSDB_ERR;
    }

    /* 4.删除vxlan隧道 */
    if (NULL != paDstIp) {
        /* 4.1.先删除头端复制列表*/
        snprintf(send_data, sizeof(send_data),
            "<edit-config>"\
              "<target><running/></target>"\
              "<default-operation>merge</default-operation>"\
              "<error-option>rollback-on-error</error-option>"\
              "<config>"\
                "<nvo3 xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
                  "<nvo3Nves>"\
                    "<nvo3Nve operation=\"merge\">"\
                      "<ifName>nve1</ifName>"\
                      "<vniMembers>"\
                        "<vniMember operation=\"merge\">"\
                          "<vniId>%d</vniId>"\
                          "<nvo3VniPeers>"\
                            "<nvo3VniPeer operation=\"delete\">"\
                              "<peerAddr>%s</peerAddr>"\
                            "</nvo3VniPeer>"\
                          "</nvo3VniPeers>"\
                        "</vniMember>"\
                      "</vniMembers>"\
                    "</nvo3Nve>"\
                  "</nvo3Nves>"\
                "</nvo3>"\
              "</config>"\
            "</edit-config>", uiVni, paDstIp);
    }
    else {
        /* 4.2.再删除VNI*/
        snprintf(send_data, sizeof(send_data),
            "<edit-config>"\
              "<target><running/></target>"\
              "<default-operation>merge</default-operation>"\
              "<error-option>rollback-on-error</error-option>"\
              "<config>"\
                "<nvo3 xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
                  "<nvo3Nves>"\
                    "<nvo3Nve operation=\"merge\">"\
                      "<ifName>nve1</ifName>"\
                      "<vniMembers>"\
                        "<vniMember operation=\"delete\">"\
                          "<vniId>%d</vniId>"\
                        "</vniMember>"\
                      "</vniMembers>"\
                    "</nvo3Nve>"\
                  "</nvo3Nves>"\
                "</nvo3>"\
              "</config>"\
            "</edit-config>", uiVni);
    }
    uiRet = netconf_ce_set_config(send_data);
    if (OVSDB_OK != uiRet)
    {
        if (NULL != paDstIp)
            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [undo vni %d head-end peer-list %s].", uiVni, paDstIp);
        else
            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [undo vni %d]", uiVni);
        /*有可能多条隧道对应同一个vni,这里不应该返回错误 */
        //return OVSDB_ERR;
    }

    return OVSDB_OK;
}


unsigned int netconf_ce_config_vxlan_tunnel_static_mac(char* paStaticMac, char* paSourceIp, char* paDstIp, unsigned int uiVniId)
{
    OVSDB_PRINTF_DEBUG_TRACE("********************netconf_ce_config_vxlan_tunnel_static_mac********************");
    unsigned int uiLoop                           = 0;
    unsigned int uiRet                            = 0;
    char         send_data[NETCONF_SEND_DATA_LEN] = {0};

    OVSDB_PRINTF_DEBUG_TRACE("[Info]ce_config_vxlan_tunnel_static_mac");
    OVSDB_PRINTF_DEBUG_TRACE("[Info]ce_mac=%s, source_ip=%s, dst_ip=%s,", paStaticMac, paSourceIp, paDstIp);
    OVSDB_PRINTF_DEBUG_TRACE("[Info]vni = %d", uiVniId);

    if(!paSourceIp)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]source_ip is NULL.");
        return OVSDB_ERR;
    }

    if(!paDstIp)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]dst_ip is NULL.");
        return OVSDB_ERR;
    }

    if(!paStaticMac)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]ce_mac is NULL.");
        return OVSDB_ERR;
    }

    /* 配置mac-address static paStaticMac bridge-domain uiVniId source paSourceIp peer paDstIp vni uiVniId */
    snprintf(send_data, sizeof(send_data),
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
            "<mac xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<vxlanFdbs>"\
                "<vxlanFdb operation=\"create\">"\
                  "<slotId>0</slotId>"\
                  "<macAddress>%s</macAddress>"\
                  "<bdId>%d</bdId>"\
                  "<macType>static</macType>"\
                  "<sourceIP>%s</sourceIP>"\
                  "<peerIP>%s</peerIP>"\
                  "<vnId>%d</vnId>"\
                "</vxlanFdb>"\
              "</vxlanFdbs>"\
            "</mac>"\
          "</config>"\
        "</edit-config>", paStaticMac, uiVniId, paSourceIp, paDstIp, uiVniId);
    uiRet = netconf_ce_set_config(send_data);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [mac-address static %s bridge-domain %d source %s peer %s vni %d]",
            paStaticMac, uiVniId, paSourceIp, paDstIp, uiVniId);
        return OVSDB_ERR;
    }

    return OVSDB_OK;
}

unsigned int netconf_ce_undo_config_vxlan_tunnel_static_mac(char* paStaticMac, char* paSourceIp, char* paDstIp, unsigned int uiVniId)
{
    OVSDB_PRINTF_DEBUG_TRACE("********************netconf_ce_undo_config_vxlan_tunnel_static_mac********************");
    unsigned int uiRet                            = 0;
    char         send_data[NETCONF_SEND_DATA_LEN] = {0};

    OVSDB_PRINTF_DEBUG_TRACE("[Info]ce_config_vxlan_tunnel_static_mac");
    OVSDB_PRINTF_DEBUG_TRACE("[Info]ce_mac=%s, source_ip=%s, dst_ip=%s,", paStaticMac, paSourceIp, paDstIp);
    OVSDB_PRINTF_DEBUG_TRACE("[Info]vni = %d", uiVniId);

    if(!paSourceIp)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]source_ip is NULL");
        return OVSDB_ERR;
    }

    if(!paDstIp)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]dst_ip is NULL");
        return OVSDB_ERR;
    }

    if(!paStaticMac)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]ce_mac is NULL");
        return OVSDB_ERR;
    }

    /* 删除mac-address static paStaticMac bridge-domain uiVniId source paSourceIp peer paDstIp vni uiVniId */
    snprintf(send_data, sizeof(send_data),
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
            "<mac xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<vxlanFdbs>"\
                "<vxlanFdb operation=\"delete\">"\
                  "<slotId>0</slotId>"\
                  "<macAddress>%s</macAddress>"\
                  "<bdId>%d</bdId>"\
                  "<macType>static</macType>"\
                  "<sourceIP>%s</sourceIP>"\
                  "<peerIP>%s</peerIP>"\
                  "<vnId>%d</vnId>"\
                "</vxlanFdb>"\
              "</vxlanFdbs>"\
            "</mac>"\
          "</config>"\
        "</edit-config>", paStaticMac, uiVniId, paSourceIp, paDstIp, uiVniId);
    uiRet = netconf_ce_set_config(send_data);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [undo mac-address static %s bridge-domain %d source %s peer %s vni %d]",
            paStaticMac, uiVniId, paSourceIp, paDstIp, uiVniId);
        return OVSDB_ERR;
    }

    return OVSDB_OK;
}


unsigned int netconf_ce_config_drop_conflict_packet(void)
{
    OVSDB_PRINTF_DEBUG_TRACE("********************netconf_ce_config_drop_conflict_packet********************");
    unsigned int    uiRet                            = 0;
    char            send_data[NETCONF_SEND_DATA_LEN] = {0};

    /* config [undo mac-address drop static-conflict enable] */
    snprintf(send_data, sizeof(send_data),
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
            "<mac xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<ovsdbs>"\
                "<ovsdb operation=\"merge\">"\
                  "<enable>0</enable>"\
                "</ovsdb>"\
              "</ovsdbs>"\
            "</mac>"\
          "</config>"\
        "</edit-config>");

    uiRet = netconf_ce_set_config(send_data);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [undo mac-address drop static-conflict enable]");
        return OVSDB_ERR;
    }

    return OVSDB_OK;
}

unsigned int netconf_ce_undo_config_drop_conflict_packet(void)
{
    OVSDB_PRINTF_DEBUG_TRACE("********************netconf_ce_undo_config_drop_conflict_packet********************");
    unsigned int    uiRet                            = 0;
    char            send_data[NETCONF_SEND_DATA_LEN] = {0};

    /* config [undo mac-address drop static-conflict enable] */
    snprintf(send_data, sizeof(send_data),
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
            "<mac xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<ovsdbs>"\
                "<ovsdb operation=\"merge\">"\
                  "<enable>1</enable>"\
                "</ovsdb>"\
              "</ovsdbs>"\
            "</mac>"\
          "</config>"\
        "</edit-config>");

    uiRet = netconf_ce_set_config(send_data);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [undo mac-address drop static-conflict enable]");
        return OVSDB_ERR;
    }

    return OVSDB_OK;
}

unsigned int netconf_ce_query_global_bfd_enabled(bool * pbEnable)
{
    OVSDB_PRINTF_DEBUG_TRACE("********************netconf_ce_query_global_bfd_enabled********************");
    unsigned int uiRet = 0;
    char send_data[NETCONF_SEND_DATA_LEN] = {0};
    char * paReplyData = NULL;
    char * paReplyDataValue = NULL;
    char aBfdEnableLeft[] = "<bfdEnable>";
    char aBfdEnableRight[] = "</bfdEnable>";
    char aBfdEnableStatus[BFD_ENABLE_STATUS] = {0};

    OVSDB_CHECK_NULL_PTR_RET(pbEnable);

    *pbEnable = false;

    snprintf(send_data, sizeof(send_data),
        "<get>"\
          "<filter type=\"subtree\">"\
            "<bfd xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<bfdSchGlobal>"\
                "<bfdEnable></bfdEnable>"\
              "</bfdSchGlobal>"\
            "</bfd>"\
          "</filter>"\
        "</get>");

    uiRet = netconf_ce_query_config_data(send_data, &paReplyData);
    if (uiRet != OVSDB_OK)
    {
        OVSDB_PRINTF_DEBUG_ERROR("Failed to query BFD global enable configuration.");
        return OVSDB_ERR;
    }

    paReplyDataValue = paReplyData;
    OVSDB_CLIENT_GET_STRING_FROM_NCREPLY(aBfdEnableStatus, BFD_ENABLE_STATUS, aBfdEnableLeft, aBfdEnableRight, paReplyDataValue);

    free(paReplyData);
    paReplyData = NULL;

    if (0 != strcmp("false", aBfdEnableStatus))
    {
        *pbEnable = true;
    }

    return OVSDB_OK;
}

unsigned int netconf_ce_config_global_bfd(bool bEnable)
{
    OVSDB_PRINTF_DEBUG_TRACE("********************netconf_ce_enable_global_bfd********************");
    unsigned int uiRet = 0;
    bool bCurrentEnable = false;
    char send_data[NETCONF_SEND_DATA_LEN] = {0};
    char * pcEnable = (true == bEnable) ? "true" : "false";

    uiRet = netconf_ce_query_global_bfd_enabled(&bCurrentEnable);
    if (uiRet != OVSDB_OK)
    {
        return uiRet;
    }

    if (bEnable == bCurrentEnable)
    {
        return OVSDB_OK;
    }

    snprintf(send_data, sizeof(send_data),
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
            "<bfd xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<bfdSchGlobal>"\
                "<bfdEnable>%s</bfdEnable>"\
              "</bfdSchGlobal>"\
            "</bfd>"\
          "</config>"\
        "</edit-config>",
        pcEnable);

    uiRet = netconf_ce_set_config(send_data);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("Failed to configure BFD global %s.", pcEnable);
        return OVSDB_ERR;
    }

    return OVSDB_OK;
}

unsigned int netconf_ce_query_bfd_session(struct netconf_ce_bfd_session * pstBfdSession, bool *pbExist)
{
    OVSDB_PRINTF_DEBUG_TRACE("********************netconf_ce_query_bfd_session********************");
    unsigned int uiRet = 0;
    char send_data[NETCONF_SEND_DATA_LEN] = {0};
    char * paReplyData = NULL;

    OVSDB_CHECK_NULL_PTR_RET(pstBfdSession);
    OVSDB_CHECK_NULL_PTR_RET(pbExist);
    OVSDB_CHECK_NULL_PTR_RET(pstBfdSession->bfd_session_name);

    /* 2 是否查询到sessName配置，查询到，删除在配置，查询不到则配置sessName, IP, MAC, 时间参数 */
    snprintf(send_data, sizeof(send_data),
        "<get>"\
          "<filter type=\"subtree\">"\
            "<bfd xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<bfdCfgSessions>"\
                "<bfdCfgSession>"\
                  "<sessName>%s</sessName>"\
                "</bfdCfgSession>"\
              "</bfdCfgSessions>"\
            "</bfd>"\
          "</filter>"\
        "</get>", pstBfdSession->bfd_session_name);

    uiRet = netconf_ce_query_config_data(send_data, &paReplyData);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("Failed to query BFD configure.");
        return OVSDB_ERR;
    }

    /* 查询到vxlan bfd会话已经配置，删除会话 */
    if ('\0' != paReplyData[0])
    {
        *pbExist = true;
    }
    else
    {
        *pbExist = false;
    }

    free(paReplyData);
    paReplyData = NULL;

    return OVSDB_OK;
}

unsigned int netconf_ce_config_bfd_session(struct netconf_ce_bfd_session * pstBfdSession)
{
    OVSDB_PRINTF_DEBUG_TRACE("********************netconf_ce_config_bfd_session********************");
    unsigned int uiRet = 0;
    bool bExist = false;
    char send_data[NETCONF_SEND_DATA_LEN] = {0};

    OVSDB_CHECK_NULL_PTR_RET(pstBfdSession);
    OVSDB_CHECK_NULL_PTR_RET(pstBfdSession->bfd_session_name);
    OVSDB_CHECK_NULL_PTR_RET(pstBfdSession->bfd_peer_ip);
    OVSDB_CHECK_NULL_PTR_RET(pstBfdSession->bfd_peer_mac);
    OVSDB_CHECK_NULL_PTR_RET(pstBfdSession->bfd_src_ip);
    OVSDB_CHECK_NULL_PTR_RET(pstBfdSession->min_tx);
    OVSDB_CHECK_NULL_PTR_RET(pstBfdSession->min_rx);

    uiRet = netconf_ce_config_global_bfd(true);
    if (uiRet != OVSDB_OK)
    {
        OVSDB_PRINTF_DEBUG_ERROR("netconf enable global BFD faild.");
        return OVSDB_ERR;
    }

    uiRet = netconf_ce_query_bfd_session(pstBfdSession, &bExist);
    if (uiRet != OVSDB_OK)
    {
        OVSDB_PRINTF_DEBUG_ERROR("netconf query BFD session %s faild.", pstBfdSession->bfd_session_name);
        return OVSDB_ERR;
    }

    if (false != bExist)
    {
        OVSDB_PRINTF_DEBUG_WARN("BFD session %s has existed.", pstBfdSession->bfd_session_name);
        return OVSDB_OK;
    }

    /* 配置BFD会话 */
    snprintf(send_data, sizeof(send_data),
    "<edit-config>"\
      "<target><running/></target>"\
      "<default-operation>merge</default-operation>"\
      "<error-option>rollback-on-error</error-option>"\
      "<config>"\
        "<bfd xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
          "<bfdCfgSessions>"\
            "<bfdCfgSession operation=\"create\">"\
              "<sessName>%s</sessName>"\
              "<createType>SESS_AUTO</createType>"\
              "<localDiscr/>"\
              "<remoteDiscr/>"\
              "<linkType>VXLAN</linkType>"\
              "<addrType>IPV4</addrType>"\
              "<outIfName/>"\
              "<destAddr>%s</destAddr>"\
              "<srcAddr>%s</srcAddr>"\
              "<minTxInt>%s</minTxInt>"\
              "<minRxInt>%s</minRxInt>"\
              "<detectMulti></detectMulti>"\
              "<wtrTimerInt/>"\
              "<tosExp/>"\
              "<adminDown></adminDown>"\
              "<description/>"\
              "<pis>false</pis>"\
              "<pisSubIf>false</pisSubIf>"\
              "<useDefaultIp>false</useDefaultIp>"\
              "<perLink>false</perLink>"\
              "<bundleMode>-</bundleMode>"\
              "<destMac>%s</destMac>"\
            "</bfdCfgSession>"\
          "</bfdCfgSessions>"\
        "</bfd>"\
      "</config>"\
    "</edit-config>",
    pstBfdSession->bfd_session_name,
    pstBfdSession->bfd_peer_ip,
    pstBfdSession->bfd_src_ip,
    pstBfdSession->min_tx,
    pstBfdSession->min_rx,
    pstBfdSession->bfd_peer_mac);

    uiRet = netconf_ce_set_config(send_data);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("Failed to config BFD session %s.",
            pstBfdSession->bfd_session_name);
        return OVSDB_ERR;
    }

    return OVSDB_OK;
}

unsigned int netconf_ce_undo_config_bfd_session(struct netconf_ce_bfd_session * pstBfdSession)
{
    OVSDB_PRINTF_DEBUG_TRACE("********************netconf_ce_config_bfd_session********************");
    unsigned int uiRet = 0;
    bool bExist = false;
    char send_data[NETCONF_SEND_DATA_LEN] = {0};

    OVSDB_CHECK_NULL_PTR_RET(pstBfdSession);
    OVSDB_CHECK_NULL_PTR_RET(pstBfdSession->bfd_session_name);

    uiRet = netconf_ce_query_bfd_session(pstBfdSession, &bExist);
    if (uiRet != OVSDB_OK)
    {
        OVSDB_PRINTF_DEBUG_ERROR("netconf query BFD session %s faild.", pstBfdSession->bfd_session_name);
        return OVSDB_ERR;
    }

    if (false == bExist)
    {
        OVSDB_PRINTF_DEBUG_WARN("BFD session %s has not existed.", pstBfdSession->bfd_session_name);
        return OVSDB_OK;
    }

    snprintf(send_data, sizeof(send_data),
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
            "<bfd xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<bfdCfgSessions>"\
                "<bfdCfgSession operation=\"delete\">"\
                  "<sessName>%s</sessName>"\
                "</bfdCfgSession>"\
              "</bfdCfgSessions>"\
            "</bfd>"\
          "</config>"\
        "</edit-config>", pstBfdSession->bfd_session_name);

    uiRet = netconf_ce_set_config(send_data);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("Failed to config BFD session %s.",
            pstBfdSession->bfd_session_name);
        return OVSDB_ERR;
    }

    return OVSDB_OK;
}

unsigned int netconf_ce_query_ethernet_mac(char * pcMAC)
{
    unsigned int uiRet                            = 0;
    char         send_data[NETCONF_SEND_DATA_LEN] = {0};
    char         *pReplyData                      = NULL;
    char         aEthernetPositon[]               = "<ifName>Ethernet";
    char         aEthernetLeft[]                  = "<ifMac>";
    char         aEthernetRight[]                 = "</ifMac>";
    char         *pEthernetPosition               = NULL;

    snprintf(send_data, sizeof(send_data),
        "<get>"\
          "<filter type=\"subtree\">"\
            "<ifm xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<interfaces>"\
                "<interface>"\
                  "<ifName></ifName>"\
                  "<ifMac></ifMac>"\
                "</interface>"\
              "</interfaces>"\
            "</ifm>"\
          "</filter>"\
        "</get>");

    uiRet = netconf_ce_query_config_all(send_data, &pReplyData);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("Failed to query ethernet mac.");
        return OVSDB_ERR;
    }

    /* get ethernet mac-address */
    pEthernetPosition = strstr(pReplyData, aEthernetPositon);
    if (NULL == pEthernetPosition)
    {
        OVSDB_PRINTF_DEBUG_ERROR("Failed to get ethernet interface.");
        return OVSDB_ERR;
    }

    OVSDB_CLIENT_GET_STRING_FROM_NCREPLY(pcMAC, MAX_CE_MAC_LEN, aEthernetLeft, aEthernetRight, pEthernetPosition);

    OVSDB_FREE(pReplyData);

    return OVSDB_OK;
}

unsigned int ovsdb_get_interface(char *paData)
{
    char         aIfNameLeft[]           = "<ifName>";
    char         aIfNameRight[]          = "</ifName>";
    char         aIfName[MAX_IFNAME_LEN] = {0};
    char         *pStart                 = paData;

    if (NULL == paData)
    {
        return OVSDB_ERR;
    }

    while (NULL != strstr(pStart, aIfNameLeft))
    {
        OVSDB_CLIENT_GET_STRING_FROM_NCREPLY(aIfName, MAX_IFNAME_LEN, aIfNameLeft, aIfNameRight, pStart);
        if (NULL == pStart)
            return OVSDB_ERR;

        /* 添加interface至软表 */
        (void)ovsdb_sub_table_interface_add(aIfName);
    }

    return OVSDB_OK;

}

unsigned int ovsdb_get_db_mac(char *paData)
{
    char         aMacAdrLeft[]              = "<macAddress>";
    char         aMacAdrRight[]             = "</macAddress>";
    char         aMacTypeLeft[]             = "<macType>";
    char         aMacTypeRight[]            = "</macType>";
    char         aBdIdLeft[]                = "<bdId>";
    char         aBdIdRight[]               = "</bdId>";
    char         aOutIfnameLeft[]           = "<outIfName>";
    char         aOutIfnameRight[]          = "</outIfName>";
    char         aMac[MAX_CE_MAC_LEN]       = {0};
    char         aOutIfName[MAX_IFNAME_LEN] = {0};
    char         aBdId[MAX_BDID_LEN]        = {0};
    char         aMacType[MAX_MAC_TYPE_LEN] = {0};
    unsigned int uiMacType                  = 0;
    char         *pStart                    = paData;

    if (NULL == paData)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Reply data of db mac is NULL");
        return OVSDB_ERR;
    }

    while (NULL != strstr(pStart, aMacAdrLeft))
    {
        /* 获取macAddress */
        OVSDB_CLIENT_GET_STRING_FROM_NCREPLY(aMac, MAX_CE_MAC_LEN, aMacAdrLeft, aMacAdrRight, pStart);
        if (NULL == pStart)
            return OVSDB_ERR;

        /* 获取macType */
        OVSDB_CLIENT_GET_STRING_FROM_NCREPLY(aMacType, MAX_MAC_TYPE_LEN, aMacTypeLeft, aMacTypeRight, pStart);
        if (NULL == pStart)
            return OVSDB_ERR;

        if (0 == strcmp(aMacType, "dynamic"))
        {
            uiMacType = MAC_DYNAMIC;
        }
        else if (0 == strcmp(aMacType, "static"))
        {
            uiMacType = MAC_STATIC;
        }

        /* 获取bdId */
        OVSDB_CLIENT_GET_STRING_FROM_NCREPLY(aBdId, MAX_BDID_LEN, aBdIdLeft, aBdIdRight, pStart);
        if (NULL == pStart)
            return OVSDB_ERR;

        /* 获取outIfName */
        OVSDB_CLIENT_GET_STRING_FROM_NCREPLY(aOutIfName, MAX_IFNAME_LEN, aOutIfnameLeft, aOutIfnameRight, pStart);
        if (NULL == pStart)
            return OVSDB_ERR;

        /* 添加mac至软表 */
        (void)ovsdb_sub_table_mac_add(aMac, aBdId, aOutIfName, (int)uiMacType);
    }

    return OVSDB_OK;

}

unsigned int netconf_ce_query_interface(void)
{
    unsigned int    uiRet                             = 0;
    unsigned int    uiLoop                            = 0;
    char            send_data[NETCONF_SEND_DATA_LEN]  = {0};
    char            *pReplyData                       = NULL;
    char            *paReplySeg                       = NULL;
    char            aSetId[MAX_SET_ID_LEN]            = {0};

    snprintf(send_data, sizeof(send_data),
        "<get>"\
          "<filter type=\"subtree\">"\
            "<ifm xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<interfaces>"\
                "<interface>"\
                  "<ifName></ifName>"\
                  "<ifDescr/>"\
                "</interface>"\
              "</interfaces>"\
            "</ifm>"\
          "</filter>"\
        "</get>");

    uiRet = netconf_ce_query_config_all(send_data, &pReplyData);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to query interface");
        return OVSDB_ERR;
    }

    while(NULL != pReplyData)
    {
        /* 解析reply消息中的interface */
        uiRet = ovsdb_get_interface(pReplyData);

        if (uiRet != OVSDB_OK)
        {
            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to get interface from reply message");
            free(pReplyData);
            pReplyData = NULL;
            return OVSDB_ERR;
        }

        /* 判断reply消息是否分片 */
        paReplySeg = strstr(pReplyData, "set-id");

        if (NULL == paReplySeg)
        {
            free(pReplyData);
            pReplyData = NULL;
            break;
        }

        /* 获取set-id以查询下一个回复消息分片 */
        paReplySeg = paReplySeg + strlen("set-id") + 2;
        while ('"' != *paReplySeg)
        {
            aSetId[uiLoop++] = *paReplySeg;
            paReplySeg++;
        }
        aSetId[uiLoop] = '\0';

        snprintf(send_data, sizeof(send_data),
            "<get-next xmlns=\"http://www.huawei.com/netconf/capability/base/1.0\" set-id=\"%s\">"\
            "</get-next>", aSetId);

        free(pReplyData);
        pReplyData = NULL;

        uiRet = netconf_ce_query_config_all(send_data, &pReplyData);
        if (OVSDB_OK != uiRet)
        {
            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to query next interface");
            return OVSDB_ERR;
        }

        uiLoop = 0;
    }

    (void)ovsdb_sub_table_interface_delete();

    return OVSDB_OK;
}


unsigned int netconf_ce_query_db_mac(void)
{
    unsigned int    uiRet                             = 0;
    unsigned int    uiLoop                            = 0;
    char            send_data[NETCONF_SEND_DATA_LEN]  = {0};
    char            *pReplyData                       = NULL;
    char            *paReplySeg                       = NULL;
    char            aSetId[MAX_SET_ID_LEN]            = {0};

    snprintf(send_data, sizeof(send_data),
        "<get>"\
          "<filter type=\"subtree\">"\
            "<mac xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<bdFdbs>"\
                "<bdFdb>"\
                  "<slotId>0</slotId>"\
                  "<macAddress></macAddress>"\
                  "<bdId></bdId>"\
                  "<macType></macType>"\
                  "<outIfName></outIfName>"\
                  "<unTag></unTag>"\
                  "<peDefault></peDefault>"\
                  "<vid></vid>"\
                "</bdFdb>"\
              "</bdFdbs>"\
            "</mac>"\
          "</filter>"\
        "</get>");

    /*sprintf(send_data,
        "<get>"\
          "<filter type=\"subtree\">"\
            "<mac xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<vlanFdbs>"\
                "<vlanFdb>"\
                  "<macAddress></macAddress>"\
                  "<vlanId></vlanId>"\
                  "<slotId>0</slotId>"\
                  "<macType></macType>"\
                  "<outIfName></outIfName>"\
                "</vlanFdb>"\
              "</vlanFdbs>"\
            "</mac>"\
          "</filter>"\
        "</get>");*/

    uiRet = netconf_ce_query_config_all(send_data, &pReplyData);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to query db mac");
        return OVSDB_ERR;
    }

    while(NULL != pReplyData)
    {
        /* 解析reply消息中的db mac */
        uiRet = ovsdb_get_db_mac(pReplyData);

        if (uiRet != OVSDB_OK)
        {
            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to get db mac from reply message");
            free(pReplyData);
            pReplyData = NULL;
            return OVSDB_ERR;
        }

        /* 判断reply消息是否分片 */
        paReplySeg = strstr(pReplyData, "set-id");

        if (NULL == paReplySeg)
        {
            free(pReplyData);
            pReplyData = NULL;
            break;
        }

        /* 获取set-id以查询下一个回复消息分片 */
        paReplySeg = paReplySeg + strlen("set-id") + 2;
        while ('"' != *paReplySeg)
        {
            aSetId[uiLoop++] = *paReplySeg;
            paReplySeg++;
        }
        aSetId[uiLoop] = '\0';

        snprintf(send_data, sizeof(send_data),
            "<get-next xmlns=\"http://www.huawei.com/netconf/capability/base/1.0\" set-id=\"%s\">"\
            "</get-next>", aSetId);

        free(pReplyData);
        pReplyData = NULL;

        uiRet = netconf_ce_query_config_all(send_data, &pReplyData);
        if (OVSDB_OK != uiRet)
        {
            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to query next db mac");
            return OVSDB_ERR;
        }
        uiLoop = 0;
    }

    (void)ovsdb_sub_table_mac_delete();

    return OVSDB_OK;
}
#endif

#if OVSDB_DESC("OVSDB TABLE")
typedef bool (* scan_filter)(void * input, void * entry);
typedef int  (* scan_proc)(void * input, void * output, void * entry);

struct ovsdb_vtep_table_logical_switch *
ovsdb_table_logical_switch_query(struct uuid * uuid_self)
{
    int i;
    for (i = 0; i < TABLE_LOGICAL_SWITCH_NUM; i++)
    {
        if (uuid_equals(uuid_self, &ovsdb_vtep_db_table.table_logical_switch[i].uuid_self))
        {
            return &ovsdb_vtep_db_table.table_logical_switch[i];
        }
    }

    return NULL;
}

int 
ovsdb_table_logical_switch_add(struct uuid * uuid_self, char* description, char* name, int tunnel_key)
{
    struct uuid empty_uuid;
    struct ovsdb_vtep_table_logical_switch * empty_entry;

    uuid_zero(&empty_uuid);

    empty_entry = ovsdb_table_logical_switch_query(uuid_self);
    if (NULL != empty_entry) {
        return OVSDB_ERR_EXISTED;
    }

    empty_entry = ovsdb_table_logical_switch_query(&empty_uuid);
    if (NULL == empty_entry) {
        return OVSDB_ERR_INDEX_FULL;
    }

    (void)memcpy(&empty_entry->uuid_self, uuid_self, sizeof(struct uuid));
    OVSDB_SET_STR(empty_entry->description, description);
    OVSDB_SET_STR(empty_entry->name, name);
    empty_entry->tunnel_key = tunnel_key;

    ovsdb_vtep_db_table.used_num_table_logical_switch++;

    return OVSDB_OK;
}

int 
ovsdb_table_logical_switch_delete(struct uuid * uuid_self)
{
    struct ovsdb_vtep_table_logical_switch * entry;

    entry = ovsdb_table_logical_switch_query(uuid_self);
    if (NULL == entry) {
        return OVSDB_ERR_NOT_EXISTED;
    }

    OVSDB_FREE(entry->description);
    OVSDB_FREE(entry->name);
    (void)memset(entry, 0, sizeof(*entry));
    ovsdb_vtep_db_table.used_num_table_logical_switch--;

    return OVSDB_OK;
}

struct ovsdb_vtep_table_physical_locator *
ovsdb_table_physical_locator_query(struct uuid * uuid_self)
{
    int i;
    for (i = 0; i < TABLE_PHYSICAL_LOCATOR_NUM; i++)
    {
        if (uuid_equals(uuid_self, &ovsdb_vtep_db_table.table_physical_locator[i].uuid_self))
        {
            return &ovsdb_vtep_db_table.table_physical_locator[i];
        }
    }

    return NULL;
}

char * 
ovsdb_table_physical_locator_query_ip(struct uuid * uuid_pl)
{
    struct ovsdb_vtep_table_physical_locator * pstPL = NULL;

    pstPL = ovsdb_table_physical_locator_query(uuid_pl);
    if (NULL == pstPL)
        return NULL;

    return pstPL->dst_ip;
}

void
ovsdb_table_physical_locator_scan(void * input, void * output, scan_proc pProc)
{
    int i, ret;

    for (i = 0; i < TABLE_PHYSICAL_LOCATOR_NUM; i++)
    {
        if (uuid_is_zero(&ovsdb_vtep_db_table.table_physical_locator[i].uuid_self))
            continue;

        ret = pProc(input, output, (void *)&ovsdb_vtep_db_table.table_physical_locator[i]);
        if (ret != OVSDB_OK)
            return;
    }

    return;
}

int ovsdb_table_physical_locator_query_byip_proc(void * input, void * output, void * entry)
{
    char * dst_ip = (char *)input;
    struct ovsdb_vtep_table_physical_locator ** ppstPL =
        (struct ovsdb_vtep_table_physical_locator **)output;
    struct ovsdb_vtep_table_physical_locator * query_entry =
        (struct ovsdb_vtep_table_physical_locator *)entry;

    if (0 == strcmp(dst_ip, query_entry->dst_ip)) {
        *ppstPL = query_entry;
        return OVSDB_ERR;
    }

    return OVSDB_OK;
}

struct ovsdb_vtep_table_physical_locator *
ovsdb_table_physical_locator_query_byip(char * dst_ip)
{
    struct ovsdb_vtep_table_physical_locator * pstPL = NULL;

    ovsdb_table_physical_locator_scan((void *)dst_ip,
        (void *)&pstPL, ovsdb_table_physical_locator_query_byip_proc);

    return pstPL;
}

int 
ovsdb_table_physical_locator_add(struct uuid * uuid_self, char * dst_ip)
{
    struct uuid empty_uuid;
    struct ovsdb_vtep_table_physical_locator * empty_entry;

    uuid_zero(&empty_uuid);

    empty_entry = ovsdb_table_physical_locator_query(uuid_self);
    if (NULL != empty_entry) {
        return OVSDB_ERR_EXISTED;
    }

    empty_entry = ovsdb_table_physical_locator_query(&empty_uuid);
    if (NULL == empty_entry) {
        return OVSDB_ERR_INDEX_FULL;
    }

    (void)memcpy(&empty_entry->uuid_self, uuid_self, sizeof(struct uuid));

    OVSDB_SET_STR(empty_entry->dst_ip, dst_ip);

    ovsdb_vtep_db_table.used_num_table_physical_locator++;

    return OVSDB_OK;
}

int 
ovsdb_table_physical_locator_delete(struct uuid * uuid_self)
{
    struct ovsdb_vtep_table_physical_locator * entry;

    entry = ovsdb_table_physical_locator_query(uuid_self);
    if (NULL == entry) {
        return OVSDB_ERR_NOT_EXISTED;
    }

    OVSDB_FREE(entry->dst_ip);
    (void)memset(entry, 0, sizeof(*entry));
    ovsdb_vtep_db_table.used_num_table_physical_locator--;

    return OVSDB_OK;
}

struct ovsdb_vtep_table_physical_locator_set *
ovsdb_table_physical_locator_set_query(struct uuid * uuid_self)
{
    int i;
    for (i = 0; i < TABLE_PHYSICAL_LOCATOR_SET_NUM; i++)
    {
        if (uuid_equals(uuid_self, &ovsdb_vtep_db_table.table_physical_locator_set[i].uuid_self))
        {
            return &ovsdb_vtep_db_table.table_physical_locator_set[i];
        }
    }

    return NULL;
}

void
ovsdb_table_physical_locator_set_scan(void * input, void * output, scan_proc pProc)
{
    int i, ret;

    for (i = 0; i < TABLE_PHYSICAL_LOCATOR_SET_NUM; i++)
    {
        if (uuid_is_zero(&ovsdb_vtep_db_table.table_physical_locator_set[i].uuid_self))
            continue;

        ret = pProc(input, output, (void *)&ovsdb_vtep_db_table.table_physical_locator_set[i]);
        if (ret != OVSDB_OK)
            return;
    }

    return;
}

int 
ovsdb_table_physical_locator_set_add
(
    struct uuid * uuid_self,
    struct uuid * locators,
    int used_num_locators
)
{
    struct uuid empty_uuid;
    struct ovsdb_vtep_table_physical_locator_set * empty_entry;

    uuid_zero(&empty_uuid);

    empty_entry = ovsdb_table_physical_locator_set_query(uuid_self);
    if (NULL != empty_entry) {
        return OVSDB_ERR_EXISTED;
    }

    empty_entry = ovsdb_table_physical_locator_set_query(&empty_uuid);
    if (NULL == empty_entry) {
        return OVSDB_ERR_INDEX_FULL;
    }

    (void)memcpy(&empty_entry->uuid_self, uuid_self, sizeof(struct uuid));

    (void)memcpy(empty_entry->locators, locators,
                 sizeof(struct uuid) * LOCATOR_NUM_IN_LOCATION_SET);

    empty_entry->used_num_locators = used_num_locators;

    ovsdb_vtep_db_table.used_num_table_physical_locator_set++;

    return OVSDB_OK;
}

int 
ovsdb_table_physical_locator_set_delete(struct uuid * uuid_self)
{
    struct ovsdb_vtep_table_physical_locator_set * entry;

    entry = ovsdb_table_physical_locator_set_query(uuid_self);
    if (NULL == entry) {
        return OVSDB_ERR_NOT_EXISTED;
    }

    (void)memset(entry, 0, sizeof(*entry));
    ovsdb_vtep_db_table.used_num_table_physical_locator_set--;

    return OVSDB_OK;
}

struct ovsdb_vtep_table_ucast_macs_remote *
ovsdb_table_ucast_macs_remote_query(struct uuid * uuid_self)
{
    int i;
    for (i = 0; i < TABLE_UCAST_MACS_REMOTE_NUM; i++)
    {
        if (uuid_equals(uuid_self, &ovsdb_vtep_db_table.table_ucast_macs_remote[i].uuid_self))
        {
            return &ovsdb_vtep_db_table.table_ucast_macs_remote[i];
        }
    }

    return NULL;
}

int 
ovsdb_table_ucast_macs_remote_add
(
    struct uuid * uuid_self,
    char * MAC,
    char * ipaddr,
    struct uuid * logical_switch,
    struct uuid * locator
)
{
    struct uuid empty_uuid;
    struct ovsdb_vtep_table_ucast_macs_remote * empty_entry;

    uuid_zero(&empty_uuid);

    empty_entry = ovsdb_table_ucast_macs_remote_query(uuid_self);
    if (NULL != empty_entry) {
        return OVSDB_ERR_EXISTED;
    }

    empty_entry = ovsdb_table_ucast_macs_remote_query(&empty_uuid);
    if (NULL == empty_entry) {
        return OVSDB_ERR_INDEX_FULL;
    }

    (void)memcpy(&empty_entry->uuid_self, uuid_self, sizeof(struct uuid));

    OVSDB_SET_STR(empty_entry->MAC, MAC);
    OVSDB_SET_STR(empty_entry->ipaddr, ipaddr);
    (void)memcpy(&empty_entry->logical_switch, logical_switch, sizeof(struct uuid));
    (void)memcpy(&empty_entry->locator, locator, sizeof(struct uuid));

    ovsdb_vtep_db_table.used_num_table_ucast_macs_remote++;

    return OVSDB_OK;
}

int 
ovsdb_table_ucast_macs_remote_delete(struct uuid * uuid_self)
{
    struct ovsdb_vtep_table_ucast_macs_remote * entry;

    entry = ovsdb_table_ucast_macs_remote_query(uuid_self);
    if (NULL == entry) {
        return OVSDB_ERR_NOT_EXISTED;
    }

    OVSDB_FREE(entry->MAC);
    OVSDB_FREE(entry->ipaddr);
    (void)memset(entry, 0, sizeof(*entry));
    ovsdb_vtep_db_table.used_num_table_ucast_macs_remote--;

    return OVSDB_OK;
}

struct ovsdb_vtep_table_mcast_macs_remote *
ovsdb_table_mcast_macs_remote_query(struct uuid * uuid_self)
{
    int i;
    for (i = 0; i < TABLE_MCAST_MACS_REMOTE_NUM; i++)
    {
        if (uuid_equals(uuid_self, &ovsdb_vtep_db_table.table_mcast_macs_remote[i].uuid_self))
        {
            return &ovsdb_vtep_db_table.table_mcast_macs_remote[i];
        }
    }

    return NULL;
}

void
ovsdb_table_mcast_macs_remote_scan(void * input, void * output, scan_proc pProc)
{
    int i;

    for (i = 0; i < TABLE_MCAST_MACS_REMOTE_NUM; i++)
    {
        if (uuid_is_zero(&ovsdb_vtep_db_table.table_mcast_macs_remote[i].uuid_self))
            continue;

        (void)pProc(input, output, (void *)&ovsdb_vtep_db_table.table_mcast_macs_remote[i]);
    }

    return;
}

int 
ovsdb_table_mcast_macs_remote_add
(
    struct uuid * uuid_self,
    char * MAC,
    char * ipaddr,
    struct uuid * logical_switch,
    struct uuid * locator_set
)
{
    struct uuid empty_uuid;
    struct ovsdb_vtep_table_mcast_macs_remote * empty_entry;

    uuid_zero(&empty_uuid);

    empty_entry = ovsdb_table_mcast_macs_remote_query(uuid_self);
    if (NULL != empty_entry) {
        return OVSDB_ERR_EXISTED;
    }

    empty_entry = ovsdb_table_mcast_macs_remote_query(&empty_uuid);
    if (NULL == empty_entry) {
        return OVSDB_ERR_INDEX_FULL;
    }

    (void)memcpy(&empty_entry->uuid_self, uuid_self, sizeof(struct uuid));

    OVSDB_SET_STR(empty_entry->MAC, MAC);
    OVSDB_SET_STR(empty_entry->ipaddr, ipaddr);
    (void)memcpy(&empty_entry->logical_switch, logical_switch, sizeof(struct uuid));
    (void)memcpy(&empty_entry->locator_set, locator_set, sizeof(struct uuid));

    ovsdb_vtep_db_table.used_num_table_mcast_macs_remote++;

    return OVSDB_OK;
}

int 
ovsdb_table_mcast_macs_remote_delete(struct uuid * uuid_self)
{
    struct ovsdb_vtep_table_mcast_macs_remote * entry;

    entry = ovsdb_table_mcast_macs_remote_query(uuid_self);
    if (NULL == entry) {
        return OVSDB_ERR_NOT_EXISTED;
    }

    OVSDB_FREE(entry->MAC);
    OVSDB_FREE(entry->ipaddr);
    (void)memset(entry, 0, sizeof(*entry));
    ovsdb_vtep_db_table.used_num_table_mcast_macs_remote--;

    return OVSDB_OK;
}

struct ovsdb_vtep_table_physical_port *
ovsdb_table_physical_port_query(struct uuid * uuid_self)
{
    int i;
    for (i = 0; i < TABLE_PHYSICAL_PORT_NUM; i++)
    {
        if (uuid_equals(uuid_self, &ovsdb_vtep_db_table.table_physical_port[i].uuid_self))
        {
            return &ovsdb_vtep_db_table.table_physical_port[i];
        }
    }

    return NULL;
}

int 
ovsdb_table_physical_port_add
(
    struct uuid * uuid_self,
    char* name
)
{
    struct uuid empty_uuid;
    struct ovsdb_vtep_table_physical_port * empty_entry;

    uuid_zero(&empty_uuid);

    empty_entry = ovsdb_table_physical_port_query(uuid_self);
    if (NULL != empty_entry) {
        return OVSDB_ERR_EXISTED;
    }

    empty_entry = ovsdb_table_physical_port_query(&empty_uuid);
    if (NULL == empty_entry) {
        return OVSDB_ERR_INDEX_FULL;
    }

    (void)memcpy(&empty_entry->uuid_self, uuid_self, sizeof(struct uuid));

    OVSDB_SET_STR(empty_entry->name, name);

    ovsdb_vtep_db_table.used_num_table_physical_port++;

    return OVSDB_OK;
}

int 
ovsdb_table_physical_port_delete(struct uuid * uuid_self)
{
    struct ovsdb_vtep_table_physical_port * entry;

    entry = ovsdb_table_physical_port_query(uuid_self);
    if (NULL == entry) {
        return OVSDB_ERR_NOT_EXISTED;
    }

    OVSDB_FREE(entry->name);

    (void)memset(entry, 0, sizeof(*entry));
    ovsdb_vtep_db_table.used_num_table_physical_port--;

    return OVSDB_OK;
}

void
ovsdb_table_tunnel_destroy_entry
(
    struct ovsdb_vtep_table_tunnel * entry
)
{
    OVSDB_FREE(entry->bfd_config_local.bfd_mac);
    OVSDB_FREE(entry->bfd_config_local.bfd_ip);

    OVSDB_FREE(entry->bfd_config_remote.bfd_mac);
    OVSDB_FREE(entry->bfd_config_remote.bfd_ip);

    OVSDB_FREE(entry->bfd_params.enable);
    OVSDB_FREE(entry->bfd_params.min_rx);
    OVSDB_FREE(entry->bfd_params.min_tx);
    OVSDB_FREE(entry->bfd_params.decay_min_rx);
    OVSDB_FREE(entry->bfd_params.forwarding_if_rx);
    OVSDB_FREE(entry->bfd_params.cpath_down);
    OVSDB_FREE(entry->bfd_params.check_tnl_key);

    OVSDB_FREE(entry->bfd_status.enable);
    OVSDB_FREE(entry->bfd_status.state);
    OVSDB_FREE(entry->bfd_status.forwarding);
    OVSDB_FREE(entry->bfd_status.diagnostic);
    OVSDB_FREE(entry->bfd_status.remote_state);
    OVSDB_FREE(entry->bfd_status.remote_diagnostic);
    OVSDB_FREE(entry->bfd_status.info);

    (void)memset(entry, 0, sizeof(*entry));

    return;
}

struct ovsdb_vtep_table_tunnel *
ovsdb_table_tunnel_query(struct uuid * uuid_self)
{
    int i;
    for (i = 0; i < TABLE_TUNNEL_NUM; i++)
    {
        if (uuid_equals(uuid_self, &ovsdb_vtep_db_table.table_tunnel[i].uuid_self1))
        {
            return &ovsdb_vtep_db_table.table_tunnel[i];
        }
    }

    return NULL;
}

int 
ovsdb_table_tunnel_add
(
    struct ovsdb_vtep_table_tunnel * entry
)
{
    struct uuid empty_uuid;
    struct ovsdb_vtep_table_tunnel * empty_entry;

    uuid_zero(&empty_uuid);

    empty_entry = ovsdb_table_tunnel_query(&entry->uuid_self1);
    if (NULL != empty_entry) {
        return OVSDB_ERR_EXISTED;
    }

    empty_entry = ovsdb_table_tunnel_query(&empty_uuid);
    if (NULL == empty_entry) {
        return OVSDB_ERR_INDEX_FULL;
    }

    (void)memcpy(&empty_entry->uuid_self1,
                 &entry->uuid_self1, sizeof(struct uuid));
    (void)memcpy(&empty_entry->name,
                 &entry->name, BFD_SESSION_NAME_LEN);
    (void)memcpy(&empty_entry->local,
                 &entry->local, sizeof(struct uuid));
    (void)memcpy(&empty_entry->remote,
                 &entry->remote, sizeof(struct uuid));

    OVSDB_SET_STR(empty_entry->bfd_config_local.bfd_mac,
                        entry->bfd_config_local.bfd_mac);
    OVSDB_SET_STR(empty_entry->bfd_config_local.bfd_ip,
                        entry->bfd_config_local.bfd_ip);

    OVSDB_SET_STR(empty_entry->bfd_config_remote.bfd_mac,
                        entry->bfd_config_remote.bfd_mac);
    OVSDB_SET_STR(empty_entry->bfd_config_remote.bfd_ip,
                        entry->bfd_config_remote.bfd_ip);

    OVSDB_SET_STR(empty_entry->bfd_params.enable,
                        entry->bfd_params.enable);
    OVSDB_SET_STR(empty_entry->bfd_params.min_rx,
                        entry->bfd_params.min_rx);
    OVSDB_SET_STR(empty_entry->bfd_params.min_tx,
                        entry->bfd_params.min_tx);
    OVSDB_SET_STR(empty_entry->bfd_params.decay_min_rx,
                        entry->bfd_params.decay_min_rx);
    OVSDB_SET_STR(empty_entry->bfd_params.forwarding_if_rx,
                        entry->bfd_params.forwarding_if_rx);
    OVSDB_SET_STR(empty_entry->bfd_params.cpath_down,
                        entry->bfd_params.cpath_down);
    OVSDB_SET_STR(empty_entry->bfd_params.check_tnl_key,
                        entry->bfd_params.check_tnl_key);

    OVSDB_SET_STR(empty_entry->bfd_status.enable,
                        entry->bfd_status.enable);
    OVSDB_SET_STR(empty_entry->bfd_status.state,
                        entry->bfd_status.state);
    OVSDB_SET_STR(empty_entry->bfd_status.forwarding,
                        entry->bfd_status.forwarding);
    OVSDB_SET_STR(empty_entry->bfd_status.diagnostic,
                        entry->bfd_status.diagnostic);
    OVSDB_SET_STR(empty_entry->bfd_status.remote_state,
                        entry->bfd_status.remote_state);
    OVSDB_SET_STR(empty_entry->bfd_status.remote_diagnostic,
                        entry->bfd_status.remote_diagnostic);
    OVSDB_SET_STR(empty_entry->bfd_status.info,
                        entry->bfd_status.info);

    ovsdb_vtep_db_table.used_num_table_tunnel++;

    return OVSDB_OK;
}

int 
ovsdb_table_tunnel_delete(struct uuid * uuid_self)
{
    struct ovsdb_vtep_table_tunnel * entry;

    entry = ovsdb_table_tunnel_query(uuid_self);
    if (NULL == entry) {
        return OVSDB_ERR_NOT_EXISTED;
    }

    ovsdb_table_tunnel_destroy_entry(entry);
    ovsdb_vtep_db_table.used_num_table_tunnel--;

    return OVSDB_OK;
}

#endif

#if OVSDB_DESC("SWITCH TABLE")
struct hw_vtep_vxlan_tunnel *
hw_vtep_vxlan_tunnel_query(
    int vni,
    char* dst_ip
)
{
    int i;
    for (i = 0; i < VXLAN_TUNNEL_NUM_MAX; i++)
    {
        if (switch_vxlan_tunnel[i].used_bit == 0)
            continue;

        if ((switch_vxlan_tunnel[i].vni == vni) &&
            (0 == strcmp(switch_vxlan_tunnel[i].dst_ip, dst_ip)))
            return &switch_vxlan_tunnel[i];
    }

    return NULL;
}

struct hw_vtep_vxlan_tunnel *
hw_vtep_vxlan_tunnel_get_empty(void)
{
    int i;
    for (i = 0; i < VXLAN_TUNNEL_NUM_MAX; i++)
    {
        if (switch_vxlan_tunnel[i].used_bit == 0)
            return &switch_vxlan_tunnel[i];
    }

    return NULL;
}

void 
hw_vtep_vxlan_tunnel_delete_by_vni
(
    int vni
)
{
    int i;

    for (i = 0; i < VXLAN_TUNNEL_NUM_MAX; i++) {
        if (switch_vxlan_tunnel[i].vni != vni)
            continue;

        /*释放switch_vxlan_tunnel中的该条表项*/
        OVSDB_FREE(switch_vxlan_tunnel[i].source_ip);
        OVSDB_FREE(switch_vxlan_tunnel[i].dst_ip);
        memset(&switch_vxlan_tunnel[i], 0, sizeof(struct hw_vtep_vxlan_tunnel));
    }

    return;
}

int 
hw_vtep_vxlan_tunnel_add
(
    int vni,
    char* dst_ip,
    enum HW_VTEP_VXLAN_TUNNEL_TYPE type
)
{
    struct hw_vtep_vxlan_tunnel * entry;

    entry = hw_vtep_vxlan_tunnel_query(vni, dst_ip);
    if (entry != NULL) {
        HW_BIT_SET(entry->used_bit, type);
        return OVSDB_OK;
    }

    entry = hw_vtep_vxlan_tunnel_get_empty();
    if (entry == NULL) {
        return OVSDB_ERR_INDEX_FULL;
    }

    entry->vni = vni;
    OVSDB_SET_STR(entry->dst_ip, dst_ip);
    HW_BIT_SET(entry->used_bit, type);

    return OVSDB_OK;
}

int 
hw_vtep_vxlan_tunnel_delete
(
    int vni,
    char* dst_ip,
    enum HW_VTEP_VXLAN_TUNNEL_TYPE type
)
{
    struct hw_vtep_vxlan_tunnel * entry;

    entry = hw_vtep_vxlan_tunnel_query(vni, dst_ip);
    if (NULL == entry)
        return OVSDB_ERR_NOT_EXISTED;

    HW_BIT_CLEAR(entry->used_bit, type);

    if (0 == entry->used_bit) {
        OVSDB_FREE(entry->dst_ip);
        (void)memset(entry, 0, sizeof(*entry));
    }

    return OVSDB_OK;    
}

struct vxlan_tunnel_static_mac *
hw_vtep_vxlan_static_mac_query
(
    int vni,
    char* source_ip,
    char* dst_ip,
    char* ce_mac
)
{
    int i;
    for (i = 0; i < VXLAN_TUNNEL_MAC_MAX; i++)
    {
        if (switch_vxlan_static_mac[i].used_bit == 0)
            continue;

        if ((switch_vxlan_static_mac[i].vni == vni) &&
            (0 == strcmp(switch_vxlan_static_mac[i].source_ip, source_ip)) &&
            (0 == strcmp(switch_vxlan_static_mac[i].dst_ip, dst_ip)) &&
            (0 == strcmp(switch_vxlan_static_mac[i].ce_mac, ce_mac)))
            return &switch_vxlan_static_mac[i];
    }

    return NULL;
}

struct vxlan_tunnel_static_mac *
hw_vtep_vxlan_static_mac_query_byTunnel
(
    int vni,
    char* source_ip,
    char* dst_ip
)
{
    int i;
    for (i = 0; i < VXLAN_TUNNEL_MAC_MAX; i++)
    {
        if (switch_vxlan_static_mac[i].used_bit == 0)
            continue;

        if ((switch_vxlan_static_mac[i].vni == vni) &&
            (0 == strcmp(switch_vxlan_static_mac[i].source_ip, source_ip)) &&
            (0 == strcmp(switch_vxlan_static_mac[i].dst_ip, dst_ip)))
            return &switch_vxlan_static_mac[i];
    }

    return NULL;
}

struct vxlan_tunnel_static_mac *
hw_vtep_vxlan_static_mac_get_empty(void)
{
    int i;
    for (i = 0; i < VXLAN_TUNNEL_MAC_MAX; i++)
    {
        if (switch_vxlan_static_mac[i].used_bit == 0)
            return &switch_vxlan_static_mac[i];
    }

    return NULL;
}

int 
hw_vtep_vxlan_static_mac_add
(
    int vni,
    char* source_ip,
    char* dst_ip,
    char* ce_mac
)
{
    struct vxlan_tunnel_static_mac * entry;

    entry = hw_vtep_vxlan_static_mac_query(vni, source_ip, dst_ip, ce_mac);
    if (entry != NULL) {
        return OVSDB_OK;
    }

    entry = hw_vtep_vxlan_static_mac_get_empty();
    if (entry == NULL) {
        return OVSDB_ERR_INDEX_FULL;
    }

    entry->vni = vni;
    OVSDB_SET_STR(entry->source_ip, source_ip);
    OVSDB_SET_STR(entry->dst_ip, dst_ip);
    OVSDB_SET_STR(entry->ce_mac, ce_mac);
    entry->used_bit = 1;

    return OVSDB_OK;
}

int 
hw_vtep_vxlan_static_mac_delete
(
    int vni,
    char* source_ip,
    char* dst_ip,
    char* ce_mac
)
{
    struct vxlan_tunnel_static_mac * entry;

    entry = hw_vtep_vxlan_static_mac_query(vni, source_ip, dst_ip, ce_mac);
    if (NULL == entry)
        return OVSDB_ERR_NOT_EXISTED;

    OVSDB_FREE(entry->source_ip);
    OVSDB_FREE(entry->dst_ip);
    OVSDB_FREE(entry->ce_mac);
    (void)memset(entry, 0, sizeof(*entry));

    return OVSDB_OK;    
}

#endif

#if OVSDB_DEBUG
struct port_vlan_to_vni_map switch_vxlan_map[TABLE_PHYSICAL_PORT_NUM] = {0};
void ovsdb_port_update_vlanbinding_process(struct json *new, struct json *old, char* node_name, int* update_type)
{

    struct json *new_vlan_binding;
    struct json *old_vlan_binding;
    struct json *new_vlanbinding_elems;
    struct json *old_vlanbinding_elems;
    struct json_array *new_vlanbinding_elems_array;
    struct json_array *old_vlanbinding_elems_array;
    struct uuid uuid_port;
    char* port_name =NULL;
    int port_num=0;
    int new_vlanbinding_elem_num = 0;
    int old_vlanbinding_elem_num = 0;
    int add_port_map_exist = 0;

    if((!new)||(!old))
    {
        return;
    }

    (void)uuid_from_string(&uuid_port, node_name);
    OVSDB_PRINTF_DEBUG_TRACE("vlan_binding update port uuid = "UUID_FMT, UUID_ARGS(&uuid_port));

    new_vlan_binding = shash_find_data(json_object(new), "vlan_bindings");
    old_vlan_binding = shash_find_data(json_object(old), "vlan_bindings");

    if((!new_vlan_binding)||(!old_vlan_binding))    /*说明更新和vlan_binding无关，可能是更新的description之类的*/
    {
        OVSDB_PRINTF_DEBUG_TRACE("port table update has nothing to do with vlan_binding.");
        return;
    }

    new_vlanbinding_elems = json_array(new_vlan_binding)->elems[1]; /*elems[0]* is "map" string*/
    new_vlanbinding_elems_array = json_array(new_vlanbinding_elems);
    new_vlanbinding_elem_num = new_vlanbinding_elems_array->n;

    old_vlanbinding_elems = json_array(old_vlan_binding)->elems[1]; /*elems[0]* is "map" string*/
    old_vlanbinding_elems_array = json_array(old_vlanbinding_elems);
    old_vlanbinding_elem_num = old_vlanbinding_elems_array->n;

    OVSDB_PRINTF_DEBUG_TRACE("new_vlanbinding_elem_num = %d, old_vlanbinding_elem_num = %d.",
                              new_vlanbinding_elem_num, old_vlanbinding_elem_num);

    if(new_vlanbinding_elem_num > old_vlanbinding_elem_num)
    {
        *update_type = ADD_VLAN_BINGDING;
        OVSDB_PRINTF_DEBUG_TRACE("update_type = ADD_VLAN_BINGDING");
    }
    else if(new_vlanbinding_elem_num < old_vlanbinding_elem_num)
    {
        *update_type = DELETE_VLAN_BINGDING;
        OVSDB_PRINTF_DEBUG_TRACE("update_type = DELETE_VLAN_BINGDING");
    }
    else
    {
        *update_type = PORT_UPDATE_INVALID_TYPE;
    }

    /*获取port name*/
    for(port_num=0; port_num<TABLE_PHYSICAL_PORT_NUM; port_num++)
    {
        if(uuid_equals(&uuid_port, &ovsdb_vtep_db_table.table_physical_port[port_num].uuid_self))
        {
            port_name = malloc(strlen(ovsdb_vtep_db_table.table_physical_port[port_num].name)+1);
            memcpy(port_name, ovsdb_vtep_db_table.table_physical_port[port_num].name,
                    strlen(ovsdb_vtep_db_table.table_physical_port[port_num].name)+1);

            /*below is temp to delete*/
            OVSDB_PRINTF_DEBUG_TRACE("ovsdb_vtep_db_table.table_physical_port[port_num].name=%s",
                    ovsdb_vtep_db_table.table_physical_port[port_num].name);

            break;
        }
    }

    if(!port_name)
    {
        OVSDB_PRINTF_DEBUG_ERROR("do not find port name.");
        return;
    }

    OVSDB_PRINTF_DEBUG_TRACE("vlan_binding update port name = %s.", port_name);

    if(*update_type == ADD_VLAN_BINGDING)
    {
        int i=0;
        int j=0;
        int k=0;
        int vlanid = 4096;
        int vni_temp = 0;
        struct uuid uuid_ls;
        unsigned int uiRet = 0;
        /*检查switch_vxlan_map全局变量中是否已经有该该port的映射*/
        for(i=0; i<TABLE_PHYSICAL_PORT_NUM; i++)
        {
            if(uuid_equals(&uuid_port, &switch_vxlan_map[i].port_uuid))
            {
                add_port_map_exist = 1;
                break;
            }
        }

        if(!add_port_map_exist)
        {
            for(i=0; i<TABLE_PHYSICAL_PORT_NUM; i++)
            {
                if(uuid_is_zero(&switch_vxlan_map[i].port_uuid))
                {
                    memcpy(&switch_vxlan_map[i].port_uuid, &uuid_port, sizeof(uuid_port));
                    break;
                }
            }
        }

        /*找到对应的映射表项进行操作*/
        for(i=0; i<TABLE_PHYSICAL_PORT_NUM; i++)
        {
            if(uuid_equals(&uuid_port, &switch_vxlan_map[i].port_uuid))
            {
                for(j=0; j<new_vlanbinding_elem_num; j++)
                {
                    vlanid = json_integer(json_array(new_vlanbinding_elems_array->elems[j])->elems[0]);

                    if((vlanid > 4093)||(vlanid<0))
                    {
                        OVSDB_PRINTF_DEBUG_TRACE("vlan_id is not valid, which is %d.", vlanid);
                    }
                    if(switch_vxlan_map[i].vlan_vni_map[vlanid].used_bit)
                    {
                        OVSDB_PRINTF_DEBUG_TRACE("vlan_id %d mapping is exist, do not process.", vlanid);
                    }
                    else
                    {
                        OVSDB_PRINTF_DEBUG_TRACE("vlan_id %d mapping is absent, now do process.", vlanid);
                        uuid_from_string(&uuid_ls, json_string(json_array(json_array(new_vlanbinding_elems_array->elems[j])->elems[1])->elems[1]));
                        for(k=0; k<TABLE_LOGICAL_SWITCH_NUM; k++)
                        {
                            if(uuid_equals(&ovsdb_vtep_db_table.table_logical_switch[k].uuid_self, &uuid_ls))
                            {
                                vni_temp = ovsdb_vtep_db_table.table_logical_switch[k].tunnel_key;
                                break;
                            }
                        }

                        if(vni_temp > 4095)
                        {
                            switch_vxlan_map[i].vlan_vni_map[vlanid].vni = vni_temp;
                            switch_vxlan_map[i].vlan_vni_map[vlanid].used_bit = 1;

                            /*配置子接口和vxlan映射*/

                            //ce_config_port(vlanid, switch_vxlan_map[i].vlan_vni_map[vlanid].vni, port_name);
                            uiRet = netconf_ce_config_port(vlanid, switch_vxlan_map[i].vlan_vni_map[vlanid].vni, port_name);
                            if (OVSDB_OK != uiRet)
                            {
                                OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config subinterface when processing port vlanbinding.");
                                return;
                            }

                            /*往ovsdb_vtep_db_table全局变量中也写一下*/
                            ovsdb_vtep_db_table.table_physical_port[port_num].vlan_bindings.vlan_bindings[vlanid].vlan_id = vlanid; /*这里也把vlanid作为下标，好与switch_vxlan_map对应*/
                            memcpy(&ovsdb_vtep_db_table.table_physical_port[port_num].vlan_bindings.vlan_bindings[vlanid].uuid_logical_switch ,&ovsdb_vtep_db_table.table_logical_switch[k].uuid_self,
                                sizeof(ovsdb_vtep_db_table.table_logical_switch[k]));
                        }
                    }
                }

                break;
            }
        }

    }

    else if(*update_type == DELETE_VLAN_BINGDING)
    {
        int i=0;
        int j=0;
        int k=0;
        int m=0;
        int vlanid = 4096;
        unsigned int uiRet = 0;

        for(i=0; i<TABLE_PHYSICAL_PORT_NUM; i++)
        {
            if(uuid_equals(&uuid_port, &switch_vxlan_map[i].port_uuid))
            {
                for(j=0; j<VXLAN_PORT_MAP_MAX; j++)
                {
                    if(!switch_vxlan_map[i].vlan_vni_map[j].used_bit)
                    {
                        continue;
                    }
                    else
                    {
                        int vlan_binding_exist=0;

                        for(k=0; k<new_vlanbinding_elem_num; k++)
                        {
                            vlanid = json_integer(json_array(new_vlanbinding_elems_array->elems[k])->elems[0]);
                            if(vlanid == j)
                            {
                               vlan_binding_exist=1;
                               OVSDB_PRINTF_DEBUG_TRACE("vlan_id %d mapping is not deleted, do not process.", j);
                            }
                        }
                        if(!vlan_binding_exist) /*在switch_vxlan_map中有，但是new中没有，说明在这次操作中被删除了*/
                        {
                            int port_mappint_exist=0;
                            OVSDB_PRINTF_DEBUG_TRACE("vlan_id %d mapping is now deleted, do process now.", j);

                            //ce_undo_config_port(j, switch_vxlan_map[i].vlan_vni_map[j].vni, port_name);
                            uiRet = netconf_ce_undo_config_port(j, port_name);
                            if (OVSDB_OK != uiRet)
                            {
                                OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config undo subinterface when processing port vlanbinding.");
                                return;
                            }

                            switch_vxlan_map[i].vlan_vni_map[j].vni = 0;
                            switch_vxlan_map[i].vlan_vni_map[j].used_bit= 0;

                            /*检查是否switch_vxlan_map[i]所有的vlan_mapping都没有了，如果全删除了，删除整个switch_vxlan_map[i]*/
                            for(m=0; m<VXLAN_PORT_MAP_MAX; m++)
                            {
                                if(switch_vxlan_map[i].vlan_vni_map[m].used_bit)
                                {
                                    port_mappint_exist =1;
                                    break;
                                }
                            }

                            if(!port_mappint_exist)
                            {
                                OVSDB_PRINTF_DEBUG_TRACE("clear all mapping of port %s.", port_name);
                                memset(&switch_vxlan_map[i], 0, sizeof(struct port_vlan_to_vni_map));
                            }

                            /*往ovsdb_vtep_db_table全局变量中也写一下*/
                            memset(&ovsdb_vtep_db_table.table_physical_port[port_num].vlan_bindings.vlan_bindings[j], 0, sizeof(struct ovsdb_vtep_vlan_binding));
                        }
                    }
                }

                break;
            }
        }
    }

    if(port_name)
    {
        free(port_name);
    }
}
#endif

void ovsdb_port_update_vlanbinding_process
(
    char * port_name,
    struct json *new_port_vlan_bindings,
    struct json *old_port_vlan_bindings
)
{
    struct json_array *new_vlanbinding_elems_array = NULL;
    int new_vlanbinding_elem_num = 0;
    struct json_array *old_vlanbinding_elems_array = NULL;
    int old_vlanbinding_elem_num = 0;
    int i, j;
    int ret;
    int new_vlanid, old_vlanid;
    bool flag;
    struct uuid new_uuid_ls, old_uuid_ls;
    struct ovsdb_vtep_table_logical_switch * pstLS;

    if (NULL != new_port_vlan_bindings)
    {
        new_vlanbinding_elems_array = json_array(json_array(new_port_vlan_bindings)->elems[1]);
        new_vlanbinding_elem_num = new_vlanbinding_elems_array->n;
    }

    if (NULL != old_port_vlan_bindings)
    {
        old_vlanbinding_elems_array = json_array(json_array(old_port_vlan_bindings)->elems[1]);
        old_vlanbinding_elem_num = old_vlanbinding_elems_array->n;
    }

    for (i = 0; i < old_vlanbinding_elem_num; i++)
    {
        flag = false;
        old_vlanid = json_integer(json_array(old_vlanbinding_elems_array->elems[i])->elems[0]);
        uuid_from_string(&old_uuid_ls, json_string(json_array(json_array(old_vlanbinding_elems_array->elems[i])->elems[1])->elems[1]));

        for (j = 0; j < new_vlanbinding_elem_num; j++)
        {
            new_vlanid = json_integer(json_array(new_vlanbinding_elems_array->elems[j])->elems[0]);
            uuid_from_string(&new_uuid_ls, json_string(json_array(json_array(new_vlanbinding_elems_array->elems[j])->elems[1])->elems[1]));

            if (new_vlanid == old_vlanid) {
                flag = true;
                break;
            }
        }

        if (flag == true)
            continue;

        if((old_vlanid > 4093)||(old_vlanid < 0))
        {
            OVSDB_PRINTF_DEBUG_ERROR("vlan_id is not valid, which is %d.", old_vlanid);
            continue;
        }

        ret = netconf_msg_list_undo_config_port(old_vlanid, port_name);
        if (OVSDB_OK != ret)
        {
            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config subinterface, new_vlanid = %d, port = %s.",
                                     old_vlanid, port_name);
            continue;
        }
    }

    for (i = 0; i < new_vlanbinding_elem_num; i++)
    {
        flag = false;
        new_vlanid = json_integer(json_array(new_vlanbinding_elems_array->elems[i])->elems[0]);
        uuid_from_string(&new_uuid_ls, json_string(json_array(json_array(new_vlanbinding_elems_array->elems[i])->elems[1])->elems[1]));

        for (j = 0; j < old_vlanbinding_elem_num; j++)
        {
            old_vlanid = json_integer(json_array(old_vlanbinding_elems_array->elems[j])->elems[0]);
            uuid_from_string(&old_uuid_ls, json_string(json_array(json_array(old_vlanbinding_elems_array->elems[j])->elems[1])->elems[1]));

            if ((new_vlanid == old_vlanid) &&
                uuid_equals(&new_uuid_ls, &old_uuid_ls)) {
                flag = true;
                break;
            }
        }

        if (flag == true)
            continue;

        if((new_vlanid > 4093)||(new_vlanid < 0))
        {
            OVSDB_PRINTF_DEBUG_ERROR("vlan_id is not valid, which is %d.", new_vlanid);
            continue;
        }

        pstLS = ovsdb_table_logical_switch_query(&new_uuid_ls);
        if (pstLS == NULL)
        {
            OVSDB_PRINTF_DEBUG_ERROR("query pstLS faild, uuid "UUID_FMT, UUID_ARGS(&new_uuid_ls));
            continue;
        }

        ret = netconf_msg_list_config_port(new_vlanid, pstLS->tunnel_key, port_name);
        if (OVSDB_OK != ret)
        {
            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config subinterface, new_vlanid = %d, vni = %d, port = %s.",
                                     new_vlanid, pstLS->tunnel_key, port_name);
            continue;
        }
    }

    return;
}

void ovsdb_switch_update_management_ips_process(struct json *new, struct json *old, char* node_name)
{
    struct json *new_management_ips;
    struct json *old_management_ips;
    struct uuid uuid_ps;
    int i=0;
    unsigned int uiRet = 0;

    if((!new)||(!old))
    {
        return;
    }

    uuid_from_string(&uuid_ps, node_name);

    new_management_ips = shash_find_data(json_object(new), "management_ips");
    old_management_ips = shash_find_data(json_object(old), "management_ips");

    if((!new_management_ips)||(!old_management_ips))    /*说明更新和managemenet ip无关，可能是更新的description之类的*/
    {
        OVSDB_PRINTF_DEBUG_TRACE("physical switch table update has nothing to do with management_ips.");
        return;
    }

    for(i=0; i<TABLE_PHYSICAL_SWITCH_NUM; i++)
    {
        if(uuid_equals(&uuid_ps, &ovsdb_vtep_db_table.table_physical_switch[i].uuid_self))
        {
            if(JSON_STRING == new_management_ips->type)
            {
                ovsdb_vtep_db_table.table_physical_switch[i].management_ips[0]=malloc(strlen(json_string(new_management_ips))+1);
                memcpy(ovsdb_vtep_db_table.table_physical_switch[i].management_ips[0],
                    json_string(new_management_ips), strlen(json_string(new_management_ips))+1);
                OVSDB_PRINTF_DEBUG_TRACE("update management_ips of %s, which is %s.",
                    ovsdb_vtep_db_table.table_physical_switch[i].name, ovsdb_vtep_db_table.table_physical_switch[i].management_ips[0]);
            }
            break;
        }
    }
}

void ovsdb_switch_update_tunnel_ips_process(struct json *new, struct json *old, char* node_name)
{
    struct json *new_tunnel_ips;
    struct json *old_tunnel_ips;
    struct uuid uuid_ps;
    int i=0;
    unsigned int uiRet = 0;

    if((!new)||(!old))
    {
        return;
    }

    uuid_from_string(&uuid_ps, node_name);

    new_tunnel_ips = shash_find_data(json_object(new), "tunnel_ips");
    old_tunnel_ips = shash_find_data(json_object(old), "tunnel_ips");

    if((!new_tunnel_ips)||(!old_tunnel_ips))    /*说明更新和tunnel ip无关，可能是更新的description之类的*/
    {
        OVSDB_PRINTF_DEBUG_TRACE("physical switch table update has nothing to do with tunnel_ips.");
        return;
    }

    for(i=0; i<TABLE_PHYSICAL_SWITCH_NUM; i++)
    {
        if(uuid_equals(&uuid_ps, &ovsdb_vtep_db_table.table_physical_switch[i].uuid_self))
        {
            if(JSON_STRING == new_tunnel_ips->type)
            {
                ovsdb_vtep_db_table.table_physical_switch[i].tunnel_ips[0]=malloc(strlen(json_string(new_tunnel_ips))+1);
                memcpy(ovsdb_vtep_db_table.table_physical_switch[i].tunnel_ips[0],
                    json_string(new_tunnel_ips), strlen(json_string(new_tunnel_ips))+1);
                OVSDB_PRINTF_DEBUG_TRACE("update tunnel_ips of %s, which is %s.",
                    ovsdb_vtep_db_table.table_physical_switch[i].name, ovsdb_vtep_db_table.table_physical_switch[i].tunnel_ips[0]);
            }
            break;
        }
    }

    //ce_config_nve1_source();
    uiRet = netconf_ce_config_nve1_source(ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0]);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config Nve 1 source when updating tunnel ips.");
        return;
    }

}

void ovsdb_switch_update_tunnel_process(struct json * new, struct json * old, char * node_name)
{
    struct json *new_tunnels;
    struct json *old_tunnels;
    struct uuid uuid_ps;
    int i = 0;
    unsigned int uiRet = 0;

    if ((!new) || (!old))
    {
        return;
    }

    uuid_from_string(&uuid_ps, node_name);

    new_tunnels = shash_find_data(json_object(new), "tunnels");
    old_tunnels = shash_find_data(json_object(old), "tunnels");

    if ((!new_tunnels) || (!old_tunnels))
    {
        OVSDB_PRINTF_DEBUG_TRACE("Physical switch table update has nothing to do with tunnels.");
        return;
    }

    for (i = 0; i < TABLE_PHYSICAL_SWITCH_NUM; i++)
    {
        if (uuid_equals(&uuid_ps, &ovsdb_vtep_db_table.table_physical_switch[i].uuid_self))
        {
            if (JSON_STRING == new_tunnels->type)
            {
                // TODO: table_ucast_macs_local[i].uuid_self 可能有问题:
                (void)uuid_from_string(&ovsdb_vtep_db_table.table_ucast_macs_local[i].uuid_self, json_string(new_tunnels));
            }
            break;
        }
    }
}

void ovsdb_mcast_local_update_locator_set_process(struct json *new, struct json *old, char* node_name)
{
    struct json *new_locator_set;
    struct json *old_locator_set;
    struct uuid uuid_mcast_local;
    int i = 0;

    if((!new)||(!old))
    {
        return;
    }

    uuid_from_string(&uuid_mcast_local, node_name);

    new_locator_set = shash_find_data(json_object(new), "locator_set");
    old_locator_set = shash_find_data(json_object(old), "locator_set");

    if((!new_locator_set)||(!old_locator_set))    /*说明更新和locator_set无关*/
    {
        OVSDB_PRINTF_DEBUG_TRACE("mcast_remote table update has nothing to do with locator_set.");
        return;
    }

    for(i=0; i<TABLE_MCAST_MACS_LOCAL_NUM; i++)
    {
        if(uuid_equals(&uuid_mcast_local, &ovsdb_vtep_db_table.table_mcast_macs_local[i].uuid_self))
        {
            OVSDB_PRINTF_DEBUG_TRACE("updated mcast_local uuid ="UUID_FMT, UUID_ARGS(&uuid_mcast_local));
            OVSDB_PRINTF_DEBUG_TRACE("old locator set uuid = "UUID_FMT, UUID_ARGS(&ovsdb_vtep_db_table.table_mcast_macs_local[i].locator_set));

            uuid_from_string(&ovsdb_vtep_db_table.table_mcast_macs_local[i].locator_set, json_string(json_array(new_locator_set)->elems[1]));
            OVSDB_PRINTF_DEBUG_TRACE("new locator set uuid = "UUID_FMT, UUID_ARGS(&ovsdb_vtep_db_table.table_mcast_macs_local[i].locator_set));

            break;
        }
    }


}


void ovsdb_physical_locator_process(struct jsonrpc * rpc, struct uuid *uuid_pl, char *pl_dst_ip)
{
    int id_ps = 0;
    int id_t = 0;

    if((!uuid_pl)||(!pl_dst_ip))
    {
        return;
    }

    /*如果physical switch[0]中的tunnel ip为空，则认为有问题，直接返回*/
    /*此处代码不健壮，只是针对测试场景的特殊处理，须考虑改进*/
    if(NULL == ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0])
    {
        OVSDB_PRINTF_DEBUG_TRACE("No tunnel ip in physical switch[0]!!!");
        return;
    }
    else
    {
        OVSDB_PRINTF_DEBUG_TRACE("tunnel ip in physical switch[0] is %s.",
            ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0]);
    }

    /*上面的ip是本端source ip，则不配置隧道*/
    for(id_ps=0; id_ps<TABLE_PHYSICAL_SWITCH_NUM; id_ps++) {
        for(id_t=0; id_t<PHYSICAL_SWITCH_TUNNEL_IP_NUM; id_t++)
        {
            if(NULL == ovsdb_vtep_db_table.table_physical_switch[id_ps].tunnel_ips[id_t])
            {
                continue;
            }
            else
            {
                if(0 == strcmp(pl_dst_ip, ovsdb_vtep_db_table.table_physical_switch[id_ps].tunnel_ips[id_t]))
                {
                    OVSDB_PRINTF_DEBUG_TRACE("source vtep ip, return.");
                    return;    /*说明locator表中的dst ip是本端source ip，直接返回*/
                }
            }
        }
    }

    /*两种方法配置隧道*/
    /*(1)首先到Physical_Locator_Set的locators列找uuid,如果有相同的,通过Physical_Locator_Set*/
    /*的uuid到Mcast_Macs_Remote中找locator_set的uuid，如果有相同的话，再到对应的logical_switch中找vni*/
    /*通过上述方法找到的应该是service node对应隧道的的vni*/
    /*上述方法中一个service node的ip可能对应多个ls.就有多条隧道*/
    /*(2)如果上述方法找不到,通过Physical_Locator的uuid到Ucast_Macs_Remote的locator列找，如果有相同的，*/
    /*查看对应的logical_switch的tunnel_key是否为0,是否大于4095，如果满足要求，则就是这个值*/
    /*通过这种方法找到的应该是hypervisor对应的隧道的vni*/

    ovsdb_physical_locator_process_hypervisor_ip(uuid_pl, pl_dst_ip);
    ovsdb_physical_locator_process_service_node_ip(rpc, uuid_pl, pl_dst_ip);
}

void ovsdb_physical_locator_process_hypervisor_ip_set_list(int tunnel_key, char *pl_dst_ip)
{
    int k=0;

    if(tunnel_key < 4096)
    {
        return;
    }
    OVSDB_PRINTF_DEBUG_TRACE("tunnel_key=%d.", tunnel_key);

    /*将隧道信息写入待创建隧道全局变量，在第二阶段进行创建*/
    for(k = 0; k < HYPERVISOR_MAX; k++)
    {
        if(hypervisor_vxlan_tunnel_to_be_created[k].used_bit)
        {
            continue;
        }
        else
        {
            /*vni*/
            hypervisor_vxlan_tunnel_to_be_created[k].vni = tunnel_key;

            /*dst_ip*/
            hypervisor_vxlan_tunnel_to_be_created[k].dst_ip = malloc(strlen(pl_dst_ip)+1);
            memcpy(hypervisor_vxlan_tunnel_to_be_created[k].dst_ip, pl_dst_ip,
                strlen(pl_dst_ip)+1);

            /*source_ip*/
            hypervisor_vxlan_tunnel_to_be_created[k].source_ip = malloc(strlen(ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0])+1);
            memcpy(hypervisor_vxlan_tunnel_to_be_created[k].source_ip, ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0],
                strlen(ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0])+1);

            /*used_bit*/
            hypervisor_vxlan_tunnel_to_be_created[k].used_bit = 1;

            /*创建标志位，用于第二阶段*/
            vxlan_tunnel_to_be_create_flag = 1;

            break;
        }
    }
    
    return;
}

void ovsdb_physical_locator_process_hypervisor_ip(struct uuid *uuid_pl, char *pl_dst_ip)
{
    int l=0;
    int m=0;
    struct uuid uuid_logical_switch;
    int tunnel_key=0;

    for(l=0; l<TABLE_UCAST_MACS_REMOTE_NUM; l++)
    {
        uuid_zero(&uuid_logical_switch);
        if(uuid_equals(uuid_pl, &ovsdb_vtep_db_table.table_ucast_macs_remote[l].locator))
        {
            memcpy(&uuid_logical_switch, &ovsdb_vtep_db_table.table_ucast_macs_remote[l].logical_switch, sizeof(struct uuid));

            /*below is temp to delete*/
            OVSDB_PRINTF_DEBUG_TRACE("uuid_logical_switch = "UUID_FMT, UUID_ARGS(&uuid_logical_switch));

            for(m=0; m<TABLE_LOGICAL_SWITCH_NUM; m++)
            {
                if(uuid_equals(&uuid_logical_switch, &ovsdb_vtep_db_table.table_logical_switch[m].uuid_self))
                {
                    if(ovsdb_vtep_db_table.table_logical_switch[m].tunnel_key < 4096)
                    {
                        OVSDB_PRINTF_DEBUG_TRACE("tunnel key does not meet requirement, which is %d.",
                            ovsdb_vtep_db_table.table_logical_switch[m].tunnel_key);
                    }
                    else
                    {
                        tunnel_key = ovsdb_vtep_db_table.table_logical_switch[m].tunnel_key;
                        OVSDB_PRINTF_DEBUG_TRACE("tunnel key when condig vxlan tunnel is %d.", tunnel_key);
                        ovsdb_physical_locator_process_hypervisor_ip_set_list(tunnel_key, pl_dst_ip);
                    }
                }
            }
        }
    }

    return;
}

void ovsdb_physical_locator_process_service_node_ip(struct jsonrpc * rpc, struct uuid *uuid_pl, char *pl_dst_ip)
{
    int k=0;
    int j=0;
    int l=0;
    int m=0;
    int i=0;
    struct uuid uuid_locator_set;
    struct uuid uuid_logical_switch;
    int tunnel_key=0;

    for(j=0; j<TABLE_PHYSICAL_LOCATOR_SET_NUM; j++)
    {
        if(uuid_is_zero(&ovsdb_vtep_db_table.table_physical_locator_set[j].uuid_self))
        {
            continue;
        }

        for(k=0; k<LOCATOR_NUM_IN_LOCATION_SET; k++)
        {
            if(!uuid_equals(uuid_pl, &ovsdb_vtep_db_table.table_physical_locator_set[j].locators[k]))
                continue;

            memcpy(&uuid_locator_set, &ovsdb_vtep_db_table.table_physical_locator_set[j].uuid_self, sizeof(struct uuid));

            /*below is temp to delete*/
            OVSDB_PRINTF_DEBUG_TRACE("uuid_locator_set = "UUID_FMT, UUID_ARGS(&uuid_locator_set));

            for(l=0; l<TABLE_MCAST_MACS_REMOTE_NUM; l++)
            {
                if(!uuid_equals(&uuid_locator_set, &ovsdb_vtep_db_table.table_mcast_macs_remote[l].locator_set))
                    continue;

                memcpy(&uuid_logical_switch, &ovsdb_vtep_db_table.table_mcast_macs_remote[l].logical_switch, sizeof(struct uuid));

                /*below is temp to delete*/
                OVSDB_PRINTF_DEBUG_TRACE("uuid_logical_switch= "UUID_FMT, UUID_ARGS(&uuid_logical_switch));

                for(m=0; m<TABLE_LOGICAL_SWITCH_NUM; m++)
                {
                    if(!uuid_equals(&uuid_logical_switch, &ovsdb_vtep_db_table.table_logical_switch[m].uuid_self))
                        continue;

                    if(ovsdb_vtep_db_table.table_logical_switch[m].tunnel_key < 4096)
                    {
                        OVSDB_PRINTF_DEBUG_WARN("tunnel key does not meet requirement,which is %d.",
                            ovsdb_vtep_db_table.table_logical_switch[m].tunnel_key);
                        return;
                    }

                    tunnel_key = ovsdb_vtep_db_table.table_logical_switch[m].tunnel_key;
                    OVSDB_PRINTF_DEBUG_TRACE("tunnel key when config vxlan tunnel is %d.", tunnel_key);

                    /*将隧道信息写入待创建隧道全局变量，在第二阶段进行创建*/
                    for(i=0; i<SERVICE_NODE_MAX; i++)
                    {
                        if(service_node_vxlan_tunnel_to_be_created[i].used_bit)
                        {
                            continue;
                        }

                        /*vni*/
                        service_node_vxlan_tunnel_to_be_created[i].vni = tunnel_key;

                        /*dst_ip*/
                        service_node_vxlan_tunnel_to_be_created[i].dst_ip = malloc(strlen(pl_dst_ip)+1);
                        memcpy(service_node_vxlan_tunnel_to_be_created[i].dst_ip, pl_dst_ip,
                            strlen(pl_dst_ip)+1);

                        /*source_ip*/
                        service_node_vxlan_tunnel_to_be_created[i].source_ip = malloc(strlen(ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0])+1);
                        memcpy(service_node_vxlan_tunnel_to_be_created[i].source_ip, ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0],
                            strlen(ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0])+1);

                        /*used_bit*/
                        service_node_vxlan_tunnel_to_be_created[i].used_bit = 1;

                        /*创建标志位，用于第二阶段*/
                        vxlan_tunnel_to_be_create_flag = 1;

                        break;
                    }

                    return;
                }
            }
        }
    }

}

void ovsdb_physical_locator_process_config_vxlan_tunnel
(
    int tunnel_key,
    char *pl_dst_ip,
    enum HW_VTEP_VXLAN_TUNNEL_TYPE type
)
{
    int ret = 0;
    struct hw_vtep_vxlan_tunnel * pstHW_vxlan_tunnel;

    if(tunnel_key < MIN_VNI_ID) {
        OVSDB_PRINTF_DEBUG_ERROR("tunnel_key %d invalid.", tunnel_key);
        return;
    }

    pstHW_vxlan_tunnel = hw_vtep_vxlan_tunnel_query(tunnel_key, pl_dst_ip);
    if (NULL == pstHW_vxlan_tunnel) {
        ret = netconf_msg_list_config_vxlan_tunnel(tunnel_key, pl_dst_ip);
        if (OVSDB_OK != ret) {
            OVSDB_PRINTF_DEBUG_ERROR("Failed to config vxlan tunnel, vni %d, dstip %s, type = %d.",
                tunnel_key, pl_dst_ip, type);
            //return;
        }
    }

    ret = hw_vtep_vxlan_tunnel_add(tunnel_key, pl_dst_ip, type);
    if (ret != OVSDB_OK) {
        OVSDB_PRINTF_DEBUG_ERROR("Failed to add vxlan tunnel table. ret %#x, vni %d, dstip %s, type = %d.",
                ret, tunnel_key, pl_dst_ip, type);
        return;
    }

    return;
}

void ovsdb_physical_locator_process_undo_config_vxlan_tunnel
(
    int tunnel_key,
    char *pl_dst_ip,
    enum HW_VTEP_VXLAN_TUNNEL_TYPE type
)
{
    int ret = 0;
    struct hw_vtep_vxlan_tunnel * pstHW_vxlan_tunnel;

    if(tunnel_key < MIN_VNI_ID) {
        OVSDB_PRINTF_DEBUG_ERROR("tunnel_key %d invalid.", tunnel_key);
        return;
    }

    pstHW_vxlan_tunnel = hw_vtep_vxlan_tunnel_query(tunnel_key, pl_dst_ip);
    if (NULL == pstHW_vxlan_tunnel) {
        return;
    }

    ret = hw_vtep_vxlan_tunnel_delete(tunnel_key, pl_dst_ip, type);
    if (ret != OVSDB_OK) {
        OVSDB_PRINTF_DEBUG_ERROR("Failed to delete vxlan tunnel table. ret %#x, vni %d, dstip %s, type = %d.",
                ret, tunnel_key, pl_dst_ip, type);
        return;
    }

    if (0 == pstHW_vxlan_tunnel->used_bit) {
        ret = netconf_msg_list_undo_config_vxlan_tunnel(tunnel_key, pl_dst_ip);
        if (OVSDB_OK != ret) {
            OVSDB_PRINTF_DEBUG_ERROR("Failed to undo config vxlan tunnel, vni %d, dstip %s, type = %d.",
                tunnel_key, pl_dst_ip, type);
            //return;
        }
    }

    return;
}

void ovsdb_ucast_macs_remote_process_add(struct uuid * uuidUMR)
{
    int ret;
    char mac_ce[MAX_CE_MAC_LEN] = {0};
    struct ovsdb_vtep_table_ucast_macs_remote * pstUMR;
    struct ovsdb_vtep_table_logical_switch * pstLS;
    struct ovsdb_vtep_table_physical_locator * pstPL;

    pstUMR = ovsdb_table_ucast_macs_remote_query(uuidUMR);
    if (NULL == pstUMR) {
        OVSDB_PRINTF_DEBUG_ERROR("Can not find mcast_macs_remote, uuid: "UUID_FMT,
            UUID_ARGS(uuidUMR));
        return;
    }

    pstLS = ovsdb_table_logical_switch_query(&pstUMR->logical_switch);
    if (NULL == pstLS) {
        OVSDB_PRINTF_DEBUG_ERROR("Can not find logical_switch, uuid: "UUID_FMT,
            UUID_ARGS(&pstUMR->logical_switch));
        return;
    }

    pstPL = ovsdb_table_physical_locator_query(&pstUMR->locator);
    if (NULL == pstPL) {
        OVSDB_PRINTF_DEBUG_ERROR("Can not find physical_locator, uuid: "UUID_FMT,
            UUID_ARGS(&pstUMR->locator));
        return;
    }

    /* 下发指向hypervisor的隧道 */
    ovsdb_physical_locator_process_config_vxlan_tunnel(pstLS->tunnel_key,
        pstPL->dst_ip, HW_VTEP_VXLAN_TUNNEL_HYPERVISOR);

    mac_translate_ovsdb_to_ce(pstUMR->MAC, mac_ce);

    /* 下发远端静态MAC表 */
    ret = netconf_msg_list_config_vxlan_tunnel_static_mac(mac_ce,
        ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0],
        pstPL->dst_ip, pstLS->tunnel_key);

    if (ret != OVSDB_OK) {
        OVSDB_PRINTF_DEBUG_ERROR("Configure static mac failed, uuid: "UUID_FMT,
            UUID_ARGS(uuidUMR));
        return;
    }

    ret = hw_vtep_vxlan_static_mac_add(pstLS->tunnel_key,
          ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0],
          pstPL->dst_ip, pstUMR->MAC);
    if (ret != OVSDB_OK) {
        OVSDB_PRINTF_DEBUG_ERROR("Save static mac table failed, uuid: "UUID_FMT,
            UUID_ARGS(uuidUMR));
        return;
    }
    
    return;
}

void ovsdb_ucast_macs_remote_process_delete(struct uuid * uuidUMR)
{
    int ret;
    char mac_ce[MAX_CE_MAC_LEN] = {0};
    struct ovsdb_vtep_table_ucast_macs_remote * pstUMR;
    struct ovsdb_vtep_table_logical_switch * pstLS;
    struct ovsdb_vtep_table_physical_locator * pstPL;

    pstUMR = ovsdb_table_ucast_macs_remote_query(uuidUMR);
    if (NULL == pstUMR) {
        OVSDB_PRINTF_DEBUG_ERROR("Can not find mcast_macs_remote, uuid: "UUID_FMT,
            UUID_ARGS(uuidUMR));
        return;
    }

    pstLS = ovsdb_table_logical_switch_query(&pstUMR->logical_switch);
    if (NULL == pstLS) {
        OVSDB_PRINTF_DEBUG_ERROR("Can not find logical_switch, uuid: "UUID_FMT,
            UUID_ARGS(&pstUMR->logical_switch));
        return;
    }

    pstPL = ovsdb_table_physical_locator_query(&pstUMR->locator);
    if (NULL == pstPL) {
        OVSDB_PRINTF_DEBUG_ERROR("Can not find physical_locator, uuid: "UUID_FMT,
            UUID_ARGS(&pstUMR->locator));
        return;
    }

    mac_translate_ovsdb_to_ce(pstUMR->MAC, mac_ce);

    /* 删除远端静态MAC表 */
    ret = netconf_msg_list_undo_config_vxlan_tunnel_static_mac(mac_ce,
        ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0],
        pstPL->dst_ip, pstLS->tunnel_key);
    if (ret != OVSDB_OK) {
        OVSDB_PRINTF_DEBUG_ERROR("Configure undo static mac failed, uuid: "UUID_FMT,
            UUID_ARGS(uuidUMR));
        return;
    }

    ret = hw_vtep_vxlan_static_mac_delete(pstLS->tunnel_key,
          ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0],
          pstPL->dst_ip, pstUMR->MAC);
    if (ret != OVSDB_OK) {
        OVSDB_PRINTF_DEBUG_ERROR("Delete static mac table failed, uuid: "UUID_FMT,
            UUID_ARGS(uuidUMR));
        return;
    }

    /* 删除指向hypervisor的隧道 */
    if (NULL == hw_vtep_vxlan_static_mac_query_byTunnel(pstLS->tunnel_key,
                      ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0],
                      pstPL->dst_ip))
    {
        ovsdb_physical_locator_process_undo_config_vxlan_tunnel(pstLS->tunnel_key,
                      pstPL->dst_ip, HW_VTEP_VXLAN_TUNNEL_HYPERVISOR);
    }
    
    return;
}

int ovsdb_mcast_macs_remote_is_onlyone(void * input, void * output, void * entry)
{
    struct ovsdb_vtep_table_mcast_macs_remote * pstMMR =
        (struct ovsdb_vtep_table_physical_locator_set *)input;
    bool * flag = (bool *)output;
    struct ovsdb_vtep_table_mcast_macs_remote * pstMMR_entry =
        (struct ovsdb_vtep_table_mcast_macs_remote *)entry;

    if (uuid_equals(pstMMR, pstMMR_entry))
        return OVSDB_OK;

    *flag = false;

    return OVSDB_ERR_EXISTED;
}

void ovsdb_mcast_macs_remote_process_add(struct jsonrpc *rpc, struct uuid * uuidMMR)
{
    int i;
    struct ovsdb_vtep_table_mcast_macs_remote * pstMMR;
    struct ovsdb_vtep_table_logical_switch * pstLS;
    struct ovsdb_vtep_table_physical_locator_set * pstPLS;
    struct ovsdb_vtep_table_physical_locator * pstPL;
    bool flag = true; //需要添加tunnel标记位;
    struct ovsdb_vtep_table_physical_locator * pstLocalPL = NULL;

    pstMMR = ovsdb_table_mcast_macs_remote_query(uuidMMR);
    if (NULL == pstMMR) {
        OVSDB_PRINTF_DEBUG_ERROR("Can not find mcast_macs_remote, uuid: "UUID_FMT,
            UUID_ARGS(uuidMMR));
        return;
    }

    pstLS = ovsdb_table_logical_switch_query(&pstMMR->logical_switch);
    if (NULL == pstLS) {
        OVSDB_PRINTF_DEBUG_ERROR("Can not find logical_switch, uuid: "UUID_FMT,
            UUID_ARGS(&pstMMR->logical_switch));
        return;
    }

    if (pstLS->tunnel_key < MIN_VNI_ID) {
        OVSDB_PRINTF_DEBUG_ERROR("tunnel_key is illegal, %d.", pstLS->tunnel_key);
        return;
    }

    pstPLS = ovsdb_table_physical_locator_set_query(&pstMMR->locator_set);
    if (NULL == pstPLS) {
        OVSDB_PRINTF_DEBUG_ERROR("Can not find physical_locator_set, uuid: "UUID_FMT,
            UUID_ARGS(&pstMMR->locator_set));
        return;
    }

    //只有在第一次添加mcast_macs_remote时需要添加对应的Tunnel table
    ovsdb_table_mcast_macs_remote_scan(uuidMMR, &flag, ovsdb_mcast_macs_remote_is_onlyone);
    if (true == flag) {
        //查询local的physical_locator
        pstLocalPL = ovsdb_table_physical_locator_query_byip
            (OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_TUNNERIP));
    }

    for (i = 0; i < pstPLS->used_num_locators; i++)
    {
        pstPL = ovsdb_table_physical_locator_query(&pstPLS->locators[i]);
        if (NULL == pstPL) {
            OVSDB_PRINTF_DEBUG_ERROR("Can not find physical_locator, uuid: "UUID_FMT,
                UUID_ARGS(&pstPLS->locators[i]));
            continue;
        }

        /* 下发指向service node的隧道 */
        ovsdb_physical_locator_process_config_vxlan_tunnel(pstLS->tunnel_key,
            pstPL->dst_ip, HW_VTEP_VXLAN_TUNNEL_SERVICENODE);

        /* 添加Tunnle table */
        if (NULL != pstLocalPL)
            ovsdb_tunnel_add_ovsdb(rpc, &pstPL->uuid_self, &pstLocalPL->uuid_self);
    }

    return;
}

void ovsdb_mcast_macs_remote_process_delete(struct jsonrpc *rpc, struct uuid * uuidMMR)
{
    int i;
    struct ovsdb_vtep_table_mcast_macs_remote * pstMMR;
    struct ovsdb_vtep_table_logical_switch * pstLS;
    struct ovsdb_vtep_table_physical_locator_set * pstPLS;
    struct ovsdb_vtep_table_physical_locator * pstPL;
    bool flag = true;

    pstMMR = ovsdb_table_mcast_macs_remote_query(uuidMMR);
    if (NULL == pstMMR) {
        OVSDB_PRINTF_DEBUG_ERROR("Can not find mcast_macs_remote, uuid: "UUID_FMT,
            UUID_ARGS(uuidMMR));
        return;
    }

    pstLS = ovsdb_table_logical_switch_query(&pstMMR->logical_switch);
    if (NULL == pstLS) {
        OVSDB_PRINTF_DEBUG_ERROR("Can not find logical_switch, uuid: "UUID_FMT,
            UUID_ARGS(&pstMMR->logical_switch));
        return;
    }

    if (pstLS->tunnel_key < MIN_VNI_ID) {
        OVSDB_PRINTF_DEBUG_ERROR("tunnel_key is illegal, %d.", pstLS->tunnel_key);
        return;
    }

    pstPLS = ovsdb_table_physical_locator_set_query(&pstMMR->locator_set);
    if (NULL == pstPLS) {
        OVSDB_PRINTF_DEBUG_ERROR("Can not find physical_locator_set, uuid: "UUID_FMT,
            UUID_ARGS(&pstMMR->locator_set));
        return;
    }

    for (i = 0; i < pstPLS->used_num_locators; i++)
    {
        pstPL = ovsdb_table_physical_locator_query(&pstPLS->locators[i]);
        if (NULL == pstPL) {
            OVSDB_PRINTF_DEBUG_ERROR("Can not find physical_locator, uuid: "UUID_FMT,
                UUID_ARGS(&pstPLS->locators[i]));
            continue;
        }

        /* 删除指向service node的隧道 */
        ovsdb_physical_locator_process_undo_config_vxlan_tunnel(pstLS->tunnel_key,
            pstPL->dst_ip, HW_VTEP_VXLAN_TUNNEL_SERVICENODE);
    }

    //在删除最后一条MMR表项时需要删除所有的Tunnel Table
    ovsdb_table_mcast_macs_remote_scan(uuidMMR, &flag, ovsdb_mcast_macs_remote_is_onlyone);
    if (false == flag)
        return;

    //删除所有的Tunnel Table
    do_transact_temp_delete_all_tunnel(rpc);

    return;
}

int ovsdb_physical_locator_set_process_add_proc(void * input, void * output OVS_UNUSED, void * entry)
{
    struct uuid * uuid_PLS = (struct uuid *)input;
    struct ovsdb_vtep_table_mcast_macs_remote * pstMMR =
        (struct ovsdb_vtep_table_mcast_macs_remote *)entry;

    if (!uuid_equals(uuid_PLS, &pstMMR->locator_set))
        return OVSDB_OK;

    //ovsdb_mcast_macs_remote_process_add(&pstMMR->uuid_self);
    //理论上应该不存在先有Mcast_Macs_Remote, 再有replicator的场景，physical_locator_set添加反搜Mcast_Macs_Remote下指向servicenode隧道的场景尝试删除
    OVSDB_PRINTF_DEBUG_ERROR("Check if needs download Mcast macs remote, uuid: "UUID_FMT,
        UUID_ARGS(&pstMMR->uuid_self));

    return OVSDB_OK;
}

void ovsdb_physical_locator_set_process_add(struct uuid * uuidPLS)
{
    /* search mcast_macs_remote, and download service node tunnel */
    ovsdb_table_mcast_macs_remote_scan((void *)uuidPLS, NULL, ovsdb_physical_locator_set_process_add_proc);

    return;
}

int ovsdb_physical_locator_set_process_delete_proc(void * input, void * output OVS_UNUSED, void * entry)
{
    struct uuid * uuid_PLS = (struct uuid *)input;
    struct ovsdb_vtep_table_mcast_macs_remote * pstMMR =
        (struct ovsdb_vtep_table_mcast_macs_remote *)entry;
    struct jsonrpc *rpc = (struct jsonrpc *)output;

    if (!uuid_equals(uuid_PLS, &pstMMR->locator_set))
        return OVSDB_OK;

    ovsdb_mcast_macs_remote_process_delete(rpc, &pstMMR->uuid_self);

    return OVSDB_OK;
}

void ovsdb_physical_locator_set_process_delete(struct jsonrpc *rpc, struct uuid * uuidPLS)
{
    /* search mcast_macs_remote, and download service node tunnel */
    ovsdb_table_mcast_macs_remote_scan((void *)uuidPLS, rpc, ovsdb_physical_locator_set_process_delete_proc);

    return;
}

int ovsdb_physical_locator_process_add_proc(void * input, void * output, void * entry)
{
    int i;
    struct jsonrpc * rpc = (struct jsonrpc *)input;
    struct ovsdb_vtep_table_mcast_macs_remote * pstMMR = 
        (struct ovsdb_vtep_table_mcast_macs_remote *)entry;
    struct ovsdb_vtep_table_physical_locator_set * pstPLS;
    struct ovsdb_vtep_table_physical_locator * pstPL;
    struct ovsdb_vtep_table_physical_locator * pstLocalPL = 
        (struct ovsdb_vtep_table_physical_locator *)output;

    pstPLS = ovsdb_table_physical_locator_set_query(&pstMMR->locator_set);
    if (NULL == pstPLS) {
        OVSDB_PRINTF_DEBUG_ERROR("Can not find physical_locator_set, uuid: "UUID_FMT,
            UUID_ARGS(&pstMMR->locator_set));
        return;
    }

    for (i = 0; i < pstPLS->used_num_locators; i++)
    {
        pstPL = ovsdb_table_physical_locator_query(&pstPLS->locators[i]);
        if (NULL == pstPL) {
            OVSDB_PRINTF_DEBUG_ERROR("Can not find physical_locator, uuid: "UUID_FMT,
                UUID_ARGS(&pstPLS->locators[i]));
            continue;
        }

        ovsdb_tunnel_add_ovsdb(rpc, &pstPL->uuid_self, &pstLocalPL->uuid_self);
    }

    return OVSDB_ERR;
}

void ovsdb_physical_locator_process_add(struct jsonrpc * rpc, struct uuid *uuid_pl)
{
    struct ovsdb_vtep_table_physical_locator * pstPL = NULL;

    pstPL = ovsdb_table_physical_locator_query(uuid_pl);
    if (NULL == pstPL)
        return;

    if (0 == strcmp(pstPL->dst_ip, OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_TUNNERIP))) {
        ovsdb_table_mcast_macs_remote_scan((void *)rpc, (void *)pstPL, ovsdb_physical_locator_process_add_proc);
    }
    //else {
    //    /* 添加Tunnel表，内部流程暂时不处理 */
    //    ovsdb_tunnel_add_process(rpc, uuid_pl);
    //}

    return;
}

enum args_needed {
    NEED_NONE,            /* No JSON-RPC connection or database name needed. */
    NEED_RPC,             /* JSON-RPC connection needed. */
    NEED_DATABASE         /* JSON-RPC connection and database name needed. */
};

struct ovsdb_client_command {
    const char *name;
    enum args_needed need;
    int min_args;
    int max_args;
    void (*handler)(struct jsonrpc *rpc, const char *database,
                    int argc, char *argv[]);
};

/* --timestamp: Print a timestamp before each update on "monitor" command? */
static bool timestamp;

/* Format for table output. */
static struct table_style table_style = TABLE_STYLE_DEFAULT;

static const struct ovsdb_client_command *get_all_commands(void);

OVS_NO_RETURN static void usage(void);
static void parse_options(int argc, char *argv[]);
static struct jsonrpc *open_jsonrpc(const char *server);
static void fetch_dbs(struct jsonrpc *, struct svec *dbs);

struct jsonrpc * g_rpc_transact1 = NULL;
struct jsonrpc * g_rpc_transact2 = NULL;

int
main(int argc, char *argv[])
{
    const struct ovsdb_client_command *command;
    const char *database;
    struct jsonrpc *rpc;

    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    parse_options(argc, argv);
    fatal_ignore_sigpipe();

    daemon_become_new_user(false);
    if (optind >= argc) {
        ovs_fatal(0, "missing command name; use --help for help");
    }

    for (command = get_all_commands(); ; command++) {
        if (!command->name) {
            VLOG_FATAL("unknown command '%s'; use --help for help",
                       argv[optind]);
        } else if (!strcmp(command->name, argv[optind])) {
            break;
        }
    }
    optind++;

    if (command->need != NEED_NONE) {
        if (argc - optind > command->min_args
            && (isalpha((unsigned char) argv[optind][0])
                && strchr(argv[optind], ':'))) {
            rpc = open_jsonrpc(argv[optind]);
            g_rpc_transact1 = open_jsonrpc(argv[optind]);
            g_rpc_transact2 = open_jsonrpc(argv[optind]);
            optind++;
        } else {
            char *sock = xasprintf("unix:%s/db.sock", ovs_rundir());
            rpc = open_jsonrpc(sock);
            g_rpc_transact1 = open_jsonrpc(sock);
            g_rpc_transact2 = open_jsonrpc(sock);
            free(sock);
        }
    } else {
        rpc = NULL;
    }

    if (command->need == NEED_DATABASE) {
        struct svec dbs;

        svec_init(&dbs);
        fetch_dbs(rpc, &dbs);
        if (argc - optind > command->min_args
            && svec_contains(&dbs, argv[optind])) {
            database = argv[optind++];
        } else if (dbs.n == 1) {
            database = xstrdup(dbs.names[0]);
        } else if (svec_contains(&dbs, "Open_vSwitch")) {
            database = "Open_vSwitch";
        } else {
            ovs_fatal(0, "no default database for `%s' command, please "
                      "specify a database name", command->name);
        }
        svec_destroy(&dbs);
    } else {
        database = NULL;
    }

    if (argc - optind < command->min_args ||
        argc - optind > command->max_args) {
        VLOG_FATAL("invalid syntax for '%s' (use --help for help)",
                    command->name);
    }

    command->handler(rpc, database, argc - optind, argv + optind);

    jsonrpc_close(rpc);
    jsonrpc_close(g_rpc_transact1);
    jsonrpc_close(g_rpc_transact2);

    if (ferror(stdout)) {
        VLOG_FATAL("write to stdout failed");
    }
    if (ferror(stderr)) {
        VLOG_FATAL("write to stderr failed");
    }

    return 0;
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_BOOTSTRAP_CA_CERT = UCHAR_MAX + 1,
        OPT_TIMESTAMP,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS,
        TABLE_OPTION_ENUMS
    };
    static const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {"timestamp", no_argument, NULL, OPT_TIMESTAMP},
        VLOG_LONG_OPTIONS,
        DAEMON_LONG_OPTIONS,
#ifdef HAVE_OPENSSL
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        STREAM_SSL_LONG_OPTIONS,
#endif
        TABLE_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS
        TABLE_OPTION_HANDLERS(&table_style)
        STREAM_SSL_OPTION_HANDLERS

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(optarg, true);
            break;

        case OPT_TIMESTAMP:
            timestamp = true;
            break;

        case '?':
            exit(EXIT_FAILURE);

        case 0:
            /* getopt_long() already set the value for us. */
            break;

        default:
            abort();
        }
    }
    free(short_options);
}

static void
usage(void)
{
    printf("%s: Open vSwitch database JSON-RPC client\n"
           "usage: %s [OPTIONS] COMMAND [ARG...]\n"
           "\nValid commands are:\n"
           "\n  list-dbs [SERVER]\n"
           "    list databases available on SERVER\n"
           "\n  get-schema [SERVER] [DATABASE]\n"
           "    retrieve schema for DATABASE from SERVER\n"
           "\n  get-schema-version [SERVER] [DATABASE]\n"
           "    retrieve schema for DATABASE from SERVER and report only its\n"
           "    version number on stdout\n"
           "\n  list-tables [SERVER] [DATABASE]\n"
           "    list tables for DATABASE on SERVER\n"
           "\n  list-columns [SERVER] [DATABASE] [TABLE]\n"
           "    list columns in TABLE (or all tables) in DATABASE on SERVER\n"
           "\n  transact [SERVER] TRANSACTION\n"
           "    run TRANSACTION (a JSON array of operations) on SERVER\n"
           "    and print the results as JSON on stdout\n"
           "\n  monitor [SERVER] [DATABASE] TABLE [COLUMN,...]...\n"
           "    monitor contents of COLUMNs in TABLE in DATABASE on SERVER.\n"
           "    COLUMNs may include !initial, !insert, !delete, !modify\n"
           "    to avoid seeing the specified kinds of changes.\n"
           "\n  monitor [SERVER] [DATABASE] ALL\n"
           "    monitor all changes to all columns in all tables\n"
           "    in DATBASE on SERVER.\n"
           "\n  dump [SERVER] [DATABASE] [TABLE [COLUMN]...]\n"
           "    dump contents of DATABASE on SERVER to stdout\n"
           "\nThe default SERVER is unix:%s/db.sock.\n"
           "The default DATABASE is Open_vSwitch.\n",
           program_name, program_name, ovs_rundir());
    stream_usage("SERVER", true, true, true);
    printf("\nOutput formatting options:\n"
           "  -f, --format=FORMAT         set output formatting to FORMAT\n"
           "                              (\"table\", \"html\", \"csv\", "
           "or \"json\")\n"
           "  --no-headings               omit table heading row\n"
           "  --pretty                    pretty-print JSON in output\n"
           "  --timestamp                 timestamp \"monitor\" output");
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help                  display this help message\n"
           "  -V, --version               display version information\n");
    exit(EXIT_SUCCESS);
}

static void
check_txn(int error, struct jsonrpc_msg **reply_)
{
    struct jsonrpc_msg *reply = *reply_;

    if (error) {
        ovs_fatal(error, "transaction failed");
    }

    if (reply->error) {
        ovs_fatal(error, "transaction returned error: %s",
                  json_to_string(reply->error, table_style.json_flags));
    }
}

static struct json *
parse_json(const char *s)
{
    struct json *json = json_from_string(s);
    if (json->type == JSON_STRING) {
        ovs_fatal(0, "\"%s\": %s", s, json->u.string);
    }
    return json;
}

static struct jsonrpc *
open_jsonrpc(const char *server)
{
    struct stream *stream;
    int error;

    error = stream_open_block(jsonrpc_stream_open(server, &stream,
                              DSCP_DEFAULT), &stream);
    if (error == EAFNOSUPPORT) {
        struct pstream *pstream;

        error = jsonrpc_pstream_open(server, &pstream, DSCP_DEFAULT);
        if (error) {
            ovs_fatal(error, "failed to connect or listen to \"%s\"", server);
        }

        VLOG_INFO("%s: waiting for connection...", server);
        error = pstream_accept_block(pstream, &stream);
        if (error) {
            ovs_fatal(error, "failed to accept connection on \"%s\"", server);
        }

        pstream_close(pstream);
    } else if (error) {
        ovs_fatal(error, "failed to connect to \"%s\"", server);
    }

    return jsonrpc_open(stream);
}

static void
print_json(struct json *json)
{
    char *string = json_to_string(json, table_style.json_flags);
    fputs(string, stdout);
    free(string);
}

static void
print_and_free_json(struct json *json)
{
    print_json(json);
    json_destroy(json);
}

static void
check_ovsdb_error(struct ovsdb_error *error)
{
    if (error) {
        ovs_fatal(0, "%s", ovsdb_error_to_string(error));
    }
}

static struct ovsdb_schema *
fetch_schema(struct jsonrpc *rpc, const char *database)
{
    struct jsonrpc_msg *request, *reply;
    struct ovsdb_schema *schema;

    request = jsonrpc_create_request("get_schema",
                                     json_array_create_1(
                                         json_string_create(database)),
                                     NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);
    check_ovsdb_error(ovsdb_schema_from_json(reply->result, &schema));
    jsonrpc_msg_destroy(reply);

    return schema;
}

static void
fetch_dbs(struct jsonrpc *rpc, struct svec *dbs)
{
    struct jsonrpc_msg *request, *reply;
    size_t i;

    request = jsonrpc_create_request("list_dbs", json_array_create_empty(),
                                     NULL);

    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);
    if (reply->result->type != JSON_ARRAY) {
        ovs_fatal(0, "list_dbs response is not array");
    }

    for (i = 0; i < reply->result->u.array.n; i++) {
        const struct json *name = reply->result->u.array.elems[i];

        if (name->type != JSON_STRING) {
            ovs_fatal(0, "list_dbs response %"PRIuSIZE" is not string", i);
        }
        svec_add(dbs, name->u.string);
    }
    jsonrpc_msg_destroy(reply);
    svec_sort(dbs);
}

static void
do_list_dbs(struct jsonrpc *rpc, const char *database OVS_UNUSED,
            int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    const char *db_name;
    struct svec dbs;
    size_t i;

    svec_init(&dbs);
    fetch_dbs(rpc, &dbs);
    SVEC_FOR_EACH (i, db_name, &dbs) {
        puts(db_name);
    }
    svec_destroy(&dbs);
}

static void
do_get_schema(struct jsonrpc *rpc, const char *database,
              int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ovsdb_schema *schema = fetch_schema(rpc, database);
    print_and_free_json(ovsdb_schema_to_json(schema));
    ovsdb_schema_destroy(schema);
}

static void
do_get_schema_version(struct jsonrpc *rpc, const char *database,
                      int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ovsdb_schema *schema = fetch_schema(rpc, database);
    puts(schema->version);
    ovsdb_schema_destroy(schema);
}

static void
do_list_tables(struct jsonrpc *rpc, const char *database,
               int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ovsdb_schema *schema;
    struct shash_node *node;
    struct table t;

    schema = fetch_schema(rpc, database);
    table_init(&t);
    table_add_column(&t, "Table");
    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *ts = node->data;

        table_add_row(&t);
        table_add_cell(&t)->text = xstrdup(ts->name);
    }
    ovsdb_schema_destroy(schema);
    table_print(&t, &table_style);
}

static void
do_list_columns(struct jsonrpc *rpc, const char *database,
                int argc OVS_UNUSED, char *argv[])
{
    const char *table_name = argv[0];
    struct ovsdb_schema *schema;
    struct shash_node *table_node;
    struct table t;

    schema = fetch_schema(rpc, database);
    table_init(&t);
    if (!table_name) {
        table_add_column(&t, "Table");
    }
    table_add_column(&t, "Column");
    table_add_column(&t, "Type");
    SHASH_FOR_EACH (table_node, &schema->tables) {
        struct ovsdb_table_schema *ts = table_node->data;

        if (!table_name || !strcmp(table_name, ts->name)) {
            struct shash_node *column_node;

            SHASH_FOR_EACH (column_node, &ts->columns) {
                const struct ovsdb_column *column = column_node->data;

                table_add_row(&t);
                if (!table_name) {
                    table_add_cell(&t)->text = xstrdup(ts->name);
                }
                table_add_cell(&t)->text = xstrdup(column->name);
                table_add_cell(&t)->json = ovsdb_type_to_json(&column->type);
            }
        }
    }
    ovsdb_schema_destroy(schema);
    table_print(&t, &table_style);
}

static void
do_transact(struct jsonrpc *rpc, const char *database OVS_UNUSED,
            int argc OVS_UNUSED, char *argv[])
{
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;

    transaction = parse_json(argv[0]);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);
    print_json(reply->result);
    putchar('\n');
    jsonrpc_msg_destroy(reply);
}

/* "monitor" command. */

struct monitored_table {
    struct ovsdb_table_schema *table;
    struct ovsdb_column_set columns;
};

static void
monitor_print_row(struct json *row, const char *type, const char *uuid,
                  const struct ovsdb_column_set *columns, struct table *t)
{
    size_t i;

    if (!row) {
        ovs_error(0, "missing %s row", type);
        return;
    } else if (row->type != JSON_OBJECT) {
        ovs_error(0, "<row> is not object");
        return;
    }

    table_add_row(t);
    table_add_cell(t)->text = xstrdup(uuid);
    table_add_cell(t)->text = xstrdup(type);
    for (i = 0; i < columns->n_columns; i++) {
        const struct ovsdb_column *column = columns->columns[i];
        struct json *value = shash_find_data(json_object(row), column->name);
        struct cell *cell = table_add_cell(t);
        if (value) {
            cell->json = json_clone(value);
            cell->type = &column->type;
        }
    }
}

void global_table_process(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------global_table_node, action=%s----------------", ACTION_TYPE(action));

    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        {
            if(uuid_is_zero(&ovsdb_vtep_db_table.table_global.uuid_self))
            {
                (void)uuid_from_string(&ovsdb_vtep_db_table.table_global.uuid_self, node_name);

                OVSDB_PRINTF_DEBUG_TRACE("global_table uuid = "UUID_FMT, UUID_ARGS(&ovsdb_vtep_db_table.table_global.uuid_self));

            }

            break;
        }

        case TABLE_DELETE:
        {
            break;
        }

        case TABLE_UPDATE:
        {
            break;
        }

        default:
            break;

    }


}

void global_table_process_2(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------global_table_node_stage_2, action=%s----------------",ACTION_TYPE(action));

    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        {

            break;
        }

        case TABLE_DELETE:
        {

            break;
        }

        case TABLE_UPDATE:
        {

            break;
        }

        default:
            break;

    }

}

void physical_switch_table_process(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------physical_switch_table_node, action=%s----------------",ACTION_TYPE(action));

    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        {
            int i = 0;
            struct json *name;
            struct json *des;
            struct json *tunnel_ips;
            struct json *management_ips;
            //struct json_array *ports;
            //struct json_array *ports_set;
            //int id = 0;
            //struct json_array *ports_uuid;
            unsigned int uiRet = 0;

            name = shash_find_data(json_object(new), "name");
            des = shash_find_data(json_object(new), "description");

            tunnel_ips = shash_find_data(json_object(new), "tunnel_ips");
            management_ips = shash_find_data(json_object(new), "management_ips");

            /*这里port的处理不正确，当port个数为一个时，init会有问题*/
            #if 0
            ports = json_array(shash_find_data(json_object(new), "ports"));
            ports_set = json_array(ports->elems[1]);    /*elems[0] is "set" string */
            #endif

            for(i=0; i<TABLE_PHYSICAL_SWITCH_NUM; i++)
            {
                /*获取表中的第一个不为0的表项*/
                if(!uuid_is_zero(&ovsdb_vtep_db_table.table_physical_switch[i].uuid_self))
                {
                    continue;
                }
                else
                {
                    /*uuid*/
                    (void)uuid_from_string(&ovsdb_vtep_db_table.table_physical_switch[i].uuid_self, node_name);

                    /*name*/
                    ovsdb_vtep_db_table.table_physical_switch[i].name= malloc(strlen(json_string(name))+1) ;
                    memcpy(ovsdb_vtep_db_table.table_physical_switch[i].name, json_string(name), strlen(json_string(name))+1);

                    /*description*/
                    ovsdb_vtep_db_table.table_physical_switch[i].description= malloc(strlen(json_string(des))+1) ;
                    memcpy(ovsdb_vtep_db_table.table_physical_switch[i].description, json_string(des), strlen(json_string(des))+1);
                    #if 1
                    OVSDB_PRINTF_DEBUG_TRACE("physical_switch_table i=%d, name=%s, description=%s.", i,
                         ovsdb_vtep_db_table.table_physical_switch[i].name, ovsdb_vtep_db_table.table_physical_switch[i].description);
                    OVSDB_PRINTF_DEBUG_TRACE("physical_switch_table uuid = "UUID_FMT, UUID_ARGS(&ovsdb_vtep_db_table.table_physical_switch[i].uuid_self));
                    #endif

                    /*management_ips*/
                    if(JSON_STRING == management_ips->type) /*只有1个management ip*/
                    {
                        ovsdb_vtep_db_table.table_physical_switch[i].management_ips[0]= malloc(strlen(json_string(management_ips))+1) ;
                        memcpy(ovsdb_vtep_db_table.table_physical_switch[i].management_ips[0], json_string(management_ips), strlen(json_string(management_ips))+1);
                        OVSDB_PRINTF_DEBUG_TRACE("\nonly one management_ips = %s", ovsdb_vtep_db_table.table_physical_switch[i].management_ips[0]);
                    }
                    else if(JSON_ARRAY == management_ips->type) /*有多个management ip*/
                    {
                        struct json_array *management_ips_set;
                        struct json_array *management_ips_set_value;
                        struct json *ip_value;
                        int j =0;

                        management_ips_set = json_array(management_ips);
                        management_ips_set_value = json_array(management_ips_set->elems[1]);    /*elems[0] is "set" string*/
                        if(!management_ips_set_value->n) OVSDB_PRINTF_DEBUG_TRACE("physical switch has no management ips.");
                        else OVSDB_PRINTF_DEBUG_TRACE("physical switch has more than one management ips.");
                        for(; j < management_ips_set_value->n; j++)
                        {
                            if(j >= PHYSICAL_SWITCH_MANAGE_IP_NUM)
                            {
                                break;
                            }
                            ip_value = management_ips_set_value->elems[j];
                            ovsdb_vtep_db_table.table_physical_switch[i].management_ips[j]= malloc(strlen(json_string(ip_value))+1) ;
                            memcpy(ovsdb_vtep_db_table.table_physical_switch[i].management_ips[j], json_string(ip_value), strlen(json_string(ip_value))+1);
                            OVSDB_PRINTF_DEBUG_TRACE("management_ips = %s", ovsdb_vtep_db_table.table_physical_switch[i].management_ips[j]);
                        }
                    }


                    /*tunnel_ips*/
                    if(JSON_STRING == tunnel_ips->type) /*只有1个tunnel ip*/
                    {
                        ovsdb_vtep_db_table.table_physical_switch[i].tunnel_ips[0]= malloc(strlen(json_string(tunnel_ips))+1) ;
                        memcpy(ovsdb_vtep_db_table.table_physical_switch[i].tunnel_ips[0], json_string(tunnel_ips), strlen(json_string(tunnel_ips))+1);
                        OVSDB_PRINTF_DEBUG_TRACE("only one tunnel_ips = %s", ovsdb_vtep_db_table.table_physical_switch[i].tunnel_ips[0]);
                    }
                    else if(JSON_ARRAY == tunnel_ips->type) /*有多个tunnel ip*/
                    {
                        struct json_array *tunnel_ips_set;
                        struct json_array *tunnel_ips_set_value;
                        struct json *ip_value;
                        int j =0;

                        tunnel_ips_set = json_array(tunnel_ips);
                        tunnel_ips_set_value = json_array(tunnel_ips_set->elems[1]);    /*elems[0] is "set" string*/
                        if(!tunnel_ips_set_value->n)
                        {
                            OVSDB_PRINTF_DEBUG_TRACE("physical switch has no tunnel ips.");
                        }
                        else
                        {
                            OVSDB_PRINTF_DEBUG_TRACE("physical switch has more than one tunnel ips.");
                        }

                        for(; j < tunnel_ips_set_value->n; j++)
                        {
                            if(j >= PHYSICAL_SWITCH_TUNNEL_IP_NUM)
                            {
                                break;
                            }
                            ip_value = tunnel_ips_set_value->elems[j];
                            ovsdb_vtep_db_table.table_physical_switch[i].tunnel_ips[j]= malloc(strlen(json_string(ip_value))+1) ;
                            memcpy(ovsdb_vtep_db_table.table_physical_switch[i].tunnel_ips[j], json_string(ip_value), strlen(json_string(ip_value))+1);
                            OVSDB_PRINTF_DEBUG_TRACE("tunnel_ips = %s.", ovsdb_vtep_db_table.table_physical_switch[i].tunnel_ips[j]);
                        }
                    }

                    //ce_config_nve1_source();
                    uiRet = netconf_ce_config_nve1_source(ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0]);
                    if (OVSDB_OK != uiRet)
                    {
                        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config Nve 1 source when processing physical switch table.");
                        return;
                    }

                    /*ports*/
                    #if 0
                    for(; id < ports_set->n; id++)
                    {
                        ports_uuid = json_array(ports_set->elems[id]);
                        (void)uuid_from_string(&ovsdb_vtep_db_table.table_physical_switch[i].ports[id], json_string(ports_uuid->elems[1])); /*elems[0] is "uuid" string*/
                        #if 1
                        printf("physical_switch_table port uuid = "UUID_FMT"\n", UUID_ARGS(&ovsdb_vtep_db_table.table_physical_switch[i].ports[id]));
                        #endif
                    }
                    #endif

                    break;
                }
            }
            break;
        }

        case TABLE_DELETE:
        {
            break;
        }

        case TABLE_UPDATE:  /*主要是添加port的场景,management_ip的问题后续如何处理?*/
        {
            ovsdb_switch_update_management_ips_process(new, old, node_name);
            ovsdb_switch_update_tunnel_ips_process(new, old, node_name);
            ovsdb_switch_update_tunnel_process(new, old, node_name);
            break;
        }

        default:
            break;

    }

}

void physical_switch_table_process_2(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------physical_switch_table_node_stage_2,action=%s----------------", ACTION_TYPE(action));
    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        {

            break;
        }

        case TABLE_DELETE:
        {

            break;
        }

        case TABLE_UPDATE:
        {

            break;
        }

        default:
            break;

    }

}


void logical_switch_table_process(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------logical_switch_table_node,action=%s----------------", ACTION_TYPE(action));

    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        {
            int i = 0;
            int iRet = 0;
            int vni = 0;
            struct json *name;
            struct json *des;
            struct json *tunnel_key;    /*vni*/
            char *paReply = NULL;
            struct uuid uuid_self;

            name = shash_find_data(json_object(new), "name");
            des = shash_find_data(json_object(new), "description");
            tunnel_key = shash_find_data(json_object(new), "tunnel_key");

            /*uuid*/
            (void)uuid_from_string(&uuid_self, node_name);

            /*tunnel_key*/
            /*如果tunnel-key的json类型为JSON_INTEGER，则有值,如果为JSON_ARRAY，则没有值*/
            //printf("\n tunnel key type =%d\n", tunnel_key->type);
            if(JSON_INTEGER == tunnel_key->type)
            {
                vni = json_integer(tunnel_key);
            }

            iRet = ovsdb_table_logical_switch_add(&uuid_self, json_string(des), json_string(name), vni);
            if (iRet != OVSDB_OK)
            {
                OVSDB_PRINTF_DEBUG_ERROR("Add logical switch error, ret = %d, UUDI: "UUID_FMT, iRet, UUID_ARGS(&uuid_self));
            }

            iRet = netconf_msg_list_config_bd(vni);
            if (OVSDB_OK != iRet)
            {
                OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config bridge-domain when inserting table in processing logical switch table");
                //return;
            }

            break;
        }

        case TABLE_DELETE:
        {
#if OVSDB_DEBUG
            struct uuid deleted_ls_uuid;
            int j=0;
            int k=0;
            int iRet = 0;
            int other_ls_has_same_vni_exist=0;
            unsigned int uiRet = 0;

            uuid_zero(&deleted_ls_uuid);
            (void)uuid_from_string(&deleted_ls_uuid, node_name);
            OVSDB_PRINTF_DEBUG_TRACE("deleted logical_switch uuid = "UUID_FMT, UUID_ARGS(&deleted_ls_uuid));

            iRet = ovsdb_table_logical_switch_delete(&deleted_ls_uuid);
            if (iRet != OVSDB_OK)
            {
                OVSDB_PRINTF_DEBUG_ERROR("Delete logical switch error, ret = %d, UUDI: "UUID_FMT, iRet, UUID_ARGS(&deleted_ls_uuid));
            }

            for(j=0; j<TABLE_LOGICAL_SWITCH_NUM; j++)
            {
                if(uuid_equals(&deleted_ls_uuid, &ovsdb_vtep_db_table.table_logical_switch[j].uuid_self))
                {
                   /*调试打印*/
                   OVSDB_PRINTF_DEBUG_TRACE("deleted logical_switch name = %s.", ovsdb_vtep_db_table.table_logical_switch[j].name);

                   /*如果没有其他的ls的vni与当前删除的ls的vni相同，则undo bridge-domain*/
                   for(k=0; k<TABLE_LOGICAL_SWITCH_NUM; k++)
                   {
                       if(k == j)
                       {
                           continue;
                       }
                       else if(ovsdb_vtep_db_table.table_logical_switch[k].tunnel_key == ovsdb_vtep_db_table.table_logical_switch[j].tunnel_key)
                       {
                           other_ls_has_same_vni_exist = 1;
                           break;
                       }
                   }

                   if(!other_ls_has_same_vni_exist)
                   {
                       //ce_undo_config_bd(ovsdb_vtep_db_table.table_logical_switch[j].tunnel_key);
                       uiRet = netconf_ce_undo_config_bd(ovsdb_vtep_db_table.table_logical_switch[j].tunnel_key);
                       if (OVSDB_OK != uiRet)
                       {
                           OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config undo bridge-domain when deleting table in processing logical switch table");
                           return;
                       }
                   }

                    /*释放空间*/
                    if(ovsdb_vtep_db_table.table_logical_switch[j].name)
                    {
                        free(ovsdb_vtep_db_table.table_logical_switch[j].name);
                    }
                    if(ovsdb_vtep_db_table.table_logical_switch[j].description)
                    {
                        free(ovsdb_vtep_db_table.table_logical_switch[j].description);
                    }
                    memset(&ovsdb_vtep_db_table.table_logical_switch[j], 0, sizeof(struct ovsdb_vtep_table_logical_switch));

                    break;
                }
            }
#endif
            break;
        }

        case TABLE_UPDATE:  /*主要针对给ls添加vni的场景*/
        {
            OVSDB_PRINTF_DEBUG_ERROR("Unknow porcess.");
#if OVSDB_DEBUG
            /*是否要考虑改变vni时，隧道配置的改变，代码改动会比较大*/
            /*是否要考虑改变vni时，隧道配置的改变，代码改动会比较大*/
            /*是否要考虑改变vni时，隧道配置的改变，代码改动会比较大*/
            /*是否要考虑改变vni时，隧道配置的改变，代码改动会比较大*/
            struct uuid updated_ls_uuid;
            struct json *tunnel_key;    /*vni*/
            int k=0;
            int m=0;
            int other_ls_has_same_vni_exist=0;
            unsigned int uiRet = 0;

            uuid_zero(&updated_ls_uuid);
            (void)uuid_from_string(&updated_ls_uuid, node_name);
            OVSDB_PRINTF_DEBUG_TRACE("updated logical_switch uuid = "UUID_FMT, UUID_ARGS(&updated_ls_uuid));

            tunnel_key = shash_find_data(json_object(new), "tunnel_key");
            if(NULL == tunnel_key)
            {
                break;
            }

            for(k=0; k<TABLE_LOGICAL_SWITCH_NUM; k++)
            {
                if(uuid_equals(&updated_ls_uuid, &ovsdb_vtep_db_table.table_logical_switch[k].uuid_self))
                {
                    if(JSON_INTEGER == tunnel_key->type)
                    {
                        int tunnel_key_temp = json_integer(tunnel_key);

                        if(ovsdb_vtep_db_table.table_logical_switch[k].tunnel_key == tunnel_key_temp)
                        {
                            OVSDB_PRINTF_DEBUG_TRACE("logical_swutch %s's tunnel_key is not updated,tunnel_key = %d.",
                                ovsdb_vtep_db_table.table_logical_switch[k].name, ovsdb_vtep_db_table.table_logical_switch[k].tunnel_key);
                        }
                        else
                        {
                            OVSDB_PRINTF_DEBUG_TRACE("logical_swutch %s's tunnel_key is updated,old tunnel_key = %d.",
                                ovsdb_vtep_db_table.table_logical_switch[k].name,
                                ovsdb_vtep_db_table.table_logical_switch[k].tunnel_key);
                            OVSDB_PRINTF_DEBUG_TRACE("new tunnel_key = %d.", tunnel_key_temp);

                            /*在TOR上进行相应的配置BD和删除BD操作*/
                            if(tunnel_key_temp > 4095)  /*如果新的vni大于4095,则创建BD，暂时未考虑tor上已经创建了该BD的情况*/
                            {
                                //ce_config_bd(tunnel_key_temp);
                                uiRet = netconf_ce_config_bd(tunnel_key_temp);
                                if (OVSDB_OK != uiRet)
                                {
                                    OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config bridge-domain when updating table in processing logical switch table");
                                    return;
                                }
                            }
                            /*如果旧的vni大于4095, 则查看其他的ls的vni是否有与当前的相同的，如果没有,在tor上删除BD*/
                            if(ovsdb_vtep_db_table.table_logical_switch[k].tunnel_key > 4095)
                            {
                                for(m=0; m<TABLE_LOGICAL_SWITCH_NUM; m++)
                                {
                                    if(m == k)
                                    {
                                        continue;
                                    }
                                    else if(ovsdb_vtep_db_table.table_logical_switch[m].tunnel_key == ovsdb_vtep_db_table.table_logical_switch[k].tunnel_key)
                                    {
                                        other_ls_has_same_vni_exist = 1;
                                        break;
                                    }
                                }

                                if(!other_ls_has_same_vni_exist)
                                {
                                    //ce_undo_config_bd(ovsdb_vtep_db_table.table_logical_switch[k].tunnel_key);
                                    uiRet = netconf_ce_undo_config_bd(ovsdb_vtep_db_table.table_logical_switch[k].tunnel_key);
                                    if (OVSDB_OK != uiRet)
                                    {
                                        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config undo bridge-domain when updating table in processing logical switch table");
                                        return;
                                    }
                                }
                            }

                            /*写表*/
                            ovsdb_vtep_db_table.table_logical_switch[k].tunnel_key = tunnel_key_temp;
                        }
                    }
                    break;
                }
            }
#endif
            break;
        }

        default:
            break;

    }

}

void logical_switch_table_process_2(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------logical_switch_table_node_stage_2,action=%s----------------",ACTION_TYPE(action));
    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        {
            break;
        }

        case TABLE_DELETE:
        {
            struct uuid deleted_ls_uuid;
            int j=0;
            int k=0;
            int iRet = 0;
            int other_ls_has_same_vni_exist=0;
            struct ovsdb_vtep_table_logical_switch * pstLS;

            uuid_zero(&deleted_ls_uuid);
            (void)uuid_from_string(&deleted_ls_uuid, node_name);
            OVSDB_PRINTF_DEBUG_TRACE("deleted logical_switch uuid = "UUID_FMT, UUID_ARGS(&deleted_ls_uuid));

            pstLS = ovsdb_table_logical_switch_query(&deleted_ls_uuid);
            if (NULL == pstLS)
            {
                OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to query logical_switch uuid = "UUID_FMT, UUID_ARGS(&deleted_ls_uuid));
                return;
            }

            iRet = netconf_msg_list_undo_config_bd(pstLS->tunnel_key);
            if (OVSDB_OK != iRet)
            {
                OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config bridge-domain when inserting table in processing logical switch table");
                return;
            }

            hw_vtep_vxlan_tunnel_delete_by_vni(pstLS->tunnel_key);

            iRet = ovsdb_table_logical_switch_delete(&deleted_ls_uuid);
            if (iRet != OVSDB_OK)
            {
                OVSDB_PRINTF_DEBUG_ERROR("Delete logical switch error, ret = %d, UUDI: "UUID_FMT, iRet, UUID_ARGS(&deleted_ls_uuid));
            }

            break;
        }

        case TABLE_UPDATE:
        {

            break;
        }

        default:
            break;

    }

}


void physical_locator_table_process(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------physical_locator_table_node,action=%s----------------",ACTION_TYPE(action));

    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        {
            int iRet = 0;
            struct uuid uuid_self;
            struct json *dst_ip;

            (void)uuid_from_string(&uuid_self, node_name);
            dst_ip = shash_find_data(json_object(new), "dst_ip");

            iRet = ovsdb_table_physical_locator_add(&uuid_self, json_string(dst_ip));
            if (iRet != OVSDB_OK)
            {
                OVSDB_PRINTF_DEBUG_ERROR("Add physical locator error, ret = %d, UUDI: "UUID_FMT, iRet, UUID_ARGS(&uuid_self));
            }

            ovsdb_physical_locator_process_add(rpc, &uuid_self);

            break;
        }

        case TABLE_DELETE:
        {
#if OVSDB_DEBUG
            struct uuid deleted_pl_uuid;
            int iRet = 0;
            int j=0;
            int m=0;
            unsigned int uiRet = 0;

            uuid_zero(&deleted_pl_uuid);
            (void)uuid_from_string(&deleted_pl_uuid, node_name);
            OVSDB_PRINTF_DEBUG_TRACE("deleted physical_locator uuid = "UUID_FMT, UUID_ARGS(&deleted_pl_uuid));

            iRet = ovsdb_table_physical_locator_delete(&deleted_pl_uuid);
            if (iRet != OVSDB_OK)
            {
                OVSDB_PRINTF_DEBUG_ERROR("Delete physical locator error, ret = %d, UUDI: "UUID_FMT,
                    iRet, UUID_ARGS(&deleted_pl_uuid));
            }

            /* 删除Tunnel table */
            ovsdb_tunnel_delete_process(rpc, &deleted_pl_uuid);

            for(j=0; j<TABLE_PHYSICAL_LOCATOR_NUM; j++)
            {
                if(uuid_equals(&deleted_pl_uuid, &ovsdb_vtep_db_table.table_physical_locator[j].uuid_self))
                {
                    continue;
                }

                ///*首先在switch_vxlan_tunnel全局变量中找对应的隧道*/
                //for(m=0; m<VXLAN_TUNNEL_NUM_MAX; m++)
                //{
                //    if(switch_vxlan_tunnel[m].used_bit)
                //    {
                //        if(0 == strcmp(switch_vxlan_tunnel[m].dst_ip, ovsdb_vtep_db_table.table_physical_locator[j].dst_ip))
                //        {
                //            //ce_undo_config_vxlan_tunnel(switch_vxlan_tunnel[m].vni,
                //                //ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0], switch_vxlan_tunnel[m].dst_ip);
                //
                //            uiRet = netconf_ce_undo_config_vxlan_tunnel(switch_vxlan_tunnel[m].vni, switch_vxlan_tunnel[m].dst_ip);
                //            if (OVSDB_OK != uiRet)
                //            {
                //                OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to undo vxlan tunnel");
                //                return;
                //            }
                //
                //            OVSDB_PRINTF_DEBUG_TRACE("delete entry to switch_vxlan_tunnel. m =%d, vni = %d,", m, switch_vxlan_tunnel[m].vni);
                //            OVSDB_PRINTF_DEBUG_TRACE("source_ip = %s, dst_ip = %s.", switch_vxlan_tunnel[m].source_ip, switch_vxlan_tunnel[m].dst_ip);
                //
                //            /*释放switch_vxlan_tunnel中的该条表项*/
                //            if(switch_vxlan_tunnel[m].source_ip)
                //            {
                //                free(switch_vxlan_tunnel[m].source_ip);
                //            }
                //            if(switch_vxlan_tunnel[m].dst_ip)
                //            {
                //                free(switch_vxlan_tunnel[m].dst_ip);
                //            }
                //
                //            memset(&switch_vxlan_tunnel[m], 0, sizeof(struct hw_vtep_vxlan_tunnel));
                //
                //            break;
                //        }
                //    }
                //}
                //
                ///*如果是本端的vtep ip，则删除Nve接口*/
                //if((ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0]) && (ovsdb_vtep_db_table.table_physical_locator[j].dst_ip))
                //{
                //    if(0 == strcmp(ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0], ovsdb_vtep_db_table.table_physical_locator[j].dst_ip))
                //    {
                //        uiRet = netconf_ce_undo_config_nve1_source(ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0]);
                //        if (OVSDB_OK != uiRet)
                //        {
                //            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to undo Nve 1.");
                //        }
                //    }
                //}

                if(ovsdb_vtep_db_table.table_physical_locator[j].dst_ip)
                {
                    free(ovsdb_vtep_db_table.table_physical_locator[j].dst_ip);
                }
                memset(&ovsdb_vtep_db_table.table_physical_locator[j], 0, sizeof(struct ovsdb_vtep_table_physical_locator));
                ovsdb_vtep_db_table.used_num_table_physical_locator -= 1;                        

                break;
            }
#endif
            break;
        }

        case TABLE_UPDATE:
        {
            OVSDB_PRINTF_DEBUG_ERROR("Unknow porcess.");
            break;
        }

        default:
            break;

    }

}

void physical_locator_table_process_2(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------physical_locator_table_node_stage_2,action=%s----------------",ACTION_TYPE(action));

    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        case TABLE_UPDATE:
        {
#if OVSDB_DEBUG
            int i =0;

            /*只有在标志位置起的时候才会创建隧道*/
            /*多个locator对应的隧道一起创建*/
            /*先创建service node的隧道，再创建hypervisror的隧道*/
            if(vxlan_tunnel_to_be_create_flag)
            {
                /*service node隧道创建*/
                for(i=0; i<SERVICE_NODE_MAX; i++)
                {
                    if(service_node_vxlan_tunnel_to_be_created[i].used_bit)
                    {
                        //ovsdb_physical_locator_process_config_vxlan_tunnel(
                        //    service_node_vxlan_tunnel_to_be_created[i].vni,
                        //    service_node_vxlan_tunnel_to_be_created[i].dst_ip
                        //    );

                        /*清除缓冲区数据*/
                        if(service_node_vxlan_tunnel_to_be_created[i].dst_ip)
                        {
                            free(service_node_vxlan_tunnel_to_be_created[i].dst_ip);
                        }

                        if(service_node_vxlan_tunnel_to_be_created[i].source_ip)
                        {
                            free(service_node_vxlan_tunnel_to_be_created[i].source_ip);
                        }

                        memset(&service_node_vxlan_tunnel_to_be_created[i], 0, sizeof(struct hw_vtep_vxlan_tunnel));
                    }
                }

                /*hypervisor隧道创建*/
                for(i=0; i<HYPERVISOR_MAX; i++)
                {
                    if(hypervisor_vxlan_tunnel_to_be_created[i].used_bit)
                    {
                        //ovsdb_physical_locator_process_config_vxlan_tunnel(
                        //    hypervisor_vxlan_tunnel_to_be_created[i].vni,
                        //    hypervisor_vxlan_tunnel_to_be_created[i].dst_ip
                        //    );

                        /*清除缓冲区数据*/
                        if(hypervisor_vxlan_tunnel_to_be_created[i].dst_ip)
                        {
                            free(hypervisor_vxlan_tunnel_to_be_created[i].dst_ip);
                        }

                        if(hypervisor_vxlan_tunnel_to_be_created[i].source_ip)
                        {
                            free(hypervisor_vxlan_tunnel_to_be_created[i].source_ip);
                        }

                        memset(&hypervisor_vxlan_tunnel_to_be_created[i], 0, sizeof(struct hw_vtep_vxlan_tunnel));
                    }
                }

                /*创建完标志位清零*/
                vxlan_tunnel_to_be_create_flag= 0;
            }
#endif
            break;
        }

        case TABLE_DELETE:
        {
            struct uuid deleted_pl_uuid;
            int iRet = 0;
            int j=0;
            int m=0;
            unsigned int uiRet = 0;

            uuid_zero(&deleted_pl_uuid);
            (void)uuid_from_string(&deleted_pl_uuid, node_name);
            OVSDB_PRINTF_DEBUG_TRACE("deleted physical_locator uuid = "UUID_FMT, UUID_ARGS(&deleted_pl_uuid));

            iRet = ovsdb_table_physical_locator_delete(&deleted_pl_uuid);
            if (iRet != OVSDB_OK)
            {
                OVSDB_PRINTF_DEBUG_ERROR("Delete physical locator error, ret = %d, UUDI: "UUID_FMT,
                    iRet, UUID_ARGS(&deleted_pl_uuid));
            }

            break;
        }

        default:
            break;

    }

}


void physical_locator_set_table_process(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action) /*not completed yet*/
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------physical_locator_set__table_node,action=%s----------------",ACTION_TYPE(action));

    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        {
            int iRet = 0;
            struct uuid uuid_self;
            struct json *locators;
            struct json_array *locators_value;
            int k = 0;
            struct uuid array_locators[LOCATOR_NUM_IN_LOCATION_SET];
            int used_num_locators = 0;

            (void)uuid_from_string(&uuid_self, node_name);
            (void)memset(array_locators, 0, sizeof(struct uuid) * LOCATOR_NUM_IN_LOCATION_SET);

            locators = shash_find_data(json_object(new), "locators");
            locators_value = json_array(locators);
            if(0 == strcmp(json_string(locators_value->elems[0]), "uuid"))
            {
                used_num_locators = 1;
                (void)uuid_from_string(&array_locators[0],
                    json_string(locators_value->elems[1]));
            }
            /*然后考虑多个locator的情况*/
            else if(0 == strcmp(json_string(locators_value->elems[0]), "set"))
            {
                struct json_array *locator_elems;
                locator_elems = json_array(locators_value->elems[1]);

                for(k=0; k<locator_elems->n; k++)
                {
                    if(k<LOCATOR_NUM_IN_LOCATION_SET)
                    {
                        uuid_from_string(&array_locators[k],
                            json_string(json_array(locator_elems->elems[k])->elems[1]));
                        used_num_locators++;
                    }
                }
            }

            iRet = ovsdb_table_physical_locator_set_add(&uuid_self, array_locators, used_num_locators);
            if (iRet != OVSDB_OK)
            {
                OVSDB_PRINTF_DEBUG_ERROR("Add physical locator set error, ret = %d, UUDI: "UUID_FMT, iRet, UUID_ARGS(&uuid_self));
            }

            //理论上应该不存在先有Mcast_Macs_Remote, 再有replicator的场景，此流程可以先屏蔽
            ovsdb_physical_locator_set_process_add(&uuid_self);

            break;
        }

        case TABLE_DELETE:
        {
            int iRet;
            struct uuid deleted_pls_uuid;

            uuid_zero(&deleted_pls_uuid);
            (void)uuid_from_string(&deleted_pls_uuid, node_name);

            ovsdb_physical_locator_set_process_delete(rpc, &deleted_pls_uuid);

            iRet = ovsdb_table_physical_locator_set_delete(&deleted_pls_uuid);
            if (iRet != OVSDB_OK)
            {
                OVSDB_PRINTF_DEBUG_ERROR("Delete physical locator set error, ret = %d, UUDI: "UUID_FMT, iRet, UUID_ARGS(&deleted_pls_uuid));
            }

            break;
        }
#if OVSDB_DEBUG
        case TABLE_DELETE:
        {
            struct uuid deleted_pls_uuid;
            struct json *locators;
            struct json_array *locators_value;
            struct uuid table_physical_locator_set_locators_0;
            int j=0;

            uuid_zero(&deleted_pls_uuid);
            uuid_zero(&table_physical_locator_set_locators_0);
            (void)uuid_from_string(&deleted_pls_uuid, node_name);
            locators = shash_find_data(json_object(old), "locators");
            locators_value = json_array(locators);

            OVSDB_PRINTF_DEBUG_TRACE("deleted physical_locator_set uuid = "UUID_FMT, UUID_ARGS(&deleted_pls_uuid));

            for(j=0; j<TABLE_PHYSICAL_LOCATOR_SET_NUM; j++)
            {
                if(uuid_equals(&deleted_pls_uuid, &ovsdb_vtep_db_table.table_physical_locator_set[j].uuid_self))
                {
                    uuid_from_string(&table_physical_locator_set_locators_0, json_string(locators_value->elems[1]));

                    /*释放空间*/
                    memset(&ovsdb_vtep_db_table.table_physical_locator_set[j], 0, sizeof(struct ovsdb_vtep_table_physical_locator_set));
                    ovsdb_vtep_db_table.table_physical_locator_set[j].used_num_locators = 0;
                    ovsdb_vtep_db_table.used_num_table_physical_locator_set -= 1;

                    /* 删除tunnel表 */
                    ovsdb_tunnel_delete_process(rpc, &deleted_pls_uuid);

                    /* 当不存在locator set的时候，变量locator清零 */
                    if (0 == ovsdb_vtep_db_table.used_num_table_physical_locator_set)
                    {
                        ovsdb_vtep_db_table.used_num_table_physical_locator = 0;

                        for (j = 0; j < TABLE_PHYSICAL_LOCATOR_NUM; j++)
                        {
                            if (!uuid_is_zero(&ovsdb_vtep_db_table.table_physical_locator[j].uuid_self))
                            {
                                if (ovsdb_vtep_db_table.table_physical_locator[j].dst_ip)
                                {
                                    free(ovsdb_vtep_db_table.table_physical_locator[j].dst_ip);
                                }
                                memset(&ovsdb_vtep_db_table.table_physical_locator[j], 0, sizeof(struct ovsdb_vtep_table_physical_locator));
                            }
                        }
                    }
                    break;
                }
            }

            break;
        }
#endif
        case TABLE_UPDATE:  /*不存在更新的情况，往locator_set中添加或删除一个locator时，会删掉老的set，并创建新的set*/
        {
            OVSDB_PRINTF_DEBUG_ERROR("Unknow porcess.");
            break;
        }

        default:
            break;

    }

}

void physical_locator_set_table_process_2(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action) /*not completed yet*/
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------physical_locator_set_table_node_stage_2,action=%s----------------", ACTION_TYPE(action));
    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        {

            break;
        }

        case TABLE_DELETE:
        {

            break;
        }

        case TABLE_UPDATE:
        {

            break;
        }

        default:
            break;

    }

}

void physical_port_table_process(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------physical_port_table_node,action=%s----------------",ACTION_TYPE(action));

    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        {
            int iRet = 0;
            struct uuid uuid_self;
            struct json *port_name;
            struct json *port_vlan_bindings;

            (void)uuid_from_string(&uuid_self, node_name);
            port_name = shash_find_data(json_object(new), "name");/*find name  in table*/

            iRet = ovsdb_table_physical_port_add(&uuid_self, json_string(port_name));
            if (iRet != OVSDB_OK) {
                OVSDB_PRINTF_DEBUG_ERROR("Add physical port error, ret = %d, UUDI: "UUID_FMT, iRet, UUID_ARGS(&uuid_self));
            }

            port_vlan_bindings = shash_find_data(json_object(new), "vlan_bindings");
            if (NULL == port_vlan_bindings)
                break;

            ovsdb_port_update_vlanbinding_process(json_string(port_name), port_vlan_bindings, NULL);

            break;

#if OVSDB_DEBUG
            int i=0;
            struct json *port_name;
            struct json *port_des;
            struct json *port_vlan_bindings;

            port_name = shash_find_data(json_object(new), "name");/*find name  in table*/
            port_des = shash_find_data(json_object(new), "description");/*find description  in  table*/
            port_vlan_bindings = shash_find_data(json_object(new), "vlan_bindings");

            for(i=0; i<TABLE_PHYSICAL_PORT_NUM; i++)
            {
                /*获取表中的第一个不为0的表项*/
                if(!uuid_is_zero(&ovsdb_vtep_db_table.table_physical_port[i].uuid_self))
                {
                    continue;
                }
                else
                {
                    /*uuid*/
                    (void)uuid_from_string(&ovsdb_vtep_db_table.table_physical_port[i].uuid_self, node_name);
                    OVSDB_PRINTF_DEBUG_TRACE("port uuid = "UUID_FMT, UUID_ARGS(&ovsdb_vtep_db_table.table_physical_port[i].uuid_self));

                    /*name*/
                    ovsdb_vtep_db_table.table_physical_port[i].name = malloc(strlen(json_string(port_name))+1) ;
                    memcpy(ovsdb_vtep_db_table.table_physical_port[i].name, json_string(port_name), strlen(json_string(port_name))+1);
                    OVSDB_PRINTF_DEBUG_TRACE("port name is %s, i = %d", ovsdb_vtep_db_table.table_physical_port[i].name, i);

                    /*description*/
                    ovsdb_vtep_db_table.table_physical_port[i].description = malloc(strlen(json_string(port_des))+1) ;
                    memcpy(ovsdb_vtep_db_table.table_physical_port[i].description, json_string(port_des), strlen(json_string(port_des))+1);
                    OVSDB_PRINTF_DEBUG_TRACE("port description is %s, i = %d", ovsdb_vtep_db_table.table_physical_port[i].description, i);

                    /*vlan bingding*/
                    /*vlan bingding的处理逻辑不正确，有时间重写一下*/
                    //ovsdb_port_add_vlanbinding_process(new, old, node_name);
                    
                    /*port中有vlan binding才继续处理*/
                    if(port_vlan_bindings)
                    {
                        struct json *new_vlanbinding_elems;
                        struct json_array *new_vlanbinding_elems_array;
                        int new_vlanbinding_elem_num = 0;
                        int m = 0;
                        int add_port_map_exist = 0;
                        int j = 0;
                        int k = 0;
                        int vlanid = 4096;
                        int vni_temp = 0;
                        struct uuid uuid_ls;
                        unsigned int uiRet = 0;
                        
                        new_vlanbinding_elems = json_array(port_vlan_bindings)->elems[1]; /*elems[0]* is "map" string*/
                        new_vlanbinding_elems_array = json_array(new_vlanbinding_elems);
                        new_vlanbinding_elem_num = new_vlanbinding_elems_array->n;
                        
                        /*检查switch_vxlan_map全局变量中是否已经有该port的映射*/
                        for(m=0; m<TABLE_PHYSICAL_PORT_NUM; m++)
                        {
                            if(uuid_equals(&ovsdb_vtep_db_table.table_physical_port[i].uuid_self, &switch_vxlan_map[m].port_uuid))
                            {
                                add_port_map_exist = 1;
                                break;
                            }
                        }
                        
                        if(!add_port_map_exist)
                        {
                            for(m=0; m<TABLE_PHYSICAL_PORT_NUM; m++)
                            {
                                if(uuid_is_zero(&switch_vxlan_map[m].port_uuid))
                                {
                                    memcpy(&switch_vxlan_map[m].port_uuid, 
                                        &ovsdb_vtep_db_table.table_physical_port[i].uuid_self,
                                        sizeof(ovsdb_vtep_db_table.table_physical_port[i].uuid_self));
                                    break;
                                }
                            }
                        }
                        
                        for(m=0; m<TABLE_PHYSICAL_PORT_NUM; m++)
                        {
                            if(uuid_equals(&ovsdb_vtep_db_table.table_physical_port[i].uuid_self, &switch_vxlan_map[m].port_uuid))
                            {
                                for(j=0; j<new_vlanbinding_elem_num; j++)
                                {
                                    vlanid = json_integer(json_array(new_vlanbinding_elems_array->elems[j])->elems[0]);
                                    
                                    if((vlanid > 4093)||(vlanid<0))
                                    {
                                        OVSDB_PRINTF_DEBUG_TRACE("vlan_id is not valid, which is %d.",vlanid);
                                    }
                                    if(switch_vxlan_map[m].vlan_vni_map[vlanid].used_bit)
                                    {
                                        OVSDB_PRINTF_DEBUG_TRACE("vlan_id %d mapping is exist, do not process.",vlanid);
                                    }
                                    else
                                    {
                                        OVSDB_PRINTF_DEBUG_TRACE("vlan_id %d mapping is absent, now do process.", vlanid);
                                        uuid_from_string(&uuid_ls, json_string(json_array(json_array(new_vlanbinding_elems_array->elems[j])->elems[1])->elems[1]));
                                        for(k=0; k<TABLE_LOGICAL_SWITCH_NUM; k++)
                                        {
                                            if(uuid_equals(&ovsdb_vtep_db_table.table_logical_switch[k].uuid_self, &uuid_ls))
                                            {
                                                vni_temp = ovsdb_vtep_db_table.table_logical_switch[k].tunnel_key;
                                                break;
                                            }
                                        }
                                        
                                        if(vni_temp > 4095)
                                        {
                                            switch_vxlan_map[m].vlan_vni_map[vlanid].vni = vni_temp;
                                            switch_vxlan_map[m].vlan_vni_map[vlanid].used_bit = 1;
                                            
                                            /*配置子接口和vxlan映射*/
                                            
                                            //ce_config_port(vlanid, switch_vxlan_map[i].vlan_vni_map[vlanid].vni, port_name);
                                            uiRet = netconf_ce_config_port(vlanid, switch_vxlan_map[m].vlan_vni_map[vlanid].vni, ovsdb_vtep_db_table.table_physical_port[i].name);
                                            if (OVSDB_OK != uiRet)
                                            {
                                                OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config subinterface when processing port vlanbinding.");
                                                return;
                                            }
                                            
                                            /*往ovsdb_vtep_db_table全局变量中也写一下*/
                                            ovsdb_vtep_db_table.table_physical_port[i].vlan_bindings.vlan_bindings[vlanid].vlan_id = vlanid; /*这里也把vlanid作为下标，好与switch_vxlan_map对应*/
                                            memcpy(&ovsdb_vtep_db_table.table_physical_port[i].vlan_bindings.vlan_bindings[vlanid].uuid_logical_switch, &ovsdb_vtep_db_table.table_logical_switch[k].uuid_self,
                                                sizeof(ovsdb_vtep_db_table.table_logical_switch[k]));
                                        }
                                    }
                                }
                                
                                break;
                            }
                        }
                        
                    }
                    /*port中没有vlan binding，记录日志，方便定位*/
                    else 
                    {
                        OVSDB_PRINTF_DEBUG_ERROR("init or insert port %s do not have vlan binding", ovsdb_vtep_db_table.table_physical_port[i].name);
                    }
                    
                    break;
            
                }
            }
            break;
#endif
        }

        case TABLE_DELETE:
        {
            struct uuid deleted_port_uuid;
            int j=0;

            uuid_zero(&deleted_port_uuid);
            (void)uuid_from_string(&deleted_port_uuid, node_name);
            OVSDB_PRINTF_DEBUG_TRACE("deleted physical port uuid = "UUID_FMT, UUID_ARGS(&deleted_port_uuid));

            (void)ovsdb_table_physical_port_delete(&deleted_port_uuid);

            break;
        }

        case TABLE_UPDATE:  /*添加和去除vlan_binding的场景*/
        {
            struct json *port_name;
            struct json *new_port_vlan_bindings, *old_port_vlan_bindings;

            port_name = shash_find_data(json_object(new), "name");/*find name  in table*/
            new_port_vlan_bindings = shash_find_data(json_object(new), "vlan_bindings");
            old_port_vlan_bindings = shash_find_data(json_object(old), "vlan_bindings");

            ovsdb_port_update_vlanbinding_process(json_string(port_name), new_port_vlan_bindings, old_port_vlan_bindings);

            break;
        }

        default:
            break;

    }

    return;
}

void physical_port_table_process_2(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------physical_port_table_node_stage_2,action=%s----------------",ACTION_TYPE(action));
    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        {

            break;
        }

        case TABLE_DELETE:
        {

            break;
        }

        case TABLE_UPDATE:
        {

            break;
        }

        default:
            break;

    }

}


void ucast_macs_local_table_process(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------ucast_macs_local_table_node,action=%s----------------",ACTION_TYPE(action));

    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        {
            struct json *MAC;
            struct json *ip_addr;
            struct json *logic_switch;
            struct json_array *logic_switch_array;
            struct json *uuid_logic_switch;

            struct json *locator;
            struct json_array *locator_array;
            struct json *uuid_locator;

            int i = 0;

            MAC = shash_find_data(json_object(new), "MAC");
            ip_addr = shash_find_data(json_object(new), "ipaddr");    /*ipaddr is always empty,so ignore it. otherwise ,error occur while memcpy.*/

            logic_switch= shash_find_data(json_object(new), "logical_switch");
            logic_switch_array = json_array(logic_switch);
            uuid_logic_switch = logic_switch_array->elems[1];   /*elems[0] is "uuid" const string*/

            locator= shash_find_data(json_object(new), "locator");
            locator_array = json_array(locator);
            uuid_locator = locator_array->elems[1];   /*elems[0] is "uuid" const string*/

            for(i=0; i<TABLE_UCAST_MACS_LOCAL_NUM; i++)
            {
                /*获取表中的第一个不为0的表项*/
                if(!uuid_is_zero(&ovsdb_vtep_db_table.table_ucast_macs_local[i].uuid_self))
                {
                    continue;
                }
                else
                {
                    /*uuid*/
                    (void)uuid_from_string(&ovsdb_vtep_db_table.table_ucast_macs_local[i].uuid_self, node_name);
                    /*MAC*/
                    ovsdb_vtep_db_table.table_ucast_macs_local[i].MAC = malloc(strlen(json_string(MAC))+1) ;
                    memcpy(ovsdb_vtep_db_table.table_ucast_macs_local[i].MAC, json_string(MAC), strlen(json_string(MAC))+1);
                    /*ip_addr*/
                    /*不处理ipaddr*/
                    //ovsdb_vtep_db_table.table_ucast_macs_local[i].ipaddr = malloc(strlen(json_string(ip_addr))+1) ;
                    //memcpy(ovsdb_vtep_db_table.table_ucast_macs_local[i].ipaddr, json_string(ip_addr), strlen(json_string(ip_addr))+1);
                    OVSDB_PRINTF_DEBUG_TRACE("ucast_macs_local_table i=%d, MAC=%s, ipaddr=NULL.", i, ovsdb_vtep_db_table.table_ucast_macs_local[i].MAC);
                    OVSDB_PRINTF_DEBUG_TRACE("ucast_macs_local_table uuid = "UUID_FMT, UUID_ARGS(&ovsdb_vtep_db_table.table_ucast_macs_local[i].uuid_self));

                    /*uuid of Logical_Switch*/
                    (void)uuid_from_string(&ovsdb_vtep_db_table.table_ucast_macs_local[i].logical_switch, json_string(uuid_logic_switch));
                    OVSDB_PRINTF_DEBUG_TRACE("U Local table Logical_Switch uuid = "UUID_FMT, UUID_ARGS(&ovsdb_vtep_db_table.table_ucast_macs_local[i].logical_switch));

                    /*uuid of Physical_Locator*/
                    (void)uuid_from_string(&ovsdb_vtep_db_table.table_ucast_macs_local[i].locator, json_string(uuid_locator));
                    OVSDB_PRINTF_DEBUG_TRACE("U Local table Physical_Locator uuid = "UUID_FMT, UUID_ARGS(&ovsdb_vtep_db_table.table_ucast_macs_local[i].locator));

                    break;
                }
            }
            break;
        }

        case TABLE_DELETE:
        {
            struct uuid deleted_ucast_local_uuid;
            int j=0;

            uuid_zero(&deleted_ucast_local_uuid);
            (void)uuid_from_string(&deleted_ucast_local_uuid, node_name);
            OVSDB_PRINTF_DEBUG_TRACE("deleted ucast local uuid = "UUID_FMT, UUID_ARGS(&deleted_ucast_local_uuid));

            for(j=0; j<TABLE_UCAST_MACS_LOCAL_NUM; j++)
            {
                if(uuid_equals(&deleted_ucast_local_uuid, &ovsdb_vtep_db_table.table_ucast_macs_local[j].uuid_self))
                {

                    /*释放空间*/
                    if(ovsdb_vtep_db_table.table_ucast_macs_local[j].MAC)
                    {
                        free(ovsdb_vtep_db_table.table_ucast_macs_local[j].MAC);
                    }
                    if(ovsdb_vtep_db_table.table_ucast_macs_local[j].ipaddr)
                    {
                        free(ovsdb_vtep_db_table.table_ucast_macs_local[j].ipaddr);
                    }
                    memset(&ovsdb_vtep_db_table.table_ucast_macs_local[j], 0, sizeof(struct ovsdb_vtep_table_ucast_macs_local));

                    break;
                }
            }

            break;
        }

        case TABLE_UPDATE:/*暂未想到更新场景*/
        {
            break;
        }

        default:
            break;

    }

}

void ucast_macs_local_table_process_2(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------ucast_macs_local_table_node_stage_2,action=%s----------------",ACTION_TYPE(action));
    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        {

            break;
        }

        case TABLE_DELETE:
        {

            break;
        }

        case TABLE_UPDATE:
        {

            break;
        }

        default:
            break;

    }

}


void ucast_macs_remote_table_process(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------ucast_macs_remote_table_node,action=%s----------------",ACTION_TYPE(action));

    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        {

            struct json *MAC;
            struct json *ip_addr;
            struct json *logic_switch;
            struct json_array *logic_switch_array;
            struct uuid uuid_logic_switch;

            struct json *locator;
            struct json_array *locator_array;
            struct uuid uuid_locator;

            int i = 0;
            int ret = 0;
            struct uuid uuid_self;

            /*uuid*/
            (void)uuid_from_string(&uuid_self, node_name);

            MAC = shash_find_data(json_object(new), "MAC");
            ip_addr = shash_find_data(json_object(new), "ipaddr");

            logic_switch= shash_find_data(json_object(new), "logical_switch");
            logic_switch_array = json_array(logic_switch);
            (void)uuid_from_string(&uuid_logic_switch, json_string(logic_switch_array->elems[1]));

            locator= shash_find_data(json_object(new), "locator");
            locator_array = json_array(locator);
            (void)uuid_from_string(&uuid_locator, json_string(locator_array->elems[1]));

            ret = ovsdb_table_ucast_macs_remote_add(&uuid_self, json_string(MAC), json_string(ip_addr),
                                                    &uuid_logic_switch, &uuid_locator);
            if (ret != OVSDB_OK)
            {
                OVSDB_PRINTF_DEBUG_ERROR("Add ucast macs remote error, ret = %d, UUDI: "UUID_FMT, ret, UUID_ARGS(&uuid_self));
            }

            ovsdb_ucast_macs_remote_process_add(&uuid_self);

            break;
        }


        case TABLE_DELETE:
        {
            int ret = 0;
            int j = 0;
            int k =0;
            int m = 0;
            int con_1  =0;  /*条件1*/
            int con_2  =0;
            int con_3  =0;
            unsigned int uiRet = 0;
            struct uuid deleted_ucast_remote_uuid;

            uuid_zero(&deleted_ucast_remote_uuid);
            (void)uuid_from_string(&deleted_ucast_remote_uuid, node_name);
            OVSDB_PRINTF_DEBUG_TRACE("deleted ucast remote uuid = "UUID_FMT, UUID_ARGS(&deleted_ucast_remote_uuid));

            ovsdb_ucast_macs_remote_process_delete(&deleted_ucast_remote_uuid);

            ret = ovsdb_table_ucast_macs_remote_delete(&deleted_ucast_remote_uuid);
            if (ret != OVSDB_OK)
            {
                OVSDB_PRINTF_DEBUG_ERROR("Delete ucast macs remote error, ret = %d, UUDI: "UUID_FMT, ret, UUID_ARGS(&deleted_ucast_remote_uuid));
            }

#if OVSDB_DEBUG
            for(j=0; j<TABLE_UCAST_MACS_REMOTE_NUM; j++)
            {
                if(uuid_equals(&deleted_ucast_remote_uuid, &ovsdb_vtep_db_table.table_ucast_macs_remote[j].uuid_self))
                {

                    #if 1
                    /*未考虑到logical_switch和ucast_remote同时删除的情况，这样会找不到vni*/
                    /*未考虑到logical_switch和ucast_remote同时删除的情况，这样会找不到vni*/

                    /*先找physical_locator中的dst_ip*/
                    for(k=0; k<TABLE_PHYSICAL_LOCATOR_NUM; k++)
                    {
                        if(uuid_equals(&ovsdb_vtep_db_table.table_ucast_macs_remote[j].locator, &ovsdb_vtep_db_table.table_physical_locator[k].uuid_self))
                        {
                            break;
                        }
                    }

                    /*再找logical_switch中的tunnel_key*/
                    for(m=0; m<TABLE_LOGICAL_SWITCH_NUM; m++)
                    {
                        if(uuid_equals(&ovsdb_vtep_db_table.table_ucast_macs_remote[j].logical_switch, &ovsdb_vtep_db_table.table_logical_switch[m].uuid_self))
                        {
                            break;
                        }
                    }
                    /*条件1:交换机tunnel ip存在*/
                    if(ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0])
                    {
                        con_1 = 1;
                    }
                    /*条件2: physical locator的dst ip存在*/
                    if(ovsdb_vtep_db_table.table_physical_locator[k].dst_ip)
                    {
                        con_2 = 1;
                    }
                    /*条件3;logical_switch的vni大于4095*/
                    if(ovsdb_vtep_db_table.table_logical_switch[m].tunnel_key > 4095)
                    {
                        con_3 = 1;
                    }

                    if(con_1 && con_2 && con_3)
                    {
                        /*MAC格式转换*/
                        char mac_ce[MAX_CE_MAC_LEN];
                        memset(mac_ce, 0 ,MAX_CE_MAC_LEN);
                        mac_translate_ovsdb_to_ce(ovsdb_vtep_db_table.table_ucast_macs_remote[j].MAC, mac_ce);

                        /*ce_undo_config_vxlan_tunnel_static_mac(mac_ce,
                            ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0],
                            ovsdb_vtep_db_table.table_physical_locator[k].dst_ip,
                            ovsdb_vtep_db_table.table_logical_switch[m].tunnel_key);*/

                        uiRet = netconf_ce_undo_config_vxlan_tunnel_static_mac(
                            mac_ce,
                            ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0],
                            ovsdb_vtep_db_table.table_physical_locator[k].dst_ip,
                            ovsdb_vtep_db_table.table_logical_switch[m].tunnel_key);

                        if (OVSDB_OK != uiRet)
                        {
                            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to undo static mac of vxlan tunnel");
                            return;
                        }

                    }

                    #endif

                    /*释放空间*/
                    if(ovsdb_vtep_db_table.table_mcast_macs_local[j].MAC)
                    {
                        free(ovsdb_vtep_db_table.table_mcast_macs_local[j].MAC);
                    }
                    if(ovsdb_vtep_db_table.table_mcast_macs_local[j].ipaddr)
                    {
                        free(ovsdb_vtep_db_table.table_mcast_macs_local[j].ipaddr);
                    }
                    memset(&ovsdb_vtep_db_table.table_mcast_macs_local[j], 0, sizeof(struct ovsdb_vtep_table_mcast_macs_local));

                    break;
                }
            }
#endif

            break;
        }

        case TABLE_UPDATE:
        {
            break;
        }

        default:
            break;

    }

}


void ucast_macs_remote_table_process_2(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------ucast_macs_remote_table_node_stage_2,action=%s----------------",ACTION_TYPE(action));

    unsigned int uiRet = 0;
    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        case TABLE_UPDATE:
        {
#if OVSDB_DEBUG
            int i = 0;
            int j =0;
            int k = 0;
            int tunnel_key = 0;
            int physical_locator_exist = 0;
            struct uuid uuid_self;

            (void)uuid_from_string(&uuid_self, node_name);

            for(i = 0; i < TABLE_MCAST_MACS_REMOTE_NUM; i++)
            {
                if(uuid_equals(&uuid_self, &ovsdb_vtep_db_table.table_ucast_macs_remote[i].uuid_self))
                {
                    /*1.首先找到对应的ls的vni，如果vni不满足要求，可以直接返回*/
                    for(j = 0; j < TABLE_LOGICAL_SWITCH_NUM; j++)
                    {
                        if(uuid_equals(&ovsdb_vtep_db_table.table_ucast_macs_remote[i].logical_switch, &ovsdb_vtep_db_table.table_logical_switch[j].uuid_self))
                        {
                            tunnel_key = ovsdb_vtep_db_table.table_logical_switch[j].tunnel_key;
                            break;
                        }
                    }

                    if(tunnel_key < 4096)
                    {
                        break;  /*vni不满足则退出*/
                    }

                    /*2.确保隧道的dst_ip能找到*/
                    for(k = 0; k < TABLE_PHYSICAL_LOCATOR_NUM; k++)
                    {
                        if(uuid_equals(&ovsdb_vtep_db_table.table_ucast_macs_remote[i].locator, &ovsdb_vtep_db_table.table_physical_locator[k].uuid_self))
                        {
                            if(ovsdb_vtep_db_table.table_physical_locator[k].dst_ip)
                            {
                                physical_locator_exist = 1;
                            }

                            break;
                        }
                    }

                    if(!physical_locator_exist)
                    {
                        break;  /*没找到dst_ip则退出*/
                    }

                    /*3.判断隧道源IP是否存在*/
                    if(NULL == ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0])
                    {
                        OVSDB_PRINTF_DEBUG_ERROR("No tunnel ip in physical switch[0].");
                        break ;
                    }

                    /*4. MAC格式转换*/
                    char mac_ce[MAX_CE_MAC_LEN];
                    memset(mac_ce, 0, MAX_CE_MAC_LEN);
                    mac_translate_ovsdb_to_ce(ovsdb_vtep_db_table.table_ucast_macs_remote[i].MAC, mac_ce);

                    /*5. 配置静态MAC，这时候对应的隧道应该已经创建了*/
                    /*ce_config_vxlan_tunnel_static_mac(
                        mac_ce,
                        ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0],
                        ovsdb_vtep_db_table.table_physical_locator[k].dst_ip,
                        tunnel_key);*/
                    uiRet = netconf_ce_config_vxlan_tunnel_static_mac(
                        mac_ce,
                        ovsdb_vtep_db_table.table_physical_switch[0].tunnel_ips[0],
                        ovsdb_vtep_db_table.table_physical_locator[k].dst_ip,
                        tunnel_key);

                    if (OVSDB_OK != uiRet)
                    {
                        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config static mac of vxlan tunnel.");
                        return;
                    }

                    break;
                }
            }
#endif
            break;
        }

        case TABLE_DELETE:
        {

            break;
        }

        default:
            break;

    }

}


void mcast_macs_local_table_process(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------mcast_macs_local_table_node,action=%s----------------",ACTION_TYPE(action));

    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        {
            struct json *MAC;
            struct json *ip_addr;
            struct json *logic_switch;
            struct json_array *logic_switch_array;
            struct json *uuid_logic_switch;

            struct json *locator_set;
            struct json_array *locator_set_array;
            struct json *uuid_locator_set;

            int i = 0;

            MAC = shash_find_data(json_object(new), "MAC");
            ip_addr = shash_find_data(json_object(new), "ipaddr");    /*ipaddr is always empty,so ignore it. otherwise ,error occur while memcpy.*/

            logic_switch= shash_find_data(json_object(new), "logical_switch");
            logic_switch_array = json_array(logic_switch);
            uuid_logic_switch = logic_switch_array->elems[1];   /*elems[0] is "uuid" const string*/

            locator_set= shash_find_data(json_object(new), "locator_set");
            locator_set_array = json_array(locator_set);
            uuid_locator_set = locator_set_array->elems[1];   /*elems[0] is "uuid" const string*/

            for(i=0; i<TABLE_MCAST_MACS_LOCAL_NUM; i++)
            {
                /*获取表中的第一个不为0的表项*/
                if(!uuid_is_zero(&ovsdb_vtep_db_table.table_mcast_macs_local[i].uuid_self))
                {
                    continue;
                }
                else
                {
                    /*uuid*/
                    (void)uuid_from_string(&ovsdb_vtep_db_table.table_mcast_macs_local[i].uuid_self, node_name);
                    /*MAC*/
                    ovsdb_vtep_db_table.table_mcast_macs_local[i].MAC = malloc(strlen(json_string(MAC))+1) ;
                    memcpy(ovsdb_vtep_db_table.table_mcast_macs_local[i].MAC, json_string(MAC), strlen(json_string(MAC))+1);
                    /*ip_addr*/
                    /*不处理ipaddr*/
                    //ovsdb_vtep_db_table.table_ucast_macs_local[i].ipaddr = malloc(strlen(json_string(ip_addr))+1) ;
                    //memcpy(ovsdb_vtep_db_table.table_ucast_macs_local[i].ipaddr, json_string(ip_addr), strlen(json_string(ip_addr))+1);
                    OVSDB_PRINTF_DEBUG_TRACE("mcast_macs_local_table i=%d, MAC=%s, ipaddr=NULL", i, ovsdb_vtep_db_table.table_mcast_macs_local[i].MAC);
                    OVSDB_PRINTF_DEBUG_TRACE("mcast_macs_local_table uuid = "UUID_FMT, UUID_ARGS(&ovsdb_vtep_db_table.table_mcast_macs_local[i].uuid_self));

                    /*uuid of Logical_Switch*/
                    (void)uuid_from_string(&ovsdb_vtep_db_table.table_mcast_macs_local[i].logical_switch, json_string(uuid_logic_switch));
                    OVSDB_PRINTF_DEBUG_TRACE("M Local table Logical_Switch uuid = "UUID_FMT, UUID_ARGS(&ovsdb_vtep_db_table.table_mcast_macs_local[i].logical_switch));

                    /*uuid of Physical_Locator_Set*/
                    (void)uuid_from_string(&ovsdb_vtep_db_table.table_mcast_macs_local[i].locator_set, json_string(uuid_locator_set));
                    OVSDB_PRINTF_DEBUG_TRACE("M Local table Physical_Locator_Set uuid = "UUID_FMT, UUID_ARGS(&ovsdb_vtep_db_table.table_mcast_macs_local[i].locator_set));

                    break;
                }
            }
            break;
        }

        case TABLE_DELETE:
        {
            struct uuid deleted_mcast_local_uuid;
            int j=0;

            uuid_zero(&deleted_mcast_local_uuid);
            (void)uuid_from_string(&deleted_mcast_local_uuid, node_name);
            OVSDB_PRINTF_DEBUG_TRACE("deleted mcast local uuid = "UUID_FMT, UUID_ARGS(&deleted_mcast_local_uuid));

            for(j=0; j<TABLE_MCAST_MACS_LOCAL_NUM; j++)
            {
                if(uuid_equals(&deleted_mcast_local_uuid, &ovsdb_vtep_db_table.table_mcast_macs_local[j].uuid_self))
                {

                    /*释放空间*/
                    if(ovsdb_vtep_db_table.table_mcast_macs_local[j].MAC)
                    {
                        free(ovsdb_vtep_db_table.table_mcast_macs_local[j].MAC);
                    }
                    if(ovsdb_vtep_db_table.table_mcast_macs_local[j].ipaddr)
                    {
                        free(ovsdb_vtep_db_table.table_mcast_macs_local[j].ipaddr);
                    }
                    memset(&ovsdb_vtep_db_table.table_mcast_macs_local[j], 0, sizeof(struct ovsdb_vtep_table_mcast_macs_local));

                    break;
                }
            }

            break;
        }

        case TABLE_UPDATE:
        {
            ovsdb_mcast_local_update_locator_set_process(new, old, node_name);

            break;
        }

        default:
            break;

    }

}


void mcast_macs_local_table_process_2(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------mcast_macs_local_table_node_stage_2,action=%s----------------",ACTION_TYPE(action));
    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        {

            break;
        }

        case TABLE_DELETE:
        {

            break;
        }

        case TABLE_UPDATE:
        {

            break;
        }

        default:
            break;

    }

}

void mcast_macs_remote_table_process_add
(
    struct jsonrpc *rpc,
    struct json *new,
    struct json *old OVS_UNUSED,
    char* node_name,
    int action OVS_UNUSED
)
{
    int ret;
    struct uuid uuid_self;
    struct json *MAC;
    struct json *ip_addr;
    struct json *logic_switch;
    struct json_array *logic_switch_array;
    struct uuid uuid_logic_switch;
    struct json *locator_set;
    struct json_array *locator_set_array;
    struct uuid uuid_locator_set;

    /*uuid*/
    (void)uuid_from_string(&uuid_self, node_name);

    MAC = shash_find_data(json_object(new), "MAC");
    ip_addr = shash_find_data(json_object(new), "ipaddr");

    logic_switch= shash_find_data(json_object(new), "logical_switch");
    logic_switch_array = json_array(logic_switch);
    (void)uuid_from_string(&uuid_logic_switch, json_string(logic_switch_array->elems[1]));

    locator_set= shash_find_data(json_object(new), "locator_set");
    locator_set_array = json_array(locator_set);
    (void)uuid_from_string(&uuid_locator_set, json_string(locator_set_array->elems[1]));

    ret = ovsdb_table_mcast_macs_remote_add(&uuid_self, json_string(MAC), json_string(ip_addr),
                                            &uuid_logic_switch, &uuid_locator_set);
    if (ret != OVSDB_OK)
    {
        OVSDB_PRINTF_DEBUG_ERROR("Add mcast macs remote error, ret = %d, UUDI: "UUID_FMT,
                                 ret, UUID_ARGS(&uuid_self));
        return;
    }

    /* 下发servicenode节点 */
    ovsdb_mcast_macs_remote_process_add(rpc, &uuid_self);

    return;
}

void mcast_macs_remote_table_process_delete
(
    struct jsonrpc *rpc,
    struct json *new OVS_UNUSED,
    struct json *old OVS_UNUSED,
    char* node_name,
    int action OVS_UNUSED
)
{
    struct uuid deleted_mcast_remote_uuid;
    int ret;

    uuid_zero(&deleted_mcast_remote_uuid);
    (void)uuid_from_string(&deleted_mcast_remote_uuid, node_name);
    OVSDB_PRINTF_DEBUG_TRACE("deleted mcast remote uuid = "UUID_FMT, UUID_ARGS(&deleted_mcast_remote_uuid));

    /* 删除servicenode节点 */
    ovsdb_mcast_macs_remote_process_delete(rpc, &deleted_mcast_remote_uuid);

    ret = ovsdb_table_mcast_macs_remote_delete(&deleted_mcast_remote_uuid);
    if (ret != OVSDB_OK) {
        OVSDB_PRINTF_DEBUG_ERROR("Delete mcast macs remote error, ret = %d, UUDI: "UUID_FMT,
            ret, UUID_ARGS(&deleted_mcast_remote_uuid));
    }

    return;
}

void mcast_macs_remote_table_process_update
(
    struct jsonrpc *rpc,
    struct json *new,
    struct json *old,
    char* node_name,
    int action
)
{
    struct uuid update_mcast_remote_uuid;
    int ret;
    struct ovsdb_vtep_table_mcast_macs_remote * pstMMR;
    struct ovsdb_vtep_table_physical_locator_set * pstPLS;
    struct ovsdb_vtep_table_physical_locator * pstLocalPL;

    mcast_macs_remote_table_process_delete(rpc, new, old, node_name, action);
    mcast_macs_remote_table_process_add(rpc, new, old, node_name, action);

    uuid_zero(&update_mcast_remote_uuid);
    (void)uuid_from_string(&update_mcast_remote_uuid, node_name);
    OVSDB_PRINTF_DEBUG_TRACE("deleted mcast remote uuid = "UUID_FMT, UUID_ARGS(&update_mcast_remote_uuid));

    //找出当前的所有BFD Tunnel列表
    struct tunnel_table_query current_tunnel_list[PHYSICAL_SWITCH_TUNNELS_NUM];
    unsigned int tunnel_num = 0;
    unsigned int i, j;
    bool exist;

    (void)memset(current_tunnel_list, 0, sizeof(struct tunnel_table_query) * PHYSICAL_SWITCH_TUNNELS_NUM);

    do_transact_temp_query_all_tunnel_uuid(rpc, current_tunnel_list, &tunnel_num);

    //找出现在存在应该下发的BFD Tunnel列表
    pstMMR = ovsdb_table_mcast_macs_remote_query(&update_mcast_remote_uuid);
    if (NULL == pstMMR) {
        OVSDB_PRINTF_DEBUG_ERROR("Can't find mcast_macs_remote entry, UUDI: "UUID_FMT,
            UUID_ARGS(&update_mcast_remote_uuid));
        return;
    }

    pstPLS = ovsdb_table_physical_locator_set_query(&pstMMR->locator_set);
    if (NULL == pstPLS) {
        OVSDB_PRINTF_DEBUG_ERROR("Can't find physical_locator_set entry, UUDI: "UUID_FMT,
            UUID_ARGS(&pstMMR->locator_set));
        return;
    }

    for (j = 0; j < tunnel_num; j++)
    {
        exist = false;
        for (i = 0; i < pstPLS->used_num_locators; i++)
        {
            if (uuid_equals(&current_tunnel_list[j].remote_uuid, &pstPLS->locators[i])) {
                exist = true;
                break;
            }
        }

        if (true == exist) {
            continue;
        }

        do_transact_temp_delete_tunnel_byuuid(rpc, &current_tunnel_list[j].tunnel_uuid);
    }

    pstLocalPL = ovsdb_table_physical_locator_query_byip(OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_TUNNERIP));
    if (NULL == pstLocalPL)
        return;
    
    for (i = 0; i < pstPLS->used_num_locators; i++)
    {
        exist = false;
        for (j = 0; j < tunnel_num; j++)
        {
            if (uuid_equals(&current_tunnel_list[j].remote_uuid, &pstPLS->locators[i])) {
                exist = true;
                break;
            }
        }

        if (true == exist) {
            continue;
        }

        ovsdb_tunnel_add_ovsdb(rpc, &pstPLS->locators[i], &pstLocalPL->uuid_self);
    }

    return;
}

void mcast_macs_remote_table_process(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------mcast_macs_remote_table_node,action=%s----------------",ACTION_TYPE(action));

    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        {
            mcast_macs_remote_table_process_add(rpc, new, old, node_name, action);
            break;
        }

        case TABLE_DELETE:
        {
            mcast_macs_remote_table_process_delete(rpc, new, old, node_name, action);
            break;
        }

        case TABLE_UPDATE:
        {
            mcast_macs_remote_table_process_update(rpc, new, old, node_name, action);
            break;
        }

        default:
            break;
    }
}

void mcast_macs_remote_table_process_2(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------mcast_macs_remote_table_node_stage_2,action=%s----------------",ACTION_TYPE(action));
    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        {

            break;
        }

        case TABLE_DELETE:
        {

            break;
        }

        case TABLE_UPDATE:
        {

            break;
        }

        default:
            break;

    }

}

void tunnel_table_process_translate_entry
(
    struct ovsdb_vtep_table_tunnel *tunnel_entry,
    char *node_name,
    struct json *new
)
{
    struct json *new_bfd_item = NULL;

    uuid_from_string(&tunnel_entry->uuid_self1, node_name);

    /* 获取bfd_config_local参数 */
    new_bfd_item = shash_find_data(json_object(new), "bfd_config_local");
    if ((NULL != new_bfd_item) && (0 != TUNNEL_TABLE_GET_NUMBER(new_bfd_item)))
    {
        struct json *new_bfd_config_local_ip = NULL;
        new_bfd_config_local_ip = TUNNEL_TABLE_GET_VALUE(new_bfd_item, 0);
        OVSDB_SET_STR(tunnel_entry->bfd_config_local.bfd_ip, json_string(new_bfd_config_local_ip));

        struct json *new_bfd_config_local_mac = NULL;
        new_bfd_config_local_mac = TUNNEL_TABLE_GET_VALUE(new_bfd_item, 1);
        OVSDB_SET_STR(tunnel_entry->bfd_config_local.bfd_mac, json_string(new_bfd_config_local_mac));
    }

    /* 获取bfd_config_remote参数 */
    new_bfd_item = shash_find_data(json_object(new), "bfd_config_remote");
    if ((NULL != new_bfd_item) && (0 != TUNNEL_TABLE_GET_NUMBER(new_bfd_item)))
    {
        struct json *new_bfd_config_remote_ip = NULL;
        new_bfd_config_remote_ip = TUNNEL_TABLE_GET_VALUE(new_bfd_item, 0);
        OVSDB_SET_STR(tunnel_entry->bfd_config_remote.bfd_ip, json_string(new_bfd_config_remote_ip));

        struct json *new_bfd_config_remote_mac = NULL;
        new_bfd_config_remote_mac = TUNNEL_TABLE_GET_VALUE(new_bfd_item, 1);
        OVSDB_SET_STR(tunnel_entry->bfd_config_remote.bfd_mac, json_string(new_bfd_config_remote_mac));
    }

    /* 获取bfd_params参数 */
    new_bfd_item = shash_find_data(json_object(new), "bfd_params");
    if (NULL != new_bfd_item)
    {
        int i;
        char * item_name;
        char * item_value;

        for (i = 0; i < TUNNEL_TABLE_GET_NUMBER(new_bfd_item); i++)
        {
            item_name = json_string(TUNNEL_TABLE_GET_NAME(new_bfd_item, i));
            item_value = TUNNEL_TABLE_GET_VALUE(new_bfd_item, i);
            if (0 == strcmp("enable", item_name))
            {
                OVSDB_SET_STR(tunnel_entry->bfd_params.enable, json_string(item_value));
            }
            else if (!strcmp("min_rx", item_name))
            {
                OVSDB_SET_STR(tunnel_entry->bfd_params.min_rx, json_string(item_value));
            }
            else if (!strcmp("min_tx", item_name))
            {
                OVSDB_SET_STR(tunnel_entry->bfd_params.min_tx, json_string(item_value));
            }
            else if (!strcmp("decay_min_rx", item_name))
            {
                OVSDB_SET_STR(tunnel_entry->bfd_params.decay_min_rx, json_string(item_value));
            }
            else if (!strcmp("forwarding_if_rx", item_name))
            {
                OVSDB_SET_STR(tunnel_entry->bfd_params.forwarding_if_rx, json_string(item_value));
            }
            else if (!strcmp("cpath_down", item_name))
            {
                OVSDB_SET_STR(tunnel_entry->bfd_params.cpath_down, json_string(item_value));
            }
            else if (!strcmp("check_tnl_key", item_name))
            {
                OVSDB_SET_STR(tunnel_entry->bfd_params.check_tnl_key, json_string(item_value));
            }
        }
    }

    /* 获取bfd_status参数 */
    new_bfd_item = shash_find_data(json_object(new), "bfd_status");
    if (NULL != new_bfd_item)
    {
        int i;
        char * item_name;
        char * item_value;

        for (i = 0; i < TUNNEL_TABLE_GET_NUMBER(new_bfd_item); i++)
        {
            item_name = json_string(TUNNEL_TABLE_GET_NAME(new_bfd_item, i));
            item_value = TUNNEL_TABLE_GET_VALUE(new_bfd_item, i);
            if (0 == strcmp("enable", item_name))
            {
                OVSDB_SET_STR(tunnel_entry->bfd_status.enable, json_string(item_value));
            }
            else if (!strcmp("state", item_name))
            {
                OVSDB_SET_STR(tunnel_entry->bfd_status.state, json_string(item_value));
            }
            else if (!strcmp("forwarding", item_name))
            {
                OVSDB_SET_STR(tunnel_entry->bfd_status.forwarding, json_string(item_value));
            }
            else if (!strcmp("diagnostic", item_name))
            {
                OVSDB_SET_STR(tunnel_entry->bfd_status.diagnostic, json_string(item_value));
            }
            else if (!strcmp("remote_state", item_name))
            {
                OVSDB_SET_STR(tunnel_entry->bfd_status.remote_state, json_string(item_value));
            }
            else if (!strcmp("remote_diagnostic", item_name))
            {
                OVSDB_SET_STR(tunnel_entry->bfd_status.remote_diagnostic, json_string(item_value));
            }
            else if (!strcmp("info", item_name))
            {
                OVSDB_SET_STR(tunnel_entry->bfd_status.info, json_string(item_value));
            }
        }
    }

    /* 生成name */
    if (NULL != tunnel_entry->bfd_config_remote.bfd_ip) {
        if (OVSDB_OK != ip_translate_bfd_sessname(tunnel_entry->bfd_config_remote.bfd_ip, tunnel_entry->name)) {
            OVSDB_PRINTF_DEBUG_ERROR("BFD remote dst ip is illegal, ip: %s, tunnel uuid:"UUID_FMT,
                        tunnel_entry->bfd_config_remote.bfd_ip, UUID_ARGS(&tunnel_entry->uuid_self1));
            return;
        }
    }

    /* 设置默认值 */
    if (NULL == tunnel_entry->bfd_params.min_rx)
        OVSDB_SET_STR(tunnel_entry->bfd_params.min_rx, "1000");

    if (NULL == tunnel_entry->bfd_params.min_tx)
        OVSDB_SET_STR(tunnel_entry->bfd_params.min_tx, "1000");

    return;
}

bool tunnel_table_entry_check(struct ovsdb_vtep_table_tunnel *entry)
{
    if (0 == strlen(entry->name))
        return false;

    if ((NULL == entry->bfd_config_remote.bfd_ip) ||
        (NULL == entry->bfd_config_remote.bfd_mac) ||
        (NULL == entry->bfd_config_local.bfd_ip) ||
        ((NULL == entry->bfd_params.enable) ||
        (0 != strcmp(entry->bfd_params.enable, "true"))))
        return false;

    return true;
}

void tunnel_table_process_update(struct jsonrpc *rpc, struct json *new, struct json *old, char *node_name, int action)
{
    struct ovsdb_vtep_table_tunnel *current_tunnel;
    struct ovsdb_vtep_table_tunnel new_tunnel;
    struct netconf_ce_bfd_session stBfdSession;
    unsigned int ret;
    int iret;
    char mac_ce[MAX_CE_MAC_LEN];

    (void)memset(&new_tunnel, 0, sizeof(new_tunnel));
    (void)memset(&stBfdSession, 0, sizeof(stBfdSession));

    tunnel_table_process_translate_entry(&new_tunnel, node_name, new);

    current_tunnel = ovsdb_table_tunnel_query(&new_tunnel.uuid_self1);
    if (NULL == current_tunnel) {
        //添加流程
        if (false == tunnel_table_entry_check(&new_tunnel))
            return;

        stBfdSession.bfd_session_name = new_tunnel.name;
        stBfdSession.bfd_peer_ip = new_tunnel.bfd_config_remote.bfd_ip;
        mac_translate_ovsdb_to_ce(new_tunnel.bfd_config_remote.bfd_mac, mac_ce);
        stBfdSession.bfd_peer_mac = mac_ce;
        stBfdSession.bfd_src_ip = new_tunnel.bfd_config_local.bfd_ip;

        stBfdSession.min_rx = new_tunnel.bfd_params.min_rx;
        stBfdSession.min_tx = new_tunnel.bfd_params.min_tx;
            
        ret = netconf_ce_config_bfd_session(&stBfdSession);
        if (ret != OVSDB_OK) {
            OVSDB_PRINTF_DEBUG_ERROR("Config BFD error, UUID: "UUID_FMT,
                UUID_ARGS(&new_tunnel.uuid_self1));
        }

        iret = ovsdb_table_tunnel_add(&new_tunnel);
        if (ret != OVSDB_OK) {
            OVSDB_PRINTF_DEBUG_ERROR("Save BFD entry error, UUID: "UUID_FMT,
                UUID_ARGS(&new_tunnel.uuid_self1));
        }
    }
    else {
        //更新流程
        if (false == tunnel_table_entry_check(&new_tunnel)) {
            //删除现有隧道
            stBfdSession.bfd_session_name = current_tunnel->name;
            ret = netconf_ce_undo_config_bfd_session(&stBfdSession);
            if (ret != OVSDB_OK) {
                OVSDB_PRINTF_DEBUG_ERROR("Undo config BFD error, UUID: "UUID_FMT,
                    UUID_ARGS(&current_tunnel->uuid_self1));
            }
            
            iret = ovsdb_table_tunnel_delete(&current_tunnel->uuid_self1);
            if (ret != OVSDB_OK) {
                OVSDB_PRINTF_DEBUG_ERROR("Delete BFD entry error, UUID: "UUID_FMT,
                    UUID_ARGS(&current_tunnel->uuid_self1));
            }
        }
        else {
            if ((0 != strcmp(new_tunnel.bfd_params.min_rx, current_tunnel->bfd_params.min_rx)) ||
                (0 != strcmp(new_tunnel.bfd_params.min_tx, current_tunnel->bfd_params.min_tx))) {
                stBfdSession.bfd_session_name = new_tunnel.name;
                stBfdSession.bfd_peer_ip = new_tunnel.bfd_config_remote.bfd_ip;
                mac_translate_ovsdb_to_ce(new_tunnel.bfd_config_remote.bfd_mac, mac_ce);
                stBfdSession.bfd_peer_mac = mac_ce;
                stBfdSession.bfd_src_ip = new_tunnel.bfd_config_local.bfd_ip;

                stBfdSession.min_rx = new_tunnel.bfd_params.min_rx;
                stBfdSession.min_tx = new_tunnel.bfd_params.min_tx;
                    
                ret = netconf_ce_config_bfd_session(&stBfdSession);
                if (ret != OVSDB_OK) {
                    OVSDB_PRINTF_DEBUG_ERROR("Config BFD error, UUID: "UUID_FMT,
                        UUID_ARGS(&new_tunnel.uuid_self1));
                }

                OVSDB_SET_STR(current_tunnel->bfd_params.min_rx, new_tunnel.bfd_params.min_rx);
                OVSDB_SET_STR(current_tunnel->bfd_params.min_tx, new_tunnel.bfd_params.min_tx);
            }
            
        }
    }

    ovsdb_table_tunnel_destroy_entry(&new_tunnel);

    return;
}

void tunnel_table_process_delete(struct jsonrpc *rpc, struct json *new, struct json *old, char *node_name, int action)
{
    struct uuid uuid_self;
    struct ovsdb_vtep_table_tunnel *current_tunnel;
    struct netconf_ce_bfd_session stBfdSession;
    unsigned int ret;
    int iret;

    uuid_from_string(&uuid_self, node_name);

    current_tunnel = ovsdb_table_tunnel_query(&uuid_self);
    if (NULL != current_tunnel) {
        stBfdSession.bfd_session_name = current_tunnel->name;
        ret = netconf_ce_undo_config_bfd_session(&stBfdSession);
        if (ret != OVSDB_OK) {
            OVSDB_PRINTF_DEBUG_ERROR("Undo config BFD error, UUID: "UUID_FMT,
                UUID_ARGS(&current_tunnel->uuid_self1));
        }
        
        iret = ovsdb_table_tunnel_delete(&current_tunnel->uuid_self1);
        if (ret != OVSDB_OK) {
            OVSDB_PRINTF_DEBUG_ERROR("Delete BFD entry error, UUID: "UUID_FMT,
                UUID_ARGS(&current_tunnel->uuid_self1));
        }
    }

    return;
}

void tunnel_table_process(struct jsonrpc *rpc, struct json *new, struct json *old, char *node_name, int action)
{
    OVSDB_PRINTF_DEBUG_TRACE("----------------tunnel_table_node, action=%s----------------",ACTION_TYPE(action));

    switch(action)
    {
        case TABLE_INITIAL:
        case TABLE_INSERT:
        case TABLE_UPDATE:
        {
            tunnel_table_process_update(rpc, new, old, node_name, action);
            break;
        }

        case TABLE_DELETE:
        {
            tunnel_table_process_delete(rpc, new, old, node_name, action);
            break;
        }

        default:
            break;

    }
    return;
}

void tunnel_table_process_2(struct jsonrpc *rpc, struct json *new, struct json *old, char *node_name, int action)
{
    return;
}

void logical_binding_stats_table_process(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    return;
}

void logical_binding_stats_table_process_2(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{

    return;
}

void logical_router_table_process(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    return;
}

void logical_router_table_process_2(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    return;
}


void manager_table_process(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    return;
}

void manager_table_process_2(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    return;
}

void arp_sources_local_table_process(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    return;
}

void arp_sources_local_table_process_2(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    return;
}


void arp_sources_remote_table_process(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    return;
}

void arp_sources_remote_table_process_2(struct jsonrpc *rpc, struct json *new, struct json *old, char* node_name, int action)
{
    return;
}



static void
monitor_print_table(struct json *table_update,
                    const struct monitored_table *mt, char *caption,
                    bool initial)
{
    const struct ovsdb_table_schema *table = mt->table;
    const struct ovsdb_column_set *columns = &mt->columns;
    struct shash_node *node;
    struct table t;
    size_t i;

    if (table_update->type != JSON_OBJECT) {
        ovs_error(0, "<table-update> for table %s is not object", table->name);
        return;
    }

    table_init(&t);
    table_set_timestamp(&t, timestamp);
    table_set_caption(&t, caption);

    table_add_column(&t, "row");
    table_add_column(&t, "action");
    for (i = 0; i < columns->n_columns; i++) {
        table_add_column(&t, "%s", columns->columns[i]->name);
    }
    SHASH_FOR_EACH (node, json_object(table_update)) {
        struct json *row_update = node->data;
        struct json *old, *new;

        if (row_update->type != JSON_OBJECT) {
            ovs_error(0, "<row-update> is not object");
            continue;
        }
        old = shash_find_data(json_object(row_update), "old");
        new = shash_find_data(json_object(row_update), "new");
        if (initial) {
            monitor_print_row(new, "initial", node->name, columns, &t);
        } else if (!old) {
            monitor_print_row(new, "insert", node->name, columns, &t);
        } else if (!new) {
            monitor_print_row(old, "delete", node->name, columns, &t);
        } else {
            monitor_print_row(old, "old", node->name, columns, &t);
            monitor_print_row(new, "new", "", columns, &t);
        }
    }
    table_print(&t, &table_style);
    table_destroy(&t);
}

static void
monitor_print(struct json *table_updates,
              const struct monitored_table *mts, size_t n_mts,
              bool initial)
{
    size_t i;

    if (table_updates->type != JSON_OBJECT) {
        ovs_error(0, "<table-updates> is not object");
        return;
    }

    for (i = 0; i < n_mts; i++) {
        const struct monitored_table *mt = &mts[i];

#if 1
        if (0 == strcmp("Manager", mt->table->name))
            continue;
#endif

        struct json *table_update = shash_find_data(json_object(table_updates),
                                                    mt->table->name);
        if (table_update) {
            monitor_print_table(table_update, mt,
                                n_mts > 1 ? xstrdup(mt->table->name) : NULL,
                                initial);
        }
    }
}

static void
add_column(const char *server, const struct ovsdb_column *column,
           struct ovsdb_column_set *columns, struct json *columns_json)
{
    if (ovsdb_column_set_contains(columns, column->index)) {
        ovs_fatal(0, "%s: column \"%s\" mentioned multiple times",
                  server, column->name);
    }
    ovsdb_column_set_add(columns, column);
    json_array_add(columns_json, json_string_create(column->name));
}

static struct json *
parse_monitor_columns(char *arg, const char *server, const char *database,
                      const struct ovsdb_table_schema *table,
                      struct ovsdb_column_set *columns)
{
    bool initial, insert, delete, modify;
    struct json *mr, *columns_json;
    char *save_ptr = NULL;
    char *token;

    mr = json_object_create();
    columns_json = json_array_create_empty();
    json_object_put(mr, "columns", columns_json);

    initial = insert = delete = modify = true;
    for (token = strtok_r(arg, ",", &save_ptr); token != NULL;
         token = strtok_r(NULL, ",", &save_ptr)) {
        if (!strcmp(token, "!initial")) {
            initial = false;
        } else if (!strcmp(token, "!insert")) {
            insert = false;
        } else if (!strcmp(token, "!delete")) {
            delete = false;
        } else if (!strcmp(token, "!modify")) {
            modify = false;
        } else {
            const struct ovsdb_column *column;

            column = ovsdb_table_schema_get_column(table, token);
            if (!column) {
                ovs_fatal(0, "%s: table \"%s\" in %s does not have a "
                          "column named \"%s\"",
                          server, table->name, database, token);
            }
            add_column(server, column, columns, columns_json);
        }
    }

    if (columns_json->u.array.n == 0) {
        const struct shash_node **nodes;
        size_t i, n;

        n = shash_count(&table->columns);
        nodes = shash_sort(&table->columns);
        for (i = 0; i < n; i++) {
            const struct ovsdb_column *column = nodes[i]->data;
            if (column->index != OVSDB_COL_UUID
                && column->index != OVSDB_COL_VERSION) {
                add_column(server, column, columns, columns_json);
            }
        }
        free(nodes);

        add_column(server, ovsdb_table_schema_get_column(table, "_version"),
                   columns, columns_json);
    }

    if (!initial || !insert || !delete || !modify) {
        struct json *select = json_object_create();
        json_object_put(select, "initial", json_boolean_create(initial));
        json_object_put(select, "insert", json_boolean_create(insert));
        json_object_put(select, "delete", json_boolean_create(delete));
        json_object_put(select, "modify", json_boolean_create(modify));
        json_object_put(mr, "select", select);
    }

    return mr;
}

static void
ovsdb_client_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
}

static void
ovsdb_client_block(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[] OVS_UNUSED, void *blocked_)
{
    bool *blocked = blocked_;

    if (!*blocked) {
        *blocked = true;
        unixctl_command_reply(conn, NULL);
    } else {
        unixctl_command_reply(conn, "already blocking");
    }
}

static void
ovsdb_client_unblock(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *blocked_)
{
    bool *blocked = blocked_;

    if (*blocked) {
        *blocked = false;
        unixctl_command_reply(conn, NULL);
    } else {
        unixctl_command_reply(conn, "already unblocked");
    }
}

static void
add_monitored_table(int argc, char *argv[],
                    const char *server, const char *database,
                    struct ovsdb_table_schema *table,
                    struct json *monitor_requests,
                    struct monitored_table **mts,
                    size_t *n_mts, size_t *allocated_mts)
{
    struct json *monitor_request_array;
    struct monitored_table *mt;

    if (*n_mts >= *allocated_mts) {
        *mts = x2nrealloc(*mts, allocated_mts, sizeof **mts);
    }
    mt = &(*mts)[(*n_mts)++];
    mt->table = table;
    ovsdb_column_set_init(&mt->columns);

    monitor_request_array = json_array_create_empty();
    if (argc > 1) {
        int i;

        for (i = 1; i < argc; i++) {
            json_array_add(
                monitor_request_array,
                parse_monitor_columns(argv[i], server, database, table,
                                      &mt->columns));
        }
    } else {
        /* Allocate a writable empty string since parse_monitor_columns()
         * is going to strtok() it and that's risky with literal "". */
        char empty[] = "";
        json_array_add(
            monitor_request_array,
            parse_monitor_columns(empty, server, database,
                                  table, &mt->columns));
    }

    json_object_put(monitor_requests, table->name, monitor_request_array);
}


void do_table_process(struct jsonrpc *rpc, struct json *table_updates,
              const struct monitored_table *mts, size_t n_mts,
              bool initial)
{
    size_t i;

    if (table_updates->type != JSON_OBJECT) {
        ovs_error(0, "<table-updates> is not object");
        return;
    }

    for (i = 0; i < MAX_TABLE_ID; i++) {
        struct json *table_update = shash_find_data(json_object(table_updates),
                                                    table_func_map[i].table_name);
        if (table_update)
        {
            int table_id = 0;
            struct shash_node *node;

            OVSDB_PRINTF_DEBUG_TRACE("#################begin to process table [%s]#################", table_func_map[i].table_name);

            if (table_update->type != JSON_OBJECT) {
                ovs_error(0, "<table-update> for table %s is not object", table_func_map[i].table_name);
                return;
            }

            SHASH_FOR_EACH (node, json_object(table_update))
            {
                struct json *row_update = node->data;
                struct json *old, *new;

                if (row_update->type != JSON_OBJECT) {
                    ovs_error(0, "<row-update> is not object");
                    continue;
                }
                old = shash_find_data(json_object(row_update), "old");
                new = shash_find_data(json_object(row_update), "new");


                if (initial)
                {
                    table_func_map[i].callback(rpc, new, NULL, node->name, TABLE_INITIAL);
                }
                else if (!old)
                {
                    table_func_map[i].callback(rpc, new, NULL, node->name, TABLE_INSERT);
                }
                else if (!new)
                {
                    table_func_map[i].callback(rpc,NULL, old, node->name, TABLE_DELETE);
                }
                else
                {
                    table_func_map[i].callback(rpc, new, old, node->name, TABLE_UPDATE);
                }
            }
        }
    }
}

void do_table_process_2(struct jsonrpc *rpc, struct json *table_updates,
              const struct monitored_table *mts, size_t n_mts,
              bool initial)
{
    size_t i;

    if (table_updates->type != JSON_OBJECT) {
        ovs_error(0, "<table-updates> is not object");
        return;
    }

    for (i = 0; i < MAX_TABLE_ID; i++) {
        struct json *table_update = shash_find_data(json_object(table_updates),
                                                    table_func_map_2[i].table_name);
        if (table_update)
        {
            int table_id = 0;
            struct shash_node *node;

            OVSDB_PRINTF_DEBUG_TRACE("#################begin to process table [%s]#################", table_func_map_2[i].table_name);

            if (table_update->type != JSON_OBJECT) {
                ovs_error(0, "<table-update> for table %s is not object", table_func_map_2[i].table_name);
                return;
            }

            SHASH_FOR_EACH (node, json_object(table_update))
            {
                struct json *row_update = node->data;
                struct json *old, *new;

                if (row_update->type != JSON_OBJECT) {
                    ovs_error(0, "<row-update> is not object");
                    continue;
                }
                old = shash_find_data(json_object(row_update), "old");
                new = shash_find_data(json_object(row_update), "new");


                if (initial)
                {
                    table_func_map_2[i].callback(rpc, new, NULL, node->name, TABLE_INITIAL);
                }
                else if (!old)
                {
                    table_func_map_2[i].callback(rpc, new, NULL, node->name, TABLE_INSERT);
                }
                else if (!new)
                {
                    table_func_map_2[i].callback(rpc,NULL, old, node->name, TABLE_DELETE);
                }
                else
                {
                    table_func_map_2[i].callback(rpc, new, old, node->name, TABLE_UPDATE);
                }
            }
        }
    }
}


static void
do_monitor(struct jsonrpc *rpc, const char *database,
           int argc, char *argv[])
{
    const char *server = jsonrpc_get_name(rpc);
    const char *table_name = argv[0];
    struct unixctl_server *unixctl;
    struct ovsdb_schema *schema;
    struct jsonrpc_msg *request;
    struct json *monitor, *monitor_requests, *request_id;
    bool exiting = false;
    bool blocked = false;

    struct monitored_table *mts;
    size_t n_mts, allocated_mts;

    daemon_save_fd(STDOUT_FILENO);
    daemonize_start(false);
    if (get_detach()) {
        int error;

        error = unixctl_server_create(NULL, &unixctl);
        if (error) {
            ovs_fatal(error, "failed to create unixctl server");
        }

        unixctl_command_register("exit", "", 0, 0,
                                 ovsdb_client_exit, &exiting);
        unixctl_command_register("ovsdb-client/block", "", 0, 0,
                                 ovsdb_client_block, &blocked);
        unixctl_command_register("ovsdb-client/unblock", "", 0, 0,
                                 ovsdb_client_unblock, &blocked);
    } else {
        unixctl = NULL;
    }

    schema = fetch_schema(rpc, database);

    monitor_requests = json_object_create();

    mts = NULL;
    n_mts = allocated_mts = 0;
    if (strcmp(table_name, "ALL")) {
        struct ovsdb_table_schema *table;

        table = shash_find_data(&schema->tables, table_name);
        if (!table) {
            ovs_fatal(0, "%s: %s does not have a table named \"%s\"",
                      server, database, table_name);
        }

        add_monitored_table(argc, argv, server, database, table,
                            monitor_requests, &mts, &n_mts, &allocated_mts);
    } else {
        size_t n = shash_count(&schema->tables);
        const struct shash_node **nodes = shash_sort(&schema->tables);
        size_t i;

        for (i = 0; i < n; i++) {
            struct ovsdb_table_schema *table = nodes[i]->data;

            add_monitored_table(argc, argv, server, database, table,
                                monitor_requests,
                                &mts, &n_mts, &allocated_mts);
        }
        free(nodes);
    }

    monitor = json_array_create_3(json_string_create(database),
                                  json_null_create(), monitor_requests);
    request = jsonrpc_create_request("monitor", monitor, NULL);
    request_id = json_clone(request->id);
    jsonrpc_send(rpc, request);

    for (;;) {
        unixctl_server_run(unixctl);
        while (!blocked) {
            struct jsonrpc_msg *msg;
            int error;

            error = jsonrpc_recv(rpc, &msg);
            if (error == EAGAIN) {
                break;
            } else if (error) {
                ovs_fatal(error, "%s: receive failed", server);
            }

            if (msg->type == JSONRPC_REQUEST && !strcmp(msg->method, "echo")) {
                jsonrpc_send(rpc, jsonrpc_create_reply(json_clone(msg->params),
                                                       msg->id));
            } else if (msg->type == JSONRPC_REPLY
                       && json_equal(msg->id, request_id)) {
                monitor_print(msg->result, mts, n_mts, true);
                fflush(stdout);
                daemonize_complete();
            } else if (msg->type == JSONRPC_NOTIFY
                       && !strcmp(msg->method, "update")) {
                struct json *params = msg->params;
                if (params->type == JSON_ARRAY
                    && params->u.array.n == 2
                    && params->u.array.elems[0]->type == JSON_NULL) {
                    monitor_print(params->u.array.elems[1], mts, n_mts, false);
                    fflush(stdout);
                }
            }
            jsonrpc_msg_destroy(msg);
        }

        if (exiting) {
            break;
        }

        jsonrpc_run(rpc);
        jsonrpc_wait(rpc);
        if (!blocked) {
            jsonrpc_recv_wait(rpc);
        }
        unixctl_server_wait(unixctl);
        poll_block();
    }
}

struct dump_table_aux {
    struct ovsdb_datum **data;
    const struct ovsdb_column **columns;
    size_t n_columns;
};

static int
compare_data(size_t a_y, size_t b_y, size_t x,
             const struct dump_table_aux *aux)
{
    return ovsdb_datum_compare_3way(&aux->data[a_y][x],
                                    &aux->data[b_y][x],
                                    &aux->columns[x]->type);
}

static int
compare_rows(size_t a_y, size_t b_y, void *aux_)
{
    struct dump_table_aux *aux = aux_;
    size_t x;

    /* Skip UUID columns on the first pass, since their values tend to be
     * random and make our results less reproducible. */
    for (x = 0; x < aux->n_columns; x++) {
        if (aux->columns[x]->type.key.type != OVSDB_TYPE_UUID) {
            int cmp = compare_data(a_y, b_y, x, aux);
            if (cmp) {
                return cmp;
            }
        }
    }

    /* Use UUID columns as tie-breakers. */
    for (x = 0; x < aux->n_columns; x++) {
        if (aux->columns[x]->type.key.type == OVSDB_TYPE_UUID) {
            int cmp = compare_data(a_y, b_y, x, aux);
            if (cmp) {
                return cmp;
            }
        }
    }

    return 0;
}

static void
swap_rows(size_t a_y, size_t b_y, void *aux_)
{
    struct dump_table_aux *aux = aux_;
    struct ovsdb_datum *tmp = aux->data[a_y];
    aux->data[a_y] = aux->data[b_y];
    aux->data[b_y] = tmp;
}

static int
compare_columns(const void *a_, const void *b_)
{
    const struct ovsdb_column *const *ap = a_;
    const struct ovsdb_column *const *bp = b_;
    const struct ovsdb_column *a = *ap;
    const struct ovsdb_column *b = *bp;

    return strcmp(a->name, b->name);
}

static void
dump_table(const char *table_name, const struct shash *cols,
           struct json_array *rows)
{
    const struct ovsdb_column **columns;
    size_t n_columns;

    struct ovsdb_datum **data;

    struct dump_table_aux aux;
    struct shash_node *node;
    struct table t;
    size_t x, y;

    /* Sort columns by name, for reproducibility. */
    columns = xmalloc(shash_count(cols) * sizeof *columns);
    n_columns = 0;
    SHASH_FOR_EACH (node, cols) {
        struct ovsdb_column *column = node->data;
        if (strcmp(column->name, "_version")) {
            columns[n_columns++] = column;
        }
    }
    qsort(columns, n_columns, sizeof *columns, compare_columns);

    /* Extract data from table. */
    data = xmalloc(rows->n * sizeof *data);
    for (y = 0; y < rows->n; y++) {
        struct shash *row;

        if (rows->elems[y]->type != JSON_OBJECT) {
            ovs_fatal(0,  "row %"PRIuSIZE" in table %s response is not a JSON object: "
                      "%s", y, table_name, json_to_string(rows->elems[y], 0));
        }
        row = json_object(rows->elems[y]);

        data[y] = xmalloc(n_columns * sizeof **data);
        for (x = 0; x < n_columns; x++) {
            const struct json *json = shash_find_data(row, columns[x]->name);
            if (!json) {
                ovs_fatal(0, "row %"PRIuSIZE" in table %s response lacks %s column",
                          y, table_name, columns[x]->name);
            }

            check_ovsdb_error(ovsdb_datum_from_json(&data[y][x],
                                                    &columns[x]->type,
                                                    json, NULL));
        }
    }

    /* Sort rows by column values, for reproducibility. */
    aux.data = data;
    aux.columns = columns;
    aux.n_columns = n_columns;
    sort(rows->n, compare_rows, swap_rows, &aux);

    /* Add column headings. */
    table_init(&t);
    table_set_caption(&t, xasprintf("%s table", table_name));
    for (x = 0; x < n_columns; x++) {
        table_add_column(&t, "%s", columns[x]->name);
    }

    /* Print rows. */
    for (y = 0; y < rows->n; y++) {
        table_add_row(&t);
        for (x = 0; x < n_columns; x++) {
            struct cell *cell = table_add_cell(&t);
            cell->json = ovsdb_datum_to_json(&data[y][x], &columns[x]->type);
            cell->type = &columns[x]->type;
            ovsdb_datum_destroy(&data[y][x], &columns[x]->type);
        }
        free(data[y]);
    }
    table_print(&t, &table_style);
    table_destroy(&t);

    free(data);
    free(columns);
}

static void
do_dump(struct jsonrpc *rpc, const char *database,
        int argc, char *argv[])
{
    struct jsonrpc_msg *request, *reply;
    struct ovsdb_schema *schema;
    struct json *transaction;

    const struct shash_node *node, **tables;
    size_t n_tables;
    struct ovsdb_table_schema *tschema;
    const struct shash *columns;
    struct shash custom_columns;

    size_t i;

    shash_init(&custom_columns);
    schema = fetch_schema(rpc, database);
    if (argc) {
        node = shash_find(&schema->tables, argv[0]);
        if (!node) {
            ovs_fatal(0, "No table \"%s\" found.", argv[0]);
        }
        tables = xmemdup(&node, sizeof(&node));
        n_tables = 1;
        tschema = tables[0]->data;
        for (i = 1; i < argc; i++) {
            node = shash_find(&tschema->columns, argv[i]);
            if (!node) {
                ovs_fatal(0, "Table \"%s\" has no column %s.", argv[0], argv[1]);
            }
            shash_add(&custom_columns, argv[1], node->data);
        }
    } else {
        tables = shash_sort(&schema->tables);
        n_tables = shash_count(&schema->tables);
    }

    /* Construct transaction to retrieve entire database. */
    transaction = json_array_create_1(json_string_create(database));
    for (i = 0; i < n_tables; i++) {
        const struct ovsdb_table_schema *ts = tables[i]->data;
        struct json *op, *jcolumns;

        if (argc > 1) {
            columns = &custom_columns;
        } else {
            columns = &ts->columns;
        }
        jcolumns = json_array_create_empty();
        SHASH_FOR_EACH (node, columns) {
            const struct ovsdb_column *column = node->data;

            if (strcmp(column->name, "_version")) {
                json_array_add(jcolumns, json_string_create(column->name));
            }
        }

        op = json_object_create();
        json_object_put_string(op, "op", "select");
        json_object_put_string(op, "table", tables[i]->name);
        json_object_put(op, "where", json_array_create_empty());
        json_object_put(op, "columns", jcolumns);
        json_array_add(transaction, op);
    }

    /* Send request, get reply. */
    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);

    /* Print database contents. */
    if (reply->result->type != JSON_ARRAY
        || reply->result->u.array.n != n_tables) {
        ovs_fatal(0, "reply is not array of %"PRIuSIZE" elements: %s",
                  n_tables, json_to_string(reply->result, 0));
    }
    for (i = 0; i < n_tables; i++) {
        const struct ovsdb_table_schema *ts = tables[i]->data;
        const struct json *op_result = reply->result->u.array.elems[i];
        struct json *rows;

        if (op_result->type != JSON_OBJECT
            || !(rows = shash_find_data(json_object(op_result), "rows"))
            || rows->type != JSON_ARRAY) {
            ovs_fatal(0, "%s table reply is not an object with a \"rows\" "
                      "member array: %s",
                      ts->name, json_to_string(op_result, 0));
        }

        if (argc > 1) {
            dump_table(tables[i]->name, &custom_columns, &rows->u.array);
        } else {
            dump_table(tables[i]->name, &ts->columns, &rows->u.array);
        }
    }

    jsonrpc_msg_destroy(reply);
    shash_destroy(&custom_columns);
    free(tables);
    ovsdb_schema_destroy(schema);
}



void
do_transact_temp(struct jsonrpc *rpc, char *json_char)
{
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;

    transaction = parse_json(json_char);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);
    //print_json(reply->result);
    //putchar('\n');
    jsonrpc_msg_destroy(reply);
}

void
do_transact_temp_query_global(struct jsonrpc *rpc, int* global_uuid_num, struct uuid *uuid_global)
{
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct json_array *global_uuid;
    struct json *elem_0;
    struct json *rows;
    struct json_array *rows_elem;

    char *json_char = "[\"hardware_vtep\",{\"columns\":[\"_uuid\"],\"table\":\"Global\",\"where\":[],\"op\":\"select\"}]";

    transaction = parse_json(json_char);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);
    //print_json(reply->result);
    //putchar('\n');

    global_uuid = json_array(reply->result);
    elem_0 = global_uuid->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");
    rows_elem = json_array(rows);
    //printf("\nglobal_uuid number is %d\n", rows_elem->n);
    *global_uuid_num = rows_elem->n;
    if(!*global_uuid_num)
    {
        OVSDB_PRINTF_DEBUG_TRACE("global table is not present.\n");
    }

    if(*global_uuid_num)
    {
        struct json *rows_0;
        struct json *g_uuid;
        struct json_array *uuid_array;
        rows_0 = rows_elem->elems[0];
        g_uuid = shash_find_data(json_object(rows_0), "_uuid");
        uuid_array = json_array(g_uuid);
        uuid_from_string(uuid_global, json_string(uuid_array->elems[1]));/*elems[0] is "uuid" string*/
    }

    jsonrpc_msg_destroy(reply);
}

/*过滤不含tunnel_key的情况*/
void
do_transact_temp_query_logical_switch(struct jsonrpc *rpc, int *ls_num, struct logical_switch_uuid_and_vni *ls_info)
{
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct json_array *ls;
    struct json *elem_0;
    struct json *rows;
    struct json_array *rows_elem;
    int rows_elem_num=0;
    int i=0;
    int j=0;

    char *json_char = "[\"hardware_vtep\",{\"columns\":[\"description\",\"name\",\"_uuid\",\"tunnel_key\"],\"table\":\"Logical_Switch\",\"where\":[],\"op\":\"select\"}]";

    transaction = parse_json(json_char);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);
    //print_json(reply->result);
    //putchar('\n');

    ls = json_array(reply->result);
    elem_0 = ls->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");
    rows_elem = json_array(rows);
    rows_elem_num = rows_elem->n;
    if(!rows_elem_num)
    {
        OVSDB_PRINTF_DEBUG_TRACE("No logical switch present.");
    }
    else   /*rows_elem_num >= 1*/
    {
        for(i=0; i<rows_elem_num; i++)
        {
            struct json* ls_instance;
            struct json* tunnel_key;
            struct json* uuid_ls;
            struct json_array* uuid_array;

            ls_instance = rows_elem->elems[i];
            tunnel_key = shash_find_data(json_object(ls_instance), "tunnel_key");
            uuid_ls= shash_find_data(json_object(ls_instance), "_uuid");
            uuid_array = json_array(uuid_ls);

            if(JSON_ARRAY == tunnel_key->type)  /*which means this ls does not have a tunnel_key*/
            {
                OVSDB_PRINTF_DEBUG_TRACE("This logical_Switch does not have a tunnel_key.");
                continue;
            }
            else if(JSON_INTEGER == tunnel_key->type)
            {
                OVSDB_PRINTF_DEBUG_TRACE("This logical_Switch has a tunnel_key.");
                *ls_num=*ls_num + 1;
                for(j=0; j<TABLE_LOGICAL_SWITCH_NUM; j++)
                {
                    if(0 != ls_info[j].vni) /*not empty entry*/
                    {
                        continue;
                    }
                    else
                    {
                        ls_info[j].vni = json_integer(tunnel_key);
                        (void)uuid_from_string(&ls_info[j].uuid_ls, json_string(uuid_array->elems[1]));/*elems[0] is "uuid" string*/

                        //printf("ls_info[%d].vni = %d\n", j, ls_info[j].vni);
                        //printf("ls_info[%d].uuid_ls ="UUID_FMT"\n", j, UUID_ARGS(&ls_info[j].uuid_ls));

                        break;
                    }
                }
            }
        }
    }

    //printf("ls_num = %d\n", *ls_num);
    jsonrpc_msg_destroy(reply);
}


void do_transact_temp_query_logical_switch_has_mcast_local_record(struct jsonrpc *rpc, struct uuid *ls_uuid, int *ls_has_mcast_local_record, struct uuid *mac_uuid)
{
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct json_array *ls;
    struct json *elem_0;
    struct json *rows;
    struct json_array *rows_elem;
    int rows_elem_num=0;
    
    char json_char[1000]={0};
    
    snprintf(json_char, 1000, 
            "[\"hardware_vtep\",{\"columns\":[\"ipaddr\",\"_uuid\",\"logical_switch\",\"locator_set\",\"MAC\"],"
            "\"table\":\"Mcast_Macs_Local\",\"where\":[[\"logical_switch\",\"==\",[\"uuid\", \""UUID_FMT"\"]]],\"op\":\"select\"}]",
            UUID_ARGS(ls_uuid));
            
    transaction = parse_json(json_char);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);

    ls = json_array(reply->result);
    elem_0 = ls->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");
    rows_elem = json_array(rows);
    rows_elem_num = rows_elem->n;
    if(!rows_elem_num)
    {
        *ls_has_mcast_local_record = 0;
        OVSDB_PRINTF_DEBUG_TRACE("logical switch with uuid = "UUID_FMT"has no mcast local record.", UUID_ARGS(ls_uuid));
    }
    else
    {
        struct json* mac_instance;
        struct json* uuid_mac;
        struct json_array* uuid_array;
        
        *ls_has_mcast_local_record = 1;
        OVSDB_PRINTF_DEBUG_TRACE("logical switch with uuid = "UUID_FMT"has mcast local record.", UUID_ARGS(ls_uuid));
        
        /*理论上只会有一条记录*/
        mac_instance = rows_elem->elems[0];
        uuid_mac = shash_find_data(json_object(mac_instance), "_uuid");
        uuid_array = json_array(uuid_mac);
        (void)uuid_from_string(mac_uuid, json_string(uuid_array->elems[1]));

    }


    jsonrpc_msg_destroy(reply);
}

void do_transact_temp_query_logical_switch_has_ucast_remote_record(struct jsonrpc *rpc, struct uuid *ls_uuid, int *ls_has_mcast_local_record)
{
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct json_array *ls;
    struct json *elem_0;
    struct json *rows;
    struct json_array *rows_elem;
    int rows_elem_num=0;
    char json_char[1000]={0};
    
    snprintf(json_char, 1000, 
            "[\"hardware_vtep\",{\"columns\":[\"ipaddr\",\"_uuid\",\"logical_switch\",\"MAC\"],"
            "\"table\":\"Ucast_Macs_Remote\",\"where\":[[\"logical_switch\",\"==\",[\"uuid\", \""UUID_FMT"\"]]],\"op\":\"select\"}]",
            UUID_ARGS(ls_uuid));
            
    transaction = parse_json(json_char);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);

    ls = json_array(reply->result);
    elem_0 = ls->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");
    rows_elem = json_array(rows);
    rows_elem_num = rows_elem->n;
    if(!rows_elem_num)
    {
        *ls_has_mcast_local_record = 0;
        OVSDB_PRINTF_DEBUG_TRACE("logical switch with uuid = "UUID_FMT"has no ucast remote record.", UUID_ARGS(ls_uuid));
    }
    else
    {
        *ls_has_mcast_local_record = 1;
        OVSDB_PRINTF_DEBUG_TRACE("logical switch with uuid = "UUID_FMT"has ucast remote record.", UUID_ARGS(ls_uuid));
    }


    jsonrpc_msg_destroy(reply);
}


void
do_transact_temp_query_locator_dstip(struct jsonrpc *rpc, char *json_char, int *pl_exist, char* pl_dst_ip)
{
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct json_array *pl;
    struct json *elem_0;
    struct json *rows;
    struct json_array *rows_elem;
    int rows_elem_num = 0;
    struct json *dst_ip;

    transaction = parse_json(json_char);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);

    pl = json_array(reply->result);
    elem_0 = pl->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");
    rows_elem = json_array(rows);
    rows_elem_num = rows_elem->n;

    if(!rows_elem_num)
    {
        *pl_exist = 0;
    }
    else
    {
        *pl_exist = 1;
        dst_ip = shash_find_data(json_object(rows_elem->elems[0]), "dst_ip");
        if(dst_ip)
        {
            memcpy(pl_dst_ip, json_string(dst_ip), strlen(json_string(dst_ip))+1);
        }
    }

    jsonrpc_msg_destroy(reply);
}


void
do_transact_temp_query_locator_uuid(struct jsonrpc *rpc, char *dst_ip, struct uuid *locator_uuid)
{
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct json_array *pl;
    struct json *elem_0;
    struct json *rows;
    struct json *rows_0;
    struct json *uuid;
    struct json *uuid_value;
    char json_char[256] = {0};

    uuid_zero(locator_uuid);

    (void)snprintf(json_char, 256,
        "[\"hardware_vtep\",{\"columns\":[\"_uuid\",\"dst_ip\",\"encapsulation_type\"],"\
        "\"table\":\"Physical_Locator\",\"where\":[[\"dst_ip\",\"==\",\"%s\"]],\"op\":\"select\"}]",
        dst_ip);

    transaction = parse_json(json_char);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);

    //print_json(reply->result);
    //putchar('\n');

    pl= json_array(reply->result);
    elem_0 = pl->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");

    if(!json_array(rows)->n)
    {
        jsonrpc_msg_destroy(reply);
        return;
    }

    rows_0 = json_array(rows)->elems[0];
    uuid = shash_find_data(json_object(rows_0), "_uuid");

    if(!uuid )
    {
        jsonrpc_msg_destroy(reply);
        return;
    }

    uuid_value = json_array(uuid)->elems[1];    /*elems[0] is "uuid" string*/

    uuid_from_string(locator_uuid, json_string(uuid_value));

    jsonrpc_msg_destroy(reply);
}


void
do_transact_temp_query_physical_switch_uuid(struct jsonrpc *rpc, char *tunnel_ip, struct uuid *physical_switch_uuid)
{
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct json_array *pl;
    struct json *elem_0;
    struct json *rows;
    struct json_array *rows_elem;
    struct json *js_uuid;
    struct json *uuid_value;
    char json_query_physical_switch[256];

    (void)snprintf(json_query_physical_switch, 256,
        "[\"hardware_vtep\",{\"columns\":[\"_uuid\"],\"table\":\"Physical_Switch\","\
        "\"where\":[[\"tunnel_ips\",\"==\",\"%s\"]],\"op\":\"select\"}]", tunnel_ip);

    uuid_zero(physical_switch_uuid);

    transaction = parse_json(json_query_physical_switch);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);

    pl= json_array(reply->result);
    elem_0 = pl->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");

    if(0 == json_array(rows)->n) {
        jsonrpc_msg_destroy(reply);
        return;
    }

    rows = shash_find_data(json_object(elem_0), "rows");
    rows_elem = json_array(rows);
    js_uuid = shash_find_data(json_object(rows_elem->elems[0]),"_uuid");
    if (NULL != js_uuid) {
        uuid_value = json_array(js_uuid)->elems[1];    /*elems[0] is "uuid" string*/
        uuid_from_string(physical_switch_uuid, json_string(uuid_value));
    } 

    jsonrpc_msg_destroy(reply);

    return;
}

void
do_transact_temp_query_physical_switch_exist(struct jsonrpc *rpc, int *ps_exist, char *tunnel_ip)
{
    struct uuid physical_switch_uuid;

    do_transact_temp_query_physical_switch_uuid(rpc, tunnel_ip, &physical_switch_uuid);

    *ps_exist = (uuid_is_zero(&physical_switch_uuid)) ? 0 : 1;

    return;
}

void
do_transact_temp_query_physical_switch_tunnels(struct jsonrpc *rpc, int *ps_exist, char **tunnels)
{
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct json_array *pl;
    struct json *elem_0;
    struct json *rows;
    struct json_array *rows_elem;
    int rows_elem_num = 0;
    struct json *js_tunnels;
    struct json *tunnels_elem0 = NULL;
    struct json *tunnels_elem1 = NULL;
    char* json_query_physical_switch_tunnels = "[\"hardware_vtep\",{\"columns\":[\"_uuid\",\"tunnels\"],"\
        "\"table\":\"Physical_Switch\",\"where\":[],\"op\":\"select\"}]";
    int number = 0;

    transaction = parse_json(json_query_physical_switch_tunnels);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);

    //print_json(reply->result);
    //putchar('\n');

    pl = json_array(reply->result);
    elem_0 = pl->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");

    if (json_array(rows)->n)
    {
        rows = shash_find_data(json_object(elem_0), "rows");
        rows_elem = json_array(rows);
        rows_elem_num = rows_elem->n;
        js_tunnels = shash_find_data(json_object(rows_elem->elems[0]), "tunnels");
        tunnels_elem0 = json_array(js_tunnels)->elems[0];
        tunnels_elem1 = json_array(js_tunnels)->elems[1];

        if (0 == strcmp(json_string(tunnels_elem0), "set"))
        {
            number = json_array(tunnels_elem1)->n;
            if (0 != number)
            {
                char *string = json_to_string(reply->result, table_style.json_flags);
                char *stringOrig = string;
                char *stringLeft = NULL;
                char aTunnelsLeft[] = "\"set\",[";
                char aTunnelsRight[] = "]]}]}]";
                int tunnels_len = 0;
                OVSDB_CLIENT_GET_TUNNELS_FROM_PHYSICAL_SWITCH(stringLeft, &tunnels_len, aTunnelsLeft, aTunnelsRight, string);

                *tunnels = malloc(tunnels_len + 1);
                memset(*tunnels, 0, tunnels_len + 1);
                memcpy(*tunnels, stringLeft, tunnels_len);

                *ps_exist = 1;
                free(stringOrig);
                stringOrig = NULL;
            }
            else
            {
                *ps_exist = 0;
            }
        }
        else
        {
            /* get one uuid */
            char *string = json_to_string(reply->result, table_style.json_flags);
            char *stringOrig = string;
            char *stringLeft = NULL;
            char aTunnelsLeft[] = "\"tunnels\":";
            char aTunnelsRight[] = "}]}]";
            int tunnels_len = 0;
            OVSDB_CLIENT_GET_TUNNELS_FROM_PHYSICAL_SWITCH(stringLeft, &tunnels_len, aTunnelsLeft, aTunnelsRight, string);

            *tunnels = malloc(tunnels_len + 1);
            memset(*tunnels, 0, tunnels_len + 1);
            memcpy(*tunnels, stringLeft, tunnels_len);

            *ps_exist = 1;
            free(stringOrig);
            stringOrig = NULL;
        }
    }
    else
    {
        *ps_exist = 0;
    }

    jsonrpc_msg_destroy(reply);

    return;
}

void
do_transact_temp_query_port_binding_logical_switch(struct jsonrpc *rpc, char *json_char ,int *ls_num, struct uuid *ls_uuids)
{
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct json_array *ls;
    struct json *elem_0;
    struct json *rows;
    struct json_array *rows_elem;
    struct json *vlan_bindings;
    struct json_array *vlan_bindings_elems;
    int rows_elem_num=0;
    int i=0;

    transaction = parse_json(json_char);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);
    //print_json(reply->result);
    //putchar('\n');

    ls = json_array(reply->result);
    elem_0 = ls->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");
    rows_elem = json_array(rows);
    rows_elem_num = rows_elem->n;

    if(!rows_elem_num)
    {
        OVSDB_PRINTF_DEBUG_TRACE("No such port present.");
        *ls_num = 0;
    }

    else   /*rows_elem_num >= 1*/
    {
        vlan_bindings = shash_find_data(json_object(rows_elem->elems[0]), "vlan_bindings");
        vlan_bindings_elems = json_array(json_array(vlan_bindings)->elems[1]);  /*elems[0] is "map" string*/
        *ls_num= vlan_bindings_elems->n;

        OVSDB_PRINTF_DEBUG_TRACE("vlan_bindings_elems num =%d.", vlan_bindings_elems->n);

        for(i=0; i < vlan_bindings_elems->n; i++)
        {
            uuid_from_string(&ls_uuids[i],  json_string(json_array(json_array(vlan_bindings_elems->elems[i])->elems[1])->elems[1]));
            OVSDB_PRINTF_DEBUG_TRACE("No.%d logical switch uuid = "UUID_FMT, i, UUID_ARGS(&ls_uuids[i]));
        }
    }

    //printf("ls_num = %d\n", *ls_num);
    jsonrpc_msg_destroy(reply);
}

/*根据MAC地址,在ucast-local表中查询具有该mac的表项的uuid，理论上最多只有1个，为了防止万一，支持多个的情况*/
void
do_transact_temp_query_mac_local_uuid(struct jsonrpc *rpc, char *json_char ,int *uuid_num, struct uuid *ucast_local_uuids)
{
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct json_array *ls;
    struct json *elem_0;
    struct json *rows;
    struct json_array *rows_elem;
    struct json *uuid;
    int rows_elem_num=0;
    int i=0;

    transaction = parse_json(json_char);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);
    //print_json(reply->result);
    //putchar('\n');

    ls = json_array(reply->result);
    elem_0 = ls->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");
    rows_elem = json_array(rows);
    rows_elem_num = rows_elem->n;

    *uuid_num = 0;  /*先置0*/

    if(!rows_elem_num)
    {
        OVSDB_PRINTF_DEBUG_TRACE("No such mac table present.");
        *uuid_num = 0;
    }

    else   /*rows_elem_num >= 1*/
    {
        for(i=0; i<rows_elem_num; i++)
        {
            *uuid_num = *uuid_num + 1;
            uuid = shash_find_data(json_object(rows_elem->elems[i]), "_uuid");
            uuid_from_string(&ucast_local_uuids[i], json_string(json_array(uuid)->elems[1]));
        }
    }

    jsonrpc_msg_destroy(reply);
}


void
do_transact_temp_query_logical_switch_tunnel_key(struct jsonrpc *rpc, char *json_char ,int *tunnel_key_exist, int *tunnel_key)
{
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct json_array *ls;
    struct json *elem_0;
    struct json *rows;
    struct json_array *rows_elem;
    struct json *ls_0;
    struct json *tunnel_key_json;

    transaction = parse_json(json_char);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);
    //print_json(reply->result);
    //putchar('\n');

    ls = json_array(reply->result);
    elem_0 = ls->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");
    rows_elem = json_array(rows);

    *tunnel_key_exist = 0;
    *tunnel_key = 0;

    if(!rows_elem->n)
    {
        OVSDB_PRINTF_DEBUG_TRACE("No such logical switch.");
        *tunnel_key_exist = 0;
    }
    else
    {
        ls_0 = rows_elem->elems[0];
        tunnel_key_json = shash_find_data(json_object(ls_0), "tunnel_key");

        if(JSON_INTEGER == tunnel_key_json->type)
        {
            *tunnel_key_exist = 1;
            *tunnel_key = json_integer(tunnel_key_json);

            OVSDB_PRINTF_DEBUG_TRACE("json_integer(tunnel_key_json) = %d.", json_integer(tunnel_key_json));
            OVSDB_PRINTF_DEBUG_TRACE("tunnel_key=%d.", *tunnel_key);
        }

    }

    //printf("ls_num = %d\n", *ls_num);
    jsonrpc_msg_destroy(reply);
}


/*写完后发现与do_transact_temp_query_locator_dstip功能相同，统一用do_transact_temp_query_locator_dstip*/
/*后续考虑将其删除*/
void
do_transact_temp_query_physical_locator_dst_ip(struct jsonrpc *rpc, char *json_char, char* dst_ip)
{
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct json_array *pl;
    struct json *elem_0;
    struct json *rows;
    struct json_array *rows_elem;
    struct json *pl_0;
    struct json *dst_ip_json;

    transaction = parse_json(json_char);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);
    //print_json(reply->result);
    //putchar('\n');

    pl = json_array(reply->result);
    elem_0 = pl->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");
    rows_elem = json_array(rows);

    if(!rows_elem->n)
    {
        OVSDB_PRINTF_DEBUG_TRACE("No such physical locator.");

    }
    else
    {
        pl_0 = rows_elem->elems[0];
        dst_ip_json = shash_find_data(json_object(pl_0), "dst_ip");

        if(JSON_STRING == dst_ip_json->type)
        {
            dst_ip = malloc(strlen(json_string(dst_ip_json))+1) ;
            memcpy(dst_ip, json_string(dst_ip_json), strlen(json_string(dst_ip_json)));
            OVSDB_PRINTF_DEBUG_TRACE("dst ip in physical locator is %s.", dst_ip);
        }

    }

    jsonrpc_msg_destroy(reply);
}

void
do_transact_temp_query_tunnel_uuid(struct jsonrpc * rpc, struct uuid * remote_uuid, struct uuid * tunnel_uuid)
{
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct json_array *pl;
    struct json *elem_0;
    struct json *rows;
    struct json *rows_0;
    struct json *uuid;
    struct json *uuid_value;
    char json_char[256] = {0};

    uuid_zero(tunnel_uuid);

    (void)snprintf(json_char, 256,
        "[\"hardware_vtep\",{\"columns\":[\"_uuid\",\"bfd_config_local\",\"bfd_config_remote\",\"bfd_params\",\"bfd_status\",\"local\",\"remote\"],"\
        "\"table\":\"Tunnel\",\"where\":[[\"remote\",\"==\",[\"uuid\",\""UUID_FMT"\"]]],\"op\":\"select\"}]",
        UUID_ARGS(remote_uuid));

    transaction = parse_json(json_char);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);

    pl = json_array(reply->result);
    elem_0 = pl->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");
    if (!json_array(rows)->n)
    {
        jsonrpc_msg_destroy(reply);
        return;
    }

    rows_0 = json_array(rows)->elems[0];
    uuid = shash_find_data(json_object(rows_0), "_uuid");
    if (!uuid)
    {
        jsonrpc_msg_destroy(reply);
        return;
    }

    uuid_value = json_array(uuid)->elems[1];
    uuid_from_string(tunnel_uuid, json_string(uuid_value));

    jsonrpc_msg_destroy(reply);
    return;
}

void
do_transact_temp_query_tunnel_bfd_params_enable(struct jsonrpc * rpc, char * json_char, struct uuid * tunnel_self_uuid, bool *enable)
{
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct json_array *pl;
    struct json *elem_0;
    struct json *rows;
    struct json *rows_0;
    struct json *uuid;
    struct json *uuid_value;
    struct json *rows_3;
    struct json *bfd_params;
    struct json *bfd_params_elem1;

    transaction = parse_json(json_char);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);

    pl = json_array(reply->result);
    elem_0 = pl->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");
    if (!json_array(rows)->n)
    {
        jsonrpc_msg_destroy(reply);
        return;
    }

    rows_0 = json_array(rows)->elems[0];
    uuid = shash_find_data(json_object(rows_0), "_uuid");
    if (!uuid)
    {
        jsonrpc_msg_destroy(reply);
        return;
    }

    uuid_value = json_array(uuid)->elems[1];
    uuid_from_string(tunnel_self_uuid, json_string(uuid_value));

    rows_3 = json_array(rows)->elems[3];
    bfd_params = shash_find_data(json_object(rows_0), "bfd_params");
    bfd_params_elem1 = json_array(bfd_params)->elems[1];
    if (0 != (json_array(bfd_params_elem1)->n))
    {
        if (!strcmp("true", json_string(json_array(json_array(bfd_params_elem1)->elems[0])->elems[1])))
        {
            *enable = true;
        }
        else
        {
            *enable = false;
        }
    }
    else
    {
        *enable = false;
    }

    jsonrpc_msg_destroy(reply);
    return;
}

void
do_transact_temp_query_all_tunnel_uuid(struct jsonrpc * rpc, struct tunnel_table_query * tunnel_list, unsigned int * num)
{
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct json_array *pl;
    struct json_array *rows_array;
    struct json_array *uuid_array;
    struct json *elem_0;
    struct json *rows;
    struct json *rows_0;
    struct json *uuid;
    struct json *uuid_value;
    char json_char[] = "[\"hardware_vtep\",{\"columns\":[\"_uuid\",\"remote\"],"\
        "\"table\":\"Tunnel\",\"where\":[],\"op\":\"select\"}]";
    int i;

    *num = 0;

    transaction = parse_json(json_char);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);
    pl = json_array(reply->result);

    elem_0 = pl->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");
    rows_array = json_array(rows);

    for (i = 0; i < rows_array->n; i++)
    {
        rows_0 = rows_array->elems[i];
        uuid = shash_find_data(json_object(rows_0), "_uuid");
        if (!uuid)
        {
            continue;
        }

        uuid_array = json_array(uuid);
        (void)uuid_from_string(&tunnel_list[*num].tunnel_uuid, json_string(uuid_array->elems[1]));

        uuid = shash_find_data(json_object(rows_0), "remote");
        if (!uuid)
        {
            continue;
        }

        uuid_array = json_array(uuid);
        (void)uuid_from_string(&tunnel_list[*num].remote_uuid, json_string(uuid_array->elems[1]));

        *num += 1;
    }

    jsonrpc_msg_destroy(reply);
    return;
}

void
do_transact_temp_delete_tunnel_byuuid(struct jsonrpc * rpc, struct uuid * tunnel_uuid)
{
    char json_char[256] = {0};

    (void)snprintf(json_char, 256,
        "[\"hardware_vtep\",{\"table\":\"Physical_Switch\",\"op\":\"mutate\","\
        "\"where\":[[\"name\",\"==\",\"%s\"]],"\
        "\"mutations\":[[\"tunnels\", \"delete\", [\"uuid\",\""UUID_FMT"\"]]]}]",
        OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_SWITCHNAME), UUID_ARGS(tunnel_uuid));

    do_transact_temp(rpc, json_char);

    return;
}

void
do_transact_temp_delete_all_tunnel(struct jsonrpc * rpc)
{
    struct tunnel_table_query tunnel_list[PHYSICAL_SWITCH_TUNNELS_NUM];
    unsigned int num = 0;
    unsigned int i;

    (void)memset(tunnel_list, 0, sizeof(struct tunnel_table_query) * PHYSICAL_SWITCH_TUNNELS_NUM);

    do_transact_temp_query_all_tunnel_uuid(rpc, tunnel_list, &num);

    for (i = 0; i < num; i++)
    {
        do_transact_temp_delete_tunnel_byuuid(rpc, &tunnel_list[i].tunnel_uuid);
    }

    return;
}

#if OVSDB_DESC("add Physical_Switch & Tunnel table")
void ovsdb_tunnel_update_bfd_status(struct jsonrpc * rpc, int i)
{
    char json_query[1000] = {0};

    (void)snprintf(json_query, 1000,
        "[\"hardware_vtep\",{\"row\":[{\"bfd_status\":[\"map\",[]]}],\"until\":\"==\",\"table\":\"Tunnel\","\
        "\"timeout\":0,\"op\":\"wait\",\"columns\":[\"bfd_status\"],\"where\":[[\"_uuid\",\"==\",[\"uuid\","\
        "\""UUID_FMT"\"]]]},{\"table\":\"Tunnel\",\"row\":{\"bfd_status\":[\"map\",[[\"enabled\",\"true\"]]]},"\
        "\"op\":\"update\",\"where\":[[\"_uuid\",\"==\",[\"uuid\",\""UUID_FMT"\"]]]}]",
        UUID_ARGS(&ovsdb_vtep_db_table.table_tunnel[i].uuid_self1),
        UUID_ARGS(&ovsdb_vtep_db_table.table_tunnel[i].uuid_self1));

    do_transact_temp(rpc, json_query);
    return;
}

void ovsdb_tunnel_delete_bfd_status(struct jsonrpc * rpc, int i)
{
    char json_query[1000] = {0};

    (void)snprintf(json_query, 1000,
        "[\"hardware_vtep\",{\"table\":\"Tunnel\",\"row\":{\"bfd_status\":[\"map\",[]]},"\
        "\"op\":\"update\",\"where\":[[\"_uuid\",\"==\",[\"uuid\",\""UUID_FMT"\"]]]}]",
        UUID_ARGS(&ovsdb_vtep_db_table.table_tunnel[i].uuid_self1));

    do_transact_temp(rpc, json_query);
    return;
}

int ovsdb_tunnel_create(struct uuid *remote_uuid, struct uuid *local_uuid)
{
    char name[BFD_SESSION_NAME_LEN] = {0};
    int k = 0;

    for (k = 0; k < TABLE_TUNNEL_NUM; k++)
    {
        /* 第一个空行，需要增加对越界的判断 */
        if (uuid_is_zero(&ovsdb_vtep_db_table.table_tunnel[k].local))
        {
            memcpy(&ovsdb_vtep_db_table.table_tunnel[k].local, local_uuid,
                sizeof(struct uuid));
            memcpy(&ovsdb_vtep_db_table.table_tunnel[k].remote, remote_uuid,
                sizeof(struct uuid));

            (void)snprintf(name, BFD_SESSION_NAME_LEN, "vxlan%d", k);
            strcpy(ovsdb_vtep_db_table.table_tunnel[k].name, name);

            OVSDB_SET_STR(ovsdb_vtep_db_table.table_tunnel[k].bfd_config_local.bfd_ip,
                OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_TUNNERIP));

            OVSDB_SET_STR(ovsdb_vtep_db_table.table_tunnel[k].bfd_config_local.bfd_mac,
                BFD_LOCAL_MAC);

            ovsdb_vtep_db_table.used_num_table_tunnel += 1;

            return OVSDB_OK;
        }
    }

    return OVSDB_ERR_INDEX_FULL;
}

void ovsdb_tunnel_destroy(struct uuid *remote_uuid, struct uuid *local_uuid)
{
    int k = 0;
    struct ovsdb_vtep_table_tunnel *pstTable_tunnel;         /*14 Tunnel*/

    for (k = 0; k < TABLE_TUNNEL_NUM; k++) {
        if ((uuid_equals(remote_uuid, &ovsdb_vtep_db_table.table_tunnel[k].remote))
            && (uuid_equals(local_uuid, &ovsdb_vtep_db_table.table_tunnel[k].local))) {
            pstTable_tunnel = &ovsdb_vtep_db_table.table_tunnel[k];
            uuid_zero(&pstTable_tunnel->local);
            uuid_zero(&pstTable_tunnel->remote);
            memcpy(pstTable_tunnel->name, 0, BFD_SESSION_NAME_LEN);
            OVSDB_FREE(pstTable_tunnel->bfd_config_local.bfd_mac);
            OVSDB_FREE(pstTable_tunnel->bfd_config_local.bfd_ip);
            OVSDB_FREE(pstTable_tunnel->bfd_config_remote.bfd_mac);
            OVSDB_FREE(pstTable_tunnel->bfd_config_remote.bfd_ip);
            OVSDB_FREE(pstTable_tunnel->bfd_params.enable);
            OVSDB_FREE(pstTable_tunnel->bfd_params.min_rx);
            OVSDB_FREE(pstTable_tunnel->bfd_params.min_tx);
            OVSDB_FREE(pstTable_tunnel->bfd_params.decay_min_rx);
            OVSDB_FREE(pstTable_tunnel->bfd_params.forwarding_if_rx);
            OVSDB_FREE(pstTable_tunnel->bfd_params.cpath_down);
            OVSDB_FREE(pstTable_tunnel->bfd_params.check_tnl_key);
            OVSDB_FREE(pstTable_tunnel->bfd_status.enable);
            OVSDB_FREE(pstTable_tunnel->bfd_status.state);
            OVSDB_FREE(pstTable_tunnel->bfd_status.forwarding);
            OVSDB_FREE(pstTable_tunnel->bfd_status.diagnostic);
            OVSDB_FREE(pstTable_tunnel->bfd_status.remote_state);
            OVSDB_FREE(pstTable_tunnel->bfd_status.remote_diagnostic);
            OVSDB_FREE(pstTable_tunnel->bfd_status.info);

            if (ovsdb_vtep_db_table.used_num_table_tunnel > 0) {
                ovsdb_vtep_db_table.used_num_table_tunnel -= 1;
            }

            break;
        }
    }

    return;
}

void ovsdb_tunnel_add_ovsdb(struct jsonrpc * rpc, struct uuid *uuid_remote_pl, struct uuid *uuid_local_pl)
{
    struct ovsdb_vtep_table_physical_locator * pstLocalPL = NULL;
    char json_query[1000] = {0};
    int iRet = 0;
    struct json *transaction;
    struct jsonrpc_msg *request, *reply;
    struct json_array *ls;
    struct json *elem_0;
    struct json *rows;
    struct json_array *rows_elem;

    /* 使能条件: 1.全局使能标志 */
    if (0 != strcmp(OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_TUNNERBFDENABLE), "true"))
        return;

    /* 是否已经存在表项 */
    (void)snprintf(json_query, 1000,
        "[\"hardware_vtep\",{\"columns\":[\"_uuid\"],\"table\":\"Tunnel\","\
        "\"where\":[[\"remote\",\"==\",[\"uuid\",\""UUID_FMT"\"]]],\"op\":\"select\"}]",
        UUID_ARGS(uuid_remote_pl));
    transaction = parse_json(json_query);
    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);
    ls = json_array(reply->result);
    elem_0 = ls->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");
    rows_elem = json_array(rows);
    if (0 != rows_elem->n) {
        jsonrpc_msg_destroy(reply);
        return;
    }

    jsonrpc_msg_destroy(reply);

    /* 写入Tunnel表 */
    (void)snprintf(json_query, 1000,
        "[\"hardware_vtep\",{\"op\":\"insert\",\"table\":\"Tunnel\","\
        "\"row\":{\"remote\":[\"uuid\",\""UUID_FMT"\"],\"local\":[\"uuid\",\""UUID_FMT"\"],"\
        "\"bfd_config_local\":[\"map\",[[\"bfd_dst_ip\",\"%s\"],[\"bfd_dst_mac\",\"%s\"]]],"\
        "\"bfd_status\":[\"map\",[[\"diagnostic\",\"No Diagnostic\"],[\"enabled\",\"true\"],"\
        "[\"state\",\"init\"],[\"remote_state\",\"init\"]]]},"\
        "\"uuid-name\":\"anotheritem\"},"\
        "{\"op\":\"mutate\",\"table\":\"Physical_Switch\",\"where\":[[\"name\",\"==\",\"%s\"]],"\
        "\"mutations\":[[\"tunnels\",\"insert\",[\"set\",[[\"named-uuid\",\"anotheritem\"]]]]]}]",
        UUID_ARGS(uuid_remote_pl), UUID_ARGS(uuid_local_pl),
        OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_TUNNERIP),
        BFD_LOCAL_MAC,
        OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_SWITCHNAME));

    do_transact_temp(rpc, json_query);

    return;    
}

int ovsdb_tunnel_add_process_scan_proc(void * input, void * output, void * entry)
{
    struct uuid * uuid_local_pl = (struct uuid *)input;
    struct ovsdb_vtep_table_physical_locator * query_entry = 
        (struct ovsdb_vtep_table_physical_locator *)entry;
    struct jsonrpc * rpc = (struct jsonrpc *)output;

    if (!uuid_equals(uuid_local_pl, &query_entry->uuid_self)) {
        ovsdb_tunnel_add_ovsdb(rpc, &query_entry->uuid_self, uuid_local_pl);
    }

    return OVSDB_OK;
}

void ovsdb_tunnel_add_process(struct jsonrpc * rpc, struct uuid *uuid_remote_pl)
{
    struct ovsdb_vtep_table_physical_locator * pstLocalPL = NULL;
    char json_query[1000] = {0};
    int iRet = 0;
    struct json *transaction;
    struct jsonrpc_msg *request, *reply;
    struct json_array *ls;
    struct json *elem_0;
    struct json *rows;
    struct json_array *rows_elem;

    /* 使能条件: 1.全局使能标志 */
    if (0 != strcmp(OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_TUNNERBFDENABLE), "true"))
        return;

    OVSDB_PRINTF_DEBUG_BFD_Debuf("uuid_remote_pl = {"UUID_FMT"}.", UUID_ARGS(uuid_remote_pl));

    pstLocalPL = ovsdb_table_physical_locator_query_byip(OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_TUNNERIP));
    if (NULL == pstLocalPL)
        return;

    if (!uuid_equals(&pstLocalPL->uuid_self, uuid_remote_pl)) {
        ovsdb_tunnel_add_ovsdb(rpc, uuid_remote_pl, &pstLocalPL->uuid_self);
        return;
    }

    ovsdb_table_physical_locator_scan((void *)&pstLocalPL->uuid_self, (void *)rpc, ovsdb_tunnel_add_process_scan_proc);

    return;
}

#if OVSDB_DEBUG
void ovsdb_tunnel_delete_process(struct jsonrpc * rpc, struct uuid * deleted_pl_uuid)
{
    struct uuid physical_locator_uuid;
    struct uuid physical_switch_uuid;
    struct uuid tunnel_self_uuid;
    struct uuid tunnel_uuid;
    char json_query[1000] = {0};
    int i = 0;
    int table_num = ovsdb_vtep_db_table.used_num_table_tunnel;
    struct ovsdb_vtep_table_tunnel * pstTableTunnel;

    /* 判断条件: 1.全局使能 */
    if (0 != strcmp(OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_TUNNERBFDENABLE), "true"))
        return;

    do_transact_temp_query_physical_switch_uuid(rpc, OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_TUNNERIP), &physical_switch_uuid);

    do_transact_temp_query_locator_uuid(rpc, OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_TUNNERIP), &physical_locator_uuid);

    if (uuid_equals(&physical_locator_uuid, deleted_pl_uuid)) {
        /* 删除所有的Tunnel */
        for (i = 0; i < TABLE_TUNNEL_NUM; i ++) {
            pstTableTunnel = &(ovsdb_vtep_db_table.table_tunnel[i]);
            if (uuid_is_zero(&pstTableTunnel->remote))
                continue;

            do_transact_temp_query_tunnel_uuid(rpc, &pstTableTunnel->remote, &tunnel_uuid);
            if (uuid_is_zero(&tunnel_uuid)) {
                continue;
            }

            do_transact_temp_delete_tunnel_uuid(rpc, &physical_switch_uuid, &tunnel_uuid);

            ovsdb_tunnel_destroy(&pstTableTunnel->remote, &pstTableTunnel->local);
        }
    }
    else {
        do_transact_temp_query_tunnel_uuid(rpc, deleted_pl_uuid, &tunnel_uuid);
        if (uuid_is_zero(&tunnel_uuid)) {
            return;
        }

        do_transact_temp_delete_tunnel_uuid(rpc, &physical_switch_uuid, &tunnel_uuid);

        ovsdb_tunnel_destroy(deleted_pl_uuid, &physical_locator_uuid);
    }

    return;
}
#endif
#endif

#if OVSDB_DESC("bfd temp")

unsigned int ovsdb_parsing_bfd_name(char * sessName, char * ip)
{
    char name[BFD_SESSION_NAME_LEN] = {0};
    int ret;

    ret = ip_translate_bfd_sessname(ip, name);
    if (ret != OVSDB_OK) {
        return ret;
    }
     
    if (0 == strcmp(sessName, name))
        return OVSDB_OK;

    return OVSDB_ERR;
}

bool ovsdb_refresh_bfd_status_check
(
    struct jsonrpc *rpc,
    char * dst_ip,
    char * diagnostic,
    char * forwarding,
    char * remote_state,
    char * state
)
{
    char json_query[512];
    struct json *transaction;
    struct jsonrpc_msg *request, *reply;
    struct json_array *pl;
    struct json *elem_0;
    struct json *rows;
    struct json_array *rows_elem;
    struct json *pl_0;
    struct json *js_status;
    int i = 0;
    char * item_name;
    char * item_value;
    int ret = 0;

    (void)snprintf(json_query, 512,
        "[\"hardware_vtep\",{\"columns\":[\"bfd_status\"],\"table\":\"Tunnel\",\"where\":"\
        "[[\"bfd_config_remote\",\"==\","\
        "[\"map\",[[\"bfd_dst_ip\",\"%s\"],[\"bfd_dst_mac\",\"00:00:00:00:00:00\"]]]]],\"op\":\"select\"}]",
        dst_ip);
    
    transaction = parse_json(json_query);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);

    pl = json_array(reply->result);
    elem_0 = pl->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");
    rows_elem = json_array(rows);
    if (0 == rows_elem->n)
        goto END;
    pl_0 = rows_elem->elems[0];

    js_status = shash_find_data(json_object(pl_0), "bfd_status");

    for (i = 0; i < TUNNEL_TABLE_GET_NUMBER(js_status); i++)
    {
        item_name = json_string(TUNNEL_TABLE_GET_NAME(js_status, i));
        item_value = TUNNEL_TABLE_GET_VALUE(js_status, i);
        if (!strcmp("state", item_name)) {
            if (0 == strcmp(state, json_string(item_value)))
                ret++;
        }
        else if (!strcmp("forwarding", item_name)) {
            if (0 == strcmp(forwarding, json_string(item_value)))
                ret++;
        }
        else if (!strcmp("diagnostic", item_name)) {
            if (0 == strcmp(diagnostic, json_string(item_value)))
                ret++;
        }
        else if (!strcmp("remote_state", item_name)) {
            if (0 == strcmp(remote_state, json_string(item_value)))
                ret++;
        }
    }

END:
    jsonrpc_msg_destroy(reply);
    if (4 == ret)
        return true;
    return false;
}

void ovsdb_refresh_bfd_status(struct jsonrpc *rpc, char * dst_ip, char * sess_stat, char * local_diag)
{
    char json_query[512];
    char * diagnostic = "Reserved for future use"; //BFD协议规定其他的消息都回此
    char * forwarding;
    char * remote_state;
    char * state = "down";
    int i;

    //转换diagnostic
    struct bfd_status_map bfd_diag_map[] =
    {
        {"NONE"                    , "No Diagnostic"                 },
        {"DETECT_DOWN"             , "Control Detection Time Expired"},
        {"ECHO_DOWN"               , "Echo Function Failed"          },
        {"NEIGHBOR_DOWN"           , "Neighbor Signaled Session Down"},
        {"FORWARDING_RESET"        , "Forwarding Plane Reset"        },
        {"PATH_DOWN"               , "Path Down"                     },
        {"CONCAT_PATH_DOWN"        , "Concatenated Path Down"        },
        {"ADMIN_DOWN"              , "Administratively Down"         },
        {"REVERSE_CONCAT_PATH_DOWN", "Reverse Concatenated Path Down"},
        {"RECEIVE_ADMIN_DOWN"      , "Reserved for future use"       },
        {NULL                      , NULL                            },
    };

    i = 0;
    while(NULL != bfd_diag_map[i].ce_word)
    {
        if (0 == strcmp(local_diag, bfd_diag_map[i].ce_word)) {
            diagnostic = bfd_diag_map[i].ovsdb_word;
            break;
        }
        i++;
    }

    //转换state
    struct bfd_status_map bfd_state_map[] =
    {
        {"ADMINDOWN" , "admin_down"},
        {"DOWN"      , "down"      },
        {"INIT"      , "init"      },
        {"UP"        , "up"        },
        {NULL        , NULL        },
    };

    i = 0;
    while(NULL != bfd_state_map[i].ce_word)
    {
        if (0 == strcmp(sess_stat, bfd_state_map[i].ce_word)) {
            state = bfd_state_map[i].ovsdb_word;
            break;
        }
        i++;
    }

    forwarding = (0 == strcmp(state, "up")) ? "true" : "false";
    remote_state = (0 == strcmp(state, "up")) ? "up" : "down";

    if (true == ovsdb_refresh_bfd_status_check(rpc, dst_ip, diagnostic, forwarding, remote_state, state))
        return;

    (void)snprintf(json_query, 512,
                "[\"hardware_vtep\",{\"table\":\"Tunnel\",\"row\":{\"bfd_status\":"\
                "[\"map\",[[\"enabled\",\"true\"],[\"state\",\"%s\"],[\"forwarding\",\"%s\"],"\
                "[\"diagnostic\",\"%s\"],[\"remote_state\",\"%s\"]]]},"\
                "\"op\":\"update\",\"where\":[[\"bfd_config_remote\",\"==\","\
                "[\"map\",[[\"bfd_dst_ip\",\"%s\"],[\"bfd_dst_mac\",\"00:00:00:00:00:00\"]]]]]}]",
                state, forwarding, diagnostic, remote_state, dst_ip);

    do_transact_temp(rpc, json_query);

    return;
}

unsigned int ovsdb_get_bfd_status(struct jsonrpc *rpc, char *paData)
{
    char aSessNameLeft[] = "<sessName>";
    char aSessNameRight[] = "</sessName>";
    char aDestAddrLeft[] = "<destAddr>";
    char aDestAddrRight[] = "</destAddr>";
    char aSessStateLeft[] = "<sessState>";
    char aSessStateRight[] = "</sessState>";
    char alocalDiagLeft[] = "<localDiag>";
    char alocalDiagRight[] = "</localDiag>";
    char aDestAddr[BFD_SESSION_DEST_ADD_LEN] = {0};
    char aSessState[BFD_SESSION_RUN_STATE_LEN] = {0};
    char aSess[BFD_SESSION_NAME_LEN] = {0};
    char alocalDiag[BFD_SESSION_DIAGNOSTIC_LEN] = {0};
    char *pStart = paData;
    unsigned int uiRet = OVSDB_OK;

    if (NULL == paData)
    {
        OVSDB_PRINTF_DEBUG_ERROR("paData is NULL");
        return OVSDB_ERR;
    }

    while (NULL != strstr(pStart, aSessNameLeft))
    {
        /* 获取sessName */
        OVSDB_CLIENT_GET_STRING_FROM_NCREPLY(aSess, BFD_SESSION_NAME_LEN, aSessNameLeft, aSessNameRight, pStart);
        if (NULL == pStart)
            return OVSDB_ERR;

        OVSDB_CLIENT_GET_STRING_FROM_NCREPLY(aDestAddr, BFD_SESSION_DEST_ADD_LEN, aDestAddrLeft, aDestAddrRight, pStart);
        if (NULL == pStart)
            return OVSDB_ERR;

        uiRet = ovsdb_parsing_bfd_name(aSess, aDestAddr);
        if (uiRet != OVSDB_OK)
            continue;

        OVSDB_CLIENT_GET_STRING_FROM_NCREPLY(aSessState, BFD_SESSION_RUN_STATE_LEN, aSessStateLeft, aSessStateRight, pStart);
        if (NULL == pStart)
            return OVSDB_ERR;

        OVSDB_CLIENT_GET_STRING_FROM_NCREPLY(alocalDiag, BFD_SESSION_DIAGNOSTIC_LEN, alocalDiagLeft, alocalDiagRight, pStart);
        if (NULL == pStart)
            return OVSDB_ERR;

        ovsdb_refresh_bfd_status(rpc, aDestAddr, aSessState, alocalDiag);

    }

    return OVSDB_OK;
}

unsigned int netconf_ce_query_bfd_status(struct jsonrpc *rpc)
{
    unsigned int uiRet = 0;
    unsigned int uiLoop = 0;
    char send_data[NETCONF_SEND_DATA_LEN] = {0};
    char *pReplyData = NULL;
    char *paReplySeg = NULL;
    char aSetId[MAX_SET_ID_LEN] = {0};

    /* 使能条件: 1.全局使能标志 */
    if (0 != strcmp(OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_TUNNERBFDENABLE), "true"))
        return;

    /*snprintf(send_data, sizeof(send_data),
        "<get>"\
          "<filtertype=\"subtree\">"\
            "<bfd xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<bfdCfgSessions>"\
                "<bfdCfgSession>"\
                  "<sessName>%s</sessName>"\
                  "<destAddr/>"\
                  "<srcAddr/>"\
                  "<bfdSessRunning>"\
                    "<sessState/>"\
                    "<udpDstPort/>"\
                    "<detectMode/>"\
                    "<actTxInt/>"\
                    "<actRxInt/>"\
                    "<actMulti/>"\
                    "<detectTime/>"\
                    "<ttl/>"\
                    "<txTmrID/>"\
                    "<detectTmrID/>"\
                    "<initTmrID/>"\
                    "<wtrTmrID/>"\
                    "<notUpReason/>"\
                    "<localDiag/>"\
                    "<localDiscr/>"\
                    "<remoteDiscr/>"\
                    "<minTxInt/>"\
                    "<minRxInt/>"\
                  "</bfdSessRunning>"\
                "</bfdCfgSession>"\
              "</bfdCfgSessions>"\
            "</bfd>"\
          "</filter>"\
        "</get>", aSess);*/
    snprintf(send_data, sizeof(send_data),
        "<get>"\
          "<filter type=\"subtree\">"\
            "<bfd xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<bfdAllSessions>"\
                "<bfdAllSession>"\
                  "<sessName/>"\
                  "<destAddr/>"\
                  "<srcAddr/>"\
                  "<bfdSessRunning>"\
                    "<sessState/>"\
                    "<localDiag/>"\
                  "</bfdSessRunning>"\
                "</bfdAllSession>"\
              "</bfdAllSessions>"\
            "</bfd>"\
          "</filter>"\
        "</get>");

    uiRet = netconf_ce_query_config_all(send_data, &pReplyData);
    if (OVSDB_OK != uiRet)
    {
        OVSDB_PRINTF_DEBUG_ERROR("Failed to query BFD status.");
        return OVSDB_ERR;
    }

    while (NULL != pReplyData)
    {
        uiRet = ovsdb_get_bfd_status(rpc, pReplyData);
        if (uiRet != OVSDB_OK)
        {
            OVSDB_PRINTF_DEBUG_ERROR("Failed to get BFD status.");
        }

        /* 判断reply消息是否分片 */
        paReplySeg = strstr(pReplyData, "set-id");

        if (NULL == paReplySeg)
        {
            free(pReplyData);
            pReplyData = NULL;
            break;
        }

        /* 获取set-id以查询下一个回复消息分片 */
        paReplySeg = paReplySeg + strlen("set-id") + 2;
        while ('"' != *paReplySeg)
        {
            aSetId[uiLoop++] = *paReplySeg;
            paReplySeg++;
        }
        aSetId[uiLoop] = '\0';

        snprintf(send_data, sizeof(send_data),
            "<get-next xmlns=\"http://www.huawei.com/netconf/capability/base/1.0\" set-id=\"%s\">"\
            "</get-next>", aSetId);

        free(pReplyData);
        pReplyData = NULL;

        uiRet = netconf_ce_query_config_all(send_data, &pReplyData);
        if (OVSDB_OK != uiRet)
        {
            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to query next db mac");
            return OVSDB_ERR;
        }
        uiLoop = 0;
    }

    return OVSDB_OK;
}

#endif

#if OVSDB_DESC("add MAC & interface")
struct ovsdb_write_mcast_local_args * g_args_local = NULL;

struct ovsdb_sub_table g_aucTBL[OVSDB_SUB_TABLE_MAX] =
{
    {"OVSDB_SUB_TABLE_MAC"      , &(g_aucTBL[0].pstTblA), &(g_aucTBL[0].pstTblB), NULL, NULL, sizeof(struct ovsdb_sub_mac_data)},
    {"OVSDB_SUB_TABLE_INTERFACE", &(g_aucTBL[1].pstTblA), &(g_aucTBL[1].pstTblB), NULL, NULL, 0},
};

static struct ovsdb_sub_entry *find_entry(struct ovsdb_sub_entry *table, char * key)
{
    struct ovsdb_sub_entry *entry;

    HASH_FIND_STR(table, key, entry);

    return entry;
}

static struct ovsdb_sub_entry *add_entry(enum OVSDB_SUB_TABLE_NAME table_name, char * key, void * pdata)
{
    int iDatalength = 0;
    struct ovsdb_sub_entry **table = &OVSDB_SUB_GET_AGEINGTABLE(table_name);
    struct ovsdb_sub_entry *entry = (struct ovsdb_sub_entry *)malloc(sizeof(struct ovsdb_sub_entry));

    if (NULL == entry)
    {
        return NULL;
    }

    (void)memset(entry, 0, sizeof(struct ovsdb_sub_entry));

    (void)strncpy(entry->key, key, OVSDB_SUB_KEY_LEN);

    iDatalength = OVSDB_SUB_GET_DATA_LENGTH(table_name);
    if (0 != iDatalength){
        entry->pdata = malloc(iDatalength);
        if (NULL == entry->pdata){
            free(entry);
            return NULL;
        }

        (void)memcpy(entry->pdata, pdata, iDatalength);
    }

    HASH_ADD_STR(*table, key, entry);

    return entry;
}

static void delete_entry(struct ovsdb_sub_entry **table, struct ovsdb_sub_entry *entry)
{
    HASH_DEL(*table, entry);
    if (NULL != entry->pdata)
        free(entry->pdata);
    free(entry);
}

int ovsdb_sub_add_port(struct ovsdb_sub_entry * entry)
{
    ovsdb_add_port(entry->key);
    return 0;
}

int ovsdb_sub_delete_port(struct ovsdb_sub_entry * entry)
{
    ovsdb_delete_port(entry->key);
    return 0;
}

int ovsdb_sub_add_mac(struct ovsdb_sub_entry * entry)
{
    char mac[32] = {0};
    char bd[OVSDB_SUB_BD_LEN] = {0};
    struct ovsdb_sub_mac_key  * key  = (struct ovsdb_sub_mac_key *)(entry->key);
    struct ovsdb_sub_mac_data * data = (struct ovsdb_sub_mac_data *)(entry->pdata);

    (void)snprintf(mac, 18, "%s", key->macAdd);

    (void)snprintf(bd, OVSDB_SUB_BD_LEN, "%s", key->BD);

    return ovsdb_add_mac(mac, bd, data->interface, data->mac_type);
}

int ovsdb_sub_delete_mac(struct ovsdb_sub_entry * entry)
{
    char mac[32] = {0};
    char bd[OVSDB_SUB_BD_LEN] = {0};
    struct ovsdb_sub_mac_key  * key  = (struct ovsdb_sub_mac_key *)(entry->key);
    struct ovsdb_sub_mac_data * data = (struct ovsdb_sub_mac_data *)(entry->pdata);

    (void)snprintf(mac, 18, "%s", key->macAdd);

    (void)snprintf(bd, OVSDB_SUB_BD_LEN, "%s", key->BD);

    ovsdb_delete_mac(mac, bd, data->interface, data->mac_type);

    return 0;
}

int ovsdb_sub_add_msg(enum OVSDB_SUB_TABLE_NAME table_name, struct ovsdb_sub_entry * entry)
{
    if (OVSDB_SUB_TABLE_MAC == table_name)
        return ovsdb_sub_add_mac(entry);

    return ovsdb_sub_add_port(entry);
}

int ovsdb_sub_delete_msg(enum OVSDB_SUB_TABLE_NAME table_name, struct ovsdb_sub_entry * entry)
{
    if (OVSDB_SUB_TABLE_MAC == table_name)
        return ovsdb_sub_delete_mac(entry);

    return ovsdb_sub_delete_port(entry);
}

int ovsdb_sub_table_add(enum OVSDB_SUB_TABLE_NAME table_name, char *key, void *data, int data_len)
{
    int ret = 0;
    bool flag = true;
    struct ovsdb_sub_entry * entry  = NULL;
    struct ovsdb_sub_entry * current  = NULL;

    if ((NULL == data) && (0 != data_len))
        return -1;

    /* 防止重复表项，现在老化流表中查找是否存在 */
    entry = find_entry(OVSDB_SUB_GET_AGEINGTABLE(table_name), key);
    if (entry != NULL) {
        if (data == NULL)
            return 0;
        else {
            if (0 != memcmp(data, entry->pdata, data_len)) {
                /* 发删除消息 */
                (void)ovsdb_sub_delete_msg(table_name, entry);

                delete_entry(&OVSDB_SUB_GET_AGEINGTABLE(table_name), entry);
            } else
                return 0;
        }
    }

    /* 查找当前软表中是否存在 */
    entry = find_entry(OVSDB_SUB_GET_TABLE(table_name), key);
    if (entry != NULL) {
        if (data != NULL) {
            if (0 != memcmp(data, entry->pdata, data_len)) {
                /* 发删除消息 */
                (void)ovsdb_sub_delete_msg(table_name, entry);
            } else
                flag = false;
        } else
            flag = false;
        delete_entry(&OVSDB_SUB_GET_TABLE(table_name), entry);
    }

    current = add_entry(table_name, key, (void *)data);
    if (NULL == current)
        return -1;

    /* 发添加消息 */
    if (true == flag)
        ret = ovsdb_sub_add_msg(table_name, current);
    if (ret != 0) {
        delete_entry(&OVSDB_SUB_GET_AGEINGTABLE(table_name), current);
        return ret;
    }

    return 0;
}

int ovsdb_sub_table_delete(enum OVSDB_SUB_TABLE_NAME table_name)
{
    struct ovsdb_sub_entry * current, *tmp;

    HASH_ITER(hh, OVSDB_SUB_GET_TABLE(table_name), current, tmp) {
        /* 发送删除消息 */
        (void)ovsdb_sub_delete_msg(table_name, current);

        delete_entry(&OVSDB_SUB_GET_TABLE(table_name), current);
    }

    /* 交换表 */
    OVSDB_SUB_EXCHANGE_AGEINGTABLE(table_name);

    return 0;
}

int ovsdb_sub_table_interface_check(char *interface)
{
    if (interface == NULL)
        return -1;

    if (OVSDB_SUB_INTERFACE_LEN <= strlen(interface))
        return -1;

    return 0;
}

int ovsdb_sub_table_mac_check(char *mac, char *bd, char *interface, int mac_type)
{
    int i = 0;

    if (mac == NULL)
        return -1;
    if (bd == NULL)
        return -1;

    if (strlen(mac) != strlen("1111-2222-3333"))
        return -1;

    for (i = 0; i < strlen(mac); i++){
        if ((i == 4)||(i == 9)){
            if (mac[i] != '-')
                return -1;
        } else {
            if ((mac[i] < '0') ||
                ((mac[i] > '9') && (mac[i] < 'A')) ||
                ((mac[i] > 'F') && (mac[i] < 'a')) ||
                (mac[i] > 'f'))
                return -1;
        }
    }

    if (OVSDB_SUB_BD_LEN <= strlen(bd))
        return -1;

    return ovsdb_sub_table_interface_check(interface);
}

int ovsdb_sub_table_mac_add(char *mac, char *bd, char *interface, int mac_type)
{
    int ret = 0;
    struct ovsdb_sub_mac_key  key   = {0};
    struct ovsdb_sub_mac_data *data = NULL;

    /* 入参检查 */
    if (0 != ovsdb_sub_table_mac_check(mac, bd, interface, mac_type))
        return -1;

    /* 构造key */
    //memcpy(key.macAdd3[0], mac,    4);
    //memcpy(key.macAdd3[1], mac+5,  4);
    //memcpy(key.macAdd3[2], mac+10, 4);
    (void)snprintf(key.macAdd, 18,
                   "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
                   mac[0], mac[1], mac[2], mac[3],
                   mac[5], mac[6], mac[7], mac[8],
                   mac[10], mac[11], mac[12], mac[13]);
    key.macAdd[17] = '_';
    (void)strncpy(key.BD, bd, OVSDB_SUB_BD_LEN);

    /* 构造data */
    data = (struct ovsdb_sub_mac_data *)malloc(sizeof(struct ovsdb_sub_mac_data));
    if (NULL == data)
        return -1;

    (void)strncpy(data->interface, interface, OVSDB_SUB_INTERFACE_LEN);
    data->mac_type = mac_type;

    ret = ovsdb_sub_table_add(OVSDB_SUB_TABLE_MAC, (char *)&key, (void *)data, sizeof(struct ovsdb_sub_mac_data));
    free(data);
    if (ret != 0)
    {
        return ret;
    }

    return 0;
}

int ovsdb_sub_table_interface_check_type(char *interface)
{
    char *pcDot = ".";
    char *pcGE = "GE";
    char *pcTrunk = "Eth-Trunk";

    if (NULL != strstr(interface, pcDot))
    {
        return -1;
    }

    if ((NULL == strstr(interface, pcGE))&&(NULL == strstr(interface, pcTrunk)))
    {
        return -1;
    }

    return 0;
}

int ovsdb_sub_table_interface_add(char *interface)
{
    int ret = 0;
    struct ovsdb_sub_port_key key = {0};

    /* 入参检查 */
    if (0 != ovsdb_sub_table_interface_check(interface))
        return -1;

    /* 判断是否是物理口和LAG口 */
    if (0 != ovsdb_sub_table_interface_check_type(interface))
        return 0;

    /* 构造key */
    (void)strncpy(key.interface, interface, OVSDB_SUB_INTERFACE_LEN);

    ret = ovsdb_sub_table_add(OVSDB_SUB_TABLE_INTERFACE, (char *)&key, NULL, 0);
    if (ret != 0)
    {
        return ret;
    }

    return 0;
}

int ovsdb_sub_table_mac_delete(void)
{
    (void)ovsdb_sub_table_delete(OVSDB_SUB_TABLE_MAC);

    return 0;
}

int ovsdb_sub_table_interface_delete(void)
{
    (void)ovsdb_sub_table_delete(OVSDB_SUB_TABLE_INTERFACE);

    return 0;
}

void ovsdb_add_port(char *interface)
{
    struct jsonrpc *rpc = g_args_local->rpc;
    char json_insert_port[512]={0};

    /*写Physical_Port表*/
    (void)snprintf(json_insert_port, 512,
        "[\"hardware_vtep\",{\"op\":\"insert\", \"table\":\"Physical_Port\", "
        "\"row\":{\"name\":\"%s\"}, \"uuid-name\":\"anotheritem\" }, "
        "{\"op\":\"mutate\", \"table\":\"Physical_Switch\", \"where\":[[\"name\",\"==\",\"%s\"]], "
        "\"mutations\":[[\"ports\", \"insert\", [\"set\",[[\"named-uuid\", \"anotheritem\"]]]]] }]", 
        interface, OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_SWITCHNAME));
    do_transact_temp(rpc, json_insert_port);

    return;
}

void ovsdb_delete_port(char *interface)
{
    int i;
    char *json_char[256];
    struct json *transaction;
    struct jsonrpc_msg *request, *reply;
    struct jsonrpc *rpc = g_args_local->rpc;
    struct json_array *pl;
    struct json *elem_0;
    struct json *rows;
    struct json_array *rows_elem;
    struct json *port_0;
    struct json *jsn_portuuid;
    struct uuid port_uuid;

    (void)snprintf(json_char, 256,
        "[\"hardware_vtep\",{\"columns\":[\"_uuid\"],\"table\":\"Physical_Port\","
        "\"where\":[[\"name\",\"==\",\"%s\"]],\"op\":\"select\"}]",
        interface);

    transaction = parse_json(json_char);
    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);

    pl = json_array(reply->result);
    elem_0 = pl->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");
    rows_elem = json_array(rows);

    if (0 == rows_elem->n) {
        jsonrpc_msg_destroy(reply);
        return;
    }

    port_0 = rows_elem->elems[0];
    jsn_portuuid = shash_find_data(json_object(port_0), "_uuid");

    if (NULL == jsn_portuuid) {
        jsonrpc_msg_destroy(reply);
        return;
    }

    uuid_from_string(&port_uuid, json_string(json_array(jsn_portuuid)->elems[1]));

    jsonrpc_msg_destroy(reply);

    /* 删除Physical_Port表*/
    (void)snprintf(json_char, 256,
        "[\"hardware_vtep\",{\"table\":\"Physical_Switch\",\"op\":\"mutate\","\
        "\"where\":[[\"name\",\"==\",\"%s\"]],\"mutations\":"
        "[[\"ports\",\"delete\",[\"uuid\",\""UUID_FMT"\"]]]}]",
        OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_SWITCHNAME),
        UUID_ARGS(&port_uuid));
    do_transact_temp(rpc, json_char);

    return;
}

int ovsdb_add_mac(char *mac, char *bd, char *interface, int mac_type)
{
    int i = 0;
    char json_query[1000] = {0};
    int ls_num = 0;
    struct uuid *ls_uuid_s;
    int tunnel_key_exist = 0;
    int tunnel_key = 0;
    struct jsonrpc *rpc = g_args_local->rpc;
    char *tunnel_ip = g_args_local->tunnel_ip;

    ls_uuid_s= (struct uuid*)malloc(TABLE_LOGICAL_SWITCH_NUM * sizeof(struct uuid));
    if(!ls_uuid_s)
    {
        OVSDB_PRINTF_DEBUG_ERROR("Error, malloc memory failed.");
        return -1;
    }
    (void)memset(ls_uuid_s, 0, TABLE_LOGICAL_SWITCH_NUM * sizeof(struct uuid));

    /*方法:先查找ifname绑定的logical_switch，可能不止一个，然后在其中找出vni符合要求的一个*/
    (void)snprintf(json_query, 1000,
        "[\"hardware_vtep\",{\"columns\":[\"name\",\"_uuid\",\"vlan_bindings\"],"
        "\"table\":\"Physical_Port\",\"where\":[[\"name\",\"==\",\"%s\"]],\"op\":\"select\"}]",
        interface);

    do_transact_temp_query_port_binding_logical_switch(rpc, json_query, &ls_num, ls_uuid_s);

    if (0 == ls_num){
        free(ls_uuid_s);
        ls_uuid_s = NULL;
        return -1;
    }

    /*是否存在多个ls的vni符合要求的情况*/
    for(i=0; i<ls_num; i++)
    {
        char tunnel_key_string[MAX_BDID_LEN] = {0};
        tunnel_key_exist = 0;
        tunnel_key = 0;

        (void)snprintf(json_query, 1000,
            "[\"hardware_vtep\",{\"columns\":[\"description\",\"name\",\"_uuid\",\"tunnel_key\"],"
            "\"table\":\"Logical_Switch\",\"where\":[[\"_uuid\",\"==\",[\"uuid\",\""UUID_FMT"\"]]],\"op\":\"select\"}]",
            UUID_ARGS(&ls_uuid_s[i]));

        do_transact_temp_query_logical_switch_tunnel_key(rpc, json_query, &tunnel_key_exist, &tunnel_key);
        OVSDB_PRINTF_DEBUG_TRACE("No.%d tunnel_key_exist = %d.", i , tunnel_key_exist);
        (void)snprintf(tunnel_key_string, MAX_BDID_LEN, "%d", tunnel_key);
        OVSDB_PRINTF_DEBUG_TRACE("tunnel_key = %s.", tunnel_key_string);

        if((tunnel_key_exist)&&(0 == strcmp(bd, tunnel_key_string)))
        {
            /*需要先获取到tunnel ip对应的locator的uuid*/
            struct uuid phyical_locator_uuid;
            do_transact_temp_query_locator_uuid(rpc, tunnel_ip, &phyical_locator_uuid);

            if(uuid_is_zero(&phyical_locator_uuid))
            {
                #if 0
                OVSDB_PRINTF_DEBUG_TRACE("Error! Does not find physical_locator uuid with ip %s.", tunnel_ip);
                free(ls_uuid_s);
                ls_uuid_s = NULL;
                return -1;
                #endif

                OVSDB_PRINTF_DEBUG_TRACE("Add MAC. The first local one");
                
                (void)snprintf(json_query, 1000,
                    "[\"hardware_vtep\",{\"row\":{\"logical_switch\":[\"uuid\",\""UUID_FMT"\"],"
                    "\"MAC\":\"%s\",\"locator\":[\"named-uuid\",\"locator_name\"]},\"table\":\"Ucast_Macs_Local\","
                    "\"uuid-name\":\"mac_name\",\"op\":\"insert\"},{\"row\":{\"dst_ip\":\"%s\",\"encapsulation_type\":\"vxlan_over_ipv4\"},"
                    "\"table\":\"Physical_Locator\",\"uuid-name\":\"locator_name\",\"op\":\"insert\"}]",
                    UUID_ARGS(&ls_uuid_s[i]), mac, tunnel_ip);

                do_transact_temp(rpc, json_query);
                OVSDB_PRINTF_DEBUG_TRACE("write a new ucast local table.");
            }
            
            else
            {
                OVSDB_PRINTF_DEBUG_TRACE("Add MAC.");

                (void)snprintf(json_query, 1000,
                    "[\"hardware_vtep\",{\"row\":{\"logical_switch\":[\"uuid\",\""UUID_FMT"\"],"
                    "\"MAC\":\"%s\",\"locator\":[\"uuid\",\""UUID_FMT"\"]},\"table\":\"Ucast_Macs_Local\","
                    "\"uuid-name\":\"ucasl_local\",\"op\":\"insert\"}]",
                    UUID_ARGS(&ls_uuid_s[i]), mac, UUID_ARGS(&phyical_locator_uuid));

                do_transact_temp(rpc, json_query);

                /*temp to delete*/
                OVSDB_PRINTF_DEBUG_TRACE("write a new ucast local table.");
            }

            break;
        }
    }

    free(ls_uuid_s);
    ls_uuid_s = NULL;

    return 0;
}

void ovsdb_delete_mac(char *mac, char *bd, char *interface, int mac_type)
{
    char json_query_mac_local_uuid[1000] = {0};
    int uuid_num = 0;
    struct uuid *ucast_local_uuid_s;
    struct jsonrpc *rpc = g_args_local->rpc;
    int j = 0;

    ucast_local_uuid_s= (struct uuid*)malloc(TABLE_LOGICAL_SWITCH_NUM * sizeof(struct uuid));
    if(!ucast_local_uuid_s)
    {
        OVSDB_PRINTF_DEBUG_ERROR("Error, malloc memory failed.");
    }
    (void)memset(ucast_local_uuid_s, 0, TABLE_LOGICAL_SWITCH_NUM * sizeof(struct uuid));

    (void)snprintf(json_query_mac_local_uuid, 1000,
        "[\"hardware_vtep\",{\"columns\":[\"ipaddr\",\"_uuid\",\"logical_switch\","
        "\"MAC\",\"locator\"],\"table\":\"Ucast_Macs_Local\",\"where\":[[\"MAC\",\"==\",\"%s\"]],\"op\":\"select\"}]",
        mac);

    /*temp to delete*/
    OVSDB_PRINTF_DEBUG_TRACE("json_query_mac_local_uuid=%s.", json_query_mac_local_uuid);

    do_transact_temp_query_mac_local_uuid(rpc, json_query_mac_local_uuid, &uuid_num, ucast_local_uuid_s);

    /*开始删ucast_local表*/
    for(j=0; j<uuid_num; j++ )
    {
        (void)snprintf(json_query_mac_local_uuid, 1000,
            "[\"hardware_vtep\",{\"table\":\"Ucast_Macs_Local\","
            "\"where\":[[\"_uuid\",\"==\",[\"uuid\",\""UUID_FMT"\"]]],\"op\":\"delete\"}]",
            UUID_ARGS(&ucast_local_uuid_s[j]));
        do_transact_temp(rpc, json_query_mac_local_uuid);

        OVSDB_PRINTF_DEBUG_TRACE("delete a old ucast local table.");
    }

    return;
}

void ovsdb_query_port_and_mac(void)
{
    /* 查找端口表 */
    (void)netconf_ce_query_interface();

    /* 查找MAC表 */
    (void)netconf_ce_query_db_mac();

    return;
}

void
ovsdb_query_mac_initial(struct jsonrpc *rpc)
{
    char *json_char = "[\"hardware_vtep\",{\"columns\":[\"MAC\",\"logical_switch\"],"\
                      "\"table\":\"Ucast_Macs_Local\",\"where\":[],\"op\":\"select\"}]";
    unsigned int i;
    int ret;
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct json_array *pl;
    struct json *elem_0;
    struct json *rows;
    struct json_array *rows_elem;
    struct json *pl_0;
    struct json *mac;
    char *pcMac, *pclogical_switch_uuid_s;
    struct json *logical_switch;
    int tunnel_key_exist, tunnel_key;
    struct ovsdb_sub_mac_key key   = {0};
    struct ovsdb_sub_mac_data data = {0};
    struct ovsdb_sub_entry *entry = NULL;

    transaction = parse_json(json_char);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);

    pl = json_array(reply->result);
    elem_0 = pl->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");
    rows_elem = json_array(rows);

    for (i = 0; i < rows_elem->n; i++) {
        pl_0 = rows_elem->elems[i];
        mac = shash_find_data(json_object(pl_0), "MAC");

        if (JSON_STRING != mac->type) {
            continue;
        }
        pcMac = json_string(mac);

        logical_switch = shash_find_data(json_object(pl_0), "logical_switch");

        if ((JSON_ARRAY != logical_switch->type) ||
            (logical_switch->u.array.n != 2) ||
            (logical_switch->u.array.elems[1]->type != JSON_STRING)) {
            continue;
        }
        pclogical_switch_uuid_s = json_string(logical_switch->u.array.elems[1]);

        json_char = (char *)malloc(256);
        if (NULL == json_char)
            break;

        (void)snprintf(json_char, 256, 
            "[\"hardware_vtep\",{\"columns\":[\"_uuid\",\"tunnel_key\"],"
            "\"table\":\"Logical_Switch\",\"where\":[[\"_uuid\",\"==\","
            "[\"uuid\",\"%s\"]]],\"op\":\"select\"}]",
            pclogical_switch_uuid_s);

        tunnel_key_exist = 0;
        tunnel_key = 0;

        do_transact_temp_query_logical_switch_tunnel_key(rpc, json_char, &tunnel_key_exist, &tunnel_key);

        free(json_char);

        if (tunnel_key_exist) {

            (void)snprintf(key.macAdd, 18, "%s", pcMac);
            key.macAdd[17] = '_';
            (void)snprintf(key.BD, OVSDB_SUB_BD_LEN, "%d", tunnel_key);
            
            entry = add_entry(OVSDB_SUB_TABLE_MAC, (char *)&key, (char *)&data);
            if (NULL == entry) {
                OVSDB_PRINTF_DEBUG_ERROR("Initial add MAC failed, mac: %s", key.macAdd);
            }
        }
        
    }

    jsonrpc_msg_destroy(reply);

    return;
}

void
ovsdb_query_port_initial(struct jsonrpc *rpc)
{
    char *json_char = "[\"hardware_vtep\",{\"columns\":[\"name\"],"\
                      "\"table\":\"Physical_Port\",\"where\":[],\"op\":\"select\"}]";
    unsigned int i;
    char * interface;
    struct ovsdb_sub_port_key key = {0};
    struct ovsdb_sub_entry *entry = NULL;
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct json_array *pl;
    struct json *elem_0;
    struct json *rows;
    struct json_array *rows_elem;
    struct json *pl_0;
    struct json *jsn_portname;

    transaction = parse_json(json_char);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);

    pl = json_array(reply->result);
    elem_0 = pl->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");
    rows_elem = json_array(rows);

    for (i = 0; i < rows_elem->n; i++) {
        pl_0 = rows_elem->elems[i];
        jsn_portname = shash_find_data(json_object(pl_0), "name");

        if(JSON_STRING == jsn_portname->type) {
            interface = json_string(jsn_portname);
            (void)strncpy(key.interface, interface, OVSDB_SUB_INTERFACE_LEN);
            entry = add_entry(OVSDB_SUB_TABLE_INTERFACE, (char *)&key, NULL);
            if (NULL == entry) {
                OVSDB_PRINTF_DEBUG_ERROR("Initial add interface failed, interface: %s", interface);
            }
        }
    }

    jsonrpc_msg_destroy(reply);

    return;
}
#endif

void ovsdb_write_mcast_local(struct jsonrpc *rpc, char *tunnel_ip)
{
    int i=0;
    int ls_num=0;
    struct logical_switch_uuid_and_vni *ls_info;

    ls_info = (struct logical_switch_uuid_and_vni*)malloc(TABLE_LOGICAL_SWITCH_NUM * sizeof(struct logical_switch_uuid_and_vni));
    if(!ls_info)
    {
        OVSDB_PRINTF_DEBUG_ERROR("Error, malloc memorf failed.");
        return;
    }
    memset(ls_info, 0, TABLE_LOGICAL_SWITCH_NUM * sizeof(struct logical_switch_uuid_and_vni));

    do_transact_temp_query_logical_switch(rpc, &ls_num, ls_info);

    /*
    添加、删除mcast local mac表的逻辑如下:
    定时遍历logical switch表(仅包含有tunnel key的ls)，查询下面两个信息
    (1)该logical switch是否有对应的mcast local表项(unknow-dst)。
    (2)ucast remote表中是否有该logical switch对应的表项
    如果(1)中没有，(2)中有，则需要新增一条mcast local记录
    如果(1)中有，(2)中没有，则需要删除对应的mcast local记录
    */

    for(i=0; i<ls_num; i++)
    {
        int ls_has_mcast_local_record = 0;
        int ls_has_ucast_remote_record = 0;
        struct uuid uuid_mac;

        /* 首选获取ls_has_mcast_local_record的值 */
        do_transact_temp_query_logical_switch_has_mcast_local_record(rpc, &ls_info[i].uuid_ls, &ls_has_mcast_local_record, &uuid_mac);
        
        /* 然后获取ls_has_ucast_remote_record的值 */
        do_transact_temp_query_logical_switch_has_ucast_remote_record(rpc, &ls_info[i].uuid_ls, &ls_has_ucast_remote_record);
        
        /* 新增一条mcast local表 */
        if((!ls_has_mcast_local_record)&&(ls_has_ucast_remote_record))
        {
            
            struct uuid phyical_locator_uuid;
            
            do_transact_temp_query_locator_uuid(rpc, tunnel_ip, &phyical_locator_uuid);
            
            /* 没有nve ip对应的locator */
            if(uuid_is_zero(&phyical_locator_uuid))
            {
                char json_insert_mcast_local[2000]={0};
                (void)snprintf(json_insert_mcast_local, 2000,
                        "[\"hardware_vtep\","\
                        "{\"row\":{\"locators\":[\"named-uuid\",\"locator_uuid\"]},"\
                        "\"table\":\"Physical_Locator_Set\","\
                        "\"uuid-name\":\"locator_set_uuid\","\
                        "\"op\":\"insert\"},"\
                        "{\"row\":{\"logical_switch\":[\"uuid\",\""UUID_FMT"\"],"\
                        "\"locator_set\":[\"named-uuid\",\"locator_set_uuid\"],"\
                        "\"MAC\":\"unknown-dst\"},"\
                        "\"table\":\"Mcast_Macs_Local\","\
                        "\"uuid-name\":\"macst_local_uuid\","\
                        "\"op\":\"insert\"},"\
                        "{\"row\":{\"dst_ip\":\"%s\","\
                        "\"encapsulation_type\":\"vxlan_over_ipv4\"},"\
                        "\"table\":\"Physical_Locator\","\
                        "\"uuid-name\":\"locator_uuid\","\
                        "\"op\":\"insert\"}]",
                UUID_ARGS(&ls_info[i].uuid_ls),tunnel_ip);
                do_transact_temp(rpc, json_insert_mcast_local);

                OVSDB_PRINTF_DEBUG_TRACE("write a new mcast local entry. nve ip is without locator before");
            }
            /* 有nve ip对应的locator */
            else
            {
                char json_insert_mcast_local[2000]={0};
                (void)snprintf(json_insert_mcast_local, 2000,
                        "[\"hardware_vtep\",{\"row\":{\"locators\":[\"uuid\",\""UUID_FMT"\"]},\"table\":\"Physical_Locator_Set\","
                        "\"uuid-name\":\"aa\",\"op\":\"insert\"},{\"row\":{\"logical_switch\":[\"uuid\",\""UUID_FMT"\"],"
                        "\"locator_set\":[\"named-uuid\",\"aa\"],\"MAC\":\"unknown-dst\"},\"table\":\"Mcast_Macs_Local\","
                        "\"uuid-name\":\"mcast_local_name\",\"op\":\"insert\"}]",
                        UUID_ARGS(&phyical_locator_uuid), UUID_ARGS(&ls_info[i].uuid_ls));
                do_transact_temp(rpc, json_insert_mcast_local);

                OVSDB_PRINTF_DEBUG_TRACE("write a new mcast local entry. nve ip is with locator before.");
            }
        }
        
        /* 删除一条mcast local表 */
        if((ls_has_mcast_local_record)&&(!ls_has_ucast_remote_record))
        {
            char json_delete_mcast_local[1000] = {0};
            (void)snprintf(json_delete_mcast_local, 1000,
                    "[\"hardware_vtep\",{\"table\":\"Mcast_Macs_Local\","
                    "\"where\":[[\"_uuid\",\"==\",[\"uuid\",\""UUID_FMT"\"]]],\"op\":\"delete\"}]",
                    UUID_ARGS(&uuid_mac));
            do_transact_temp(rpc, json_delete_mcast_local);
            OVSDB_PRINTF_DEBUG_TRACE("delete a mcast local entry.");
        }
    }

    OVSDB_FREE(ls_info);
    return;
}

#if OVSDB_DESC("netconf packet download")

#include "list.h"

struct netconf_msg_list {
    struct ovs_list head;
    unsigned int num;
    struct timeval tv;
};

struct netconf_msg_node {
    struct ovs_list list_node;
    char * msg;
    size_t len;
};

struct netconf_msg_list g_netconf_msg_list = {0};

#define netconf_msg_list_count(list) ((list)->num)

#define netconf_msg_list_init(list) \
do{ \
    list_init(&((list)->head)); \
    ((list)->num) = 0; \
    xgettimeofday(&((list)->tv)); \
}while(0)

#define netconf_msg_list_push_back(list, node) \
do{ \
    list_push_back(&((list)->head), (node)); \
    ((list)->num)++; \
    xgettimeofday(&((list)->tv)); \
}while(0)

#define netconf_msg_list_destroy_node(node) \
do{ \
    OVSDB_FREE((node)->msg); \
    OVSDB_FREE(node);        \
}while(0)

#define NETCONF_MSG_ERROR_TYPE "continue-on-error"

#define NETCONF_MSG_HEAD \
"<edit-config>"\
"<target><running/></target>"\
"<default-operation>merge</default-operation>"\
"<error-option>"NETCONF_MSG_ERROR_TYPE"</error-option>"\
"<config>"

#define NETCONF_MSG_END \
"</config>"\
"</edit-config>"

#define NETCONF_MSG_DATA_LEN 512
#define NETCONF_MSG_LIST_MAX 40
#define NETCONF_MSG_LIST_TIME 5

int netconf_msg_list_send_msg(struct netconf_msg_list * list)
{
    size_t len = 0;
    int ret = 0;
    int len_current = 0;
    struct netconf_msg_node * node;
    char * msg = NULL;

    if (0 == netconf_msg_list_count(list))
        return OVSDB_OK;

    len = strlen(NETCONF_MSG_HEAD) + strlen(NETCONF_MSG_END) + 1;

    LIST_FOR_EACH(node, list_node, &list->head) {
        len += node->len;
    }

    msg = (char *)malloc(len);
    if (NULL == msg) {
        OVSDB_PRINTF_DEBUG_ERROR("Malloc msg error, len = %d.", len);
        return OVSDB_ERR;
    }

    (void)memset(msg, 0, len);

    len_current = snprintf(msg, len, NETCONF_MSG_HEAD);
    if (len_current < 0) {
        OVSDB_FREE(msg);
        return OVSDB_ERR;
    }

    LIST_FOR_EACH_POP(node, list_node, &list->head) {
        ret = snprintf(msg + len_current, len - len_current, node->msg);

        netconf_msg_list_destroy_node(node);
        list->num --;

        if (ret < 0) {
            OVSDB_PRINTF_DEBUG_ERROR("set msg = %d.", list->num);
            OVSDB_FREE(msg);
            return OVSDB_ERR;
        }
        len_current += ret;
    }

    ret = snprintf(msg + len_current, len - len_current, NETCONF_MSG_END);
    if (ret < 0) {
        OVSDB_PRINTF_DEBUG_ERROR("set msg end fail. len = %d, current = %d.", len, len_current);
        OVSDB_FREE(msg);
        return OVSDB_ERR;
    }

    (void)netconf_ce_set_config(msg);

    OVSDB_FREE(msg);
    return OVSDB_OK;
}

void netconf_msg_list_send_all_msg(struct netconf_msg_list * list)
{
    struct timeval tv;
    time_t temp;

    if (0 == netconf_msg_list_count(list))
        return;

    xgettimeofday(&tv);
    temp = (list->tv.tv_sec <= tv.tv_sec) ?
        (tv.tv_sec - list->tv.tv_sec) : (list->tv.tv_sec - tv.tv_sec);
    if (temp >= NETCONF_MSG_LIST_TIME) {
        (void)netconf_msg_list_send_msg(list);
        (void)memcpy(&list->tv, &tv, sizeof(struct timeval));
    }

    return;
}

int netconf_msg_list_add_node(char * msg)
{
    struct netconf_msg_node * node;

    if (NULL == msg)
        return OVSDB_ERR;
        
    node = (struct netconf_msg_node *)malloc(sizeof(struct netconf_msg_node));
    if (NULL == node)
        return OVSDB_ERR;

    (void)memset(node, 0, sizeof(struct netconf_msg_node));

    OVSDB_SET_STR(node->msg, msg);

    if (NULL == node->msg) {
        OVSDB_FREE(node);
        return OVSDB_ERR;
    }

    node->len = strlen(node->msg);

    netconf_msg_list_push_back(&g_netconf_msg_list, node);

    if (netconf_msg_list_count(&g_netconf_msg_list) >= NETCONF_MSG_LIST_MAX) {
        netconf_msg_list_send_msg(&g_netconf_msg_list);
    }

    return OVSDB_OK;
}

int netconf_msg_list_config_bd(unsigned int uiVniId)
{
    int  ret                              = 0;
    char send_data[NETCONF_MSG_DATA_LEN]  = {0};

    if (uiVniId > MAX_VNI_ID || uiVniId < MIN_VNI_ID)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]The VNI id %d is illegal.", uiVniId);
        return OVSDB_ERR;
    }

    snprintf(send_data, sizeof(send_data),
            "<evc xmlns=\"http://www.huawei.com/netconf/vrp\" format-version=\"1.0\" content-version=\"1.0\">"\
              "<bds>"\
                "<bd operation=\"create\">"\
                  "<bdId>%d</bdId>"\
                "</bd>"\
              "</bds>"\
            "</evc>"\
            "<nvo3 xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<nvo3Vni2Bds>"\
                "<nvo3Vni2Bd operation=\"create\">"\
                  "<vniId>%d</vniId>"\
                  "<bdId>%d</bdId>"\
                "</nvo3Vni2Bd>"\
              "</nvo3Vni2Bds>"\
            "</nvo3>", uiVniId, uiVniId, uiVniId);

    ret = netconf_msg_list_add_node(send_data);
    if (OVSDB_OK != ret)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [vxlan vni %d]", uiVniId);
    }

    return ret;
}

/*
   undo bridge-domain xxxx
*/
int netconf_msg_list_undo_config_bd(unsigned int uiVniId)
{
    int    ret                             = 0;
    char   send_data[NETCONF_MSG_DATA_LEN] = {0};

    if (uiVniId > MAX_VNI_ID || uiVniId < MIN_VNI_ID)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]The VNI id %d is illegal.", uiVniId);
        return OVSDB_ERR;
    }

    (void)netconf_msg_list_undo_config_vxlan_tunnel(uiVniId, NULL);

    snprintf(send_data, sizeof(send_data),
            "<evc xmlns=\"http://www.huawei.com/netconf/vrp\" format-version=\"1.0\" content-version=\"1.0\">"\
              "<bds>"\
                "<bd operation=\"delete\">"\
                  "<bdId>%d</bdId>"\
                "</bd>"\
              "</bds>"\
            "</evc>", uiVniId);

    ret = netconf_msg_list_add_node(send_data);
    if (OVSDB_OK != ret)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [undo bridge-domain %d].", uiVniId);
    }

    return ret;
}

int netconf_msg_list_config_vxlan_tunnel(unsigned int uiVni, char * paDstIp)
{
    int    ret                             = 0;
    char   send_data[NETCONF_MSG_DATA_LEN] = {0};

    /* 1.判断VNI是否合法 */
    if((uiVni > MAX_VNI_ID)||(uiVni < MIN_VNI_ID))
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Vni %d is not valid.", uiVni);
        return OVSDB_ERR;
    }

    /* 2.判断dst_ip是否为空 */
    if(!paDstIp)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Dst_ip is NULL.");
        return OVSDB_ERR;
    }

    /* 4.配置vni uiVni head-end peer-list paDstIp */
    snprintf(send_data, sizeof(send_data),
            "<nvo3 xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<nvo3Nves>"\
                "<nvo3Nve operation=\"merge\">"\
                  "<ifName>nve1</ifName>"\
                  "<vniMembers>"\
                    "<vniMember operation=\"merge\">"\
                      "<vniId>%d</vniId>"\
                      "<nvo3VniPeers>"\
                        "<nvo3VniPeer operation=\"merge\">"\
                          "<peerAddr>%s</peerAddr>"\
                        "</nvo3VniPeer>"\
                      "</nvo3VniPeers>"\
                    "</vniMember>"\
                  "</vniMembers>"\
                "</nvo3Nve>"\
              "</nvo3Nves>"\
            "</nvo3>", uiVni, paDstIp);

    ret = netconf_msg_list_add_node(send_data);
    if (OVSDB_OK != ret)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [vni %d head-end peer-list %s]", uiVni, paDstIp);
        return OVSDB_ERR;
    }

    return OVSDB_OK;
}

int netconf_msg_list_undo_config_vxlan_tunnel(unsigned int uiVni, char * paDstIp)
{
    int    ret                             = 0;
    char   send_data[NETCONF_MSG_DATA_LEN] = {0};

    /* 1.判断VNI是否合法 */
    if((uiVni > MAX_VNI_ID)||(uiVni < MIN_VNI_ID))
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Vni %d is not valid.", uiVni);
        return OVSDB_ERR;
    }

    /* 4.删除vxlan隧道 */
    if (NULL != paDstIp) {
        /* 4.1.先删除头端复制列表*/
        snprintf(send_data, sizeof(send_data),
                "<nvo3 xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
                  "<nvo3Nves>"\
                    "<nvo3Nve operation=\"merge\">"\
                      "<ifName>nve1</ifName>"\
                      "<vniMembers>"\
                        "<vniMember operation=\"merge\">"\
                          "<vniId>%d</vniId>"\
                          "<nvo3VniPeers>"\
                            "<nvo3VniPeer operation=\"delete\">"\
                              "<peerAddr>%s</peerAddr>"\
                            "</nvo3VniPeer>"\
                          "</nvo3VniPeers>"\
                        "</vniMember>"\
                      "</vniMembers>"\
                    "</nvo3Nve>"\
                  "</nvo3Nves>"\
                "</nvo3>", uiVni, paDstIp);
    }
    else {
        /* 4.2.再删除VNI*/
        snprintf(send_data, sizeof(send_data),
                "<nvo3 xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
                  "<nvo3Nves>"\
                    "<nvo3Nve operation=\"merge\">"\
                      "<ifName>nve1</ifName>"\
                      "<vniMembers>"\
                        "<vniMember operation=\"delete\">"\
                          "<vniId>%d</vniId>"\
                        "</vniMember>"\
                      "</vniMembers>"\
                    "</nvo3Nve>"\
                  "</nvo3Nves>"\
                "</nvo3>", uiVni);
    }
    ret = netconf_msg_list_add_node(send_data);
    if (OVSDB_OK != ret)
    {
        if (NULL != paDstIp)
            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [undo vni %d head-end peer-list %s].", uiVni, paDstIp);
        else
            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [undo vni %d]", uiVni);
    }

    return ret;
}

int netconf_msg_list_config_port(unsigned int uiVlanId, unsigned int uiVniId, char* paIfname)
{
    int    ret = 0;
    char   subifname[NETCONF_SUBINTERFACE_LEN] = {0};
    char  *send_data = NULL;
    unsigned char netconfBit[NETCONF_VLANBIT_LEN_STR + 1] = {0};

    if((uiVlanId > MAX_VLAN_ID)||(uiVlanId < MIN_VLAN_ID))
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Vlan id %d id invalid", uiVlanId);
        return OVSDB_ERR;
    }

    if((uiVniId > MAX_VNI_ID)||(uiVniId < MIN_VNI_ID))
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Vni %d is invalid", uiVniId);
        return OVSDB_ERR;
    }

    if(!paIfname)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Port ifname name %s is NULL", paIfname);
        return;
    }

    (void)snprintf(subifname, NETCONF_SUBINTERFACE_LEN,
        "%s.%d", paIfname, uiVlanId + 1);

    send_data = (char *)malloc(NETCONF_SEND_DATA_LEN);
    if (NULL == send_data){
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to malloc msg [interface %s mode l2]", subifname);
        return OVSDB_ERR;
    }

    (void)memset(send_data, 0, NETCONF_SEND_DATA_LEN);

    /* 配置interface paIfname.uiSubInterNum mode l2 */
    (void)snprintf(send_data, NETCONF_SEND_DATA_LEN,
        "<ifm xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
          "<interfaces>"\
            "<interface operation=\"create\">"\
              "<ifName>%s</ifName>"\
              "<l2SubIfFlag>true</l2SubIfFlag>"\
            "</interface>"\
          "</interfaces>"\
        "</ifm>"\
        "<evc xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
          "<bds>"\
            "<bd operation=\"merge\">"\
              "<bdId>%d</bdId>"\
                "<servicePoints>"\
                  "<servicePoint operation=\"create\">"\
                    "<ifName>%s</ifName>"\
                  "</servicePoint>"\
              "</servicePoints>"\
            "</bd>"\
          "</bds>"\
        "</evc>", subifname, uiVniId, subifname);

    ret = netconf_msg_list_add_node(send_data);
    if (OVSDB_OK != ret)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [interface %s mode l2]", subifname);
        OVSDB_FREE(send_data);
        return ret;
    }

    if(0 == uiVlanId)
    {
        /* 配置encapsulation untag */
        (void)snprintf(send_data, NETCONF_SEND_DATA_LEN,
            "<ethernet xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<servicePoints>"\
                "<servicePoint operation=\"merge\">"\
                  "<ifName>%s</ifName>"\
                  "<flowType>untag</flowType>"\
                "</servicePoint>"\
              "</servicePoints>"\
            "</ethernet>", subifname);

        ret = netconf_msg_list_add_node(send_data);
        if (OVSDB_OK != ret)
        {
            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config %s [encapsulation untag]", subifname);
        }
    }
    else
    {
        netconf_vlanbit2netvlanbit(uiVlanId, netconfBit);

        /* 配置encapsulation dot1q vid uiVlanId */
        (void)snprintf(send_data, NETCONF_SEND_DATA_LEN,
                "<ethernet xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
                  "<servicePoints>"\
                    "<servicePoint operation=\"merge\">"\
                      "<ifName>%s</ifName>"\
                      "<flowType>dot1q</flowType>"\
                      "<flowDot1qs>"\
                        "<dot1qVids>%s:%s</dot1qVids>"\
                      "</flowDot1qs>"\
                    "</servicePoint>"\
                  "</servicePoints>"\
                "</ethernet>", subifname, netconfBit, netconfBit);

        ret = netconf_msg_list_add_node(send_data);
        if (OVSDB_OK != ret)
        {
            OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config %s [encapsulation vlan %d]", subifname, uiVlanId);
        }
    }

    OVSDB_FREE(send_data);

    return ret;
}

int netconf_msg_list_undo_config_port(unsigned int uiVlanId, char* paIfname)
{
    int    ret                             = 0;
    char   send_data[NETCONF_MSG_DATA_LEN] = {0};
    unsigned int  uiSubInterNum            = 0;

    if((uiVlanId > MAX_VLAN_ID)||(uiVlanId < MIN_VLAN_ID))
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Vlan id %d id invalid", uiVlanId);
        return OVSDB_ERR;
    }

    if(!paIfname)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Port ifname name %s is NULL", paIfname);
        return OVSDB_ERR;
    }

    /* 为子接口号赋值 */
    uiSubInterNum = uiVlanId + 1;

    /* 删除interface paIfname.uiSubInterNum mode l2 */
    snprintf(send_data, sizeof(send_data),
            "<ifm xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<interfaces>"\
                "<interface operation=\"delete\">"\
                  "<ifName>%s.%d</ifName>"\
                  "<l2SubIfFlag>true</l2SubIfFlag>"\
                "</interface>"\
              "</interfaces>"\
            "</ifm>", paIfname, uiSubInterNum);

    ret = netconf_msg_list_add_node(send_data);
    if (OVSDB_OK != ret)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [undo interface %s.%d mode l2]", paIfname, uiSubInterNum);
    }

    return ret;
}

int netconf_msg_list_config_vxlan_tunnel_static_mac(char* paStaticMac, char* paSourceIp, char* paDstIp, unsigned int uiVniId)
{
    int    ret                             = 0;
    char   send_data[NETCONF_MSG_DATA_LEN] = {0};

    if(!paSourceIp)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]source_ip is NULL.");
        return OVSDB_ERR;
    }

    if(!paDstIp)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]dst_ip is NULL.");
        return OVSDB_ERR;
    }

    if(!paStaticMac)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]ce_mac is NULL.");
        return OVSDB_ERR;
    }

    /* 配置mac-address static paStaticMac bridge-domain uiVniId source paSourceIp peer paDstIp vni uiVniId */
    snprintf(send_data, sizeof(send_data),
            "<mac xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<vxlanFdbs>"\
                "<vxlanFdb operation=\"create\">"\
                  "<slotId>0</slotId>"\
                  "<macAddress>%s</macAddress>"\
                  "<bdId>%d</bdId>"\
                  "<macType>static</macType>"\
                  "<sourceIP>%s</sourceIP>"\
                  "<peerIP>%s</peerIP>"\
                  "<vnId>%d</vnId>"\
                "</vxlanFdb>"\
              "</vxlanFdbs>"\
            "</mac>", paStaticMac, uiVniId, paSourceIp, paDstIp, uiVniId);

    ret = netconf_msg_list_add_node(send_data);
    if (OVSDB_OK != ret)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [mac-address static %s bridge-domain %d source %s peer %s vni %d]",
            paStaticMac, uiVniId, paSourceIp, paDstIp, uiVniId);
    }

    return ret;
}

int netconf_msg_list_undo_config_vxlan_tunnel_static_mac(char* paStaticMac, char* paSourceIp, char* paDstIp, unsigned int uiVniId)
{
    int    ret                             = 0;
    char   send_data[NETCONF_MSG_DATA_LEN] = {0};

    if(!paSourceIp)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]source_ip is NULL");
        return OVSDB_ERR;
    }

    if(!paDstIp)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]dst_ip is NULL");
        return OVSDB_ERR;
    }

    if(!paStaticMac)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]ce_mac is NULL");
        return OVSDB_ERR;
    }

    /* 删除mac-address static paStaticMac bridge-domain uiVniId source paSourceIp peer paDstIp vni uiVniId */
    snprintf(send_data, sizeof(send_data),
            "<mac xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<vxlanFdbs>"\
                "<vxlanFdb operation=\"delete\">"\
                  "<slotId>0</slotId>"\
                  "<macAddress>%s</macAddress>"\
                  "<bdId>%d</bdId>"\
                  "<macType>static</macType>"\
                  "<sourceIP>%s</sourceIP>"\
                  "<peerIP>%s</peerIP>"\
                  "<vnId>%d</vnId>"\
                "</vxlanFdb>"\
              "</vxlanFdbs>"\
            "</mac>", paStaticMac, uiVniId, paSourceIp, paDstIp, uiVniId);

    ret = netconf_msg_list_add_node(send_data);
    if (OVSDB_OK != ret)
    {
        OVSDB_PRINTF_DEBUG_ERROR("[ERROR]Failed to config [undo mac-address static %s bridge-domain %d source %s peer %s vni %d]",
            paStaticMac, uiVniId, paSourceIp, paDstIp, uiVniId);
    }

    return ret;
}

#endif

/*以do monitor函数为主体*/
void
do_vtep(struct jsonrpc *rpc, const char *database,
        int argc , char *argv[] )
{
    int ret = 0;

    OVSDB_PRINTF_DEBUG_TRACE("Enter ovsdb-client do_vtep.");
    
    if (0 != ovsdb_client_init_cfg())
        return;

    /* create netconf connection*/
    gst_nc_sess[0].tid = gettid();
    ret = netconf_ce_config_init(&gst_nc_sess[0]);
    if (0 != ret)
    {
        OVSDB_PRINTF_DEBUG_ERROR("Netconf session connects failed.");
        return;
    }

    ret = ovsdb_client_init_system_mac();
    if (0 != ret)
    {
        OVSDB_PRINTF_DEBUG_ERROR("Get system mac failed.");
        return;
    }

    if(!strcmp(argv[0], "monitor"))
    {
        OVSDB_PRINTF_DEBUG_TRACE("ovsdb-client transact.");
        do_vtep_transact(g_rpc_transact2);

        OVSDB_PRINTF_DEBUG_TRACE("ovsdb-client monitor.");
        do_vtep_monitor(rpc, database, argc, argv);
    }

    netconf_ce_config_destory(&gst_nc_sess[0]);
    gst_nc_sess[0].tid = 0;

    return;
}

void ovsdb_vtep_transact_thread(void *args)
{
    char *tunnel_ip;
    struct jsonrpc *rpc;
    int time=8;
    int ret;

    g_args_local = (struct ovsdb_write_mcast_local_args *)args;
    tunnel_ip = g_args_local->tunnel_ip;
    rpc = g_args_local->rpc;

    if(!rpc)
    {
        OVSDB_PRINTF_DEBUG_ERROR("rpc is NULL.");
        return;
    }

    if(!tunnel_ip)
    {
        OVSDB_PRINTF_DEBUG_ERROR("tunnel_ip is NULL.");
        return;
    }

    gst_nc_sess[1].tid = gettid();
    ret = netconf_ce_config_init(&gst_nc_sess[1]);
    if (0 != ret)
    {
        OVSDB_PRINTF_DEBUG_ERROR("Netconf session 1 connects failed.");
        return;
    }

    for(;;) /*一直在循环*/
    {
        /*a short delay*/
        sleep(1);

        if (time >= 10){
            ovsdb_query_port_and_mac();
            (void)netconf_ce_query_bfd_status(rpc);
            time = 0;
        }
        time++;

        ovsdb_write_mcast_local(rpc, tunnel_ip);
    }

    netconf_ce_config_destory(&gst_nc_sess[1]);
    gst_nc_sess[1].tid = 0;

    OVSDB_FREE(g_args_local);

    return;
}

void do_vtep_transact(struct jsonrpc *rpc)
{
    pthread_t tid_trasact;
    //pthread_t tid_socket_mcast_local;
    struct ovsdb_write_mcast_local_args * args;
    struct uuid uuid_global;

    /*1.检测到Global 有数据，将physical_switch Physical_Port信息写入OVSDB*/
    /*检测Global表是否存在.这种方法是否靠谱?是否要改成Manager表?*/
    /*3.16最好改成manager表，因为发现增加一个ls，global表也会有*/
    OVSDB_PRINTF_DEBUG_TRACE("Detect whether controller is connected.");

    int global_uuid_num;
    int physical_switch_exist = 0;

    //char* json_query_global_uuid="[\"hardware_vtep\",{\"columns\":[\"_uuid\"],\"table\":\"Global\",\"where\":[],\"op\":\"select\"}]";
    char json_insert_ps[1000]={0};
    //char json_insert_port[1000]={0};

    uuid_zero(&uuid_global);
    for(;;)
    {
        /*a short delay*/
        //int cnt=0;
        //do{cnt++;}while(cnt < 100000000);
        sleep(1);

        do_transact_temp_query_global(rpc, &global_uuid_num, &uuid_global);
        if(global_uuid_num)
        {
            OVSDB_PRINTF_DEBUG_TRACE("Global Table is present.");
            break;
        }
    }

    /*首先检查是否已有physical switch，*/
    do_transact_temp_query_physical_switch_exist(rpc, &physical_switch_exist,
        OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_TUNNERIP));
    if(!physical_switch_exist)
    {
        /*写Physical_Switch表*/
        OVSDB_PRINTF_DEBUG_TRACE("Write Physical_Switch info to OVSDB.");
        OVSDB_PRINTF_DEBUG_TRACE("global table uuid ="UUID_FMT, UUID_ARGS(&uuid_global));
        snprintf(json_insert_ps, 1000,
            "[\"hardware_vtep\",{\"op\":\"insert\", \"table\":\"Physical_Switch\", "
            "\"row\":{\"name\":\"%s\",\"description\":\"%s\",\"tunnel_ips\":\"%s\",\"management_ips\":\"%s\"}, "
            "\"uuid-name\":\"anotheritem\" }, "
            "{\"op\":\"mutate\", \"table\":\"Global\", \"where\":[[\"_uuid\",\"==\",[\"uuid\",\""UUID_FMT"\"]]], "
            "\"mutations\":[[\"switches\", \"insert\", [\"set\",[[\"named-uuid\", \"anotheritem\"]]]]] }]",
            OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_SWITCHNAME),
            OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_DESCRIPTION),
            OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_TUNNERIP),
            OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_SWITCHMANAGEIP),
            UUID_ARGS(&uuid_global));
        OVSDB_PRINTF_DEBUG_TRACE("json_insert_ps=%s.", json_insert_ps);
        do_transact_temp(rpc, json_insert_ps);
    }

    /* 导入现有mac表和接口表 */
    ovsdb_query_port_initial(rpc);
    ovsdb_query_mac_initial(rpc);

    /* 如果未使能BFD功能，需要删除全局BFD配置 */
    if (0 != strcmp(OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_TUNNERBFDENABLE), "true")) {
        (void)netconf_ce_config_global_bfd(false);
    }
    /* 使能undo静态mac drop命令 */
    else {
        netconf_ce_undo_config_drop_conflict_packet();
    }

    args = (struct ovsdb_write_mcast_local_args *)malloc(sizeof(struct ovsdb_write_mcast_local_args));
    if (NULL == args) {
        OVSDB_PRINTF_DEBUG_ERROR("Malloc args failed.");
        return;
    }

    args->rpc = rpc;
    args->tunnel_ip = NULL;
    OVSDB_SET_STR(args->tunnel_ip, OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_TUNNERIP));

    if (pthread_create(&tid_trasact, NULL, (void *)ovsdb_vtep_transact_thread, args))
    {
        printf("Error! Create Thread Failed with ovsdb_receive_mac_from_FEI\n");
        return;
    }

#if 0   /*暂时注释掉*/
    /*一直检测Logical_Switch，当创建了新的ls后，写入一条mcast-local表*/
    if (pthread_create(&tid_socket_mcast_local, NULL, (void *)ovsdb_write_mcast_local, &args))
    {
        printf("Error! Create Thread Failed with ovsdb_receive_mac_from_FEI\n");
    }

    /*维持主线程*/
    do{
        sleep(1);
    }while(1);

    ovsdb_vtep_transact_thread(&args);
#endif
}


void ovsdb_set_manager(struct jsonrpc *rpc)
{
    char json_char[512] = {0};
    unsigned int i;
    char *p;
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct json_array *pl;
    struct json *elem_0;
    struct json *rows;
    struct json_array *rows_elem;
    struct json *pl_0;
    struct uuid ui_manager = {0};
    struct uuid ui_global = {0};
    char c_manager[64] = {0};
    char c_global[64] = {0};
    
    
    (void)snprintf(json_char, 512, 
            "[\"hardware_vtep\",{\"columns\":[\"_uuid\"],"\
            "\"table\":\"Manager\",\"where\":[],\"op\":\"select\"}]");
    
    transaction = parse_json(json_char);

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);

    pl = json_array(reply->result);
    elem_0 = pl->elems[0];
    rows = shash_find_data(json_object(elem_0), "rows");
    if(0 != json_array(rows)->n)
    {
        jsonrpc_msg_destroy(reply);
        return;
    }

    jsonrpc_msg_destroy(reply);
    
    
    uuid_generate(&ui_manager);
    uuid_generate(&ui_global);
    
    snprintf(c_manager, 64, "row"UUID_FMT, UUID_ARGS(&ui_manager));
    for (p = c_manager; *p != '\0'; p++) {
        if (*p == '-'){
            *p = '_';
        }
    }
    
    snprintf(c_global, 64, "row"UUID_FMT, UUID_ARGS(&ui_global));
    for (p = c_global; *p != '\0'; p++) {
        if (*p == '-'){
            *p = '_';
        }
    }
    
    (void)snprintf(json_char, 512,
        "[\"hardware_vtep\",{\"row\":{\"target\":\"%s:%s:%s\"},"
        "\"table\":\"Manager\",\"uuid-name\":\"%s\",\"op\":\"insert\"},"
        "{\"row\":{\"managers\":[\"named-uuid\",\"%s\"]},"
        "\"table\":\"Global\",\"uuid-name\":\"%s\",\"op\":\"insert\"}]",
        OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_LINKTYPE),
        OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_CONTROLLERIP),
        OVSDB_CLIENT_CFG_GET_STRING(OVSDB_CLIENT_CFG_CONTROLLERPORT),
        c_manager, c_manager, c_global);

    do_transact_temp(rpc, json_char);
    
    return;
}

void do_vtep_monitor(struct jsonrpc *rpc, const char *database,
        int argc , char *argv[] )
{

    const char *server = jsonrpc_get_name(rpc);
    /*固定监听所有表*/
    //const char *table_name = argv[0];
    const char *table_name = "ALL";

    struct unixctl_server *unixctl;
    struct ovsdb_schema *schema;
    struct jsonrpc_msg *request;
    struct json *monitor, *monitor_requests, *request_id;
    bool exiting = false;
    bool blocked = false;

    struct monitored_table *mts;
    size_t n_mts, allocated_mts;

    netconf_msg_list_init(&g_netconf_msg_list);

#if OVSDB_DESC("Apply transact rpc")
    struct jsonrpc *rpc_transact = g_rpc_transact1;

    if (NULL == rpc_transact) {
        OVSDB_PRINTF_DEBUG_ERROR("transact rpc is NULL.");
        return;
    }
#endif

    ovsdb_set_manager(rpc_transact);
    
    daemon_save_fd(STDOUT_FILENO);
    daemonize_start(false);
    if (get_detach()) {
        int error;

        error = unixctl_server_create(NULL, &unixctl);
        if (error) {
            ovs_fatal(error, "failed to create unixctl server");
        }

        unixctl_command_register("exit", "", 0, 0,
                                 ovsdb_client_exit, &exiting);
        unixctl_command_register("ovsdb-client/block", "", 0, 0,
                                 ovsdb_client_block, &blocked);
        unixctl_command_register("ovsdb-client/unblock", "", 0, 0,
                                 ovsdb_client_unblock, &blocked);
    } else {
        unixctl = NULL;
    }

    schema = fetch_schema(rpc, database);

    monitor_requests = json_object_create();

    mts = NULL;
    n_mts = allocated_mts = 0;

    if (strcmp(table_name, "ALL")) {
        struct ovsdb_table_schema *table;

        table = shash_find_data(&schema->tables, table_name);
        if (!table) {
            ovs_fatal(0, "%s: %s does not have a table named \"%s\"",
                      server, database, table_name);
        }

        add_monitored_table(argc, argv, server, database, table,
                            monitor_requests, &mts, &n_mts, &allocated_mts);
    } else {
        size_t n = shash_count(&schema->tables);
        const struct shash_node **nodes = shash_sort(&schema->tables);
        size_t i;

        for (i = 0; i < n; i++) {
            struct ovsdb_table_schema *table = nodes[i]->data;

            add_monitored_table(argc, argv, server, database, table,
                                monitor_requests,
                                &mts, &n_mts, &allocated_mts);
        }
        free(nodes);
    }

    monitor = json_array_create_3(json_string_create(database),
                                  json_null_create(), monitor_requests);
    request = jsonrpc_create_request("monitor", monitor, NULL);
    request_id = json_clone(request->id);
    jsonrpc_send(rpc, request);

    for (;;) {
        unixctl_server_run(unixctl);
        //unsigned int uiExist = 0;
        while (!blocked) {
            struct jsonrpc_msg *msg;
            int error;

            /* netconf连接保活 */
            //if (0 == uiExist) {
            //    (void)netconf_ce_query_nve_port("Nve1", &uiExist);
            //    uiExist = 10;
            //}
            //uiExist--;

            error = jsonrpc_recv(rpc, &msg);
            if (error == EAGAIN) {
                break;
            } else if (error) {
                ovs_fatal(error, "%s: receive failed", server);
            }

            if (msg->type == JSONRPC_REQUEST && !strcmp(msg->method, "echo")) {
                jsonrpc_send(rpc, jsonrpc_create_reply(json_clone(msg->params),
                                                       msg->id));
            } else if (msg->type == JSONRPC_REPLY
                       && json_equal(msg->id, request_id)) {
                monitor_print(msg->result, mts, n_mts, true);

#if OVSDB_DEBUG
                OVSDB_PRINTF_DEBUG_TRACE("begin print msg->result.");
                print_json(msg->result);
                putchar('\n');
                OVSDB_PRINTF_DEBUG_TRACE("end print msg->result.");
#endif

                OVSDB_PRINTF_DEBUG_TRACE("begin do_table_process.");
                do_table_process(rpc_transact, msg->result, mts, n_mts, true);
                do_table_process_2(rpc_transact, msg->result, mts, n_mts, true);

                OVSDB_PRINTF_DEBUG_TRACE("end do_table_processn");

                fflush(stdout);
                daemonize_complete();
            } else if (msg->type == JSONRPC_NOTIFY
                       && !strcmp(msg->method, "update")) {
                struct json *params = msg->params;
                if (params->type == JSON_ARRAY
                    && params->u.array.n == 2
                    && params->u.array.elems[0]->type == JSON_NULL) {
                    monitor_print(params->u.array.elems[1], mts, n_mts, false);

#if OVSDB_DEBUG
                    OVSDB_PRINTF_DEBUG_TRACE("begin print params->u.array.elems[1].");
                    print_json(params->u.array.elems[1]);
                    putchar('\n');
                    OVSDB_PRINTF_DEBUG_TRACE("end print params->u.array.elems[1].");
#endif

                    OVSDB_PRINTF_DEBUG_TRACE("begin do_table_process.");
                    do_table_process(rpc_transact, params->u.array.elems[1], mts, n_mts, false);
                    do_table_process_2(rpc_transact, params->u.array.elems[1], mts, n_mts, false);

                    //发送netconf消息队列中的消息
                    netconf_msg_list_send_all_msg(&g_netconf_msg_list);

                    OVSDB_PRINTF_DEBUG_TRACE("end do_table_processn.");

                    fflush(stdout);
                }
            }
            jsonrpc_msg_destroy(msg);
        }

        if (exiting) {
            break;
        }

        jsonrpc_run(rpc);
        jsonrpc_wait(rpc);
        if (!blocked) {
            jsonrpc_recv_wait(rpc);
        }
        unixctl_server_wait(unixctl);
        poll_block();
    }
}


static void
do_help(struct jsonrpc *rpc OVS_UNUSED, const char *database OVS_UNUSED,
        int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    usage();
}

/* All command handlers (except for "help") are expected to take an optional
 * server socket name (e.g. "unix:...") as their first argument.  The socket
 * name argument must be included in max_args (but left out of min_args).  The
 * command name and socket name are not included in the arguments passed to the
 * handler: the argv[0] passed to the handler is the first argument after the
 * optional server socket name.  The connection to the server is available as
 * global variable 'rpc'. */
static const struct ovsdb_client_command all_commands[] = {
    { "list-dbs",           NEED_RPC,      0, 0,       do_list_dbs },
    { "get-schema",         NEED_DATABASE, 0, 0,       do_get_schema },
    { "get-schema-version", NEED_DATABASE, 0, 0,       do_get_schema_version },
    { "list-tables",        NEED_DATABASE, 0, 0,       do_list_tables },
    { "list-columns",       NEED_DATABASE, 0, 1,       do_list_columns },
    { "transact",           NEED_RPC,      1, 1,       do_transact },
    { "monitor",            NEED_DATABASE, 1, INT_MAX, do_monitor },
    { "dump",               NEED_DATABASE, 0, INT_MAX, do_dump },
    { "vtep",               NEED_DATABASE, 1, 2,       do_vtep },

    { "help",               NEED_NONE,     0, INT_MAX, do_help },

    { NULL,                 0,             0, 0,       NULL },
};

static const struct ovsdb_client_command *get_all_commands(void)
{
    return all_commands;
}
