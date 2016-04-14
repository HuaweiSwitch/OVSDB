
#ifndef OVSDB_CLIENT_H
#define OVSDB_CLIENT_H 1

#include "uthash.h"

#define OVSDB_PRINTF_DEBUG(szfmt, args...)\
do{\
    printf(\
        ">>>func: %s, line: %d. "szfmt"\r\n",\
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
    }unMac;   //MAC´æ´¢¸ñÊ½:11:22:33:44:55:66
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

#endif /* ovsdb/ovsdb_client.h */

