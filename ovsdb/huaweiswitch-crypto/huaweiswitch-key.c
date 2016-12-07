#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include "huaweiswitch-key.h"
#include "huaweiswitch-crypto-pub.h"

/*****************************************************************************/

// PBKDF2算法的迭代次数
#define ITERATION_NUM       100000

//日志长度
#define LOGMSG_MAX_LEN  (2*1024)

//加密解密
#define KEYNEW 0
#define KEYOLD 1

//密钥组件大小
#define COMPONENT_SIZE  256

//AES加解密块大小
#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

//明文或者密文最大长度
//#define TXT_MAX_LEN   1024

//socket监听个数
#define SOCKET_COUNT 5

//日志
#define LOG_FILE                 "/var/corootkeyproc.log"
#define LOGFILE_BAK              "/var/corootkeyproc.bak.log"

//密钥组件文件
#define FILENAME_COMPONE "/usr/share/210p81608dbf7/47329524-d6a6-411c-b1a3-21031608dbf7"
#define FILENAME_COMPTWO "/lib/a6633c855f52/a62bb5bd-fae7-4c75-8989-a66d3c865f52"

//盐值文件
#define FILENAME_COMPSALT  "/opt/792b49452ndq1/65jc630o-5t63-2dye-35fs-792b4982ndq1"

//备份密钥组件文件
#define FILENAME_COMPONE_OLD "/var/413ea3oo3ebf3/988fc561-244b-4890-9857-413ea3b3ebf3"
#define FILENAME_COMPTWO_OLD "/mnt/be6961d94f2d/8cd5c096-7455-439c-9236-be69e3d94f2d"

//备份盐值文件
#define FILENAME_COMPSALT_OLD  "/media/a35ui74fg1c/83629a37-9126-l0o2-7838-n20dl398ff12"

/*****************************************************************************/

void print_mem(char * info, unsigned char * msg, unsigned int len)
{
    unsigned int n;

    printf("%s:\r\n", info);

    for (n = 0; n < len; n++) {
        printf("%#02x ", msg[n]);
    }

    printf("\r\nEnd\r\n", info);

    return;
}


/*****************************************************************************
Func Name       : corootkeyprc_log
Date Created    : 2016-11-10
Author          : lishiyang 00193436
Description     : 日志函数
Input           : pcFmt
Output          :
Return          : NULL
Caution         :
******************************************************************************/
void corootkeyprc_log(const char* pcFmt, ...)
{
    struct timeval tv;
    struct tm*     ptm;
    va_list        pcArgs;
    const char     szTimeFmt[] = "%Y-%m-%d %H:%M:%S";
    char           szLogBuf[LOGMSG_MAX_LEN] = {0};
    char           szCurTime[64];
    FILE*          pstFile;

    (void)memset(&pcArgs, 0, sizeof(va_list));

    pstFile = fopen(LOG_FILE, "a");
    if (NULL == pstFile)
    {
        return;
    }

    if (ftell(pstFile) > LOGMSG_MAX_LEN)
    {
        (void)fclose(pstFile);
        (void)unlink(LOGFILE_BAK);
        (void)rename(LOG_FILE,LOGFILE_BAK);
        pstFile = fopen(LOG_FILE, "a");
        if (NULL == pstFile)
        {
            return;
        }
    }

    (void)gettimeofday(&tv, NULL);
    ptm = gmtime(&tv.tv_sec);
    if (NULL == ptm)
    {
        (void)fclose(pstFile);
        return;
    }
    (void)strftime(szCurTime, sizeof(szCurTime), szTimeFmt, ptm);

    va_start(pcArgs, pcFmt);
    (void)vsnprintf(szLogBuf, LOGMSG_MAX_LEN, pcFmt, pcArgs);

    va_end(pcArgs);
    szLogBuf[LOGMSG_MAX_LEN - 1] = 0;
    (void)fprintf(pstFile, "[%s.%ld] %s\r\n", szCurTime, (long)tv.tv_usec, szLogBuf);

    (void)fclose(pstFile);
}

/*****************************************************************************
Func Name       : genrootkey
Date Created    : 2016-11-15
Author          : lishiyang 00193436
Description     : 根密钥生成函数
Input           : keyver：密钥版本
Output          :rootKey：密钥
Return          : NULL
Caution         :
******************************************************************************/
int genrootkey(int keyver,unsigned char rootKey[COMPONENT_SIZE])
{
    unsigned char component1[COMPONENT_SIZE] = {0};
    unsigned char component2[COMPONENT_SIZE] = {0};
    unsigned char salt[COMPONENT_SIZE] = {0};
    unsigned char tmpComponent[COMPONENT_SIZE] = {0};
    int amount;
    int i;
    int rv;
    FILE * fp;

    //生成最新根密钥
    if(keyver == KEYNEW)
    {
        //读取密钥组件一
        fp=fopen(FILENAME_COMPONE,"r");
        if(fp == NULL)
        {
            corootkeyprc_log("Error:open file failed\n");
            return RET_NOK;
        }
        amount = fread(component1,sizeof(unsigned char), COMPONENT_SIZE,fp);
        if (amount < 0)
        {
            corootkeyprc_log("Error:get component failed\n");
            return RET_NOK;
        }
        fclose(fp);
        
        //读取密钥组件二
        fp=fopen(FILENAME_COMPTWO,"r");
        if(fp == NULL)
        {
            corootkeyprc_log("Error:open file failed!\n");
            return RET_NOK;
        }
        amount = fread(component2,sizeof(unsigned char), COMPONENT_SIZE,fp);
        if (amount < 0)
        {
            corootkeyprc_log("Error:get component failed!\n");
            return RET_NOK;
        }
        fclose(fp);
        
        //读取盐值
        fp=fopen(FILENAME_COMPSALT,"r");
        if(fp == NULL)
        {
            corootkeyprc_log("Error:open file failed!!\n");
            return RET_NOK;
        }
        amount = fread(salt,sizeof(unsigned char), COMPONENT_SIZE,fp);
        if (amount < 0)
        {
            corootkeyprc_log("Error:get salt failed!!\n");
            return RET_NOK;
        }
        fclose(fp);
    }
    
    //生成上次备份根密钥
    else if(keyver == KEYOLD)
    {
        //读取旧密钥组件一
        fp=fopen(FILENAME_COMPONE_OLD,"r");
        if(fp == NULL)
        {
            corootkeyprc_log("Error:open old file failed\n");
            return RET_NOK;
        }
        amount = fread(component1,sizeof(unsigned char), COMPONENT_SIZE,fp);
        if (amount < 0)
        {
            corootkeyprc_log("Error:get old component failed\n");
            return RET_NOK;
        }
        fclose(fp);
        
        //读取旧密钥组件二
        fp=fopen(FILENAME_COMPTWO_OLD,"r");
        if(fp == NULL)
        {
            corootkeyprc_log("Error:open old file failed!\n");
            return RET_NOK;
        }
        amount = fread(component2,sizeof(unsigned char), COMPONENT_SIZE,fp);
        if (amount < 0)
        {
            corootkeyprc_log("Error:get old component failed!\n");
            return RET_NOK;
        }
        fclose(fp);

        //读取旧盐值
        fp=fopen(FILENAME_COMPSALT_OLD,"r");
        if(fp == NULL)
        {
            corootkeyprc_log("Error:open old file failed!!\n");
            return RET_NOK;
        }
        amount = fread(salt,sizeof(unsigned char), COMPONENT_SIZE,fp);
        if (amount < 0)
        {
            corootkeyprc_log("Error:get old salt failed!!\n");
            return RET_NOK;
        }
        fclose(fp);
    }

    // 处理密钥组件
    for(i = 0; i < COMPONENT_SIZE; i++)
    {
        tmpComponent[i] = component1[i] ^ component2[i];
    }

    // 根据密钥材料生成根密钥
    rv = PKCS5_PBKDF2_HMAC( (const char *)tmpComponent,
                                COMPONENT_SIZE,
                                (const unsigned char *)salt,
                                COMPONENT_SIZE,
                                ITERATION_NUM,
                                EVP_sha256(),
                                32,
                                rootKey);

    if(rv == 0)
    {
        corootkeyprc_log("Error:rootkey generate fail\n");
        return RET_NOK;
    }

    return RET_OK;
}

/*****************************************************************************
Func Name       : parse_msg
Date Created    : 2016-11-15
Author          : lishiyang 00193436
Description     : 消息处理函数
Input           : crypt：加密/解密 len：txt长度 txt：明文/密文
Output          :tmpanswer:加密/解密结果
Return          : NULL
Caution         :
******************************************************************************/
int parse_msg(CryptMSGHead * pstMSGHead, unsigned char *in, unsigned char ** result, unsigned int * resultlen)
{
    
    switch(pstMSGHead->crypt)
    {
        case ENCRTPT:
        {
            int ret;
            unsigned char rootKey[COMPONENT_SIZE];
            unsigned int length = 0;
            unsigned char * out = NULL;
            AES_KEY aes_enc_ctx;

            //获得最新根密钥
            ret = genrootkey(KEYNEW, rootKey);
            if (ret != RET_OK) {
                corootkeyprc_log("Error: generate root key fail!\n");
                return RET_NOK;
            }

            AES_set_encrypt_key(rootKey, COMPONENT_SIZE, &aes_enc_ctx);

            //设置处理结果的长度为16的整数倍，如果正好是16的整倍数，默认加一个16，为PKCS5补码使用。
            length = pstMSGHead->len + AES_BLOCK_SIZE - (pstMSGHead->len % AES_BLOCK_SIZE);
            out = (unsigned char *)malloc(length);
            if (NULL == out) {
                corootkeyprc_log("Error: malloc out fail!\n");
                return RET_NOK;
            }
            (void)memset(out, 0, length);

            *result = out;
            *resultlen = length;

            unsigned int len = length;
            unsigned int n;
            unsigned char * iv = "e588fb8e2fd4704c";
            memcpy(out, in, pstMSGHead->len);

            //pading
            unsigned int pad = AES_BLOCK_SIZE - pstMSGHead->len % AES_BLOCK_SIZE;
            for (n = pstMSGHead->len; n < length; n++) {
                out[n] = (0 == pad) ? AES_BLOCK_SIZE : pad;
            }

            //16位为一组去处理原始数据
            while (len >= AES_BLOCK_SIZE)
            {
                for(n=0; n < AES_BLOCK_SIZE; ++n)
                    out[n] = out[n] ^ iv[n];

                AES_encrypt(out, out, &aes_enc_ctx);
                iv = out;
                len -= AES_BLOCK_SIZE;
                out += AES_BLOCK_SIZE;
            }

            break;
        }

        case DECRTPT:
        {
            int ret;
            unsigned char rootKey[COMPONENT_SIZE];
            AES_KEY aes_dec_ctx;
            int j = 0;
            unsigned int length = 0;
            unsigned int n = 0;
            unsigned char * out = NULL;
            unsigned char * iv = "e588fb8e2fd4704c";

            if (0 != pstMSGHead->len % AES_BLOCK_SIZE) {
                corootkeyprc_log("Error: length is wrong, len = %d.\n", pstMSGHead->len);
                return RET_NOK;
            }

            //获得最新根密钥
            ret = genrootkey(KEYNEW, rootKey);
            if (ret != RET_OK) {
                corootkeyprc_log("Error: generate root key fail!\n");
                return RET_NOK;
            }
            
            AES_set_decrypt_key(rootKey, COMPONENT_SIZE, &aes_dec_ctx);

            out = (unsigned char *)malloc(pstMSGHead->len);
            if (NULL == out) {
                corootkeyprc_log("Error: malloc out fail!\n");
                return RET_NOK;
            }
            (void)memcpy(out, in, pstMSGHead->len);

            *result = out;

            while(length < pstMSGHead->len) {
                AES_decrypt(out, out, &aes_dec_ctx);

                for (n = 0; n < AES_BLOCK_SIZE; n++)
                    out[n] = out[n] ^ iv[n];

                iv = in + length;
                out += AES_BLOCK_SIZE;
                length += AES_BLOCK_SIZE;
            }

            out = *result;
            length = pstMSGHead->len;
            for (n = out[pstMSGHead->len - 1]; n > 0; n--) {
                out[pstMSGHead->len - n] = '\0';
                length--;
            }

            *resultlen = length;

            break;
        }

        default:
        {
            corootkeyprc_log("Error:parse msg fail\n");
            return RET_NOK;
        }
    }

    return RET_OK;
}

/*****************************************************************************
Func Name       : main
Date Created    : 2016-11-09
Author          : lishiyang 00193436
Description     : 主入口函数
Input           :
Output          :
Return          :
Caution         :
******************************************************************************/
int main(void)
{
    struct sockaddr_un address;
    int sock, conn;
    size_t addrLength;
    CryptMSGHead cryptHead;
    int size;
    int ret;
    unsigned char * resultanswer = NULL;
    unsigned char * msg = NULL;
    unsigned int resultlen = 0;
    unsigned char * returnMSG = NULL;
    CryptMSGHead * returnHead = NULL;

    daemon(0,0);

    corootkeyprc_log("INFO:COROOTKEYPROC\n");
    
    //创建unix domain socket
    if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        corootkeyprc_log("Error:create socket fail\n");
        return RET_NOK;
    }

    //删除存在的socket文件
    unlink(SOCKET_FILE);

    //设置socket地址
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, SOCKET_FILE);

    //绑定socket
    addrLength = sizeof(address.sun_family) + strlen(address.sun_path);
    if (bind(sock, (struct sockaddr *) &address, addrLength))
    {
        corootkeyprc_log("Error:bind socket fail\n");
        return RET_NOK;
    }

    /* 修改文件权限 */
    chmod(SOCKET_FILE, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);

    //监听socket
    if (listen(sock, SOCKET_COUNT))
    {
        corootkeyprc_log("Error:listen socket fail\n");
        return RET_NOK;
    }

    //接受客户端连接并处理
    while(1) {
        //有客户端连接
        if ((conn = accept(sock, (struct sockaddr *) &address,&addrLength)) < 0) {
            sleep(1);
            continue;
        }

        /*获取前8个字节，crypt+len
        由于不知道接收到的数据长度，因此需要先获取len*/
        size = recv(conn, &cryptHead, sizeof(cryptHead), 0);
        if(size < 0) {
            corootkeyprc_log("Error: Recieving msg head faild, size = %d.\n", size);
            close(conn);
            continue;
        }

        if (0 == cryptHead.len || cryptHead.crypt > DECRTPT) {
            close(conn);
            continue;
        }

        //获取txt
        msg = (unsigned char*)malloc(cryptHead.len);
        if (NULL == msg) {
            corootkeyprc_log("Error: Malloc msg faild, length = %d.\n", cryptHead.len);
        }
        (void)memset(msg, 0, cryptHead.len);

        size = recv(conn, msg, cryptHead.len, 0);
        if(size < 0) {
            corootkeyprc_log("Error: Recieving msg msg faild, len = %d, size = %d.\n", cryptHead.len, size);
            CRYPTO_FREE(msg);
            close(conn);
            continue;
        }

        //解析消息并得到处理结果
        ret = parse_msg(&cryptHead, msg, &resultanswer, &resultlen);
        if(ret != RET_OK) {
            corootkeyprc_log("Error:operate failed\n");
            CRYPTO_FREE(msg);
            close(conn);
            continue;
        }

        returnMSG = (unsigned char *)malloc(sizeof(CryptMSGHead) + resultlen);
        if (NULL == returnMSG) {
            CRYPTO_FREE(resultanswer);
            CRYPTO_FREE(msg);
            close(conn);
            continue;
        }

        returnHead = (CryptMSGHead *)(void *)returnMSG;
        returnHead->crypt = RESULT;
        returnHead->len = resultlen;
        (void)memcpy(returnMSG+sizeof(CryptMSGHead), resultanswer, resultlen);
        
        //回复处理结果
        size = send(conn, returnMSG, (sizeof(CryptMSGHead) + resultlen), 0);
        if(size < 0) {
            corootkeyprc_log("Error: error when Sending Data\n");
        }

        CRYPTO_FREE(returnMSG);
        returnHead = NULL;
        CRYPTO_FREE(resultanswer);
        resultlen = 0;
        CRYPTO_FREE(msg);
        memset(&cryptHead, 0, sizeof(cryptHead));
        close(conn);
        continue;
    }
}
