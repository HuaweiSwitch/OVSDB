#define RET_OK 0
#define RET_NOK 1

//加密解密
#define ENCRTPT 0
#define DECRTPT 1
#define RESULT  2

//socket 文件
#define SOCKET_FILE  "/var/socket_file"

#define CRYPTO_FREE(prt) \
do { \
    if (NULL != (prt)) { \
        free(prt); \
        (prt) = NULL; \
    }\
}while(0)

//消息结构体
typedef struct tagCryptMSGHead
{
    unsigned int crypt;//加密还是解密
    unsigned int len;//明文或者密文长度
}CryptMSGHead;


