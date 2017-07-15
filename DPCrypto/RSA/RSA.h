
#ifndef HEADER_RSA_H
#define HEADER_RSA_H

#ifdef  __cplusplus
extern "C" {
#endif


#define RSAKEYBITS      1024                           // 默认RSA公钥长度（比特）
#define RSAKEYBYTES     (RSAKEYBITS/8)                 // 默认RSA公钥长度（字节）
#define RSASAVEKEYSIZE  (RSAKEYBYTES*5)                // 默认保存RSA密钥需要的长度（字节）
#define RSAMSGSIZE      (RSAKEYBYTES-11)               // 默认RSA加密的最大消息长度（字节）


typedef void RSA;



// 创建RSA对象
//   注意   创建后密钥为空，需要生成密钥，或加载密钥，或设置公钥
//   返回   RSA对象指针，如果为NULL表明创建失败
//   参数
RSA *RSA_New(void);


// 释放RSA对象
//   返回
//   参数   rsa -- RSA对象指针
void RSA_Free(RSA *rsa);


// 生成密钥
//   返回   <0 失败； =0 成功
//   参数   rsa  -- RSA对象指针
//          bits -- RSA密钥位数，必须在64到16384位之间
int  RSA_GenerateKey (RSA *rsa, const int bits);


// 保存密钥
//   返回   <0 失败； >=0 成功保存的密钥实际长度（字节）
//   参数   rsa    -- RSA对象指针
//          length -- 用来保存密钥的缓冲区长度（字节）
//          key    -- 用来保存密钥的缓冲区指针
int  RSA_SaveKey(RSA *rsa, const int length, unsigned char *key);


// 加载密钥
//   返回   <0 失败； >=0 成功读取的密钥实际长度（字节）
//   参数   rsa    -- RSA对象指针
//          length -- 密钥长度（字节）
//          key    -- 从其中读取密钥的缓冲区指针
int  RSA_LoadKey(RSA *rsa, const int length, const unsigned char *key);


// 获取公钥
//   返回   <0 失败； >=0 成功保存的公钥实际长度（字节）
//   参数   rsa    -- RSA对象指针
//          length -- 用来保存公钥的缓冲区长度（字节）
//          key    -- 用来保存公钥的缓冲区指针
int  RSA_GetPublicKey(RSA *rsa, const int length, unsigned char *key);


// 设置公钥
//   返回   <0 失败； =0 成功
//   参数   rsa    -- RSA对象指针
//          length -- 公钥长度（字节）
//          key    -- 从其中读取公钥的缓冲区指针
int  RSA_SetPublicKey(RSA *rsa, const int length, const unsigned char *key);


// 公钥加密
//   注意   原始数据长度必须保证 <= RSAMSGSIZE
//          加密后的数据比原始数据长，因此输出的加密数据缓冲区长度必须保证 >= RSAKEYBYTES
//   返回   <0 失败； >=0 成功输出的加密数据实际长度（字节）
//   参数   rsa    -- RSA对象指针
//          inbuf  -- 输入的原始数据缓冲区指针
//          outbuf -- 输出的加密数据缓冲区指针，可以与inbuf相同
//          length -- 输入的原始数据长度（字节）
int  RSA_PublicEncrypt(RSA *rsa, const unsigned char *inbuf, unsigned char *outbuf, int length);


// 公钥解密
//   返回   <0 失败； >=0 成功输出的解密数据实际长度（字节）
//   参数   rsa    -- RSA对象指针
//          inbuf  -- 输入的加密数据缓冲区指针
//          outbuf -- 输出的解密数据缓冲区指针，可以与inbuf相同
//          length -- 输入的加密数据长度（字节）
int  RSA_PublicDecrypt(RSA *rsa, const unsigned char *inbuf, unsigned char *outbuf, int length);


// 私钥加密
//   注意   原始数据长度必须保证 <= RSAMSGSIZE
//          加密后的数据比原始数据长，因此输出的加密数据缓冲区长度必须保证 >= RSAKEYBYTES
//   返回   <0 失败； >=0 成功输出的加密数据实际长度（字节）
//   参数   rsa    -- RSA对象指针
//          inbuf  -- 输入的原始数据缓冲区指针
//          outbuf -- 输出的加密数据缓冲区指针，可以与inbuf相同
//          length -- 输入的原始数据长度（字节）
int  RSA_PrivateEncrypt(RSA *rsa, const unsigned char *inbuf, unsigned char *outbuf, int length);


// 私钥解密
//   返回   <0 失败； >=0 成功输出的解密数据实际长度（字节）
//   参数   rsa    -- RSA对象指针
//          inbuf  -- 输入的加密数据缓冲区指针
//          outbuf -- 输出的解密数据缓冲区指针，可以与inbuf相同
//          length -- 输入的加密数据长度（字节）
int  RSA_PrivateDecrypt(RSA *rsa, const unsigned char *inbuf, unsigned char *outbuf, int length);


#ifdef  __cplusplus
}
#endif

#endif//HEADER_RSA_H
