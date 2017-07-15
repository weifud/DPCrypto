
#ifndef HEADER_RSACTX_H
#define HEADER_RSACTX_H

#ifdef  __cplusplus
extern "C" {
#endif


void *RSA_CTX_New(void);
void RSA_CTX_Free(void *ctx);

int  RSA_CTX_GenerateKey (void *ctx, const int bits);

int  RSA_CTX_SaveKey(void *ctx, const int length, unsigned char *key);
int  RSA_CTX_LoadKey(void *ctx, const int length, const unsigned char *key);

int  RSA_CTX_GetPublicKey(void *ctx, const int length, unsigned char *key);
int  RSA_CTX_SetPublicKey(void *ctx, const int length, const unsigned char *key);

int  RSA_CTX_PublicEncrypt(void *ctx, const unsigned char *inbuf, unsigned char *outbuf, int length);
int  RSA_CTX_PublicDecrypt(void *ctx, const unsigned char *inbuf, unsigned char *outbuf, int length);

int  RSA_CTX_PrivateEncrypt(void *ctx, const unsigned char *inbuf, unsigned char *outbuf, int length);
int  RSA_CTX_PrivateDecrypt(void *ctx, const unsigned char *inbuf, unsigned char *outbuf, int length);


#ifdef  __cplusplus
}
#endif

#endif//HEADER_RSACTX_H
