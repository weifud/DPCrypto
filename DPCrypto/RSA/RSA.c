
#include "RSA.h"
#include "RSActx.h"



//=====================================================================================================
RSA *RSA_New(void)
{
	return RSA_CTX_New();
}

//=====================================================================================================
void RSA_Free(RSA *rsa)
{
	RSA_CTX_Free(rsa);
}


//=====================================================================================================
int  RSA_GenerateKey (RSA *rsa, const int bits)
{
	return RSA_CTX_GenerateKey(rsa, bits);
}

//=====================================================================================================
int  RSA_SaveKey(RSA *rsa, const int length, unsigned char *key)
{
	return RSA_CTX_SaveKey(rsa, length, key);
}

//=====================================================================================================
int  RSA_LoadKey(RSA *rsa, const int length, const unsigned char *key)
{
	return RSA_CTX_LoadKey(rsa, length, key);
}

//=====================================================================================================
int  RSA_GetPublicKey(RSA *rsa, const int length, unsigned char *key)
{
	return RSA_CTX_GetPublicKey(rsa, length, key);
}

//=====================================================================================================
int  RSA_SetPublicKey(RSA *rsa, const int length, const unsigned char *key)
{
	return RSA_CTX_SetPublicKey(rsa, length, key);
}


//=====================================================================================================
int  RSA_PublicEncrypt(RSA *rsa, const unsigned char *inbuf, unsigned char *outbuf, int length)
{
	return RSA_CTX_PublicEncrypt(rsa, inbuf, outbuf, length);
}

//=====================================================================================================
int  RSA_PublicDecrypt(RSA *rsa, const unsigned char *inbuf, unsigned char *outbuf, int length)
{
	return RSA_CTX_PublicDecrypt(rsa, inbuf, outbuf, length);
}

//=====================================================================================================
int  RSA_PrivateEncrypt(RSA *rsa, const unsigned char *inbuf, unsigned char *outbuf, int length)
{
	return RSA_CTX_PrivateEncrypt(rsa, inbuf, outbuf, length);
}

//=====================================================================================================
int  RSA_PrivateDecrypt(RSA *rsa, const unsigned char *inbuf, unsigned char *outbuf, int length)
{
	return RSA_CTX_PrivateDecrypt(rsa, inbuf, outbuf, length);
}

