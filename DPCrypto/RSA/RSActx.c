
#include <stdlib.h>
#include <string.h>

#include "RSActx.h"
#include "RSAlib.h"


static const unsigned char exponent[] = "\x11";


typedef struct
{
	unsigned short total;
	unsigned short n;
	unsigned short e;
	unsigned short d;
	unsigned short p;
	unsigned short q;
	unsigned short dmp1;
	unsigned short dmq1;
	unsigned short iqmp;
} RSAKeyHeader;




//=========================================================================================================
void *RSA_CTX_New(void)
{
	void *ctx;
	ctx = malloc(sizeof(RSA));
	if (ctx != NULL)
	{
		RSA *rsa = (RSA*) ctx;
		memset(rsa, 0, sizeof(RSA));

		rsa->meth = RSA_PKCS1_SSLeay();
		rsa->references = 1;
		rsa->flags  = rsa->meth->flags;
		rsa->flags |= RSA_FLAG_NO_BLINDING | RSA_FLAG_NO_CONSTTIME;  //ZCY add

		if ((rsa->meth->init != NULL) && !rsa->meth->init(rsa))
		{
			free(ctx);
			ctx = NULL;
		}
	}
	return ctx;
}


//=========================================================================================================
void RSA_CTX_Free(void *ctx)
{
	RSA *rsa = (RSA*) ctx;
	if (rsa != NULL)
	{
		rsa->references --;
		if (rsa->references > 0)
			return;

		if (rsa->meth->finish)
			rsa->meth->finish(rsa);

		if (rsa->n != NULL) BN_clear_free(rsa->n);
		if (rsa->e != NULL) BN_clear_free(rsa->e);
		if (rsa->d != NULL) BN_clear_free(rsa->d);
		if (rsa->p != NULL) BN_clear_free(rsa->p);
		if (rsa->q != NULL) BN_clear_free(rsa->q);
		if (rsa->dmp1 != NULL) BN_clear_free(rsa->dmp1);
		if (rsa->dmq1 != NULL) BN_clear_free(rsa->dmq1);
		if (rsa->iqmp != NULL) BN_clear_free(rsa->iqmp);
		if (rsa->blinding != NULL) BN_BLINDING_free(rsa->blinding);
		if (rsa->mt_blinding != NULL) BN_BLINDING_free(rsa->mt_blinding);
		if (rsa->bignum_data != NULL) OPENSSL_free_locked(rsa->bignum_data);
		free(rsa);
	}
}


//=========================================================================================================
int  RSA_CTX_GenerateKey (void *ctx, const int bits)
{
	RSA *rsa = (RSA*) ctx;
	if (rsa == NULL)
		return -1;
	else if (bits < 64 || bits > OPENSSL_RSA_MAX_MODULUS_BITS)
		return -1;
	else
	{
		int ret;
		BIGNUM *exp = BN_new();
		if (exp == NULL)
			return -1;
		exp = BN_bin2bn(exponent, sizeof(exponent)-1, exp);
		ret = RSA_generate_key_ex(rsa, bits, exp, NULL);
		BN_free(exp);
		if (ret != 1)
			return -1;
		return 0;
	}
}


//=========================================================================================================
int  RSA_CTX_SaveKey(void *ctx, const int length, unsigned char *key)
{
	RSA *rsa = (RSA*) ctx;
	if (rsa == NULL)
		return -1;
	else
	{
		RSAKeyHeader len;
		len.n = BN_num_bytes(rsa->n);
		len.e = BN_num_bytes(rsa->e);
		len.d = BN_num_bytes(rsa->d);
		len.p = BN_num_bytes(rsa->p);
		len.q = BN_num_bytes(rsa->q);
		len.dmp1 = BN_num_bytes(rsa->dmp1);
		len.dmq1 = BN_num_bytes(rsa->dmq1);
		len.iqmp = BN_num_bytes(rsa->iqmp);

		len.total  = len.n + len.e + len.d + len.p + len.q + len.dmp1 + len.dmq1 + len.iqmp;
		len.total += sizeof(RSAKeyHeader);

		if (key == NULL)
			return len.total;

		if (length < (int)len.total)
			return -1;

		memcpy(key, &len, sizeof(RSAKeyHeader));
		key += sizeof(RSAKeyHeader);

		BN_bn2bin(rsa->n, key);      key += len.n;
		BN_bn2bin(rsa->e, key);      key += len.e;
		BN_bn2bin(rsa->d, key);      key += len.d;
		BN_bn2bin(rsa->p, key);      key += len.p;
		BN_bn2bin(rsa->q, key);      key += len.q;
		BN_bn2bin(rsa->dmp1, key);   key += len.dmp1;
		BN_bn2bin(rsa->dmq1, key);   key += len.dmq1;
		BN_bn2bin(rsa->iqmp, key);   key += len.iqmp;
		return len.total;
	}
}


//=========================================================================================================
int  RSA_CTX_LoadKey(void *ctx, const int length, const unsigned char *key)
{
	RSA *rsa = (RSA*) ctx;
	if (rsa == NULL)
		return -1;
	else if (key == NULL || length <= sizeof(RSAKeyHeader))
		return -1;
	else
	{
		RSAKeyHeader len;
		unsigned short sum;
		memcpy(&len, key, sizeof(RSAKeyHeader));
		key += sizeof(RSAKeyHeader);

		sum = len.n + len.e + len.d + len.p + len.q + len.dmp1 + len.dmq1 + len.iqmp;
		if (sum != (len.total-sizeof(RSAKeyHeader)) || length < (int)len.total)
			return -1;

		rsa->n = BN_bin2bn(key, len.n, rsa->n);            key += len.n;
		rsa->e = BN_bin2bn(key, len.e, rsa->e);            key += len.e;
		rsa->d = BN_bin2bn(key, len.d, rsa->d);            key += len.d;
		rsa->p = BN_bin2bn(key, len.p, rsa->p);            key += len.p;
		rsa->q = BN_bin2bn(key, len.q, rsa->q);            key += len.q;
		rsa->dmp1 = BN_bin2bn(key, len.dmp1, rsa->dmp1);   key += len.dmp1;
		rsa->dmq1 = BN_bin2bn(key, len.dmq1, rsa->dmq1);   key += len.dmq1;
		rsa->iqmp = BN_bin2bn(key, len.iqmp, rsa->iqmp);   key += len.iqmp;
		return len.total;
	}
}


//=========================================================================================================
int  RSA_CTX_GetPublicKey(void *ctx, const int length, unsigned char *key)
{
	RSA *rsa = (RSA*) ctx;
	if (rsa == NULL)
		return -1;
	if (key == NULL || length < BN_num_bytes(rsa->n))
		return -1;
	return BN_bn2bin(rsa->n, key);
}


//=========================================================================================================
int  RSA_CTX_SetPublicKey(void *ctx, const int length, const unsigned char *key)
{
	RSA *rsa = (RSA*) ctx;
	if (rsa == NULL)
		return -1;
	else if (key == NULL || length < 64/8 || length > OPENSSL_RSA_MAX_MODULUS_BITS/8)
		return -1;
	else
	{
		rsa->n = BN_bin2bn(key, length, rsa->n);
		rsa->e = BN_bin2bn(exponent, sizeof(exponent)-1, rsa->e);
		return 0;
	}
}


//=========================================================================================================
int  RSA_CTX_PublicEncrypt(void *ctx, const unsigned char *inbuf, unsigned char *outbuf, int length)
{
	RSA *rsa = (RSA*) ctx;
	if (rsa == NULL)
		return -1;
	if (inbuf == NULL || outbuf == NULL || length <= 0)
		return -1;
	return rsa->meth->rsa_pub_enc(length, inbuf, outbuf, rsa, RSA_PKCS1_PADDING);
}

//=========================================================================================================
int  RSA_CTX_PublicDecrypt(void *ctx, const unsigned char *inbuf, unsigned char *outbuf, int length)
{
	RSA *rsa = (RSA*) ctx;
	if (rsa == NULL)
		return -1;
	if (inbuf == NULL || outbuf == NULL || length <= 0)
		return -1;
	return rsa->meth->rsa_pub_dec(length, inbuf, outbuf, rsa, RSA_PKCS1_PADDING);
}

//=========================================================================================================
int  RSA_CTX_PrivateEncrypt(void *ctx, const unsigned char *inbuf, unsigned char *outbuf, int length)
{
	RSA *rsa = (RSA*) ctx;
	if (rsa == NULL)
		return -1;
	if (inbuf == NULL || outbuf == NULL || length <= 0)
		return -1;
	return rsa->meth->rsa_priv_enc(length, inbuf, outbuf, rsa, RSA_PKCS1_PADDING);
}

//=========================================================================================================
int  RSA_CTX_PrivateDecrypt(void *ctx, const unsigned char *inbuf, unsigned char *outbuf, int length)
{
	RSA *rsa = (RSA*) ctx;
	if (rsa == NULL)
		return -1;
	if (inbuf == NULL || outbuf == NULL || length <= 0)
		return -1;
	return rsa->meth->rsa_priv_dec(length, inbuf, outbuf, rsa, RSA_PKCS1_PADDING);
}

