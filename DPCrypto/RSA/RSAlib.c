
#include "RSAlib.h"
#include "Random.h"




int RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen,
	     const unsigned char *from, int flen)
	{
	int j;
	unsigned char *p;

	if (flen > (tlen-RSA_PKCS1_PADDING_SIZE))
		{
		RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1,RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
		return(0);
		}
	
	p=(unsigned char *)to;

	*(p++)=0;
	*(p++)=1; /* Private Key BT (Block Type) */

	/* pad out with 0xff data */
	j=tlen-3-flen;
	memset(p,0xff,j);
	p+=j;
	*(p++)='\0';
	memcpy(p,from,(unsigned int)flen);
	return(1);
	}

int RSA_padding_check_PKCS1_type_1(unsigned char *to, int tlen,
	     const unsigned char *from, int flen, int num)
	{
	int i,j;
	const unsigned char *p;

	p=from;
	if ((num != (flen+1)) || (*(p++) != 01))
		{
		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1,RSA_R_BLOCK_TYPE_IS_NOT_01);
		return(-1);
		}

	/* scan over padding data */
	j=flen-1; /* one for type. */
	for (i=0; i<j; i++)
		{
		if (*p != 0xff) /* should decrypt to 0xff */
			{
			if (*p == 0)
				{ p++; break; }
			else	{
				RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1,RSA_R_BAD_FIXED_HEADER_DECRYPT);
				return(-1);
				}
			}
		p++;
		}

	if (i == j)
		{
		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1,RSA_R_NULL_BEFORE_BLOCK_MISSING);
		return(-1);
		}

	if (i < 8)
		{
		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1,RSA_R_BAD_PAD_BYTE_COUNT);
		return(-1);
		}
	i++; /* Skip over the '\0' */
	j-=i;
	if (j > tlen)
		{
		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1,RSA_R_DATA_TOO_LARGE);
		return(-1);
		}
	memcpy(to,p,(unsigned int)j);

	return(j);
	}

int RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen,
	     const unsigned char *from, int flen)
	{
	int i,j;
	unsigned char *p;
	
	if (flen > (tlen-11))
		{
		RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2,RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
		return(0);
		}
	
	p=(unsigned char *)to;

	*(p++)=0;
	*(p++)=2; /* Public Key BT (Block Type) */

	/* pad out with non-zero random data */
	j=tlen-3-flen;

	if (RAND_bytes(p,j) <= 0)
		return(0);
	for (i=0; i<j; i++)
		{
		if (*p == '\0')
			do	{
				if (RAND_bytes(p,1) <= 0)
					return(0);
				} while (*p == '\0');
		p++;
		}

	*(p++)='\0';

	memcpy(p,from,(unsigned int)flen);
	return(1);
	}

int RSA_padding_check_PKCS1_type_2(unsigned char *to, int tlen,
	     const unsigned char *from, int flen, int num)
	{
	int i,j;
	const unsigned char *p;

	p=from;
	if ((num != (flen+1)) || (*(p++) != 02))
		{
		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2,RSA_R_BLOCK_TYPE_IS_NOT_02);
		return(-1);
		}
#ifdef PKCS1_CHECK
	return(num-11);
#endif

	/* scan over padding data */
	j=flen-1; /* one for type. */
	for (i=0; i<j; i++)
		if (*(p++) == 0) break;

	if (i == j)
		{
		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2,RSA_R_NULL_BEFORE_BLOCK_MISSING);
		return(-1);
		}

	if (i < 8)
		{
		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2,RSA_R_BAD_PAD_BYTE_COUNT);
		return(-1);
		}
	i++; /* Skip over the '\0' */
	j-=i;
	if (j > tlen)
		{
		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2,RSA_R_DATA_TOO_LARGE);
		return(-1);
		}
	memcpy(to,p,(unsigned int)j);

	return(j);
	}





int RSA_padding_add_none(unsigned char *to, int tlen,
	const unsigned char *from, int flen)
	{
	if (flen > tlen)
		{
		RSAerr(RSA_F_RSA_PADDING_ADD_NONE,RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
		return(0);
		}

	if (flen < tlen)
		{
		RSAerr(RSA_F_RSA_PADDING_ADD_NONE,RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE);
		return(0);
		}
	
	memcpy(to,from,(unsigned int)flen);
	return(1);
	}

int RSA_padding_check_none(unsigned char *to, int tlen,
	const unsigned char *from, int flen, int num)
	{

	if (flen > tlen)
		{
		RSAerr(RSA_F_RSA_PADDING_CHECK_NONE,RSA_R_DATA_TOO_LARGE);
		return(-1);
		}

	memset(to,0,tlen-flen);
	memcpy(to+tlen-flen,from,flen);
	return(tlen);
	}







int RSA_padding_add_SSLv23(unsigned char *to, int tlen,
	const unsigned char *from, int flen)
	{
	int i,j;
	unsigned char *p;
	
	if (flen > (tlen-11))
		{
		RSAerr(RSA_F_RSA_PADDING_ADD_SSLV23,RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
		return(0);
		}
	
	p=(unsigned char *)to;

	*(p++)=0;
	*(p++)=2; /* Public Key BT (Block Type) */

	/* pad out with non-zero random data */
	j=tlen-3-8-flen;

	if (RAND_bytes(p,j) <= 0)
		return(0);
	for (i=0; i<j; i++)
		{
		if (*p == '\0')
			do	{
				if (RAND_bytes(p,1) <= 0)
					return(0);
				} while (*p == '\0');
		p++;
		}

	memset(p,3,8);
	p+=8;
	*(p++)='\0';

	memcpy(p,from,(unsigned int)flen);
	return(1);
	}

int RSA_padding_check_SSLv23(unsigned char *to, int tlen,
	const unsigned char *from, int flen, int num)
	{
	int i,j,k;
	const unsigned char *p;

	p=from;
	if (flen < 10)
		{
		RSAerr(RSA_F_RSA_PADDING_CHECK_SSLV23,RSA_R_DATA_TOO_SMALL);
		return(-1);
		}
	if ((num != (flen+1)) || (*(p++) != 02))
		{
		RSAerr(RSA_F_RSA_PADDING_CHECK_SSLV23,RSA_R_BLOCK_TYPE_IS_NOT_02);
		return(-1);
		}

	/* scan over padding data */
	j=flen-1; /* one for type */
	for (i=0; i<j; i++)
		if (*(p++) == 0) break;

	if ((i == j) || (i < 8))
		{
		RSAerr(RSA_F_RSA_PADDING_CHECK_SSLV23,RSA_R_NULL_BEFORE_BLOCK_MISSING);
		return(-1);
		}
	for (k = -9; k<-1; k++)
		{
		if (p[k] !=  0x03) break;
		}
	if (k == -1)
		{
		RSAerr(RSA_F_RSA_PADDING_CHECK_SSLV23,RSA_R_SSLV3_ROLLBACK_ATTACK);
		return(-1);
		}

	i++; /* Skip over the '\0' */
	j-=i;
	if (j > tlen)
		{
		RSAerr(RSA_F_RSA_PADDING_CHECK_SSLV23,RSA_R_DATA_TOO_LARGE);
		return(-1);
		}
	memcpy(to,p,(unsigned int)j);

	return(j);
	}






int RSA_padding_add_X931(unsigned char *to, int tlen,
	     const unsigned char *from, int flen)
	{
	int j;
	unsigned char *p;

	/* Absolute minimum amount of padding is 1 header nibble, 1 padding
	 * nibble and 2 trailer bytes: but 1 hash if is already in 'from'.
	 */

	j = tlen - flen - 2;

	if (j < 0)
		{
		RSAerr(RSA_F_RSA_PADDING_ADD_X931,RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
		return -1;
		}
	
	p=(unsigned char *)to;

	/* If no padding start and end nibbles are in one byte */
	if (j == 0)
		*p++ = 0x6A;
	else
		{
		*p++ = 0x6B;
		if (j > 1)
			{
			memset(p, 0xBB, j - 1);
			p += j - 1;
			}
		*p++ = 0xBA;
		}
	memcpy(p,from,(unsigned int)flen);
	p += flen;
	*p = 0xCC;
	return(1);
	}

int RSA_padding_check_X931(unsigned char *to, int tlen,
	     const unsigned char *from, int flen, int num)
	{
	int i = 0,j;
	const unsigned char *p;

	p=from;
	if ((num != flen) || ((*p != 0x6A) && (*p != 0x6B)))
		{
		RSAerr(RSA_F_RSA_PADDING_CHECK_X931,RSA_R_INVALID_HEADER);
		return -1;
		}

	if (*p++ == 0x6B)
		{
		j=flen-3;
		for (i = 0; i < j; i++)
			{
			unsigned char c = *p++;
			if (c == 0xBA)
				break;
			if (c != 0xBB)
				{
				RSAerr(RSA_F_RSA_PADDING_CHECK_X931,
					RSA_R_INVALID_PADDING);
				return -1;
				}
			}

		j -= i;

		if (i == 0)
			{
			RSAerr(RSA_F_RSA_PADDING_CHECK_X931, RSA_R_INVALID_PADDING);
			return -1;
			}

		}
	else j = flen - 2;

	if (p[j] != 0xCC)
		{
		RSAerr(RSA_F_RSA_PADDING_CHECK_X931, RSA_R_INVALID_TRAILER);
		return -1;
		}

	memcpy(to,p,(unsigned int)j);

	return(j);
	}














static int rsa_builtin_keygen(RSA *rsa, int bits, BIGNUM *e_value, BN_GENCB *cb);

/* NB: this wrapper would normally be placed in rsa_lib.c and the static
 * implementation would probably be in rsa_eay.c. Nonetheless, is kept here so
 * that we don't introduce a new linker dependency. Eg. any application that
 * wasn't previously linking object code related to key-generation won't have to
 * now just because key-generation is part of RSA_METHOD. */
int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e_value, BN_GENCB *cb)
	{
	if(rsa->meth->rsa_keygen)
		return rsa->meth->rsa_keygen(rsa, bits, e_value, cb);
	return rsa_builtin_keygen(rsa, bits, e_value, cb);
	}

static int rsa_builtin_keygen(RSA *rsa, int bits, BIGNUM *e_value, BN_GENCB *cb)
	{
	BIGNUM *r0=NULL,*r1=NULL,*r2=NULL,*r3=NULL,*tmp;
	BIGNUM local_r0,local_d,local_p;
	BIGNUM *pr0,*d,*p;
	int bitsp,bitsq,ok= -1,n=0;
	BN_CTX *ctx=NULL;

	ctx=BN_CTX_new();
	if (ctx == NULL) goto err;
	BN_CTX_start(ctx);
	r0 = BN_CTX_get(ctx);
	r1 = BN_CTX_get(ctx);
	r2 = BN_CTX_get(ctx);
	r3 = BN_CTX_get(ctx);
	if (r3 == NULL) goto err;

	bitsp=(bits+1)/2;
	bitsq=bits-bitsp;

	/* We need the RSA components non-NULL */
	if(!rsa->n && ((rsa->n=BN_new()) == NULL)) goto err;
	if(!rsa->d && ((rsa->d=BN_new()) == NULL)) goto err;
	if(!rsa->e && ((rsa->e=BN_new()) == NULL)) goto err;
	if(!rsa->p && ((rsa->p=BN_new()) == NULL)) goto err;
	if(!rsa->q && ((rsa->q=BN_new()) == NULL)) goto err;
	if(!rsa->dmp1 && ((rsa->dmp1=BN_new()) == NULL)) goto err;
	if(!rsa->dmq1 && ((rsa->dmq1=BN_new()) == NULL)) goto err;
	if(!rsa->iqmp && ((rsa->iqmp=BN_new()) == NULL)) goto err;

	BN_copy(rsa->e, e_value);

	/* generate p and q */
	for (;;)
		{
		if(!BN_generate_prime_ex(rsa->p, bitsp, 0, NULL, NULL, cb))
			goto err;
		if (!BN_sub(r2,rsa->p,BN_value_one())) goto err;
		if (!BN_gcd(r1,r2,rsa->e,ctx)) goto err;
		if (BN_is_one(r1)) break;
		if(!BN_GENCB_call(cb, 2, n++))
			goto err;
		}
	if(!BN_GENCB_call(cb, 3, 0))
		goto err;
	for (;;)
		{
		/* When generating ridiculously small keys, we can get stuck
		 * continually regenerating the same prime values. Check for
		 * this and bail if it happens 3 times. */
		unsigned int degenerate = 0;
		do
			{
			if(!BN_generate_prime_ex(rsa->q, bitsq, 0, NULL, NULL, cb))
				goto err;
			} while((BN_cmp(rsa->p, rsa->q) == 0) && (++degenerate < 3));
		if(degenerate == 3)
			{
			ok = 0; /* we set our own err */
			RSAerr(RSA_F_RSA_BUILTIN_KEYGEN,RSA_R_KEY_SIZE_TOO_SMALL);
			goto err;
			}
		if (!BN_sub(r2,rsa->q,BN_value_one())) goto err;
		if (!BN_gcd(r1,r2,rsa->e,ctx)) goto err;
		if (BN_is_one(r1))
			break;
		if(!BN_GENCB_call(cb, 2, n++))
			goto err;
		}
	if(!BN_GENCB_call(cb, 3, 1))
		goto err;
	if (BN_cmp(rsa->p,rsa->q) < 0)
		{
		tmp=rsa->p;
		rsa->p=rsa->q;
		rsa->q=tmp;
		}

	/* calculate n */
	if (!BN_mul(rsa->n,rsa->p,rsa->q,ctx)) goto err;

	/* calculate d */
	if (!BN_sub(r1,rsa->p,BN_value_one())) goto err;	/* p-1 */
	if (!BN_sub(r2,rsa->q,BN_value_one())) goto err;	/* q-1 */
	if (!BN_mul(r0,r1,r2,ctx)) goto err;	/* (p-1)(q-1) */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
		{
		  pr0 = &local_r0;
		  BN_with_flags(pr0, r0, BN_FLG_CONSTTIME);
		}
	else
	  pr0 = r0;
	if (!BN_mod_inverse(rsa->d,rsa->e,pr0,ctx)) goto err;	/* d */

	/* set up d for correct BN_FLG_CONSTTIME flag */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
		{
		d = &local_d;
		BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
		}
	else
		d = rsa->d;

	/* calculate d mod (p-1) */
	if (!BN_mod(rsa->dmp1,d,r1,ctx)) goto err;

	/* calculate d mod (q-1) */
	if (!BN_mod(rsa->dmq1,d,r2,ctx)) goto err;

	/* calculate inverse of q mod p */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
		{
		p = &local_p;
		BN_with_flags(p, rsa->p, BN_FLG_CONSTTIME);
		}
	else
		p = rsa->p;
	if (!BN_mod_inverse(rsa->iqmp,rsa->q,p,ctx)) goto err;

	ok=1;
err:
	if (ok == -1)
		{
		RSAerr(RSA_F_RSA_BUILTIN_KEYGEN,ERR_LIB_BN);
		ok=0;
		}
	if (ctx != NULL)
		{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
		}

	return ok;
	}












static int RSA_eay_public_encrypt(int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa,int padding);
static int RSA_eay_private_encrypt(int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa,int padding);
static int RSA_eay_public_decrypt(int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa,int padding);
static int RSA_eay_private_decrypt(int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa,int padding);
static int RSA_eay_mod_exp(BIGNUM *r0, const BIGNUM *i, RSA *rsa, BN_CTX *ctx);
static int RSA_eay_init(RSA *rsa);
static int RSA_eay_finish(RSA *rsa);

static RSA_METHOD rsa_pkcs1_eay_meth={
	"Eric Young's PKCS#1 RSA",
	RSA_eay_public_encrypt,
	RSA_eay_public_decrypt, /* signature verification */
	RSA_eay_private_encrypt, /* signing */
	RSA_eay_private_decrypt,
	RSA_eay_mod_exp,
	BN_mod_exp_mont, /* XXX probably we should not use Montgomery if  e == 3 */
	RSA_eay_init,
	RSA_eay_finish,
	0, /* flags */
	NULL,
	0, /* rsa_sign */
	0, /* rsa_verify */
	NULL /* rsa_keygen */
	};

const RSA_METHOD *RSA_PKCS1_SSLeay(void)
	{
	return(&rsa_pkcs1_eay_meth);
	}

static int RSA_eay_public_encrypt(int flen, const unsigned char *from,
	     unsigned char *to, RSA *rsa, int padding)
	{
	BIGNUM *f,*ret;
	int i,j,k,num=0,r= -1;
	unsigned char *buf=NULL;
	BN_CTX *ctx=NULL;

	if (BN_num_bits(rsa->n) > OPENSSL_RSA_MAX_MODULUS_BITS)
		{
		RSAerr(RSA_F_RSA_EAY_PUBLIC_ENCRYPT, RSA_R_MODULUS_TOO_LARGE);
		return -1;
		}

	if (BN_ucmp(rsa->n, rsa->e) <= 0)
		{
		RSAerr(RSA_F_RSA_EAY_PUBLIC_ENCRYPT, RSA_R_BAD_E_VALUE);
		return -1;
		}

	/* for large moduli, enforce exponent limit */
	if (BN_num_bits(rsa->n) > OPENSSL_RSA_SMALL_MODULUS_BITS)
		{
		if (BN_num_bits(rsa->e) > OPENSSL_RSA_MAX_PUBEXP_BITS)
			{
			RSAerr(RSA_F_RSA_EAY_PUBLIC_ENCRYPT, RSA_R_BAD_E_VALUE);
			return -1;
			}
		}
	
	if ((ctx=BN_CTX_new()) == NULL) goto err;
	BN_CTX_start(ctx);
	f = BN_CTX_get(ctx);
	ret = BN_CTX_get(ctx);
	num=BN_num_bytes(rsa->n);
	buf = OPENSSL_malloc(num);
	if (!f || !ret || !buf)
		{
		RSAerr(RSA_F_RSA_EAY_PUBLIC_ENCRYPT,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	switch (padding)
		{
	case RSA_PKCS1_PADDING:
		i=RSA_padding_add_PKCS1_type_2(buf,num,from,flen);
		break;
#ifndef OPENSSL_NO_SHA
	case RSA_PKCS1_OAEP_PADDING:
	        i=RSA_padding_add_PKCS1_OAEP(buf,num,from,flen,NULL,0);
		break;
#endif
	case RSA_SSLV23_PADDING:
		i=RSA_padding_add_SSLv23(buf,num,from,flen);
		break;
	case RSA_NO_PADDING:
		i=RSA_padding_add_none(buf,num,from,flen);
		break;
	default:
		RSAerr(RSA_F_RSA_EAY_PUBLIC_ENCRYPT,RSA_R_UNKNOWN_PADDING_TYPE);
		goto err;
		}
	if (i <= 0) goto err;

	if (BN_bin2bn(buf,num,f) == NULL) goto err;
	
	if (BN_ucmp(f, rsa->n) >= 0)
		{
		/* usually the padding functions would catch this */
		RSAerr(RSA_F_RSA_EAY_PUBLIC_ENCRYPT,RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
		goto err;
		}

	if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
		if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n, CRYPTO_LOCK_RSA, rsa->n, ctx))
			goto err;

	if (!rsa->meth->bn_mod_exp(ret,f,rsa->e,rsa->n,ctx,
		rsa->_method_mod_n)) goto err;

	/* put in leading 0 bytes if the number is less than the
	 * length of the modulus */
	j=BN_num_bytes(ret);
	i=BN_bn2bin(ret,&(to[num-j]));
	for (k=0; k<(num-i); k++)
		to[k]=0;

	r=num;
err:
	if (ctx != NULL)
		{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
		}
	if (buf != NULL) 
		{
		OPENSSL_cleanse(buf,num);
		OPENSSL_free(buf);
		}
	return(r);
	}

static BN_BLINDING *rsa_get_blinding(RSA *rsa, int *local, BN_CTX *ctx)
{
	//ZCY UNDO
	return NULL;
}

static int rsa_blinding_convert(BN_BLINDING *b, BIGNUM *f, BIGNUM *unblind, BN_CTX *ctx)
{
	//ZCY UNDO
	return 0;
}

static int rsa_blinding_invert(BN_BLINDING *b, BIGNUM *f, BIGNUM *unblind, BN_CTX *ctx)
{
	//ZCY UNDO
	return 0;
}

/* signing */
static int RSA_eay_private_encrypt(int flen, const unsigned char *from,
	     unsigned char *to, RSA *rsa, int padding)
	{
	BIGNUM *f, *ret, *res;
	int i,j,k,num=0,r= -1;
	unsigned char *buf=NULL;
	BN_CTX *ctx=NULL;
	int local_blinding = 0;
	/* Used only if the blinding structure is shared. A non-NULL unblind
	 * instructs rsa_blinding_convert() and rsa_blinding_invert() to store
	 * the unblinding factor outside the blinding structure. */
	BIGNUM *unblind = NULL;
	BN_BLINDING *blinding = NULL;

	if ((ctx=BN_CTX_new()) == NULL) goto err;
	BN_CTX_start(ctx);
	f   = BN_CTX_get(ctx);
	ret = BN_CTX_get(ctx);
	num = BN_num_bytes(rsa->n);
	buf = OPENSSL_malloc(num);
	if(!f || !ret || !buf)
		{
		RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	switch (padding)
		{
	case RSA_PKCS1_PADDING:
		i=RSA_padding_add_PKCS1_type_1(buf,num,from,flen);
		break;
	case RSA_X931_PADDING:
		i=RSA_padding_add_X931(buf,num,from,flen);
		break;
	case RSA_NO_PADDING:
		i=RSA_padding_add_none(buf,num,from,flen);
		break;
	case RSA_SSLV23_PADDING:
	default:
		RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT,RSA_R_UNKNOWN_PADDING_TYPE);
		goto err;
		}
	if (i <= 0) goto err;

	if (BN_bin2bn(buf,num,f) == NULL) goto err;
	
	if (BN_ucmp(f, rsa->n) >= 0)
		{	
		/* usually the padding functions would catch this */
		RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT,RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
		goto err;
		}

	if (!(rsa->flags & RSA_FLAG_NO_BLINDING))
		{
		blinding = rsa_get_blinding(rsa, &local_blinding, ctx);
		if (blinding == NULL)
			{
			RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT, ERR_R_INTERNAL_ERROR);
			goto err;
			}
		}
	
	if (blinding != NULL)
		{
		if (!local_blinding && ((unblind = BN_CTX_get(ctx)) == NULL))
			{
			RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT,ERR_R_MALLOC_FAILURE);
			goto err;
			}
		if (!rsa_blinding_convert(blinding, f, unblind, ctx))
			goto err;
		}

	if ( (rsa->flags & RSA_FLAG_EXT_PKEY) ||
		((rsa->p != NULL) &&
		(rsa->q != NULL) &&
		(rsa->dmp1 != NULL) &&
		(rsa->dmq1 != NULL) &&
		(rsa->iqmp != NULL)) )
		{ 
		if (!rsa->meth->rsa_mod_exp(ret, f, rsa, ctx)) goto err;
		}
	else
		{
		BIGNUM local_d;
		BIGNUM *d = NULL;
		
		if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
			{
			BN_init(&local_d);
			d = &local_d;
			BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
			}
		else
			d= rsa->d;

		if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
			if(!BN_MONT_CTX_set_locked(&rsa->_method_mod_n, CRYPTO_LOCK_RSA, rsa->n, ctx))
				goto err;

		if (!rsa->meth->bn_mod_exp(ret,f,d,rsa->n,ctx,
				rsa->_method_mod_n)) goto err;
		}

	if (blinding)
		if (!rsa_blinding_invert(blinding, ret, unblind, ctx))
			goto err;

	if (padding == RSA_X931_PADDING)
		{
		BN_sub(f, rsa->n, ret);
		if (BN_cmp(ret, f))
			res = f;
		else
			res = ret;
		}
	else
		res = ret;

	/* put in leading 0 bytes if the number is less than the
	 * length of the modulus */
	j=BN_num_bytes(res);
	i=BN_bn2bin(res,&(to[num-j]));
	for (k=0; k<(num-i); k++)
		to[k]=0;

	r=num;
err:
	if (ctx != NULL)
		{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
		}
	if (buf != NULL)
		{
		OPENSSL_cleanse(buf,num);
		OPENSSL_free(buf);
		}
	return(r);
	}

static int RSA_eay_private_decrypt(int flen, const unsigned char *from,
	     unsigned char *to, RSA *rsa, int padding)
	{
	BIGNUM *f, *ret;
	int j,num=0,r= -1;
	unsigned char *p;
	unsigned char *buf=NULL;
	BN_CTX *ctx=NULL;
	int local_blinding = 0;
	/* Used only if the blinding structure is shared. A non-NULL unblind
	 * instructs rsa_blinding_convert() and rsa_blinding_invert() to store
	 * the unblinding factor outside the blinding structure. */
	BIGNUM *unblind = NULL;
	BN_BLINDING *blinding = NULL;

	if((ctx = BN_CTX_new()) == NULL) goto err;
	BN_CTX_start(ctx);
	f   = BN_CTX_get(ctx);
	ret = BN_CTX_get(ctx);
	num = BN_num_bytes(rsa->n);
	buf = OPENSSL_malloc(num);
	if(!f || !ret || !buf)
		{
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	/* This check was for equality but PGP does evil things
	 * and chops off the top '0' bytes */
	if (flen > num)
		{
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,RSA_R_DATA_GREATER_THAN_MOD_LEN);
		goto err;
		}

	/* make data into a big number */
	if (BN_bin2bn(from,(int)flen,f) == NULL) goto err;

	if (BN_ucmp(f, rsa->n) >= 0)
		{
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
		goto err;
		}

	if (!(rsa->flags & RSA_FLAG_NO_BLINDING))
		{
		blinding = rsa_get_blinding(rsa, &local_blinding, ctx);
		if (blinding == NULL)
			{
			RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT, ERR_R_INTERNAL_ERROR);
			goto err;
			}
		}
	
	if (blinding != NULL)
		{
		if (!local_blinding && ((unblind = BN_CTX_get(ctx)) == NULL))
			{
			RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,ERR_R_MALLOC_FAILURE);
			goto err;
			}
		if (!rsa_blinding_convert(blinding, f, unblind, ctx))
			goto err;
		}

	/* do the decrypt */
	if ( (rsa->flags & RSA_FLAG_EXT_PKEY) ||
		((rsa->p != NULL) &&
		(rsa->q != NULL) &&
		(rsa->dmp1 != NULL) &&
		(rsa->dmq1 != NULL) &&
		(rsa->iqmp != NULL)) )
		{
		if (!rsa->meth->rsa_mod_exp(ret, f, rsa, ctx)) goto err;
		}
	else
		{
		BIGNUM local_d;
		BIGNUM *d = NULL;
		
		if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
			{
			d = &local_d;
			BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
			}
		else
			d = rsa->d;

		if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
			if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n, CRYPTO_LOCK_RSA, rsa->n, ctx))
				goto err;
		if (!rsa->meth->bn_mod_exp(ret,f,d,rsa->n,ctx,
				rsa->_method_mod_n))
		  goto err;
		}

	if (blinding)
		if (!rsa_blinding_invert(blinding, ret, unblind, ctx))
			goto err;

	p=buf;
	j=BN_bn2bin(ret,p); /* j is only used with no-padding mode */

	switch (padding)
		{
	case RSA_PKCS1_PADDING:
		r=RSA_padding_check_PKCS1_type_2(to,num,buf,j,num);
		break;
#ifndef OPENSSL_NO_SHA
        case RSA_PKCS1_OAEP_PADDING:
	        r=RSA_padding_check_PKCS1_OAEP(to,num,buf,j,num,NULL,0);
                break;
#endif
 	case RSA_SSLV23_PADDING:
		r=RSA_padding_check_SSLv23(to,num,buf,j,num);
		break;
	case RSA_NO_PADDING:
		r=RSA_padding_check_none(to,num,buf,j,num);
		break;
	default:
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,RSA_R_UNKNOWN_PADDING_TYPE);
		goto err;
		}
	if (r < 0)
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,RSA_R_PADDING_CHECK_FAILED);

err:
	if (ctx != NULL)
		{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
		}
	if (buf != NULL)
		{
		OPENSSL_cleanse(buf,num);
		OPENSSL_free(buf);
		}
	return(r);
	}

/* signature verification */
static int RSA_eay_public_decrypt(int flen, const unsigned char *from,
	     unsigned char *to, RSA *rsa, int padding)
	{
	BIGNUM *f,*ret;
	int i,num=0,r= -1;
	unsigned char *p;
	unsigned char *buf=NULL;
	BN_CTX *ctx=NULL;

	if (BN_num_bits(rsa->n) > OPENSSL_RSA_MAX_MODULUS_BITS)
		{
		RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT, RSA_R_MODULUS_TOO_LARGE);
		return -1;
		}

	if (BN_ucmp(rsa->n, rsa->e) <= 0)
		{
		RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT, RSA_R_BAD_E_VALUE);
		return -1;
		}

	/* for large moduli, enforce exponent limit */
	if (BN_num_bits(rsa->n) > OPENSSL_RSA_SMALL_MODULUS_BITS)
		{
		if (BN_num_bits(rsa->e) > OPENSSL_RSA_MAX_PUBEXP_BITS)
			{
			RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT, RSA_R_BAD_E_VALUE);
			return -1;
			}
		}
	
	if((ctx = BN_CTX_new()) == NULL) goto err;
	BN_CTX_start(ctx);
	f = BN_CTX_get(ctx);
	ret = BN_CTX_get(ctx);
	num=BN_num_bytes(rsa->n);
	buf = OPENSSL_malloc(num);
	if(!f || !ret || !buf)
		{
		RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	/* This check was for equality but PGP does evil things
	 * and chops off the top '0' bytes */
	if (flen > num)
		{
		RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT,RSA_R_DATA_GREATER_THAN_MOD_LEN);
		goto err;
		}

	if (BN_bin2bn(from,flen,f) == NULL) goto err;

	if (BN_ucmp(f, rsa->n) >= 0)
		{
		RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT,RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
		goto err;
		}

	if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
		if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n, CRYPTO_LOCK_RSA, rsa->n, ctx))
			goto err;

	if (!rsa->meth->bn_mod_exp(ret,f,rsa->e,rsa->n,ctx,
		rsa->_method_mod_n)) goto err;

	if ((padding == RSA_X931_PADDING) && ((ret->d[0] & 0xf) != 12))
		if (!BN_sub(ret, rsa->n, ret)) goto err;

	p=buf;
	i=BN_bn2bin(ret,p);

	switch (padding)
		{
	case RSA_PKCS1_PADDING:
		r=RSA_padding_check_PKCS1_type_1(to,num,buf,i,num);
		break;
	case RSA_X931_PADDING:
		r=RSA_padding_check_X931(to,num,buf,i,num);
		break;
	case RSA_NO_PADDING:
		r=RSA_padding_check_none(to,num,buf,i,num);
		break;
	default:
		RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT,RSA_R_UNKNOWN_PADDING_TYPE);
		goto err;
		}
	if (r < 0)
		RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT,RSA_R_PADDING_CHECK_FAILED);

err:
	if (ctx != NULL)
		{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
		}
	if (buf != NULL)
		{
		OPENSSL_cleanse(buf,num);
		OPENSSL_free(buf);
		}
	return(r);
	}

static int RSA_eay_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
	{
	BIGNUM *r1,*m1,*vrfy;
	BIGNUM local_dmp1,local_dmq1,local_c,local_r1;
	BIGNUM *dmp1,*dmq1,*c,*pr1;
	int ret=0;

	BN_CTX_start(ctx);
	r1 = BN_CTX_get(ctx);
	m1 = BN_CTX_get(ctx);
	vrfy = BN_CTX_get(ctx);

	{
		BIGNUM local_p, local_q;
		BIGNUM *p = NULL, *q = NULL;

		/* Make sure BN_mod_inverse in Montgomery intialization uses the
		 * BN_FLG_CONSTTIME flag (unless RSA_FLAG_NO_CONSTTIME is set)
		 */
		if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
			{
			BN_init(&local_p);
			p = &local_p;
			BN_with_flags(p, rsa->p, BN_FLG_CONSTTIME);

			BN_init(&local_q);
			q = &local_q;
			BN_with_flags(q, rsa->q, BN_FLG_CONSTTIME);
			}
		else
			{
			p = rsa->p;
			q = rsa->q;
			}

		if (rsa->flags & RSA_FLAG_CACHE_PRIVATE)
			{
			if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_p, CRYPTO_LOCK_RSA, p, ctx))
				goto err;
			if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_q, CRYPTO_LOCK_RSA, q, ctx))
				goto err;
			}
	}

	if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
		if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n, CRYPTO_LOCK_RSA, rsa->n, ctx))
			goto err;

	/* compute I mod q */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
		{
		c = &local_c;
		BN_with_flags(c, I, BN_FLG_CONSTTIME);
		if (!BN_mod(r1,c,rsa->q,ctx)) goto err;
		}
	else
		{
		if (!BN_mod(r1,I,rsa->q,ctx)) goto err;
		}

	/* compute r1^dmq1 mod q */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
		{
		dmq1 = &local_dmq1;
		BN_with_flags(dmq1, rsa->dmq1, BN_FLG_CONSTTIME);
		}
	else
		dmq1 = rsa->dmq1;
	if (!rsa->meth->bn_mod_exp(m1,r1,dmq1,rsa->q,ctx,
		rsa->_method_mod_q)) goto err;

	/* compute I mod p */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
		{
		c = &local_c;
		BN_with_flags(c, I, BN_FLG_CONSTTIME);
		if (!BN_mod(r1,c,rsa->p,ctx)) goto err;
		}
	else
		{
		if (!BN_mod(r1,I,rsa->p,ctx)) goto err;
		}

	/* compute r1^dmp1 mod p */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
		{
		dmp1 = &local_dmp1;
		BN_with_flags(dmp1, rsa->dmp1, BN_FLG_CONSTTIME);
		}
	else
		dmp1 = rsa->dmp1;
	if (!rsa->meth->bn_mod_exp(r0,r1,dmp1,rsa->p,ctx,
		rsa->_method_mod_p)) goto err;

	if (!BN_sub(r0,r0,m1)) goto err;
	/* This will help stop the size of r0 increasing, which does
	 * affect the multiply if it optimised for a power of 2 size */
	if (BN_is_negative(r0))
		if (!BN_add(r0,r0,rsa->p)) goto err;

	if (!BN_mul(r1,r0,rsa->iqmp,ctx)) goto err;

	/* Turn BN_FLG_CONSTTIME flag on before division operation */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
		{
		pr1 = &local_r1;
		BN_with_flags(pr1, r1, BN_FLG_CONSTTIME);
		}
	else
		pr1 = r1;
	if (!BN_mod(r0,pr1,rsa->p,ctx)) goto err;

	/* If p < q it is occasionally possible for the correction of
         * adding 'p' if r0 is negative above to leave the result still
	 * negative. This can break the private key operations: the following
	 * second correction should *always* correct this rare occurrence.
	 * This will *never* happen with OpenSSL generated keys because
         * they ensure p > q [steve]
         */
	if (BN_is_negative(r0))
		if (!BN_add(r0,r0,rsa->p)) goto err;
	if (!BN_mul(r1,r0,rsa->q,ctx)) goto err;
	if (!BN_add(r0,r1,m1)) goto err;

	if (rsa->e && rsa->n)
		{
		if (!rsa->meth->bn_mod_exp(vrfy,r0,rsa->e,rsa->n,ctx,rsa->_method_mod_n)) goto err;
		/* If 'I' was greater than (or equal to) rsa->n, the operation
		 * will be equivalent to using 'I mod n'. However, the result of
		 * the verify will *always* be less than 'n' so we don't check
		 * for absolute equality, just congruency. */
		if (!BN_sub(vrfy, vrfy, I)) goto err;
		if (!BN_mod(vrfy, vrfy, rsa->n, ctx)) goto err;
		if (BN_is_negative(vrfy))
			if (!BN_add(vrfy, vrfy, rsa->n)) goto err;
		if (!BN_is_zero(vrfy))
			{
			/* 'I' and 'vrfy' aren't congruent mod n. Don't leak
			 * miscalculated CRT output, just do a raw (slower)
			 * mod_exp and return that instead. */

			BIGNUM local_d;
			BIGNUM *d = NULL;
		
			if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
				{
				d = &local_d;
				BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
				}
			else
				d = rsa->d;
			if (!rsa->meth->bn_mod_exp(r0,I,d,rsa->n,ctx,
						   rsa->_method_mod_n)) goto err;
			}
		}
	ret=1;
err:
	BN_CTX_end(ctx);
	return(ret);
	}

static int RSA_eay_init(RSA *rsa)
	{
	rsa->flags|=RSA_FLAG_CACHE_PUBLIC|RSA_FLAG_CACHE_PRIVATE;
	return(1);
	}

static int RSA_eay_finish(RSA *rsa)
	{
	if (rsa->_method_mod_n != NULL)
		BN_MONT_CTX_free(rsa->_method_mod_n);
	if (rsa->_method_mod_p != NULL)
		BN_MONT_CTX_free(rsa->_method_mod_p);
	if (rsa->_method_mod_q != NULL)
		BN_MONT_CTX_free(rsa->_method_mod_q);
	return(1);
	}












typedef struct ERR_string_data_st
	{
	unsigned long error;
	const char *string;
	} ERR_STRING_DATA;


#define ERR_FUNC(func) func//ERR_PACK(ERR_LIB_RSA,func,0)
#define ERR_REASON(reason) reason//ERR_PACK(ERR_LIB_RSA,0,reason)

static ERR_STRING_DATA RSA_str_functs[]=
	{
{ERR_FUNC(RSA_F_CHECK_PADDING_MD),	"CHECK_PADDING_MD"},
{ERR_FUNC(RSA_F_DO_RSA_PRINT),	"DO_RSA_PRINT"},
{ERR_FUNC(RSA_F_INT_RSA_VERIFY),	"INT_RSA_VERIFY"},
{ERR_FUNC(RSA_F_MEMORY_LOCK),	"MEMORY_LOCK"},
{ERR_FUNC(RSA_F_OLD_RSA_PRIV_DECODE),	"OLD_RSA_PRIV_DECODE"},
{ERR_FUNC(RSA_F_PKEY_RSA_CTRL),	"PKEY_RSA_CTRL"},
{ERR_FUNC(RSA_F_PKEY_RSA_CTRL_STR),	"PKEY_RSA_CTRL_STR"},
{ERR_FUNC(RSA_F_PKEY_RSA_SIGN),	"PKEY_RSA_SIGN"},
{ERR_FUNC(RSA_F_PKEY_RSA_VERIFYRECOVER),	"PKEY_RSA_VERIFYRECOVER"},
{ERR_FUNC(RSA_F_RSA_BUILTIN_KEYGEN),	"RSA_BUILTIN_KEYGEN"},
{ERR_FUNC(RSA_F_RSA_CHECK_KEY),	"RSA_check_key"},
{ERR_FUNC(RSA_F_RSA_EAY_PRIVATE_DECRYPT),	"RSA_EAY_PRIVATE_DECRYPT"},
{ERR_FUNC(RSA_F_RSA_EAY_PRIVATE_ENCRYPT),	"RSA_EAY_PRIVATE_ENCRYPT"},
{ERR_FUNC(RSA_F_RSA_EAY_PUBLIC_DECRYPT),	"RSA_EAY_PUBLIC_DECRYPT"},
{ERR_FUNC(RSA_F_RSA_EAY_PUBLIC_ENCRYPT),	"RSA_EAY_PUBLIC_ENCRYPT"},
{ERR_FUNC(RSA_F_RSA_GENERATE_KEY),	"RSA_generate_key"},
{ERR_FUNC(RSA_F_RSA_MEMORY_LOCK),	"RSA_memory_lock"},
{ERR_FUNC(RSA_F_RSA_NEW_METHOD),	"RSA_new_method"},
{ERR_FUNC(RSA_F_RSA_NULL),	"RSA_NULL"},
{ERR_FUNC(RSA_F_RSA_NULL_MOD_EXP),	"RSA_NULL_MOD_EXP"},
{ERR_FUNC(RSA_F_RSA_NULL_PRIVATE_DECRYPT),	"RSA_NULL_PRIVATE_DECRYPT"},
{ERR_FUNC(RSA_F_RSA_NULL_PRIVATE_ENCRYPT),	"RSA_NULL_PRIVATE_ENCRYPT"},
{ERR_FUNC(RSA_F_RSA_NULL_PUBLIC_DECRYPT),	"RSA_NULL_PUBLIC_DECRYPT"},
{ERR_FUNC(RSA_F_RSA_NULL_PUBLIC_ENCRYPT),	"RSA_NULL_PUBLIC_ENCRYPT"},
{ERR_FUNC(RSA_F_RSA_PADDING_ADD_NONE),	"RSA_padding_add_none"},
{ERR_FUNC(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP),	"RSA_padding_add_PKCS1_OAEP"},
{ERR_FUNC(RSA_F_RSA_PADDING_ADD_PKCS1_PSS),	"RSA_padding_add_PKCS1_PSS"},
{ERR_FUNC(RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1),	"RSA_padding_add_PKCS1_type_1"},
{ERR_FUNC(RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2),	"RSA_padding_add_PKCS1_type_2"},
{ERR_FUNC(RSA_F_RSA_PADDING_ADD_SSLV23),	"RSA_padding_add_SSLv23"},
{ERR_FUNC(RSA_F_RSA_PADDING_ADD_X931),	"RSA_padding_add_X931"},
{ERR_FUNC(RSA_F_RSA_PADDING_CHECK_NONE),	"RSA_padding_check_none"},
{ERR_FUNC(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP),	"RSA_padding_check_PKCS1_OAEP"},
{ERR_FUNC(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1),	"RSA_padding_check_PKCS1_type_1"},
{ERR_FUNC(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2),	"RSA_padding_check_PKCS1_type_2"},
{ERR_FUNC(RSA_F_RSA_PADDING_CHECK_SSLV23),	"RSA_padding_check_SSLv23"},
{ERR_FUNC(RSA_F_RSA_PADDING_CHECK_X931),	"RSA_padding_check_X931"},
{ERR_FUNC(RSA_F_RSA_PRINT),	"RSA_print"},
{ERR_FUNC(RSA_F_RSA_PRINT_FP),	"RSA_print_fp"},
{ERR_FUNC(RSA_F_RSA_PRIV_DECODE),	"RSA_PRIV_DECODE"},
{ERR_FUNC(RSA_F_RSA_PRIV_ENCODE),	"RSA_PRIV_ENCODE"},
{ERR_FUNC(RSA_F_RSA_PUB_DECODE),	"RSA_PUB_DECODE"},
{ERR_FUNC(RSA_F_RSA_SETUP_BLINDING),	"RSA_setup_blinding"},
{ERR_FUNC(RSA_F_RSA_SIGN),	"RSA_sign"},
{ERR_FUNC(RSA_F_RSA_SIGN_ASN1_OCTET_STRING),	"RSA_sign_ASN1_OCTET_STRING"},
{ERR_FUNC(RSA_F_RSA_VERIFY),	"RSA_verify"},
{ERR_FUNC(RSA_F_RSA_VERIFY_ASN1_OCTET_STRING),	"RSA_verify_ASN1_OCTET_STRING"},
{ERR_FUNC(RSA_F_RSA_VERIFY_PKCS1_PSS),	"RSA_verify_PKCS1_PSS"},
{0,NULL}
	};

static ERR_STRING_DATA RSA_str_reasons[]=
	{
{ERR_REASON(RSA_R_ALGORITHM_MISMATCH)    ,"algorithm mismatch"},
{ERR_REASON(RSA_R_BAD_E_VALUE)           ,"bad e value"},
{ERR_REASON(RSA_R_BAD_FIXED_HEADER_DECRYPT),"bad fixed header decrypt"},
{ERR_REASON(RSA_R_BAD_PAD_BYTE_COUNT)    ,"bad pad byte count"},
{ERR_REASON(RSA_R_BAD_SIGNATURE)         ,"bad signature"},
{ERR_REASON(RSA_R_BLOCK_TYPE_IS_NOT_01)  ,"block type is not 01"},
{ERR_REASON(RSA_R_BLOCK_TYPE_IS_NOT_02)  ,"block type is not 02"},
{ERR_REASON(RSA_R_DATA_GREATER_THAN_MOD_LEN),"data greater than mod len"},
{ERR_REASON(RSA_R_DATA_TOO_LARGE)        ,"data too large"},
{ERR_REASON(RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE),"data too large for key size"},
{ERR_REASON(RSA_R_DATA_TOO_LARGE_FOR_MODULUS),"data too large for modulus"},
{ERR_REASON(RSA_R_DATA_TOO_SMALL)        ,"data too small"},
{ERR_REASON(RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE),"data too small for key size"},
{ERR_REASON(RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY),"digest too big for rsa key"},
{ERR_REASON(RSA_R_DMP1_NOT_CONGRUENT_TO_D),"dmp1 not congruent to d"},
{ERR_REASON(RSA_R_DMQ1_NOT_CONGRUENT_TO_D),"dmq1 not congruent to d"},
{ERR_REASON(RSA_R_D_E_NOT_CONGRUENT_TO_1),"d e not congruent to 1"},
{ERR_REASON(RSA_R_FIRST_OCTET_INVALID)   ,"first octet invalid"},
{ERR_REASON(RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE),"illegal or unsupported padding mode"},
{ERR_REASON(RSA_R_INVALID_DIGEST_LENGTH) ,"invalid digest length"},
{ERR_REASON(RSA_R_INVALID_HEADER)        ,"invalid header"},
{ERR_REASON(RSA_R_INVALID_KEYBITS)       ,"invalid keybits"},
{ERR_REASON(RSA_R_INVALID_MESSAGE_LENGTH),"invalid message length"},
{ERR_REASON(RSA_R_INVALID_PADDING)       ,"invalid padding"},
{ERR_REASON(RSA_R_INVALID_PADDING_MODE)  ,"invalid padding mode"},
{ERR_REASON(RSA_R_INVALID_PSS_SALTLEN)   ,"invalid pss saltlen"},
{ERR_REASON(RSA_R_INVALID_TRAILER)       ,"invalid trailer"},
{ERR_REASON(RSA_R_INVALID_X931_DIGEST)   ,"invalid x931 digest"},
{ERR_REASON(RSA_R_IQMP_NOT_INVERSE_OF_Q) ,"iqmp not inverse of q"},
{ERR_REASON(RSA_R_KEY_SIZE_TOO_SMALL)    ,"key size too small"},
{ERR_REASON(RSA_R_LAST_OCTET_INVALID)    ,"last octet invalid"},
{ERR_REASON(RSA_R_MODULUS_TOO_LARGE)     ,"modulus too large"},
{ERR_REASON(RSA_R_NO_PUBLIC_EXPONENT)    ,"no public exponent"},
{ERR_REASON(RSA_R_NULL_BEFORE_BLOCK_MISSING),"null before block missing"},
{ERR_REASON(RSA_R_N_DOES_NOT_EQUAL_P_Q)  ,"n does not equal p q"},
{ERR_REASON(RSA_R_OAEP_DECODING_ERROR)   ,"oaep decoding error"},
{ERR_REASON(RSA_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE),"operation not supported for this keytype"},
{ERR_REASON(RSA_R_PADDING_CHECK_FAILED)  ,"padding check failed"},
{ERR_REASON(RSA_R_P_NOT_PRIME)           ,"p not prime"},
{ERR_REASON(RSA_R_Q_NOT_PRIME)           ,"q not prime"},
{ERR_REASON(RSA_R_RSA_OPERATIONS_NOT_SUPPORTED),"rsa operations not supported"},
{ERR_REASON(RSA_R_SLEN_CHECK_FAILED)     ,"salt length check failed"},
{ERR_REASON(RSA_R_SLEN_RECOVERY_FAILED)  ,"salt length recovery failed"},
{ERR_REASON(RSA_R_SSLV3_ROLLBACK_ATTACK) ,"sslv3 rollback attack"},
{ERR_REASON(RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD),"the asn1 object identifier is not known for this md"},
{ERR_REASON(RSA_R_UNKNOWN_ALGORITHM_TYPE),"unknown algorithm type"},
{ERR_REASON(RSA_R_UNKNOWN_PADDING_TYPE)  ,"unknown padding type"},
{ERR_REASON(RSA_R_VALUE_MISSING)         ,"value missing"},
{ERR_REASON(RSA_R_WRONG_SIGNATURE_LENGTH),"wrong signature length"},
{0,NULL}
	};


void RSAerr(int func, int reason)
{
	int i;

	for (i=0; i < sizeof(RSA_str_functs)/sizeof(ERR_STRING_DATA); i++)
	{
		if (RSA_str_functs[i].error == func)
		{
			printf("RSAerr func: %s\r\n", RSA_str_functs[i].string);
			break;
		}
	}

	for (i=0; i < sizeof(RSA_str_reasons)/sizeof(ERR_STRING_DATA); i++)
	{
		if (RSA_str_reasons[i].error == reason)
		{
			printf("RSAerr reason: %s\r\n", RSA_str_reasons[i].string);
			break;
		}
	}
}




