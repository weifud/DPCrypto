//
//  DPCrypto.m
//  DPCrypto
//
//  Created by weifu Deng on 11/22/14.
//  Copyright (c) 2014 D-Power. All rights reserved.
//

#import "DPCrypto.h"

@interface DPCrypto ()
{
    //RSA
    unsigned char mszRsaPublicKey[RSAKEYBYTES];
    //AES
    unsigned char mszAesIV[AES_BLOCK_SIZE];
    unsigned char *pAesKey;
    u_int16_t   _lenOfAesKey;
}

@end

@implementation DPCrypto
@synthesize iAesMode;

- (id)init{
    self = [super init];
    if (self) {
        _lenOfAesKey = 0;
        iAesMode = AES_MODE_CTR;
    }
    return self;
}

- (void)dealloc{
    [self freeAesKey];
    [super dealloc];
}

#pragma mark - RSA
- (void)DPRsaSetPublicKey:(unsigned char *)pStr{
    memset(mszRsaPublicKey, 0, RSAKEYBYTES);
    memcpy(mszRsaPublicKey, pStr, RSAKEYBYTES);
}

- (int)DPRsaEncoderData:(unsigned char *)pInputData LengthOfData:(int)iLengthOfData{
    int total_len = 0, ret = 0, enc_len = 0;
    int max_len = 2*RSAKEYBYTES;
    unsigned char *tempInputData = pInputData;
    unsigned char dEncData[2*RSAKEYBYTES];
    
    RSA *rsa_remote = RSA_New();
    if (!rsa_remote)
        return -1;
    
    RSA_SetPublicKey(rsa_remote, RSAKEYBYTES, mszRsaPublicKey);
    
    while(iLengthOfData > 0){
        if(iLengthOfData > RSAMSGSIZE){
            enc_len = RSAMSGSIZE;
        }
        else{
            enc_len = iLengthOfData;
        }
        
        if(max_len - total_len < RSAKEYBYTES){
            ret = -2;
            break;
        }
        
        ret = RSA_PublicEncrypt(rsa_remote, tempInputData, dEncData + total_len, enc_len);
        if(ret < 0){
            ret = -3;
            break;
        }
        
        total_len += ret;
        iLengthOfData -= enc_len;
        tempInputData += enc_len;
    }
    
    if (ret > 0){
        memcpy(pInputData, dEncData, total_len);
    }
    
    RSA_Free(rsa_remote);
    return  total_len;
}

#pragma mark - AES

- (BOOL)initAesKey:(u_int16_t)ilenOfKey{
    if (ilenOfKey != 16 &&
        ilenOfKey != 24 &&
        ilenOfKey != 32) {
        NSLog(@"aes key init err: unsupported len(supported:16, 24, 32)");
        return NO;
    }
    
    pAesKey = (unsigned char *)malloc(ilenOfKey);
    if (pAesKey) {
        memset(pAesKey, 0, _lenOfAesKey);
        _lenOfAesKey = ilenOfKey;
        return YES;
    }
    
    return NO;
}

- (void)freeAesKey{
    if (pAesKey) {
        free(pAesKey);
        pAesKey = NULL;
    }
    
    _lenOfAesKey = 0;
}

- (BOOL)DPAesSetIVKeyStr:(unsigned char *)pStr LenOfStr:(u_int16_t)ilenOfStr LenOfKey:(u_int16_t)ilenOfkey{
    if (ilenOfStr >= AES_BLOCK_SIZE + ilenOfkey) {
        [self freeAesKey];
        if ([self initAesKey:ilenOfkey]) {
            memset(mszAesIV, 0, AES_BLOCK_SIZE);
            memcpy(mszAesIV, pStr, AES_BLOCK_SIZE);
            memcpy(pAesKey, pStr + AES_BLOCK_SIZE, _lenOfAesKey);
            return YES;
        }
    }
    else{
        NSLog(@"aes set ivkey err: illegal str len");
    }
    
    return NO;
}

- (BOOL)DPAesRandomIVKey:(unsigned char *)pStr LenOfStr:(u_int16_t)ilenOfStr LenOfKey:(u_int16_t)ilenOfkey{
    if (ilenOfStr >= AES_BLOCK_SIZE + ilenOfkey) {
        [self freeAesKey];
        if ([self initAesKey:ilenOfkey]) {
            AES *aes = AES_New();
            if (aes) {
                AES_SetMode(aes, iAesMode);
                RAND_bytes(mszAesIV, AES_BLOCK_SIZE);
                RAND_bytes(pAesKey,  _lenOfAesKey);
                AES_Free(aes);
                aes = NULL;
                
                memcpy(pStr, mszAesIV, AES_BLOCK_SIZE);
                memcpy(pStr + AES_BLOCK_SIZE, pAesKey, _lenOfAesKey);
                
                return YES;
            }
        }
    }
    else{
        NSLog(@"aes random ivkey err: illegal str len");
    }
    
    return NO;
}

- (BOOL)DPAesEncodeData:(unsigned char *)pInputData LengthOfEncData:(int)iLengthOfEncData{
    BOOL bRet = NO;
    AES *aes = NULL;
    unsigned char *pBuf = NULL;
    
    if (_lenOfAesKey != 16 &&
        _lenOfAesKey != 24 &&
        _lenOfAesKey != 32) {
        NSLog(@"aes encode err: unsupported key len");
        return NO;
    }
    
    aes = AES_New();
    pBuf = (unsigned char*)malloc(iLengthOfEncData);
    if (aes == NULL || pBuf == NULL) {
        if (aes) AES_Free(aes);
        if (pBuf) free(pBuf);
        return bRet;
    }
    
    AES_SetMode(aes, iAesMode);
    AES_SetKey(aes, pAesKey, _lenOfAesKey*8);
    AES_SetEncInitVec(aes, mszAesIV);
    
    if (AES_DataEncrypt(aes, pInputData, pBuf, iLengthOfEncData) == 0) {
        memcpy(pInputData, pBuf,iLengthOfEncData);
        bRet = YES;
    }
    
    AES_Free(aes);
    free(pBuf);
    aes = NULL;
    pBuf = NULL;
    
    return bRet;
}

-(BOOL)DPAesDecodeData:(unsigned char *)pInputData LengthOfDecData:(int)iLengthOfDecData{
    BOOL bRet = NO;
    AES *aes = NULL;
    unsigned char *pBuf = NULL;
    
    if (_lenOfAesKey != 16 &&
        _lenOfAesKey != 24 &&
        _lenOfAesKey != 32) {
        NSLog(@"aes decode err: unsupported key len");
        return NO;
    }
    
    aes = AES_New();
    pBuf = (unsigned char*)malloc(iLengthOfDecData);
    if (aes == NULL || pBuf == NULL) {
        if (aes) AES_Free(aes);
        if (pBuf) free(pBuf);
        return bRet;
    }
    
    AES_SetMode(aes, iAesMode);
    AES_SetKey(aes, pAesKey, _lenOfAesKey*8);
    AES_SetDecInitVec(aes, mszAesIV);
    
    if(AES_DataDecrypt(aes, pInputData, pBuf, iLengthOfDecData) == 0){
        memcpy(pInputData, pBuf, iLengthOfDecData);
        bRet = YES;
    }
    
    AES_Free(aes);
    aes = NULL;
    pBuf = NULL;
    free(pBuf);
    
    return bRet;
}

@end
