//
//  DPCrypto.h
//  DPCrypto
//
//  Created by weifu Deng on 11/22/14.
//  Copyright (c) 2014 D-Power. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "RSA.h"
#import "Random.h"
#import "AES.h"

@interface DPCrypto : NSObject{
}

/**
 *  @brief  AES 模式：AES_MODE_ECB, 
 *                   AES_MODE_CBC,
 *                   AES_MODE_CFB,
 *                   AES_MODE_OFB,
 *                   AES_MODE_CTR, (define)
 *                   AES_MODE_SIC
 *
 */
@property(assign, nonatomic) u_int8_t iAesMode;

/**
 *  @brief  设置Rsa公钥
 *
 *  @param pStr Rsa公钥字符串
 */
- (void)DPRsaSetPublicKey:(unsigned char *)pStr;

/**
 *  @brief  RSA加密
 *
 *  @param pInputData    [in/out]要加密的数据
 *  @param iLengthOfData [in]加密前的数据长度
 *
 *  @return 加密后的数据长度
 */
- (int)DPRsaEncoderData:(unsigned char *)pInputData LengthOfData:(int)iLengthOfData;

#pragma mark - aes
/**
 *  @brief 设置AES iv 和 key
 *
 *  @param pStr      [in]aes ivkey字符串
 *  @param ilenOfStr [in]ivkey字符串长度,
 *                   不得小于ilenOfkey+16
 *  @param ilenOfkey [in]aes 密钥长度，有三种：16， 24， 32
 *
 *  @return YES/NO (成功/失败)
 */
- (BOOL)DPAesSetIVKeyStr:(unsigned char *)pStr LenOfStr:(u_int16_t)ilenOfStr LenOfKey:(u_int16_t)ilenOfkey;

/**
 *  @brief  随机生成 AES iv 和 key
 *
 *  @param pStr [in/out]AES ivkey字符串
 *               pData长度不得小于ilenOfkey+16
 *
 *  @param ilenOfkey [in]密钥长度
 *                  16 24 32
 *
 *  @return YES/NO (成功/失败)
 */
- (BOOL)DPAesRandomIVKey:(unsigned char *)pStr LenOfStr:(u_int16_t)ilenOfStr LenOfKey:(u_int16_t)ilenOfkey;

/**
 *  @brief  AES加密
 *
 *  @param pInputData       [in/out]要加密的数据
 *  @param iLengthOfEncData [in]数据长度
 *
 *  @return YES/NO (成功/失败)
 */
- (BOOL)DPAesEncodeData:(unsigned char *)pInputData LengthOfEncData:(int)iLengthOfEncData;

/**
 *  @brief  AES解密
 *
 *  @param pInputData       [in/out]要解密的数据
 *  @param iLengthOfDecData [out]数据长度
 *
 *  @return YES/NO (成功/失败)
 */
- (BOOL)DPAesDecodeData:(unsigned char *)pInputData LengthOfDecData:(int)iLengthOfDecData;

@end
