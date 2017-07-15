
#ifndef HEADER_AES_H
#define HEADER_AES_H


#ifdef  __cplusplus
extern "C" {
#endif


#define AES_MODE_ECB    0
#define AES_MODE_CBC    1
#define AES_MODE_CFB    2
#define AES_MODE_OFB    3
#define AES_MODE_CTR    4
#define AES_MODE_SIC    5


#define AES_MAXNR        14
#define AES_BLOCK_SIZE   16


struct aes_key_st
{
    unsigned int rd_key[4 *(AES_MAXNR + 1)];
    int rounds;
};
typedef struct aes_key_st AES_KEY;


struct aes_st
{
	int  mode;
	AES_KEY  enc_key;
	AES_KEY  dec_key;
	unsigned char  enc_iv[AES_BLOCK_SIZE];
	unsigned char  dec_iv[AES_BLOCK_SIZE];
	unsigned char  enc_cnt[AES_BLOCK_SIZE];
	unsigned char  dec_cnt[AES_BLOCK_SIZE];
	unsigned int   enc_num;
	unsigned int   dec_num;
};
typedef struct aes_st AES;



// ����AES����
//   ע��   ��������ԿΪ�գ�����������Կ
//   ����   AES����ָ�룬���ΪNULL��������ʧ��
//   ����
AES *AES_New(void);


// �ͷ�AES����
//   ����
//   ����   aes -- AES����ָ��
void AES_Free(AES *aes);


// ���ù���ģʽ
//   ע��   ������Ĭ�Ϲ���ģʽΪCTRģʽ
//          ���ʹ��ECB��CBCģʽ�����ܺͽ���ʱ�������ݳ��ȱ�����AES_BLOCK_SIZE�������� !!!
//   ����   <0 ʧ�ܣ� =0 �ɹ�
//   ����   aes  -- AES����ָ��
//          mode -- AES����ģʽ
int  AES_SetMode(AES *aes, const int mode);


// ������Կ
//   ����   <0 ʧ�ܣ� =0 �ɹ�
//   ����   aes     -- AES����ָ��
//          userKey -- AES��Կָ��
//          bits    -- AES��Կλ����������128��192����256λ
int  AES_SetKey(AES *aes, const unsigned char *userKey, const int bits);


// ���ü��ܳ�ʼ����
//   ����   
//   ����   aes     -- AES����ָ��
//          initvec -- AES��ʼ����
void AES_SetEncInitVec(AES *aes, const unsigned char *initvec);


// ���ý��ܳ�ʼ����
//   ����   
//   ����   aes     -- AES����ָ��
//          initvec -- AES��ʼ����
void AES_SetDecInitVec(AES *aes, const unsigned char *initvec);


// ���ݼ���
//   ע��   ���ܺ��������ԭʼ���ݳ�����ͬ���������ļ������ݻ��������ȱ��뱣֤ >= length
//   ����   <0 ʧ�ܣ� =0 �ɹ�
//   ����   aes    -- AES����ָ��
//          inbuf  -- �����ԭʼ���ݻ�����ָ��
//          outbuf -- ����ļ������ݻ�����ָ�룬������inbuf��ͬ
//          length -- �����ԭʼ���ݳ��ȣ��ֽڣ�
int  AES_DataEncrypt(AES *aes, const unsigned char *inbuf, unsigned char *outbuf, int length);


// ���ݽ���
//   ע��   ���ܺ��������������ݳ�����ͬ���������Ľ������ݻ��������ȱ��뱣֤ >= length
//   ����   <0 ʧ�ܣ� =0 �ɹ�
//   ����   aes    -- AES����ָ��
//          inbuf  -- ����ļ������ݻ�����ָ��
//          outbuf -- ����Ľ������ݻ�����ָ�룬������inbuf��ͬ
//          length -- ����ļ������ݳ��ȣ��ֽڣ�
int  AES_DataDecrypt(AES *aes, const unsigned char *inbuf, unsigned char *outbuf, int length);


#ifdef  __cplusplus
}
#endif

#endif//HEADER_AES_H
