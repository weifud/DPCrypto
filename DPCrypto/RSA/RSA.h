
#ifndef HEADER_RSA_H
#define HEADER_RSA_H

#ifdef  __cplusplus
extern "C" {
#endif


#define RSAKEYBITS      1024                           // Ĭ��RSA��Կ���ȣ����أ�
#define RSAKEYBYTES     (RSAKEYBITS/8)                 // Ĭ��RSA��Կ���ȣ��ֽڣ�
#define RSASAVEKEYSIZE  (RSAKEYBYTES*5)                // Ĭ�ϱ���RSA��Կ��Ҫ�ĳ��ȣ��ֽڣ�
#define RSAMSGSIZE      (RSAKEYBYTES-11)               // Ĭ��RSA���ܵ������Ϣ���ȣ��ֽڣ�


typedef void RSA;



// ����RSA����
//   ע��   ��������ԿΪ�գ���Ҫ������Կ���������Կ�������ù�Կ
//   ����   RSA����ָ�룬���ΪNULL��������ʧ��
//   ����
RSA *RSA_New(void);


// �ͷ�RSA����
//   ����
//   ����   rsa -- RSA����ָ��
void RSA_Free(RSA *rsa);


// ������Կ
//   ����   <0 ʧ�ܣ� =0 �ɹ�
//   ����   rsa  -- RSA����ָ��
//          bits -- RSA��Կλ����������64��16384λ֮��
int  RSA_GenerateKey (RSA *rsa, const int bits);


// ������Կ
//   ����   <0 ʧ�ܣ� >=0 �ɹ��������Կʵ�ʳ��ȣ��ֽڣ�
//   ����   rsa    -- RSA����ָ��
//          length -- ����������Կ�Ļ��������ȣ��ֽڣ�
//          key    -- ����������Կ�Ļ�����ָ��
int  RSA_SaveKey(RSA *rsa, const int length, unsigned char *key);


// ������Կ
//   ����   <0 ʧ�ܣ� >=0 �ɹ���ȡ����Կʵ�ʳ��ȣ��ֽڣ�
//   ����   rsa    -- RSA����ָ��
//          length -- ��Կ���ȣ��ֽڣ�
//          key    -- �����ж�ȡ��Կ�Ļ�����ָ��
int  RSA_LoadKey(RSA *rsa, const int length, const unsigned char *key);


// ��ȡ��Կ
//   ����   <0 ʧ�ܣ� >=0 �ɹ�����Ĺ�Կʵ�ʳ��ȣ��ֽڣ�
//   ����   rsa    -- RSA����ָ��
//          length -- �������湫Կ�Ļ��������ȣ��ֽڣ�
//          key    -- �������湫Կ�Ļ�����ָ��
int  RSA_GetPublicKey(RSA *rsa, const int length, unsigned char *key);


// ���ù�Կ
//   ����   <0 ʧ�ܣ� =0 �ɹ�
//   ����   rsa    -- RSA����ָ��
//          length -- ��Կ���ȣ��ֽڣ�
//          key    -- �����ж�ȡ��Կ�Ļ�����ָ��
int  RSA_SetPublicKey(RSA *rsa, const int length, const unsigned char *key);


// ��Կ����
//   ע��   ԭʼ���ݳ��ȱ��뱣֤ <= RSAMSGSIZE
//          ���ܺ�����ݱ�ԭʼ���ݳ����������ļ������ݻ��������ȱ��뱣֤ >= RSAKEYBYTES
//   ����   <0 ʧ�ܣ� >=0 �ɹ�����ļ�������ʵ�ʳ��ȣ��ֽڣ�
//   ����   rsa    -- RSA����ָ��
//          inbuf  -- �����ԭʼ���ݻ�����ָ��
//          outbuf -- ����ļ������ݻ�����ָ�룬������inbuf��ͬ
//          length -- �����ԭʼ���ݳ��ȣ��ֽڣ�
int  RSA_PublicEncrypt(RSA *rsa, const unsigned char *inbuf, unsigned char *outbuf, int length);


// ��Կ����
//   ����   <0 ʧ�ܣ� >=0 �ɹ�����Ľ�������ʵ�ʳ��ȣ��ֽڣ�
//   ����   rsa    -- RSA����ָ��
//          inbuf  -- ����ļ������ݻ�����ָ��
//          outbuf -- ����Ľ������ݻ�����ָ�룬������inbuf��ͬ
//          length -- ����ļ������ݳ��ȣ��ֽڣ�
int  RSA_PublicDecrypt(RSA *rsa, const unsigned char *inbuf, unsigned char *outbuf, int length);


// ˽Կ����
//   ע��   ԭʼ���ݳ��ȱ��뱣֤ <= RSAMSGSIZE
//          ���ܺ�����ݱ�ԭʼ���ݳ����������ļ������ݻ��������ȱ��뱣֤ >= RSAKEYBYTES
//   ����   <0 ʧ�ܣ� >=0 �ɹ�����ļ�������ʵ�ʳ��ȣ��ֽڣ�
//   ����   rsa    -- RSA����ָ��
//          inbuf  -- �����ԭʼ���ݻ�����ָ��
//          outbuf -- ����ļ������ݻ�����ָ�룬������inbuf��ͬ
//          length -- �����ԭʼ���ݳ��ȣ��ֽڣ�
int  RSA_PrivateEncrypt(RSA *rsa, const unsigned char *inbuf, unsigned char *outbuf, int length);


// ˽Կ����
//   ����   <0 ʧ�ܣ� >=0 �ɹ�����Ľ�������ʵ�ʳ��ȣ��ֽڣ�
//   ����   rsa    -- RSA����ָ��
//          inbuf  -- ����ļ������ݻ�����ָ��
//          outbuf -- ����Ľ������ݻ�����ָ�룬������inbuf��ͬ
//          length -- ����ļ������ݳ��ȣ��ֽڣ�
int  RSA_PrivateDecrypt(RSA *rsa, const unsigned char *inbuf, unsigned char *outbuf, int length);


#ifdef  __cplusplus
}
#endif

#endif//HEADER_RSA_H
