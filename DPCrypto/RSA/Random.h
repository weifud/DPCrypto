
#ifndef HEADER_RANDOM_H
#define HEADER_RANDOM_H

#ifdef  __cplusplus
extern "C" {
#endif


// ���������������������
//   ����   
//   ����   
void RAND_seed(void);


// ����һ�������
//   ����   ���������Χ 0 -- 32767
//   ����   
int  RAND_number(void);


// ������ȫ���������䵽ָ��������
//   ����   <0 ʧ�ܣ� >=0 �ɹ����ĳ��ȣ��ֽڣ�
//   ����   buf -- ��Ҫ���Ļ�����ָ��
//          num -- ��Ҫ���Ļ��������ȣ��ֽڣ�
int  RAND_bytes(unsigned char *buf, int num);


// ����α���������䵽ָ��������
//   ����   <0 ʧ�ܣ� >=0 �ɹ����ĳ��ȣ��ֽڣ�
//   ����   buf -- ��Ҫ���Ļ�����ָ��
//          num -- ��Ҫ���Ļ��������ȣ��ֽڣ�
int  RAND_pseudo_bytes(unsigned char *buf, int num);


#ifdef  __cplusplus
}
#endif

#endif//HEADER_RANDOM_H
