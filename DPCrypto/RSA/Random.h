
#ifndef HEADER_RANDOM_H
#define HEADER_RANDOM_H

#ifdef  __cplusplus
extern "C" {
#endif


// 更新随机数生成器的种子
//   返回   
//   参数   
void RAND_seed(void);


// 生成一个随机数
//   返回   随机数，范围 0 -- 32767
//   参数   
int  RAND_number(void);


// 生成完全随机数并填充到指定缓冲区
//   返回   <0 失败； >=0 成功填充的长度（字节）
//   参数   buf -- 需要填充的缓冲区指针
//          num -- 需要填充的缓冲区长度（字节）
int  RAND_bytes(unsigned char *buf, int num);


// 生成伪随机数并填充到指定缓冲区
//   返回   <0 失败； >=0 成功填充的长度（字节）
//   参数   buf -- 需要填充的缓冲区指针
//          num -- 需要填充的缓冲区长度（字节）
int  RAND_pseudo_bytes(unsigned char *buf, int num);


#ifdef  __cplusplus
}
#endif

#endif//HEADER_RANDOM_H
