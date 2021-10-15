/*
 * @Author: your name
 * @Date: 2021-10-12 18:47:44
 * @LastEditTime: 2021-10-12 20:01:19
 * @LastEditors: your name
 * @Description: In User Settings Edit
 * @FilePath: \RSA\RSA4096\RSA_4096_origin_private\base64.h
 */
//
// Created by tansh on 2018/9/22.
//

#ifndef RSA_2048_BASE64_H
#define RSA_2048_BASE64_H

unsigned int str_hex(unsigned char *str,unsigned char *hex) ;
int base64_encode(const unsigned char * sourcedata, char * base64);
int base64_decode(const char * base64, unsigned char * dedata);
void print_array(char *TAG, uint8_t *array, int len);
#endif //RSA_2048_BASE64_H
