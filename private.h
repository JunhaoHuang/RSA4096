/*
 * @Author: your name
 * @Date: 2021-10-12 18:47:44
 * @LastEditTime: 2021-10-15 09:55:16
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: \RSA\RSA4096\RSA_4096_origin_private\private.h
 */
//
// Created by tansh on 2018/9/22.
//

#include <stdint.h>
int private_enc_dec_test();
int private_decrypt(char base64[]);
int public_enc_dec_test(uint8_t input[256]);
int public_decrypt(char base64[]);
