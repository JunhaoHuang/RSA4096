/*
 * @Author: your name
 * @Date: 2021-10-12 18:47:44
 * @LastEditTime: 2021-10-12 20:01:54
 * @LastEditors: your name
 * @Description: In User Settings Edit
 * @FilePath: \RSA\RSA4096\RSA_4096_origin_private\public.h
 */
//
// Created by tansh on 2018/9/22.
//
#include <stdint.h>
int public_encrypt(uint8_t input[256]);
int public_decrypt(char base64[]);