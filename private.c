/*
 * @Author: your name
 * @Date: 2021-10-12 18:47:44
 * @LastEditTime: 2021-10-15 12:11:57
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: \RSA\RSA4096\RSA_4096_origin_private\private.c
 */
//
// Created by tansh on 2018/9/22.
//
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "private.h"
#include "rsa.h"
#include "keys.h"
#include "base64.h"
const int count=100;
int private_enc_dec_test()
{
	uint8_t input[512*16];
    rsa_pk_t pk = {0};
    rsa_sk_t sk = {0};
    uint8_t  output[512*16];
	unsigned char msg [512*16];
    uint32_t msg_len;
    uint32_t outputLen;
    int32_t inputLen;

    printf("RSA encryption decryption test is beginning!\n");
    printf("\n");
    pk.bits = KEY_M_BITS;
    memcpy(&pk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m)],  key_m,  sizeof(key_m));
    memcpy(&pk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_e)],  key_e,  sizeof(key_e));
    sk.bits = KEY_M_BITS;
    memcpy(&sk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m)],  key_m,  sizeof(key_m));
    memcpy(&sk.public_exponet  [RSA_MAX_MODULUS_LEN-sizeof(key_e)],  key_e,  sizeof(key_e));
    memcpy(&sk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_pe)], key_pe, sizeof(key_pe));
    memcpy(&sk.prime1          [RSA_MAX_PRIME_LEN-sizeof(key_p1)],   key_p1, sizeof(key_p1));
    memcpy(&sk.prime2          [RSA_MAX_PRIME_LEN-sizeof(key_p2)],   key_p2, sizeof(key_p2));
    memcpy(&sk.prime_exponent1 [RSA_MAX_PRIME_LEN-sizeof(key_e1)],   key_e1, sizeof(key_e1));
    memcpy(&sk.prime_exponent2 [RSA_MAX_PRIME_LEN-sizeof(key_e2)],   key_e2, sizeof(key_e2));
    memcpy(&sk.coefficient     [RSA_MAX_PRIME_LEN-sizeof(key_c)],    key_c,  sizeof(key_c));

	generate_rand(input,512*16-1);
	inputLen = strlen((const char*)input);
    // print_array("Input_message", input, inputLen);
    // printf("\n");

    // private key encrypt
	clock_t start,end;
	double sum=0,sum1=0;
	int status=0;
	for(int i=0;i<count;i++)
	{
		start=clock();
		status=rsa_public_encrypt_any_len(output, &outputLen, input, inputLen, &pk);
		// rsa_private_encrypt(output, &outputLen, input, inputLen, &sk);
		end=clock();
		if(status!=0){
			printf("rsa_public_encrypt_any_len Error Code:%x\n",status);
			break;
		}
		
		sum+=(double)(end-start)/CLOCKS_PER_SEC;
		start=clock();
		status=rsa_private_decrypt_any_len(msg, &msg_len, output, outputLen, &sk);
		end=clock();
		if(status!=0){
			printf("rsa_private_decrypt_any_len Error Code:%x\n",status);
			break;
		}
		// if(memcmp(input,msg,sizeof(input))!=0){
		// 	printf("rsa_public_encrypt_any_len and rsa_private_decrypt_any_len Error\n");
		// 	print_array("input:",input,inputLen);
		// 	print_array("decrypt:",msg,msg_len);
		// 	return 1;
		// }
		sum1+=(double)(end-start)/CLOCKS_PER_SEC;
	}
	printf("rsa_public_encrypt Average time(s): %lf; rsa_private_decrypt Average time(s): %lf\n",sum/count,sum1/count);

	sum=0,sum1=0;
	for(int i=0;i<count;i++)
	{
		start=clock();
		status=rsa_private_encrypt_any_len(output, &outputLen, input, inputLen, &pk);
		// rsa_private_encrypt(output, &outputLen, input, inputLen, &sk);
		end=clock();
		if(status!=0){
			printf("rsa_private_encrypt_any_len Error Code:%x",status);
			break;
		}
		
		sum+=(double)(end-start)/CLOCKS_PER_SEC;
		start=clock();
		status=rsa_public_decrypt_any_len(msg, &msg_len, output, outputLen, &sk);
		end=clock();
		if(status!=0){
			printf("rsa_public_decrypt_any_len Error Code:%x",status);
			break;
		}
		// if(memcmp(input,msg,sizeof(input))!=0){
		// 	printf("rsa_public_encrypt_any_len and rsa_private_decrypt_any_len Error\n");
		// 	return 1;
		// }
		// end=clock();
		sum1+=(double)(end-start)/CLOCKS_PER_SEC;
	}
	printf("rsa_private_encrypt Average time(s): %lf; rsa_public_decrypt Average time(s): %lf\n",sum/count,sum1/count);
    
    // print_array("Private_key_encrypt", output, outputLen);

    // base64 encode
    unsigned char buffer[1024];
    for(int i = 0; i<outputLen; i++) {
        sprintf(buffer+2*i, "%02X", (unsigned char) output[i]);
    }
    const unsigned char *sourcedata = buffer ;
    char base64[2048];
    base64_encode(sourcedata, base64);// encode
    // printf("ENC: %s\n",base64);
    // printf("\n");

    return 0;
}

int private_decrypt(char base64[])
{
    rsa_pk_t pk = {0};
    rsa_sk_t sk = {0};
    unsigned char msg [512];
    uint32_t msg_len;

    pk.bits = KEY_M_BITS;
    memcpy(&pk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m)],  key_m,  sizeof(key_m));
    memcpy(&pk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_e)],  key_e,  sizeof(key_e));
    sk.bits = KEY_M_BITS;
    memcpy(&sk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m)],  key_m,  sizeof(key_m));
    memcpy(&sk.public_exponet  [RSA_MAX_MODULUS_LEN-sizeof(key_e)],  key_e,  sizeof(key_e));
    memcpy(&sk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_pe)], key_pe, sizeof(key_pe));
    memcpy(&sk.prime1          [RSA_MAX_PRIME_LEN-sizeof(key_p1)],   key_p1, sizeof(key_p1));
    memcpy(&sk.prime2          [RSA_MAX_PRIME_LEN-sizeof(key_p2)],   key_p2, sizeof(key_p2));
    memcpy(&sk.prime_exponent1 [RSA_MAX_PRIME_LEN-sizeof(key_e1)],   key_e1, sizeof(key_e1));
    memcpy(&sk.prime_exponent2 [RSA_MAX_PRIME_LEN-sizeof(key_e2)],   key_e2, sizeof(key_e2));
    memcpy(&sk.coefficient     [RSA_MAX_PRIME_LEN-sizeof(key_c)],    key_c,  sizeof(key_c));

    // public key decrypt
    // base64 decode
    char dedata[2048];
    base64_decode(base64, (unsigned char*)dedata);// decode
    printf("DEC: %s", dedata);
    printf("\n");

    uint8_t str1[512];
    str_hex(dedata,str1);
	
	clock_t start,end;
	double sum=0;
	for(int i=0;i<count;i++)
	{
		start=clock();
		rsa_private_decrypt(msg, &msg_len, str1, sizeof(str1), &sk);
		end=clock();
		sum+=(double)(end-start)/CLOCKS_PER_SEC;
	}
	printf("rsa_private_decrypt Average time(s): %lf\n",sum/count);

    
    print_array("Private_key_decrypt", msg, msg_len);

    return 0;
}

int public_encrypt(uint8_t input[256])
{

    rsa_pk_t pk = {0};
    uint8_t  output[512];
    uint32_t outputLen;
    uint8_t  inputLen;

    pk.bits = KEY_M_BITS;
    memcpy(&pk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m)],  key_m,  sizeof(key_m));
    memcpy(&pk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_e)],  key_e,  sizeof(key_e));

    inputLen = strlen((const char *)input);
    print_array("Input_message", input, inputLen);
    printf("\n");

    // public key encrypt
	clock_t start=0,end=0;
	double sum=0;
	for(int i=0;i<count;i++)
	{
		start=clock();
		rsa_public_encrypt(output, &outputLen, input, inputLen, &pk);
		end=clock();
		sum+=(double)(end-start)/CLOCKS_PER_SEC;
	}
	printf("rsa_public_encrypt Average time(s): %lf\n",sum/count);

    
    print_array("Public_key_encrypt", output, outputLen);
    printf("\n");

    // base64 encode
    unsigned char buffer[1024];
    for(int i = 0; i<outputLen; i++) {
        sprintf(buffer+2*i, "%02X", (unsigned char) output[i]);
    }
    const unsigned char *sourcedata = buffer ;
    char base64[2048];
    base64_encode(sourcedata, base64);// encode
    printf("ENC: %s\n",base64);
    printf("\n");

    return 0;
}

int public_decrypt(char base64[])
{
    rsa_pk_t pk = {0};
    unsigned char msg [512];
    uint32_t msg_len;

    pk.bits = KEY_M_BITS;
    memcpy(&pk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m)],  key_m,  sizeof(key_m));
    memcpy(&pk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_e)],  key_e,  sizeof(key_e));

    // public key decrypt

    // base64 decode
    char dedata[2048];
    base64_decode(base64, (unsigned char*)dedata);// decode
    printf("DEC: %s", dedata);
    printf("\n");

    uint8_t str1[512];
    str_hex(dedata,str1);

    // public key decrypt
	clock_t start,end;
	double sum=0;
	for(int i=0;i<count;i++)
	{
		start=clock();
		rsa_public_decrypt(msg, &msg_len, str1, sizeof(str1), &pk);
		end=clock();
		sum+=(double)(end-start)/CLOCKS_PER_SEC;
	}
	printf("rsa_public_encrypt Average time(s): %lf\n",sum/count);

    
    print_array("Public_key_decrypt", msg, msg_len);

    return 0;
}



