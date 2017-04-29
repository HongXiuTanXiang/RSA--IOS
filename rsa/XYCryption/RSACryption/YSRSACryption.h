//
//  YSRSACryption.h
//  rsa
//
//  Created by lihe on 17/4/29.
//  Copyright © 2017年 lihe. All rights reserved.
//

#import <Foundation/Foundation.h>



@interface YSRSACryption : NSObject

/**
 从.der文件中加载公钥
 
 @param derFilePath 文件路径
 */
- (void)loadPublicKeyFromFile:(NSString*)derFilePath;


/**
 从NSData中加载公钥
 
 @param derData NSData数据类型的公钥
 */
- (void)loadPublicKeyFromData:(NSData*)derData;

/**
 从.p12文件中加载私钥
 
 @param p12FilePath 文件路径
 @param p12Password 文件密码
 */
- (void)loadPrivateKeyFromFile:(NSString*)p12FilePath password:(NSString*)p12Password;

/**
 从NSData中加载私钥
 
 @param p12Data 文件路径
 @param p12Password 文件密码
 */
- (void)loadPrivateKeyFromData:(NSData*)p12Data password:(NSString*)p12Password;

/**
 返回公钥
 
 @param derData NSData数据类型的公钥
 @return 不对称公钥
 */
- (SecKeyRef)getPublicKeyRefrenceFromeData:(NSData*)derData;

/**
 *  Return 不对称私钥
 *
 *  @param p12Data  The data for private key
 *  @param password The password for private key
 *
 *  @return A SecKeyRef
 */
- (SecKeyRef)getPrivateKeyRefrenceFromData:(NSData*)p12Data password:(NSString*)password;

/**
 使用rsa加密字符串
 
 @param string 需要加密的字符串
 @return 返回的是base64的加密后的字符串
 */
- (NSString*)rsaEncryptString:(NSString*)string;

/**
 使用rsa加密NSData
 
 @param data 需要加密的data
 @return 返回的是加密后的data
 */
- (NSData*)rsaEncryptData:(NSData*)data;

/**
 解密一个RSA加密后的字符串
 
 @param string 经过RSA加密的字符串
 @return 解密后的字符串
 */
- (NSString*)rsaDecryptString:(NSString*)string;

/**
 解密一个rsa加密的data
 
 @param data 经过rsa加密后的data
 @return 解密后的data
 */
- (NSData*)rsaDecryptData:(NSData*)data;

/**
 签名成sha256,
 
 @param plainData 经过rsa加密之后的data
 @return 签名之后的data
 */
- (NSData *)sha256WithRSA:(NSData *)plainData;

/**
 签名成sha256,
 
 @param plainData 经过rsa加密之后的data
 @param privateKey 私钥
 @return 签名之后的data
 */
- (NSData *)sha256WithRSA:(NSData *)plainData privateKey:(SecKeyRef)privateKey;

/**
 *  验证sha256签名
 *
 *  @param plainData The data for vertify
 *  @param signature The data of signed
 *
 *  @return Success of sha vertifying
 */
- (BOOL)rsaSHA256VertifyingData:(NSData *)plainData withSignature:(NSData *)signature;

/**
 *  验证sha256签名
 *
 *  @param plainData The data for vertify
 *  @param signature The data of signed
 *  @param publicKey The public key for vertification
 *
 *  @return Success of sha vertifying
 */
- (BOOL)rsaSHA256VertifyingData:(NSData *)plainData withSignature:(NSData *)signature publicKey:(SecKeyRef)publicKey;

@end

