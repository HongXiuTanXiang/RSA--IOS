//
//  ViewController.m
//  rsa
//
//  Created by lihe on 17/4/29.
//  Copyright © 2017年 lihe. All rights reserved.
//

#import "ViewController.h"
#import "YSRSACryption.h"

@interface ViewController ()

@property (nonatomic, strong) YSRSACryption *rsa;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    _rsa = [YSRSACryption new];
}

-(void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event{
    
    // 加载公钥
    NSString *derPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"public_key" ofType:@"der"];
    [_rsa loadPublicKeyFromFile:derPath];
    
    // 加载私钥
    NSString *p12Path = [[NSBundle bundleForClass:[self class]] pathForResource:@"private_key" ofType:@"p12"];
    [_rsa loadPrivateKeyFromFile:p12Path password:@"123"];
    
    NSString *enStr = @"需要加密的数据写在这里,必须是字符串格式！";
    
    // 加密后的数据
    NSData *enData = [_rsa rsaEncryptData:
                      [enStr dataUsingEncoding:NSUTF8StringEncoding]];
    
    // 解密后的数据
    NSData *deData = [_rsa rsaDecryptData:enData];
    NSString *deStr = [[NSString alloc] initWithData:deData encoding:NSUTF8StringEncoding];
    
    NSLog(@"%@",deStr);
    
    // 签名
    NSData *signedData = [_rsa sha256WithRSA:enData];
    
    // 对前面进行验证
    BOOL result = [_rsa rsaSHA256VertifyingData:enData withSignature:signedData];
    

}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
