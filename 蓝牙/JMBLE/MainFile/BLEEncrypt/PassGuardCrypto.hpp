//
//  PassGuardCrypto.h
//  PassGuardCrypto
//
//  Created by microdone on 16/6/16.
//  Copyright © 2016年 com.microdone.security. All rights reserved.
//
#import <Foundation/Foundation.h>

#pragma once
#include <string>
using namespace std;

namespace mdhjhx {
    
     
    /**
     *  获取SM2密文
     *  arg1p 密文
     *  arg2r 32位随机数
     *  arg3x x公钥
     *  arg4y y公钥
     *  @return SM2密文
     */
    string MicrodoneGMSM2Enc(NSData * arg1p,const char * arg2r,const char * arg3x,const char * arg4y);
    
    
    
    
}
