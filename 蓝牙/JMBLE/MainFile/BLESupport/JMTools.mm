//
//  JMTools.m
//  JMBLE
//
//  Created by 任雪强 on 17/4/11.
//  Copyright © 2017年 任雪强. All rights reserved.
//

#import "JMTools.h"
#import "PassGuardCrypto.hpp"


@implementation JMTools



+ (NSData *)encryptedChannelWithPublicKey:(NSString *)publicKey sessionKey:(NSData *)sessionKey {
    
    
    
       NSString *string1 = [publicKey substringWithRange:NSMakeRange(8, 64)];
       NSString *string2 = [publicKey substringWithRange:NSMakeRange(72, 64)];
    

       string ret = mdhjhx::MicrodoneGMSM2Enc(sessionKey, "",string1.UTF8String, string2.UTF8String);
        
        
        NSString *retString = [NSString stringWithFormat:@"%s",ret.c_str()];
        
        
        NSData *decData = [[NSData alloc] initWithBase64EncodedString:retString options:0];
    
    return decData;
}


+ (NSString *)encryptedUsePublickeyWithData:(NSData *)sessionKey {
    

      
    NSString* string1	=@"A1D78BDE9E8A9477ADB9A329FB74E3919788319A974EFDE05D725C634DED8B79";
    NSString* string2 = @"918396E2C92E84A9870218BA8E25299EE8502B6893138C90731A08A2D1326ACD";

    
    string ret = mdhjhx::MicrodoneGMSM2Enc(sessionKey, "",string1.UTF8String, string2.UTF8String);
    

       return [NSString stringWithFormat:@"%s",ret.c_str()];
}











@end
