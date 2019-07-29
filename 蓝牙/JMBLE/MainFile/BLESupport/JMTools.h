//
//  JMTools.h
//  JMBLE
//
//  Created by 任雪强 on 17/4/11.
//  Copyright © 2017年 任雪强. All rights reserved.
//

#import <Foundation/Foundation.h>



@interface JMTools : NSObject

+ (NSData*)encryptedChannelWithPublicKey:(NSString*)publicKey sessionKey:(NSData*)sessionKey;


+ (NSString *)encryptedUsePublickeyWithData:(NSData *)sessionKey;



@end
