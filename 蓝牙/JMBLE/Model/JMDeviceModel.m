//
//  JMDeviceModel.m
//  JMBLE
//
//  Created by 任雪强 on 17/4/13.
//  Copyright © 2017年 任雪强. All rights reserved.
//

#import "JMDeviceModel.h"

@implementation JMDeviceModel





- (instancetype)initWithDict:(NSDictionary *)dict {
    
    if (self = [super init]) {
        
       
        [self setValuesForKeysWithDictionary:dict];
    }
    
    return self;
    
    
}
@end
