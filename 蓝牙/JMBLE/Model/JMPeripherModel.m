//
//  JMPeripherModel.m
//  JMBLE
//
//  Created by 任雪强 on 17/4/10.
//  Copyright © 2017年 任雪强. All rights reserved.
//

#import "JMPeripherModel.h"

@implementation JMPeripherModel

+ (instancetype)questionWithDict:(NSDictionary *)dict {
    
    
    return [[self alloc] initWithDict:dict];
    
}

- (instancetype)initWithDict:(NSDictionary *)dict {
    
    if (self = [super init]) {
        
        
        [self setValuesForKeysWithDictionary:dict];
    }
    
    return self;
    
    
}

@end
