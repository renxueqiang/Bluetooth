//
//  JMPeripherModel.h
//  JMBLE
//
//  Created by 任雪强 on 17/4/10.
//  Copyright © 2017年 任雪强. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface JMPeripherModel : NSObject
@property (nonatomic,copy) NSString *name;
@property (nonatomic,copy) NSString *identify;
@property (nonatomic,strong) NSNumber *RSSI;
@property(nonatomic,copy) NSString *devType;
@property(nonatomic,copy) NSString *connectStated;

+ (instancetype)questionWithDict:(NSDictionary *)dict;
@end
