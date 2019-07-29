//
//  JMController.h
//  jimidun
//
//  Created by 任雪强 on 17/4/6.
//  Copyright © 2017年 microdone. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreBluetooth/CoreBluetooth.h>
#import "JMPeripheral.h"



@class JMCentralManager;
@class JMPeripherModel;
@protocol JMControlDelegate <NSObject>

@optional

- (void)JMController:(JMCentralManager *)cbController didConnectedPeripheral:(CBPeripheral *)peripheral;
- (void)JMController:(JMCentralManager *)cbController didDisconnectedPeripheral:(CBPeripheral *)peripheral;
- (void)JMController:(JMCentralManager *)cbController didFindPeripheral:(JMPeripherModel*)peripheral;


@end


@interface JMCentralManager : NSObject

@property(nonatomic,strong) CBCentralManager *BLEManger;

@property(nonatomic,strong) JMPeripheral *Peripheral;

@property(assign) id<JMControlDelegate> delegate;

@property(nonatomic,strong) NSArray<JMPeripherModel*> *PeripModelArray;

@property(nonatomic,strong)JMPeripherModel*PeriphModel;

@property(nonatomic,strong)NSMutableArray*ignorePeriphArray;


+(instancetype)shareManger;

- (void)startScanPeripheralWithScanTime:(NSTimeInterval)time;

- (void)stopScanPeripher;

- (void)connectDidFindPeripheral:(CBPeripheral*)peripher;

- (void)disConnectdPeripheral;

- (void)connectPeripheralWithIdentifier:(NSUUID *)identifier;



- (void)jmperipherKeepAlwaysBright;
- (void)cancelAlwaysBright;
@end
