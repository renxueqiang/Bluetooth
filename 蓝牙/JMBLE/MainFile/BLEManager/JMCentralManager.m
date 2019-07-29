//
//  JMController.m
//  jimidun
//
//  Created by 任雪强 on 17/4/6.
//  Copyright © 2017年 microdone. All rights reserved.
//

#import "JMCentralManager.h"
#import "JMPeripherModel.h"

#define UUIDSTR_ISSC_PROPRIETARY_SERVICE        @"00003900-842F-544F-5348-494241000003"
#define UUIDSTR_ISSBJ        @"49535343-FE7D-4AE5-8FA9-9FAFD205E455"

/** 读的特征    */
#define UUIDSTR_ISSC_TRANS_TX    @"0303"

/** 写的特征    */
#define UUIDSTR_ISSC_TRANS_RX    @"0103"
 #define UUIDSTR_TRANS    @"49535343-1E4D-4BD9-BA61-23C647249616"

@interface JMCentralManager ()<CBCentralManagerDelegate,CBPeripheralDelegate>






@property(nonatomic,strong) NSMutableArray *findPeripheralArray;
@property(nonatomic,strong) NSMutableArray *findPeripheralRssi;

@property(nonatomic,strong) CBCharacteristic *writeCharcter;
@property(nonatomic,strong) CBCharacteristic *readCharcter;
@property(nonatomic,strong) CBCharacteristic *notifyCharcter;

@property(nonatomic,strong) CBPeripheral *BLEPeripheral;

@end

@implementation JMCentralManager


+(instancetype)shareManger{
    
    static JMCentralManager *CbcontrolManger = nil;
    static dispatch_once_t predicate;
    dispatch_once(&predicate, ^{
        CbcontrolManger = [[self alloc] init];
    });
    return CbcontrolManger;
}


- (instancetype)init {
    
    if ( self = [super init]) {
        
        NSDictionary *dict = @{CBCentralManagerOptionShowPowerAlertKey:@NO};
        
        _BLEManger = [[CBCentralManager alloc] initWithDelegate:self queue:dispatch_get_main_queue() options:dict];
       
        _Peripheral = [[JMPeripheral alloc] init];
        
        
    }
    return self;
    
}


- (void)centralManagerDidUpdateState:(CBCentralManager *)central{
    
    switch (central.state) {
            
        case CBCentralManagerStatePoweredOn:{
            
           
            
            
            
        }
            
            
            break;
            
        default:
            break;
    }
    
}



- (void)startScanPeripheralWithScanTime:(NSTimeInterval)time {
    
    NSTimeInterval scanTime =  time > 2.0 ? time:2.0;

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        
        
        self.findPeripheralArray = nil;
        self.findPeripheralRssi = nil;
        
        NSDictionary *dict = @{CBCentralManagerScanOptionAllowDuplicatesKey:@NO};
        
        [_BLEManger scanForPeripheralsWithServices:nil options:dict];
        
        [self performSelector:@selector(findPeripheralFunction) withObject:nil
                   afterDelay:scanTime];


        
    });
    
    
}

- (void)stopScanPeripher {

     [_BLEManger stopScan];
}


- (void)findPeripheralFunction{
    
    
    [_BLEManger stopScan];
    
    JMPeripherModel *perModel;
    
    if (self.findPeripheralRssi.count) {
        
        NSNumber *number = [self.findPeripheralRssi valueForKeyPath:@"@max.intValue"];
        
        NSUInteger index = [self.findPeripheralRssi indexOfObject:number];
        
        NSMutableDictionary *muDic = [self.findPeripheralArray objectAtIndex:index];
        
         perModel = [JMPeripherModel questionWithDict:muDic];
  
    }else{
    
         perModel = nil;
    
    }
    
   

    if ([self.delegate respondsToSelector:@selector(JMController:didFindPeripheral:)]) {
        
        [self.delegate JMController:self didFindPeripheral:perModel];
         
         
         }
    
    
    
    
    
}


- (void)connectDidFindPeripheral:(CBPeripheral*)peripher {
    

    NSLog(@"%@",peripher);
    
    _BLEPeripheral = peripher;
    
     [_BLEManger connectPeripheral:_BLEPeripheral options:nil];
}





- (void)centralManager:(CBCentralManager *)central didDiscoverPeripheral:(CBPeripheral *)peripheral advertisementData:(NSDictionary<NSString *,id> *)advertisementData RSSI:(NSNumber *)RSSI{
    
    
    
    
     if([peripheral.name containsString:@"BLE"]||[peripheral.name containsString:@"LG"]){
         
         
         NSLog(@"名字:%@状态:%ld标识:%@字典:%@状态:%@",peripheral.name,(long)peripheral.state,peripheral.identifier.UUIDString,advertisementData,RSSI);
         
         
         
         NSMutableDictionary *mutDict = [NSMutableDictionary dictionary];
         mutDict[@"name"] = peripheral.name;
         mutDict[@"identify"] = peripheral.identifier.UUIDString;
         mutDict[@"RSSI"] = RSSI;
         
         
         if([peripheral.name containsString:@"K2"]||[peripheral.name containsString:@"3040"]){
             
              mutDict[@"devType"] = @"JMK2";
             
         }else if([peripheral.name containsString:@"LGBLE"]){
             
              mutDict[@"devType"] = @"JMLG";

         } else {
             
              mutDict[@"devType"] = @"JMBLE";

         }

        
         NSPredicate *predicate = [NSPredicate predicateWithFormat:@"SELF CONTAINS %@", peripheral.identifier.UUIDString];
         
         NSArray *array = [self.findPeripheralArray filteredArrayUsingPredicate:predicate];
         
         if (!array.count) {
             
             [self.findPeripheralArray addObject:mutDict];
             
             [self.findPeripheralRssi addObject:RSSI];
         }
         


    }
    
}

- (NSArray *)PeripModelArray {


    if (!_PeripModelArray) {
        
        NSMutableArray *arrayM = [NSMutableArray array];
        
        for (NSDictionary *dict in self.findPeripheralArray) {
            
            [arrayM addObject:[JMPeripherModel questionWithDict:dict]];
            

            
        }
        
        return arrayM;
    }

    return _PeripModelArray;
}




- (void)centralManager:(CBCentralManager *)central didConnectPeripheral:(CBPeripheral *)peripheral {
    
    NSLog(@"******已连接******");
//    [JMDTools sharedConnetionTool].ManualConnect = NO;
     peripheral.delegate = self;
    _Peripheral.BLEPeripheral = peripheral;
    
    NSMutableArray *uuids;
    if([peripheral.name containsString:@"K2"]||[peripheral.name containsString:@"3040"]){
        
        uuids = [[NSMutableArray alloc] initWithObjects: [CBUUID UUIDWithString:UUIDSTR_ISSC_PROPRIETARY_SERVICE], nil];
                
        self.Peripheral.devType = DevTypeK2;
        
    }else if([peripheral.name containsString:@"LGBLE"]){
        
        uuids = [[NSMutableArray alloc] initWithObjects: [CBUUID UUIDWithString:UUIDSTR_ISSC_PROPRIETARY_SERVICE], nil];
        

        self.Peripheral.devType = DevTypeLGBLE;
        
    } else {
        
        
        uuids = [[NSMutableArray alloc] initWithObjects: [CBUUID UUIDWithString:UUIDSTR_ISSBJ], nil];
        
        self.Peripheral.devType = DevTypeBLE;

       
        
    }
    
    [peripheral discoverServices:uuids];
    
    
}

- (void)peripheral:(CBPeripheral *)peripheral didDiscoverServices:(NSError *)error {
    
    
    
    [peripheral discoverCharacteristics:nil forService:peripheral.services[0]];
    
    
}


- (void)peripheral:(CBPeripheral *)peripheral didDiscoverCharacteristicsForService:(CBService *)service error:(NSError *)error {
    
       
    CBCharacteristic *character = nil;
    
    if ([service.UUID isEqual:[CBUUID UUIDWithString:UUIDSTR_ISSC_PROPRIETARY_SERVICE]] ) {
        
        for (character in service.characteristics) {
            
            if ([character.UUID isEqual:[CBUUID UUIDWithString:UUIDSTR_ISSC_TRANS_RX]]) {
                

                _writeCharcter = character;
                _Peripheral.writeCharcter = character;
                
            } else if ([character.UUID isEqual:[CBUUID UUIDWithString:UUIDSTR_ISSC_TRANS_TX]]) {
                
                
                _notifyCharcter = character;
                
                [peripheral setNotifyValue:YES forCharacteristic:character];
                
            }
        }
        
    } else {
        
   
        for (character in service.characteristics) {
            
            if ([character.UUID isEqual:[CBUUID UUIDWithString:@"49535343-8841-43F4-A8D4-ECBE34729BB3"]]) {
                

                _writeCharcter = character;
                _Peripheral.writeCharcter = character;
            } else if ([character.UUID isEqual:[CBUUID UUIDWithString:UUIDSTR_TRANS]]) {
                
                

                _notifyCharcter = character;
                [peripheral setNotifyValue:YES forCharacteristic:character];
                
            }
        }
        
        
    }
    
    NSLog(@"我是蓝牙代理对象:%@",self.delegate);
    if ([self.delegate respondsToSelector:@selector(JMController:didConnectedPeripheral:)]) {
        
        [self.delegate JMController:self didConnectedPeripheral:_BLEPeripheral];
        
        
    }
    
    
    
}








- (void)peripheral:(CBPeripheral *)peripheral didUpdateValueForCharacteristic:(CBCharacteristic *)characteristic error:(NSError *)error {


    
    NSLog(@"系统回调数据--->%@",characteristic.value);
    
    if ([characteristic.UUID isEqual:[CBUUID UUIDWithString:UUIDSTR_ISSC_TRANS_TX]] || [characteristic.UUID isEqual:[CBUUID UUIDWithString:UUIDSTR_TRANS]]) {
        
        
        if ([_Peripheral.delegate respondsToSelector:@selector(JMPeripheral:didReceiveTransparentData:)]) {
            
            [_Peripheral.delegate JMPeripheral:peripheral didReceiveTransparentData:characteristic.value];
        }
        
        
        
    }
    
    



}







- (void)centralManager:(CBCentralManager *)central didFailToConnectPeripheral:(CBPeripheral *)peripheral error:(NSError *)error {
    
    
    NSLog(@"我连接失败了:%@",[error localizedDescription]);
    
}



- (void)centralManager:(CBCentralManager *)central didDisconnectPeripheral:(CBPeripheral *)peripheral error:(NSError *)error {
    


    NSLog(@"我断开连接:%@",[error localizedDescription]);
    
}




- (void)connectPeripheralWithIdentifier:(NSUUID *)identifier {
    
  
    
    NSArray *array = [_BLEManger retrievePeripheralsWithIdentifiers:@[identifier]];
    
    _BLEPeripheral = array[0];
    
    [_BLEManger connectPeripheral:_BLEPeripheral options:nil];

}


- (void)disConnectdPeripheral {
    
    [self.Peripheral JMBLEDisconnectTheDevice];
    
}



- (NSMutableArray *)findPeripheralArray {
    
    if (!_findPeripheralArray) {
        _findPeripheralArray = [NSMutableArray array];
    }
    
    return _findPeripheralArray;
}

- (NSMutableArray *)findPeripheralRssi {
    
    if (!_findPeripheralRssi) {
        _findPeripheralRssi = [NSMutableArray array];
    }
    
    return _findPeripheralRssi;
    
}

@end
