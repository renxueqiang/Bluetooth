//
//  ViewController.m
//  JMBLE
//
//  Created by 任雪强 on 17/4/10.
//  Copyright © 2017年 任雪强. All rights reserved.
//

#import "BaseController.h"
#import "JMPeripherModel.h"
#import "JMSecurityBModle.h"
@interface BaseController ()<UITableViewDataSource,UITableViewDelegate,JMControlDelegate,JMPeripheralDelegate>

@property (nonatomic,strong) UITableView *tableView;

@property (nonatomic,strong) NSData *data;
@property (nonatomic,strong) UILabel *label;
@property (nonatomic,strong) UITextView *logTextView;





@end

@implementation BaseController


- (void)viewDidLoad {
    [super viewDidLoad];
    
    _Cbcontrol = [JMCentralManager shareManger];
    [_Cbcontrol startScanPeripheralWithScanTime:3.0];
    _Cbcontrol.delegate = self;

    [self addTheTableview];
    
  
    
}




-(NSMutableData *)DataWithString:(NSString *)name {
    
    NSMutableData *mutData = [NSMutableData data];
    [ mutData appendBytes:name.UTF8String length:name.length];
    
   
    return mutData;
    
}


- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {


    
//
//    JMPeripherModel * _peripherModel = self.Cbcontrol.PeripModelArray[indexPath.row];
//
//    NSArray *array = [self.Cbcontrol.BLEManger retrievePeripheralsWithIdentifiers:@[[[NSUUID alloc] initWithUUIDString:_peripherModel.identify]]];
//
//    CBPeripheral *peripher = array[0];

        
        JMPeripherModel *model = _Cbcontrol.PeripModelArray[indexPath.row];
        
        [_Cbcontrol connectPeripheralWithIdentifier:[[NSUUID alloc] initWithUUIDString:model.identify]];
        
        [self.view addSubview:_logTextView];
    
}


#pragma mark - 中心代理方法
- (void)JMController:(JMCentralManager *)cbController didFindPeripheral:(NSArray<JMPeripherModel *> *)peripheralArr {
    
    [_tableView reloadData];
    
}

- (void)JMController:(JMCentralManager *)cbController didConnectedPeripheral:(CBPeripheral *)peripheral {
    
  
    [self.BLETools RequestDeviceSerialNumWithResult:^(NSString *serialNoS) {
    
    NSLog(@"我是序列号:%@",serialNoS);
}];
    
    
}
- (IBAction)btn001:(UIBarButtonItem *)sender {
    
    
    [_Cbcontrol disConnectdPeripheral];
    
}


#pragma mark - 全部
- (IBAction)all:(UIButton *)sender {
    
    
    [self.BLETools RequestDeviceStatedWithResult:^(unsigned int SW1, unsigned int SW2) {
        
        
        [self.BLETools RequestDeviceInformationWithResult:^(JMDeviceModel *devInfomation) {
            
            NSLog(@"我是子设备信息:%@",devInfomation);
            NSString *pass = @"123456";
            
            //获取公钥
            [self.BLETools RequestDevPublicKeyWithResult:^(NSString *publicString) {
                
                NSLog(@"啊我是公钥啊:%@",publicString);
                
                NSString *bToken_base64 = @"AAAAANBkNBTFA0aTrn51tFIXGpQxMDExMTAwMDAwNDI0NTIw3a897A==";
                
                
                /**
                 
                 <00000000 28068a9b 3f4f44f0 9a8454c4 e5f5c796 31303131 31303030 30303030 38303430 4924a115>
                 
                 */
                
                
                char *data = "00000000 28068a9b 3f4f44f0 9a8454c4 e5f5c796 31303131 31303030 30303030 38303430 4924a115";
                
               NSData *bToken_Data = [[NSData alloc] initWithBytes:data length:40];
                
                
          
                [self.BLETools RequestSecurityChanelWithBToken:(LPBYTE)bToken_Data.bytes bTokenLength:(DWORD)bToken_Data.length withAToken:NULL ATokenLength:0 WithResult:^(NSData *sessionKey) {
                    NSLog(@"我是联机通道:%@",sessionKey);
                    
                    NSData *data = [JMTools encryptedChannelWithPublicKey:publicString sessionKey:sessionKey];
                    
                    
                    
                    //下发联机会话密钥
                    [self.BLETools RequestSetSessionKey:data WithResult:^{
                        
                        NSLog(@"下发联机会话密钥");
                        
                        
                        
                        [self.BLETools RequestRandomNumberWithResult:^(NSData *random) {
                            
                            NSLog(@"我是16位随机数:%@",random);
                            
                            
                            //验证设备PIN
                            [self.BLETools requestmodifyPIN_EM:1 WithResult:^{
                                
                                NSLog(@"验证设备PIN");
                                
                                
                                [self.BLETools RequestVerificationPIN:pass WithResult:^{
                                    NSLog(@"验证设备success");
                                    
                                    
                                    [self.BLETools RequestVerifyPINWithType:1 RandomNum:random withPin:pass WithToken:bToken_Data WithResult:^(NSData *aTokan) {
                                        
                                        NSLog(@"aTokan申请成功:%@",aTokan);
                                        
                                        
                                        
                                        
                                    } passworderrorBlock:^(int number) {
                                        NSLog(@"aTokanPIN");
                                    } errorBlock:^(ErrorCode code) {
                                        NSLog(@"aTokanError");
                                    }];
                                } passworderrorBlock:^(int number) {
                                    NSLog(@"验证设备number%d",number);
                                    
                                }];
                                
                                
                                
                            } exclusiveModeTimeOut:^{
                                
                            } operationCancel:^{
                                
                            } errorBlock:^(ErrorCode code) {
                                
                            }];
                            
                        } errorBlock:^(ErrorCode code) {
                            
                            
                        }];

                        
                        
                        
                        
                        
                    } errorBlock:^(ErrorCode code) {
                        
                        
                    }];
                    
                    
                    
                } errorBlock:^(ErrorCode code) {
                    
                    
                }];
                
            } errorBlock:^(ErrorCode code) {
                
                
            }];

            
            
            
            
            
            
            
            
        }];
        
        
    }];
    
    
    
}

#pragma mark - 设备状态
- (IBAction)btn1:(UIButton *)sender {
    
    
    
[self.BLETools RequestDeviceStatedWithResult:^(unsigned int SW1, unsigned int SW2) {
    
    
}];
  
}
#pragma mark - 设备信息

- (IBAction)btn2:(UIButton *)sender {
    
    
    [self.BLETools RequestDeviceInformationWithResult:^(JMDeviceModel *infomation) {
        
        NSLog(@"啊设备信息:%@",infomation);
    }];
}

#pragma mark - 枚举密条
- (IBAction)btn3:(UIButton *)sender {
    
    
   [self.BLETools readTheDeviceSecretBookWithResult:^(NSArray *secretBookArray) {
    
                    NSLog(@"%@",secretBookArray);
    
                } errorBlock:^(ErrorCode code) {
    
    
                }];
}

#pragma mark - 新增密条
- (IBAction)btn4:(UIButton *)sender {
    
    static int num = 2100000000;
//    NSString *string = [NSString stringWithFormat:@"%d",num++];
    
    NSString *string = [NSString stringWithFormat:@"a"];
    NSString *string1 = [NSString stringWithFormat:@"%dkjhffakhfakjhfaifhifadkfnkajhfakfwiueqieruqqrsfsfsfdfasfdsfewqerwqrrqerqerereqrqerereqrereqdsfad",num++];
    
    [self.BLETools addTheDeviceSecretBookItemTitle:string itemDescData:string1 protect:0 ResultSuccess:^{
         NSLog(@"新增密条成功");
    } errorBlock:^(ErrorCode code) {
        NSLog(@"新增密条失败");
        
    }];
    
   
}
#pragma mark - 编辑密条
- (IBAction)btn5:(UIButton *)sender {
    
    static int num = 2000000000;
    NSString *string = [NSString stringWithFormat:@"%d",num++];
    NSString *string1 = [NSString stringWithFormat:@"%dkjhffakhfakjhfaifhifadkfnkajhfakfwiueqieruqqrsfsfsfdfasfdsfewqerwqrrqerqerereeqrereqdsfad",num++];
    
    [self.BLETools EditTheDeviceSecretBookItemTitle:string itemDescData:string1 ResultSuccess:^{
        NSLog(@"编辑密条成功");
    } errorBlock:^(ErrorCode code) {
         NSLog(@"编辑密条失败");
        
    }];
    
    

    
}


#pragma mark - 删除密条
- (IBAction)btn6:(UIButton *)sender {
    
    static int num = 2000000000;
    NSString *string = [NSString stringWithFormat:@"%d",num++];
  [self.BLETools deleteTheDeviceSecretBook:string ResultSuccess:^() {
      NSLog(@"删除密条成功");
  } exclusiveModeTimeOut:^{
      NSLog(@"删除密条超时");
  } operationCancel:^{
      NSLog(@"删除密条取消");
  } errorBlock:^(ErrorCode code) {
      NSLog(@"删除密条错误");
  }];

}
#pragma mark - 只读密条
- (IBAction)btn7:(UIButton *)sender {
        

    NSString *string = [NSString stringWithFormat:@"aaaa112233"];
    
    [self.BLETools OnleReadTheDeviceSecretNote:string WithResult:^{
         NSLog(@"只读密条成功");
    } ExclusiveMode:^{
         NSLog(@"只读密条独占");
    } exclusiveModeTimeOut:^{
        NSLog(@"只读密条超时");
    } operationCancel:^{
        NSLog(@"只读密条取消");
    } errorBlock:^(ErrorCode code) {
         NSLog(@"只读密条独占");
    }];
    
    
  

}

#pragma mark - 枚举密码
- (IBAction)btn8:(UIButton *)sender {
    
    [self.BLETools readTheDevicepasssWordWithResult:^(NSArray *secretNoteArray) {
        
        [secretNoteArray enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
            
            JMSecurityBModle *mod = obj;
            
            NSLog(@"%@ %@",mod.categroryNmae,mod.securityArray);
           
        }];
        
    } errorBlock:^(ErrorCode code) {
        
        
    }];

    
}

#pragma mark - 增加密码
- (IBAction)btn9:(UIButton*)sender {
    
    NSString *string = @"121";
    NSString *string1 = @"12121212";
    [self.BLETools addTheDevicePassWordItemTitle:string itemDescData:string1 accData:string staticData:string itemCData:1 itemCNaData:string WithResult:^{
        
        
        NSLog(@"增加密码成功");
    } errorBlock:^(ErrorCode code) {
        NSLog(@"增加密码失败");
        
    }];
    
    
}
#pragma mark - 修改密码
- (IBAction)btn10:(UIButton *)sender {
    
    NSString *string = @"12121212";
    
    // 0 APP端   1 发送
    
    
    [self.BLETools EditThePassWordItemTitle:string itemDescData:string accData:string staticData:string itemCData:1 itemCNaData:string editSecurityBookType:1 WithResult:^() {
        NSLog(@"编辑密码成功");
    } ExclusiveMode:^{
        
        [self.BLETools  RequestVerificationPIN:string WithResult:^{
            NSLog(@"验证设备success");
        } passworderrorBlock:^(int number) {
            NSLog(@"编辑密码失败");
            
        }];
        
    } exclusiveModeTimeOut:^{
        NSLog(@"编辑密码超时");
    } operationCancel:^{
        
    } errorBlock:^(ErrorCode code) {
         NSLog(@"编辑密码错误");
    }];
    
  


}

#pragma mark - 删除密码
- (IBAction)btn11:(id)sender {
    
    NSString *string = @"11223344";
    
    [self.BLETools deleteTheDevicePassWord:string WithResult:^() {
        NSLog(@"删除密码成功");
    } exclusiveModeTimeOut:^{
        NSLog(@"删除密码超时");
    } operationCancel:^{
        NSLog(@"删除密码取消");
    } errorBlock:^(ErrorCode code) {
        NSLog(@"删除密码错误");
    }];


}

#pragma mark - 只读密码
- (IBAction)btn12:(UIButton *)sender {
    
    NSString *string = @"112233445566";
    
    [self.BLETools OnleReadTheDeviceSecretBook:string WithResult:^{
        NSLog(@"只读密码成功");
    } ExclusiveMode:^{
        NSLog(@"只读密码独占");
    } exclusiveModeTimeOut:^{
        
    } operationCancel:^{
        
    } errorBlock:^(ErrorCode code) {
        NSLog(@"只读密码失败");
    }];
    
  
 
}
#pragma mark - 密码分类
- (IBAction)btn13:(UIButton *)sender {

    [self.BLETools editSecurityBookCategoryWithnewCatalogName:@"金融卡包01" olditemCataID:1 oldCatalogName:@"金融卡包" WithResult:^{
      
        NSLog(@"密码分类成功");
    } errorBlock:^(ErrorCode code) {
        
      NSLog(@"密码分类失败");
    }];
    
    
    
}

#pragma mark - 密码标题

- (IBAction)btn14:(UIButton *)sender {
    
    
    NSString *string = @"2233445566";
     NSString *string1 = @"11223aaa";
    [self.BLETools requestUpdateSecurityBookItemTitle:string withNewTitle:string1 WithResult:^{
        
        NSLog(@"密码标题成功");
        
    } errorBlock:^(ErrorCode code) {
        
        NSLog(@"密码标题失败");
        
    }];
   
    
}
#pragma mark - 备份

- (IBAction)btn15:(UIButton *)sender {
    
[self.BLETools backUpTheDeceiveDataWithResult:^(NSData *backupData) {
    NSLog(@"备份成功:%@",backupData);
    
    _data = backupData;

}DevProgress:^(DWORD progress) {
    
    NSLog(@"备份错误");
    
} exclusiveModeTimeOut:^{
    NSLog(@"备份超时");

} operationCancel:^{
    NSLog(@"备份取消");

} errorBlock:^(ErrorCode code) {
    
    NSLog(@"备份错误");

}];
    
    
}

#pragma mark - 恢复
- (IBAction)btn16:(UIButton *)sender {
    
    [self.BLETools restoreBackupTheDeviceData:_data WithResult:^{
        NSLog(@"恢复成功");
    } exclusiveModeTimeOut:^{
        NSLog(@"恢复超时");
    } operationCancel:^{
        NSLog(@"恢复取消");
    } errorBlock:^(ErrorCode code) {
        NSLog(@"恢复错误");
    }];
    
    
    
}

#pragma mark - 固件升级
- (IBAction)btn17:(UIButton *)sender {
    
    
  NSString *path = [[NSBundle mainBundle] pathForResource:@"123" ofType:@"pkg"];
    
    
    NSData *data = [NSData dataWithContentsOfFile:path];
    
    [self.BLETools deceiveUpdataWithData:data Result:^{
        NSLog(@"固件升级成功");
    } updataProgress:^(CGFloat progress) {
        self.label.text = [NSString stringWithFormat:@"进度:%.3f",progress];

    } exclusiveModeTimeOut:^{
        NSLog(@"固件升级超时");
    } operationCancel:^{
        NSLog(@"固件升级取消");
    } errorBlock:^(ErrorCode code) {
        NSLog(@"固件升级失败");
    }];
    
    
    
 
    
}

#pragma mark - 改密码
- (IBAction)btn30:(UIButton *)sender {
    
    
    //验证设备PIN
    
    
    [self.BLETools requestmodifyPIN_EM:0 WithResult:^{
        [self.BLETools RequestVerificationPIN:@"aaaa" WithResult:^{
            
            NSLog(@"验证设备success");
            
            
        }passworderrorBlock:^(int number) {
            
            NSLog(@"验证设备number%d",number);
            
        }];
        
    } exclusiveModeTimeOut:^{

    } operationCancel:^{

    } errorBlock:^(ErrorCode code) {

    }];
    
  
    
    
}
#pragma mark - 改名字
- (IBAction)btn31:(UIButton *)sender {
    
    NSString *string = @"我的盾啊";
    
    [self.BLETools requestSetDeviceParamater:0 withMax:0 withTrycount:0 withSleep:0 withPoweroff:0 withNice:string WithResult:^{
    
        NSLog(@"改名成功");
        
    } errorBlock:^(ErrorCode code) {
        
        NSLog(@"改名失败");
    }];
}

- (IBAction)btn32:(UIButton *)sender {
}









#pragma mark - 上翻
- (IBAction)btn18:(UIButton *)sender {
    
    UInt8 bufferSE[1];
    memset(bufferSE, 0x00, sizeof(bufferSE));
    bufferSE[0] = 0x18;
    
    [self.BLETools RequestSendInput:bufferSE withSize:1 WithResult:^{
        NSLog(@"上翻成功");
    } errorBlock:^(ErrorCode code) {
        
        NSLog(@"下翻失败");
    }];
    
}

#pragma mark - 下翻
- (IBAction)btn19:(UIButton *)sender {
  
    UInt8 bufferSE[1];
    memset(bufferSE, 0x00, sizeof(bufferSE));
    bufferSE[0] = 0x19;
    
    [self.BLETools RequestSendInput:bufferSE withSize:1 WithResult:^{
        NSLog(@"上翻成功");
    } errorBlock:^(ErrorCode code) {
        NSLog(@"下翻失败");
    
    }];
}

#pragma mark - 枚举密钥
- (IBAction)btn20:(UIButton *)sender {
    
    [self.BLETools enumMainEncryptKeyType:1 WithResult:^{
        
    } errorBlock:^(ErrorCode code) {
        
        
    }];
}

#pragma mark - 加密初始
- (IBAction)btn21:(UIButton *)sender {
    
    
    [self.BLETools EncryptInit_3040SWithResult:^{
        
    } errorBlock:^(ErrorCode code) {
        
        
    }];
    
    
}

#pragma mark - 加密单帧
- (IBAction)btn22:(id )sender {
    
    
    if ([[sender nextResponder] isKindOfClass:[UIApplication class]]) {
        return;

    }else{
        
        NSLog(@"%@",[sender class]);
      
        [self btn22:[sender nextResponder]];
        

        
    
    }
        
}




#pragma mark - *********解密初始*********
- (IBAction)btn23:(UIButton *)sender {
    
       
}


#pragma mark - 解密单帧
- (IBAction)btn24:(UIButton *)sender {
}


- (IBAction)btn40:(UIButton *)sender {
    
    
    [self.BLETools requestBackupKeyType:0 withKeyID:0];
    
    
}

- (IBAction)btn41:(UIButton *)sender {
    
    
    NSString *string = @"a ! 我的你怕ni12ab";
    
    int a = [self stringL:string];
    
    NSLog(@"%d",a);
    
}

- (int)stringL:(NSString *)str {
    int abc = 0;
    for(int i=0; i< [str length];i++) {
        
        int a = [str characterAtIndex:i];
        
        
        abc += isascii(a) ? 1 : 2;
        
        
    }
    
    return abc;
}

- (void)JMPeripheral:(CBPeripheral *)peripheral didReceiveTransparentData:(NSData *)data {

     [self.BLETools analysisDeviceWithData:data];

}








#pragma mark - 增加TableView

- (void)addTheTableview {
    
    

    _tableView = [[UITableView alloc] initWithFrame:CGRectMake(0, 64, 375, 170)];
    _tableView.dataSource = self;
    _tableView.delegate = self;
    [self.view addSubview:_tableView];
    
    
    _logTextView = [[UITextView alloc] initWithFrame:CGRectMake(0, 64, 375, 170)];
    
    [self redirectSTD:STDOUT_FILENO];
    
    [self redirectSTD:STDERR_FILENO];

}


- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    
    return _Cbcontrol.PeripModelArray.count;
}

- (UITableViewCell*)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"cell"];
    
    
    if (!cell) {
        
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:@"cell"];
    }
    JMPeripherModel *model = _Cbcontrol.PeripModelArray[indexPath.row];
    cell.textLabel.text = model.name;
    cell.detailTextLabel.text = model.RSSI.stringValue;
    
    return cell;
}



- (JMPeripheral *)BLETools {
    
    
    if (!_BLETools) {
        

        _BLETools = _Cbcontrol.Peripheral;
        _BLETools.delegate = self;
        
    }
    
    return _BLETools;
    
}

- (UILabel *)label {

    if (!_label) {
        
        _label = [[UILabel alloc] initWithFrame:CGRectMake(130, 200, 120, 40)];
        
        _label.backgroundColor = [UIColor greenColor];
        _label.textAlignment = 1;
        
        [self.view addSubview:_label];
        
        
    }
    return _label;
    
}





- (IBAction)btn60:(UIBarButtonItem *)sender {
    
    
  

    
}

// 78 47 F1 A6 01

//    NSString *sting = @"012345我是我啊";
//
//    const char *aa = sting.UTF8String;
//
//    NSData *data = [[NSData alloc] initWithBytes:sting.UTF8String length:sting.length];
//
//
//
//    [NSString stringWithCString:sting.UTF8String encoding:NSUTF8StringEncoding];
//
//
//    NSMutableData *mutData = [self DataWithString:sting];
//
//    const char* bb = [sting cStringUsingEncoding:NSUTF8StringEncoding];

- (void)viewDidAppear:(BOOL)animated {
    
    [super viewDidAppear:animated];
    
//    NSDate *date = [NSDate dateWithTimeIntervalSinceNow:8*3600];
    
    //    [self.navigationController pushViewController:control animated:YES];
    //
  
    
    
//        JMDeviceListController *control = [[JMDeviceListController alloc] init];
//        [self.navigationController pushViewController:control animated:YES];
//        blue.navigationController.navigationBarHidden = YES;
}


- (void)redirectNotificationHandle:(NSNotification *)nf{ // 通知方法
    NSData *data = [[nf userInfo] objectForKey:NSFileHandleNotificationDataItem];
    NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    
    self.logTextView.text = [NSString stringWithFormat:@"%@\n\n%@",self.logTextView.text, str];// logTextView 就是要将日志输出的视图（UITextView）
    NSRange range;
    range.location = [self.logTextView.text length] - 1;
    range.length = 0;
    [self.logTextView scrollRangeToVisible:range];
    [[nf object] readInBackgroundAndNotify];
}

- (void)redirectSTD:(int )fd{
    NSPipe * pipe = [NSPipe pipe] ;// 初始化一个NSPipe 对象
    NSFileHandle *pipeReadHandle = [pipe fileHandleForReading] ;
    dup2([[pipe fileHandleForWriting] fileDescriptor], fd) ;
    
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(redirectNotificationHandle:)
                                                 name:NSFileHandleReadCompletionNotification
                                               object:pipeReadHandle]; // 注册通知
    [pipeReadHandle readInBackgroundAndNotify];
}





@end
