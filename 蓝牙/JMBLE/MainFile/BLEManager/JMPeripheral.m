//
//  JMPeripheral.m
//  jimidun
//
//  Created by 任雪强 on 17/4/6.
//  Copyright © 2017年 microdone. All rights reserved.
//

#import "JMPeripheral.h"
#import "SecurityBookModel.h"
#import "JMSecurityBModle.h"
#import <CommonCrypto/CommonDigest.h>
#define  BLEManger [JMBlueToolsOLD sharedMangerBLE]

#define  recData  1024
#define  BufSize  2148
#define  model [self.devModel.DevModel UTF8String]

#define  version [[self.devModel.devVer componentsSeparatedByString:@"-"].lastObject UTF8String]


typedef NS_ENUM(NSInteger, DataType) {
    
    
    deletSecret = 0,
    deceiveStated,
    deceiveNum,
    deceiveAddSec,
    deceiveEditSec,
    deceiveOnlySec,
    deceiveOnlyPass,
    deceiveAddPass,
    deceiveEditPass,
    deceiveDelePass,
    deceiveNamePass,
    deviceActive,
    deviceUpData,
    devieceJMData,
    deceivePutUserKey,
    deceivePassWord,
    deceiveSecretBook,
    deceiveBackUpData,
    deceiveInfomation,
    devPublicKey,    // 设备公钥
    devSecurityCha, //联机通道
    devPostKey,  // 下发联机会话秘钥
    devRamNu,    //随机送
    devVerifyPIN, //验证PIN
    devGetResponse, //读取响应
    devShowKeyboard,//显示安全键盘
    devSendInput,    //发送键盘字符
    devExitMode,      //退出独占
    devBackUPKey,     //备份密钥显示
    devModeifyPINTwo,  //修改PIN
    devUpdateSecurityBook,//修改密码标题
    devSetParamater,      //动态设备参数
    devResetFactory,     //重置设备
    VerificationPIN,     //验证PIN
    devEncryptKey,        //加密密钥
    EncryptInit,          //加密初始化
    DecryptInit,          //解密初始化
    Encrypt,          //加密单帧
    Decrypt,          //解密单帧
    setLicense      //下发许可
    
};
static int _lengthInfo =0;
UInt8 handleInside[160];
@interface JMPeripheral ()

@property (nonatomic,assign) int num1,num2,num3,num4,num5,num6,num7,num8,num9,num10;
@property (nonatomic,assign) BOOL numBool1,numBool2,numBool3,numBool4,numBool5;
@property (nonatomic,assign) int secretB1;


@property (nonatomic,assign) int num11,num12,num13,num14,num15,num16,num17;


@property (strong, nonatomic) NSMutableData *contentParsingData;
@property (strong, nonatomic) NSData *sendData;

@property (assign, nonatomic) BOOL backUp,backData;
@property (assign, nonatomic) int sendCountJM;
@property (assign, nonatomic) int sendTypeJM;

@property (strong, nonatomic) NSData *crcData;
@property (strong, nonatomic) NSData *numData;


@property (assign, nonatomic) int responeNum;
@property (assign, nonatomic) DWORD backOffse;

//后加的

@property (nonatomic,assign) DataType requestType;

//激活设备
@property (nonatomic,copy) void(^ActiveBlock)();



//设备状态
@property (nonatomic,copy) void(^deviceStated)(DWORD,DWORD);

//设备信息
@property (nonatomic,copy) void(^deviceInfo)(JMDeviceModel*);

//设备序列号

@property (nonatomic,copy)  void(^activeString)(NSString*);


//错误信息
@property (nonatomic,copy) void(^insideCode)(ErrorCode);

//枚举密条
@property (nonatomic,copy) void(^secretBOOK)(NSArray*);

//增加密条
@property (nonatomic,copy) void(^AddSecretBOOK)();

//编辑密条
@property (nonatomic,copy) void(^EditSecretBOOK)();

// 删除密条
//@property (nonatomic,copy) void(^DeleteSecretBOOK)();

//枚举密码
@property (nonatomic,copy) void(^passWord)(NSArray *);

// 增加密码
@property (nonatomic,copy) void(^AddPassB)();

// 编辑密码
//@property (nonatomic,copy) void(^EditPass)();

// 删除密码
//@property (nonatomic,copy) void(^DeletePass)();

// 点亮密码
@property (nonatomic,copy)  void(^lightPass)();

// 密码分类
@property (nonatomic,copy)  void(^cateModetiy)();

// 密码标题
@property (nonatomic,copy)  void(^updataTitle)();

//备份数据
@property (nonatomic,copy) void(^backString)(NSData*);

//恢复备份
@property (nonatomic,copy) void(^backUpdata)();

//固件升级进度

@property (nonatomic,copy) void(^updataNum)(CGFloat);
//固件升级

@property (nonatomic,copy) void(^updataBlackJ)();

//设备公钥
@property (nonatomic,copy) void(^PubData)(NSString*);

//联机通道
@property (nonatomic,copy) void(^secureSring)(NSData*);

//获取随机数
@property (nonatomic,copy) void(^randomNumber)(NSData*);

// 下发联机秘钥
@property (nonatomic,copy) void(^Sesskey)();

// aToken

@property (nonatomic,copy)  void(^aToken)(NSData*);

//密码剩余错误次数
@property (nonatomic,copy)  void(^passError)(int);

//绑定是否成功
@property (nonatomic,copy)  void(^userKeyBOOL)(BOOL);

//编辑密码 独占
@property (nonatomic,copy)   void(^lightonePass)();


//验证设备PIN
@property (nonatomic,copy)   void(^VerifyPIN)();

//发送键盘字符 只读 传值
@property (nonatomic,strong) NSString* SecurityString;

//
////修改PIN
//@property (nonatomic,copy) void(^motfiPIN)();

//设备重置
//@property (nonatomic,copy) void(^resetFactory)();


// 动态设备参数下发
@property (nonatomic,copy) void(^changeName)();



// 退出独占
@property (nonatomic,copy)  void(^ExitMOde)();


// 读取响应/备份秘钥
@property (nonatomic,copy)  void(^backUpdataEnterPwd)();


//类型
@property (nonatomic,assign) CBCommType JMtype;

//临时

@property (nonatomic,strong) NSData* receviceData;

@property (nonatomic,assign) NSUInteger receviceLenthJM,recevice2;


/** 读取响应    */
@property (assign, nonatomic) DWORD blockType;

/** 备份数据    */
@property (assign, nonatomic) DWORD backupBlockType;

/** 备份数据    */
@property (assign, nonatomic) DWORD backupNframe;

/** 恢复数据    */
@property (assign, nonatomic) LPDWORD backupOffset;

//超时回调  验证PIN
@property (nonatomic,copy)  void(^timeoutInside)();

//取消回调  验证PIN
@property (nonatomic,copy)  void(^operationCancelInside)();

//取消回调  验证PIN
@property (nonatomic,copy)  void(^VerificationSuccInside)();

//点亮密条  成功
@property (nonatomic,copy)  void(^lightSecretSuccInside)();


//点亮密条  独占
@property (nonatomic,copy)  void(^lightSecretExvInside)();


//加密初始化
@property (nonatomic,copy) void(^enumMainPassword)();

//加密初始化
@property (nonatomic,copy) void(^encryptInit)();

//加密单帧
@property (nonatomic,copy) void(^Encrypt_single)(NSData*);

//解密初始化
@property (nonatomic,copy) void(^DecryptInit)();


//解密单帧

@property (nonatomic,copy) void(^Decrypt_single)(NSData*);

//下发许可

@property (nonatomic,copy) void(^setLicese)();


@property (nonatomic,strong) NSMutableData *Title;
@property (nonatomic,strong) NSMutableData *Desc;
@property (nonatomic,strong) NSMutableData *Account;
@property (nonatomic,strong) NSMutableData *Password;
@property (nonatomic,strong) NSMutableData *cateName;
@property (nonatomic,assign)  UInt32   itemCaID;

@property (nonatomic,assign) int numberChange;
@property (nonatomic,copy) void(^backupNumber)(DWORD) ;

@end

@implementation JMPeripheral




#pragma mark - ************************开始************************



#pragma mark - 激活极密盾

- (void)requestTheDeviceActive:(NSData*)data WithResult:(void(^)())activeSucess errorBlock:(void(^)(ErrorCode code))error {
    
    
    
    NSData *sendData = [JMCoreCommandCenter commandWithType:CBCommActivateS object:data];
    
    
    self.ActiveBlock = activeSucess;
    self.insideCode = error;
    _requestType = deviceActive;
    
    
    
    [self sendTheBleData:sendData];
    
}



- (void)lastDeviceActive:(UInt8*)buffer withDataLength:(int)len {
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        JMD_RESULT  jmd_result;
        
        
        BTComm_Activate_3040R(buffer,(uint32_t)len, &jmd_result);
        
        
        
        if (jmd_result.ErrorCode2 == 0x9000 ||jmd_result.ErrorCode2 ==  0x0057) {
            
            if (self.ActiveBlock) {
                
                self.ActiveBlock();
            }
            
        }else {
            
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
            
        }
        
        
        
    } else {
        
        _num12++;
        
        if (_num12 <= 3) {
            
            //            [self requestTheDeviceActive:_sendData];
            
        }
    }
    
}



#pragma mark - 获取设备状态
- (void)RequestDeviceStatedWithResult:(void(^)(DWORD SW1,DWORD SW2))stated {
    NSLog(@"*********获取设备状态*********");
    
    NSData *sendData = [JMCoreCommandCenter commandWithType:CBCommgetDeviceStatusS object:NULL];
    
    self.deviceStated = stated;
    _requestType = deceiveStated;
    
    
    
    [self sendTheBleData:sendData];
    
}

- (void)lastAnalyStated:(UInt8*)buffer withDataLength:(int)len {
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        
        DWORD SW1;
        DWORD SW2;
        uint32_t	Left_Try_Times;
        int res =  BTComm_getDeviceStatus_3040D (buffer,(uint32_t)len, &SW1, &SW2,&Left_Try_Times);
        
        WORD ErrorCode1 = (WORD)((res >> 16)&0xFFFF);
        WORD ErrorCode2 = (WORD)(res);
        NSLog(@"解析设备状态:errorcode1: 0x%x", ErrorCode1);
        NSLog(@"解析设备状态:errorcode2: 0x%x", ErrorCode2);
        if (res) {
            sleep(2.0);
            //  [self RequestDeviceStated];
        }else{
            
            if (self.deviceStated) {
                self.deviceStated(SW1,SW2);
            }
        }
        
        
    } else {
        
        
        _num2++;
        
        if (_num2 <= 3) {
            
            //    [self RequestDeviceStated];
            
        }
        
    }
    
}



#pragma -mark 获取设备信息


- (void)RequestDeviceInformationWithResult:(void(^)(JMDeviceModel *devInfomation))devInfomation {
    
    NSLog(@"*********获取设备信息*********");
    
    NSData *sendData = [JMCoreCommandCenter commandWithType:CBCommgetDeviceInfoS object:NULL];
    
    self.deviceInfo = devInfomation;
    _requestType = deceiveInfomation;
    
    
    [self sendTheBleData:sendData];
}


- (void)lastAnalyDevceiveInfomation:(UInt8*)buffer withDataLength:(int)len {
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        JMD_RESULT  jmd_result;
        BTComm_getDeviceInformation_3040D (buffer, len,&jmd_result);
        
        NSStringEncoding enc = CFStringConvertEncodingToNSStringEncoding(kCFStringEncodingGB_18030_2000);
        
        NSString *str = [[NSString alloc]initWithBytes:jmd_result.ResultData length:jmd_result.ResultSize encoding:enc];
        
        if (str.length > 0) {
            
            
            
            NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:[str dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingAllowFragments error:nil];
            
            NSLog(@"设备信息:%@",dict);
            
            
            JMDeviceModel * mode =[[JMDeviceModel alloc] initWithDict:dict];
            self.devModel = mode;
            
            NSLog(@"中心的信息:%@",[JMCentralManager shareManger].Peripheral.devModel);
            
            
            if (self.deviceInfo) {
                
                self.deviceInfo(mode);
            }
            
        }
        
        
        
    } else {
        
        _num1++;
        
        if (_num1 <= 3) {
            
            //            [self RequestDeviceInformation];
            
            
        }
        
        
    }
    
    
}

#pragma mark - 获取设备序列号


- (void)RequestDeviceSerialNumWithResult:(void(^)(NSString*serialNoS))DeviceSerialNoS{
    NSLog(@"*********获取设备序列号*********");
    NSData *sendData = [JMCoreCommandCenter commandWithType:CBCommgetDeviceSerialNoS object:NULL];
    self.activeString = DeviceSerialNoS;
    _requestType = deceiveNum;
    
    
    [self sendTheBleData:sendData];
    
}



- (void)lastAnalyDevceiveSer:(UInt8*)buffer withDataLength:(int)len {
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        
        uint8_t     DevID[MAXDEVID];
        uint32_t    DevIDLength = sizeof(DevID);
        
        BTComm_getDeviceID_3040D (buffer,(uint32_t)len,DevID,&DevIDLength);
        
        NSString *string = [[NSString alloc] initWithBytes:DevID length:DevIDLength encoding:CFStringConvertEncodingToNSStringEncoding(kCFStringEncodingGB_18030_2000)];
        
        if (self.activeString) {
            
            self.activeString(string);
        }
        
    } else {
        
        _num3++;
        
        if (_num3 <= 3) {
            
            //            [self RequestDeviceSerialNum];
            
        }
        
        
    }
    
    
}


#pragma mark - 读取密条

- (void)readTheDeviceSecretBookWithResult:(void(^)(NSArray* secretBookArray))SecretBookModel errorBlock:(void(^)(ErrorCode code))error {
    
    
    NSLog(@"*********枚举密条*********");
    NSData *sendData = [JMCoreCommandCenter commandWithType:CBCommGetSecurityNoteS object:nil];
    
    self.secretBOOK = SecretBookModel;
    self.insideCode  = error;
    _requestType = deceiveSecretBook;
    self.JMtype = CBCommGetSecurityNoteS;
    
    
    
    [self sendTheBleData:sendData];
    
}

//- (void)readTheDeviceSecretBookINside {
//
//    _sendData = [JMCoreCommandCenter commandWithType:CBCommGetSecurityNoteSTwo object:nil];
//
//    [BLEManger sendTheBleData:_sendData peripheral:_periphralTools];
//
//}

- (void)preectSercetBOOKData:(UInt8*)result dataLenth:(UInt32)lenth {
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        JMD_RESULT  jmd_result;
        BTComm_getResponse_3040R (result,lenth,&jmd_result);
        
        NSLog(@"解析密条数据:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析密条数据:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        
        
        if (jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 ==0x6100){
            
            
            [self.contentParsingData appendBytes:jmd_result.ResultData length:jmd_result.ResultSize];
            [self RequestgetResponse:0];
            
            
            
        } else if (jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 ==0x9000){
            
            
            [self.contentParsingData appendBytes:jmd_result.ResultData length:jmd_result.ResultSize];
            
            LPJMD_SECURITYBOOK  jmd_sb;
            uint32_t     jmd_s_size;
            
            
            
            BTComm_enumSecurityNote_3040D ((LPBYTE)[_contentParsingData bytes],(DWORD)_contentParsingData.length,&jmd_sb, &jmd_s_size);
            
            
            [self pretectSercetBOOKData:jmd_sb dataLenth:jmd_s_size];
            
            
        }else{
            
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
            
        }
        
    }
}




- (void)pretectSercetBOOKData:(LPJMD_SECURITYBOOK)jmd_sb dataLenth:(uint32_t)jmd_s_size {
    
    NSMutableArray *mutArray = [NSMutableArray array];
    
    for ( uint32_t i       = 0; i<jmd_s_size; i ++ ){
        
        SecurityBookModel *sbm = [[SecurityBookModel alloc] init];
        
        sbm.itemTitle  = [self gbk2utf8:jmd_sb[i].itemTitle];
        sbm.itemCataName = [self gbk2utf8:jmd_sb[i].itemCataName];
        
        
        
        sbm.itemDesc           = [self gbk2utf8:jmd_sb[i].itemDesc];
        sbm.xURL               = [self gbk2utf8:jmd_sb[i].xURL];
        /**标题    */
        sbm.itemTitle = [self gbk2utf8:jmd_sb[i].itemTitle];
        
        /** 分类名    */
        sbm.itemCataName = [self gbk2utf8:jmd_sb[i].itemCataName];
        
        /** 密码页保护级别*/
        sbm.ProtectLevel = jmd_sb[i].ProtectLevel;
        /**密条保护级别*/
        sbm.mtProtectLevel = jmd_sb[i].mtProtectLevel;
        
        sbm.itemCataID = jmd_sb[i].itemCataID;
        
        /**口令项是否关联了应用*/
        sbm.appLink = jmd_sb[i].appLink;
        
        /** 显示年月日    */
        time_t  lastDate = jmd_sb[i].lastDate;
        sbm.lastDate = [self dateInFormat:lastDate format:@"%Y-%m-%d"];
        
        [mutArray addObject:sbm];
    }
    
    if (self.secretBOOK) {
        self.secretBOOK(mutArray.copy);
    }
    
    self.contentParsingData = nil;
    BTComm_getSecurityNoteF(jmd_sb);
}



#pragma mark - 增加密条

- (void)addTheDeviceSecretBookItemTitle:(NSString*)itemTitle itemDescData:(NSString*)itemDesc protect:(UInt32)mtProtectLevel ResultSuccess:(void(^)())AddSuccess errorBlock:(void(^)(ErrorCode code))error {
    
    NSLog(@"*********增加密条*********");
    self.AddSecretBOOK = AddSuccess;
    self.insideCode = error;
    self.requestType = deceiveAddSec;
    
    
    int length = [self stringLenght:itemTitle];
    
    if (length < 4 || length > 14) {
        
        [self errStrWithHexCode:0x3330];
        return;
    }
    
    int descLen = [self stringLenght:itemDesc];
    if (descLen < 4 || descLen > 128) {
        
        [self errStrWithHexCode:0x3331];
        return;
        
    }
    
    
    UInt32 utcTime;
    
    if(JMDeveiceType > 2){
        
        utcTime = (UInt32)[[NSDate date] timeIntervalSince1970];
        
    }else{
        
        utcTime = 0;
    }
    
    NSMutableData *title = [self dataWithStringS:itemTitle];
    NSMutableData *desc = [self dataWithStringS:itemDesc];
    
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    BTComm_addSecurityNote_3040S((LPBYTE)cmd_buffer, &cmd_size, title.bytes, desc.bytes, utcTime, mtProtectLevel);
    
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    
    [self sendTheBleData:sendData];
    
}


- (void)lastAddSecretBook:(UInt8*)buffer withDataLength:(int)len {
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        
        JMD_RESULT  jmd_result;
        
        BTComm_addSecurityNote_3040R (buffer,(uint32_t)len,&jmd_result);
        
        
        NSLog(@"解析增加密条:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析增加密条:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        
        if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x9000){
            
            
            if (self.AddSecretBOOK) {
                
                self.AddSecretBOOK();
            }
            
        } else {
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
        }
        
        
    } else {
        
        
        _num10++;
        
        if (_num10 <= 3) {
            
            //            [self addTheDeviceSecretBookItemTitle:_AddItemTitle itemDescData:_AdddItemDesc protect:_AddMtProtectLevel];
            
            
        }
        
    }
    
}


#pragma mark - 编辑密条

- (void)EditTheDeviceSecretBookItemTitle:(NSString*)itemTitle itemDescData:(NSString*)itemDesc  ResultSuccess:(void(^)())editSuccess errorBlock:(void(^)(ErrorCode code))error {
    NSLog(@"*********编辑密条*********");
    
    self.EditSecretBOOK = editSuccess;
    self.insideCode = error;
    self.requestType = deceiveEditSec;
    
    int length = [self stringLenght:itemTitle];
    
    if (length < 4 || length > 14) {
        
        [self errStrWithHexCode:0x3330];
        return;
    }
    
    int descLen = [self stringLenght:itemDesc];
    if (descLen < 4 || descLen > 128) {
        
        [self errStrWithHexCode:0x3331];
        return;
        
    }
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    UInt32 utcTime;
    if(JMDeveiceType > 2){
        
        utcTime = (UInt32)[[NSDate date] timeIntervalSince1970];
        
    }else{
        
        utcTime = 0;
    }
    NSMutableData *title = [self dataWithStringS:itemTitle];
    NSMutableData *desc = [self dataWithStringS:itemDesc];
    
    BTComm_updateSecurityNote_3040S ((LPBYTE)cmd_buffer,&cmd_size,title.bytes,desc.bytes, utcTime);
    
    
    NSData *  sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    [self sendTheBleData:sendData];
    
    
}

- (void)lastEditSecretBook:(UInt8*)buffer withDataLength:(int)len {
    
    if ([_numData isEqualToData:_crcData]) {
        
        JMD_RESULT  jmd_result;
        
        BTComm_updateSecurityNote_3040R (buffer,(uint32_t)len, &jmd_result);
        
        NSLog(@"解析编辑密条:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析编辑密条:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        
        if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x9000){
            
            
            if (self.EditSecretBOOK) {
                
                self.EditSecretBOOK();
            }
            
        } else {
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
        }
        
        
    } else {
        
        
        _num14++;
        
        if (_num14 <= 3) {
            
            //            [self EditTheDeviceSecretBookItemTitle:_AddItemTitle itemDescData:_AdddItemDesc];
            
            
        }
        
    }
}

#pragma mark - 删除密条

- (void)deleteTheDeviceSecretBook:(NSString*)itemTitle ResultSuccess:(void(^)())deleteSuccess exclusiveModeTimeOut:(void(^)())timeout operationCancel:(void(^)())cancelOperation errorBlock:(void(^)(ErrorCode code))error {
    
    NSLog(@"*********删除密条*********");
    
    
    NSMutableData *data = [self dataWithStringS:itemTitle];
    NSData *sendData = [JMCoreCommandCenter commandWithType:CBCommdeleteSecurityNoteS object:data];
    
    self.VerificationSuccInside = deleteSuccess;
    self.timeoutInside = timeout;
    self.operationCancelInside = cancelOperation;
    self.insideCode = error;
    _requestType = deletSecret;
    self.JMtype = CBCommdeleteSecurityNoteS;
    
    [self sendTheBleData:sendData];
    
    
}

- (void)lastDeleSecretBook:(UInt8*)buffer withDataLength:(int)len {
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        JMD_RESULT  jmd_result;
        
        BTComm_deleteSecurityNote_3040R (buffer,(uint32_t)len, &jmd_result);
        
        
        NSLog(@"解析删除密条:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析删除密条:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x6100){
            
            [self RequestgetResponse:0];
            
            
        } else if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x9000){
            
            
            if (self.VerificationSuccInside) {
                
                self.VerificationSuccInside();
            }
            
            
        } else {
            
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
        }
        
        
        
        
    } else {
        
        _num8++;
        
        if (_num8 <= 3) {
            
            //            [self deleteTheDeviceSecretBook:_SerectData];
            
        }
        
    }
    
}


#pragma mark - 只读密条


- (void)OnleReadTheDeviceSecretNote:(NSString*)securityNote WithResult:(void(^)())readSecretNote ExclusiveMode:(void(^)())exclusiveMode exclusiveModeTimeOut:(void(^)())timeout operationCancel:(void(^)())cancelOperation errorBlock:(void(^)(ErrorCode code))error{
    
    NSMutableData * itemTitleN = [self dataWithStringS:securityNote];
    
    NSData *sendData = [JMCoreCommandCenter commandWithType:CBCommGotoSecurityNoteS object:itemTitleN];
    
    self.lightSecretSuccInside = readSecretNote;
    self.lightSecretExvInside = exclusiveMode;
    self.timeoutInside = timeout;
    self.insideCode = error;
    _requestType = deceiveOnlySec;
    self.SecurityString = securityNote;
    self.JMtype = CBCommGotoSecurityNoteS;
    self.operationCancelInside = cancelOperation;
    
    [self sendTheBleData:sendData];
    
    
}


- (void)OnleReadTheDeviceSecretNote:(NSString*)securityNote {
    
    NSMutableData * itemTitleN = [self dataWithStringS:securityNote];
    
    
    NSData *sendData = [JMCoreCommandCenter commandWithType:CBCommGotoSecurityNoteS object:itemTitleN];
    
    
    [self sendTheBleData:sendData];
    
    
}


- (void)lastONlySecretBook:(UInt8*)buffer withDataLength:(int)len {
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        
        JMD_RESULT  jmd_result;
        
        BTComm_showSecurityNote_3040R (buffer,(uint32_t)len,&jmd_result);
        
        
        NSLog(@"解析只读密条:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析只读密条:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x6100){
            
            if (self.lightSecretExvInside) {
                
                self.lightSecretExvInside();
            }
            
            
            [self RequestgetResponse:0];
            
        }else if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x9000){
            
            if (self.lightSecretSuccInside) {
                
                self.lightSecretSuccInside();
            }
            
            
            
        } else {
            
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
            
            
            
        }
        
        
        
        
    } else {
        
        _num12++;
        
        if (_num12 <= 3) {
            
            //            [self OnleReadTheDeviceSecretBook:_SerectData];
            
        }
        
    }
    
    
}

#pragma mark - 读取密码


- (void)readTheDevicepasssWordWithResult:(void(^)(NSArray* secretNoteArray))SecretNoteModel errorBlock:(void(^)(ErrorCode code))error {
    
    NSLog(@"*********读取密码*********");
    NSData *sendData = [JMCoreCommandCenter commandWithType:CBCommGetSecurityBookS object:nil];
    
    
    self.passWord = SecretNoteModel;
    self.insideCode = error;
    _requestType = deceivePassWord;
    self.JMtype = CBCommGetSecurityBookS;
    
    [self sendTheBleData:sendData];
    
    
}

- (void)preectPassWordData:(UInt8*)result dataLenth:(UInt32)lenth {
    
    if ([_numData isEqualToData:_crcData]) {
        
        
        JMD_RESULT  jmd_result;
        
        BTComm_getResponse_3040R (result,lenth,&jmd_result);
        
        
        NSLog(@"解析密码数据:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析密码数据:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        
        
        if (jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 ==0x6100){
            
            
            [self.contentParsingData appendBytes:jmd_result.ResultData length:jmd_result.ResultSize];
            [self RequestgetResponse:0];
            
            
        } else if (jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 ==0x9000){
            
            [self.contentParsingData appendBytes:jmd_result.ResultData length:jmd_result.ResultSize];
            
            LPJMD_SECURITYBOOK  jmd_sb;
            uint32_t     jmd_sb_size;
            
            BTComm_enumSecurityBook_3040D ((LPBYTE)[self.contentParsingData bytes],(DWORD)self.contentParsingData.length, &jmd_sb,&jmd_sb_size);
            
            
            [self pretectPassWordData:jmd_sb dataLenth:jmd_sb_size];
            
            
            
        } else{
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
            
            
        }
        
        
        
        
        
    }
    
}



- (void)pretectPassWordData:(LPJMD_SECURITYBOOK)jmd_sb dataLenth:(uint32_t)jmd_s_size {
    
    
    
    NSMutableArray *mutArray = [NSMutableArray array];
    
    for ( uint32_t i=0; i<jmd_s_size; i ++ ){
        
        
        SecurityBookModel *SbMode = [[SecurityBookModel alloc] init];
        
        /** 分类名    */
        SbMode.itemCataName = [self gbk2utf8:jmd_sb[i].itemCataName];
        
        /**标题    */
        SbMode.itemTitle = [self gbk2utf8:jmd_sb[i].itemTitle];
        
        SbMode.acctName =  JMDeveiceType == 3 ? [self gbk2utf8:jmd_sb[i].acctName]:@"";
        
        
        
        /** 密码页保护级别*/
        SbMode.ProtectLevel = jmd_sb[i].ProtectLevel;
        
        /**密条保护级别*/
        SbMode.mtProtectLevel = jmd_sb[i].mtProtectLevel;
        
        SbMode.itemCataID = jmd_sb[i].itemCataID;
        
        /**口令项是否关联了应用*/
        SbMode.appLink = jmd_sb[i].appLink;
        
        /** 细节描述标题    */
        SbMode.itemDesc = [self gbk2utf8:jmd_sb[i].itemDesc];
        
        /** 编辑页面的 连接    */
        SbMode.xURL = [self gbk2utf8:jmd_sb[i].xURL];
        
        /** 显示年月日    */
        SbMode.lastDate = [self dateInFormat:jmd_sb[i].lastDate format: @"%Y-%m-%d"];
        
        
        NSPredicate *predicate = [NSPredicate predicateWithFormat:@"categroryNmae == %@", SbMode.itemCataName];
        
        NSArray *array = [mutArray filteredArrayUsingPredicate:predicate];
        
        
        if (array.count) {
            
            JMSecurityBModle *security = array[0];
            NSUInteger index = [mutArray indexOfObject:security];
            [security.securityArray addObject:SbMode];
            [mutArray replaceObjectAtIndex:index withObject:security];
            
        } else {
            
            JMSecurityBModle *sec = [[JMSecurityBModle alloc] init];
            sec.categroryNmae = SbMode.itemCataName;
            
            NSMutableArray * mutArr = [NSMutableArray array];
            [mutArr addObject:SbMode];
            sec.securityArray = mutArr;
            [mutArray addObject:sec];
        }
        
        
        
    }
    
    if (self.passWord) {
        
        self.passWord(mutArray.copy);
    }
    
    
    BTComm_getSecurityBookF(jmd_sb);
    self.contentParsingData = nil;
    
    
}


#pragma mark - 增加密码
- (void)addTheDevicePassWordItemTitle:(NSString*)itemTitle itemDescData:(NSString*)itemDesc accData:(NSString*)accName staticData:(NSString*)staticPwd itemCData:(UInt32)itemCataID itemCNaData:(NSString*)itemCataName WithResult:(void(^)())addSuccess errorBlock:(void(^)(ErrorCode code))error{
    
    NSLog(@"*************增加密码****************");
    
    self.AddPassB = addSuccess;
    self.insideCode = error;
    
    _requestType = deceiveAddPass;
    
    int length = [self stringLenght:itemTitle];
    
    if (length < 4 || length > 14) {
        
        [self errStrWithHexCode:0x3330];
        return;
    }
    
    int descLen = [self stringLenght:itemDesc];
    if (descLen < 4 || descLen > 128) {
        
        [self errStrWithHexCode:0x3331];
        return;
        
    }
    
    int acctNameLength = [self stringLenght:accName];
    
    if (acctNameLength < 1 || acctNameLength > 32) {
        
        [self errStrWithHexCode:0x3332];
        return;
    }
    
    int staticPwdLength = [self stringLenght:staticPwd];
    if (staticPwdLength < 1 || staticPwdLength > 32) {
        
        [self errStrWithHexCode:0x3333];
        return;
        
    }
    int itemCataNameLength = [self stringLenght:itemCataName];
    if (itemCataNameLength < 4 || itemCataNameLength > 14) {
        
        [self errStrWithHexCode:0x3334];
        return;
        
    }
    
    
    
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    UInt32 utcTime;
    
    if(JMDeveiceType > 2){
        
        utcTime = (UInt32)[[NSDate date] timeIntervalSince1970];
        
    }else{
        
        utcTime = 0;
    }
    
    
    NSMutableData * itemTitleN = [self dataWithStringS:itemTitle];
    NSMutableData * itemDescN = [self dataWithStringS:itemDesc];
    NSMutableData * accNameN = [self dataWithStringS:accName];
    NSMutableData * staticPwdN = [self dataWithStringS:staticPwd];
    NSMutableData * itemCataNameN = [self dataWithStringS:itemCataName];
    
    
    
    
    BTComm_addSecurityBook_3040S ((LPBYTE)cmd_buffer, &cmd_size,itemTitleN.bytes,itemDescN.bytes,accNameN.bytes,staticPwdN.bytes, itemCataID,itemCataNameN.bytes,utcTime);
    
    
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    
    [self sendTheBleData:sendData];
    
    
    
}


- (void)lastAddPassWord:(UInt8*)buffer withDataLength:(int)len {
    
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        JMD_RESULT  jmd_result;
        
        BTComm_addSecurityBook_3040R (buffer,(uint32_t)len, &jmd_result);
        
        NSLog(@"解析增加密码:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析增加密码:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        
        if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x9000){
            
            
            if (self.AddPassB) {
                
                self.AddPassB();
            }
            
        } else {
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
            
            
        }
        
        
    } else {
        
        
        _num10++;
        
        if (_num10 <= 3) {
            
            
            
        }
        
    }
    
}


#pragma mark - 编辑密码
- (void)EditThePassWordItemTitle:(NSString*)itemTitle itemDescData:(NSString*)itemDesc accData:(NSString*)accName staticData:(NSString*)staticPwd itemCData:(UInt32)itemCataID itemCNaData:(NSString*)itemCataName editSecurityBookType:(int)editPassType  WithResult:(void(^)())EditSuccess ExclusiveMode:(void(^)())exclusiveMode  exclusiveModeTimeOut:(void(^)())timeout operationCancel:(void(^)())cancelOperation errorBlock:(void(^)(ErrorCode code))error {
    NSLog(@"*************编辑密码****************");
    
    self.VerificationSuccInside = EditSuccess;
    self.lightonePass = exclusiveMode;
    self.operationCancelInside = cancelOperation;
    self.insideCode = error;
    self.timeoutInside = timeout;
    _requestType = deceiveEditPass;
    self.JMtype = CBCommupdateSecurityBookS;
    
    int length = [self stringLenght:itemTitle];
    
    if (length < 4 || length > 14) {
        
        [self errStrWithHexCode:0x3330];
        return;
    }
    
    int descLen = [self stringLenght:itemDesc];
    if (descLen < 4 || descLen > 128) {
        
        [self errStrWithHexCode:0x3331];
        return;
        
    }
    
    int acctNameLength = [self stringLenght:accName];
    
    if (acctNameLength < 1 || acctNameLength > 32) {
        
        [self errStrWithHexCode:0x3332];
        return;
    }
    
    int staticPwdLength = [self stringLenght:staticPwd];
    if (staticPwdLength < 1 || staticPwdLength > 32) {
        
        [self errStrWithHexCode:0x3333];
        return;
        
    }
    int itemCataNameLength = [self stringLenght:itemCataName];
    if (itemCataNameLength < 4 || itemCataNameLength > 14) {
        
        [self errStrWithHexCode:0x3334];
        return;
        
    }
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    
    
    NSMutableData * itemTitleN = [self dataWithStringS:itemTitle];
    NSMutableData * itemDescN = [self dataWithStringS:itemDesc];
    NSMutableData * accNameN = [self dataWithStringS:accName];
    NSMutableData * staticPwdN = [self dataWithStringS:staticPwd];
    NSMutableData * itemCataNameN = [self dataWithStringS:itemCataName];
    
    
    _Title = itemTitleN;
    _Desc = itemDescN;
    _Account = accNameN;
    _Password = staticPwdN;
    _cateName = itemCataNameN;
    _itemCaID = itemCataID;
    
    UInt32 utcTime;
    if(JMDeveiceType > 2){
        
        utcTime = (UInt32)[[NSDate date] timeIntervalSince1970];
        
    }else{
        
        utcTime = 0;
    }
    
    
    
    BTComm_updateSecurityBook_3040S ((LPBYTE)cmd_buffer, &cmd_size, itemTitleN.bytes, itemDescN.bytes,accNameN.bytes, staticPwdN.bytes,itemCataID, itemCataNameN.bytes,editPassType,utcTime);
    
    
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    
    
    [self sendTheBleData:sendData];
    
}



- (void)EditThePassWord {
    
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    
    
    UInt32 utcTime;
    if(JMDeveiceType > 2){
        
        utcTime = (UInt32)[[NSDate date] timeIntervalSince1970];
        
    }else{
        
        utcTime = 0;
    }
    
    
    
    BTComm_updateSecurityBook_3040S ((LPBYTE)cmd_buffer, &cmd_size, _Title.bytes, _Desc.bytes,_Account.bytes, _Password.bytes,_itemCaID, _cateName.bytes,1,utcTime);
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    
    _requestType = deceiveEditPass;
    
    
    [self sendTheBleData:sendData];
    
}


- (void)lastEditPassword:(UInt8*)buffer withDataLength:(int)len {
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        JMD_RESULT  jmd_result;
        
        BTComm_updateSecurityBook_3040R (buffer,(uint32_t)len, &jmd_result);
        
        NSLog(@"解析编辑密码:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析编辑密码:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        
        if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x6100){
            
            if (self.lightonePass) {
                self.lightonePass();
                
            }
            
            [self RequestgetResponse:0];
            
            
        }else if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x9000){
            
            
            if (self.VerificationSuccInside) {
                self.VerificationSuccInside();
            }
            
        } else {
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
        }
        
        
    } else {
        
        
        
        
    }
}

#pragma mark - 删除密码

- (void)deleteTheDevicePassWord:(NSString*)securityTitleName WithResult:(void(^)())deleteSuccess exclusiveModeTimeOut:(void(^)())timeout operationCancel:(void(^)())cancelOperation errorBlock:(void(^)(ErrorCode code))error {
    
    NSMutableData * itemTitleN = [self dataWithStringS:securityTitleName];
    
    
    
    NSData *sendData = [JMCoreCommandCenter commandWithType:CBCommdeleteSecurityBookS object:itemTitleN];
    
    self.VerificationSuccInside = deleteSuccess;
    self.timeoutInside = timeout;
    self.operationCancelInside = cancelOperation;
    self.insideCode = error;
    _requestType = deceiveDelePass;
    self.JMtype = CBCommdeleteSecurityBookS;
    
    
    [self sendTheBleData:sendData];
    
    
}



- (void)lastDeletePassword:(UInt8*)buffer withDataLength:(int)len {
    
    
    
    if ([_numData isEqualToData:_crcData]) {
        JMD_RESULT  jmd_result;
        
        
        BTComm_deleteSecurityBook_3040R (buffer,(uint32_t)len,&jmd_result);
        
        NSLog(@"解析删除密码:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析删除密码:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        
        if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x6100){
            
            
            [self RequestgetResponse:0];
            
        } else if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x9000){
            
            
            
            if (self.VerificationSuccInside) {
                
                self.VerificationSuccInside();
            }
            
            
        } else {
            
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
            
        }
        
        
    } else {
        
        
        _num16++;
        
        if (_num16 <= 3) {
            
            //            [self deleteTheDevicePassWord:_SerectData];
            
            
        }
    }
    
    
}


#pragma mark - 只读密码
- (void)OnleReadTheDeviceSecretBook:(NSString*)secyrityBookTitle WithResult:(void(^)())readSecretBook ExclusiveMode:(void(^)())exclusiveMode  exclusiveModeTimeOut:(void(^)())timeout operationCancel:(void(^)())cancelOperation errorBlock:(void(^)(ErrorCode code))error{
    
    NSLog(@"***********************点亮密码***********************");
    NSMutableData * itemTitleN = [self dataWithStringS:secyrityBookTitle];
    
    NSData *sendData = [JMCoreCommandCenter commandWithType:CBCommGotoSecurityBookS object:itemTitleN];
    
    
    self.lightPass = readSecretBook;
    self.lightSecretExvInside = exclusiveMode;
    self.insideCode = error;
    self.timeoutInside = timeout;
    self.SecurityString = secyrityBookTitle;
    self.operationCancelInside = cancelOperation;
    _requestType = deceiveOnlyPass;
    self.JMtype = CBCommGotoSecurityBookS;
    
    
    [self sendTheBleData:sendData];
    
    
}



- (void)OnleReadTheDeviceSecretBook:(NSString*)secyrityBookTitle {
    
    NSLog(@"***********************点亮密码***********************");
    NSMutableData * itemTitleN = [self dataWithStringS:secyrityBookTitle];
    
    NSData *sendData = [JMCoreCommandCenter commandWithType:CBCommGotoSecurityBookS object:itemTitleN];
    
    
    [self sendTheBleData:sendData];
    
    
}


- (void)lastOnlyPassword:(UInt8*)buffer withDataLength:(int)len{
    
    if ([_numData isEqualToData:_crcData]) {
        
        JMD_RESULT  jmd_result;
        
        BTComm_showSecurityBook_3040R (buffer, (uint32_t)len,  &jmd_result);
        
        NSLog(@"解析点亮密码:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析点亮密码:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        
        if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x9000){
            
            if (self.lightPass) {
                
                self.lightPass();
            }
            
        }else if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x6100){
            
            if (self.lightSecretExvInside) {
                
                self.lightSecretExvInside();
            }
            
            
            [self RequestgetResponse:0];
            
            
            
            
        } else {
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
            
        }
        
    }
    
}


#pragma mark - 密码分类修改

- (void)editSecurityBookCategoryWithnewCatalogName:(NSString*)newCatalogName olditemCataID:(UInt32)oldNameID oldCatalogName:(NSString*)oldCatalogName WithResult:(void(^)())successEdit errorBlock:(void(^)(ErrorCode code))error{
    NSLog(@"***********************密码分类修改***********************");
    self.cateModetiy = successEdit;
    self.insideCode = error;
    _requestType = deceiveNamePass;
    
    int itemCataNameLength = [self stringLenght:newCatalogName];
    if (itemCataNameLength < 4 || itemCataNameLength > 14) {
        
        [self errStrWithHexCode:0x3334];
        return;
        
    }
    
    
    
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    
    NSMutableData * oldName = [self dataWithStringS:oldCatalogName];
    NSMutableData * neName = [self dataWithStringS:newCatalogName];
    
    BTComm_updateCatalog_3040S ((LPBYTE)cmd_buffer,&cmd_size,oldNameID,oldName.bytes,neName.bytes, model, version);
    
    
    NSData * sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    
    [self sendTheBleData:sendData];
    
    
    
}



- (void)lastNamePassword:(UInt8*)buffer withDataLength:(int)len{
    
    if ([_numData isEqualToData:_crcData]) {
        
        JMD_RESULT  jmd_result;
        
        BTComm_updateCatalog_3040R (buffer,(uint32_t)len,&jmd_result);
        
        
        
        if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x9000){
            
            if (self.cateModetiy) {
                
                self.cateModetiy();
            }
            
        } else {
            
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
            
        }
        
    }
}



#pragma mark - 密码标题修改
- (void)requestUpdateSecurityBookItemTitle:(NSString*)old_itemTitle withNewTitle:(NSString*)new_itemTitle WithResult:(void(^)())successEdit errorBlock:(void(^)(ErrorCode code))error {
    
    NSLog(@"***********************密码标题修改***********************");
    self.updataTitle = successEdit;
    self.insideCode = error;
    _requestType = devUpdateSecurityBook;
    
    int itemCataNameLength = [self stringLenght:new_itemTitle];
    if (itemCataNameLength < 4 || itemCataNameLength > 14) {
        
        [self errStrWithHexCode:0x3330];
        return;
        
    }
    
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    NSMutableData * oldName = [self dataWithStringS:old_itemTitle];
    NSMutableData * neName = [self dataWithStringS:new_itemTitle];
    
    BTComm_updateSecurityBookItemTitle_3040S ((LPBYTE)cmd_buffer,&cmd_size, oldName.bytes,neName.bytes);
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    
    
    [self sendTheBleData:sendData];
}


- (void)lastAnalyUpdateSecurityBookItemTitle:(UInt8*)buffer withDataLength:(int)len {
    
    if ([_numData isEqualToData:_crcData]) {
        JMD_RESULT  jmd_result;
        
        BTComm_updateSecurityBookItemTitle_3040R (buffer,len,&jmd_result);
        
        NSLog(@"修改密码标题..:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"修改密码标题...:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        if(jmd_result.ErrorCode1 ==0x9000 && jmd_result.ErrorCode2 ==0x9000){
            
            if (self.updataTitle) {
                self.updataTitle();
            }
            
        }else {
            
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
        }
        
        
        
        
    }
}


#pragma mark - 备份数据
- (void)backUpTheDeceiveDataWithResult:(void(^)(NSData* backupData))backupSucess DevProgress:(void(^)(DWORD progress))progress exclusiveModeTimeOut:(void(^)())timeout operationCancel:(void(^)())cancelOperation errorBlock:(void(^)(ErrorCode code))error {
    
    NSLog(@"*********************备份数据****************************");
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    BTComm_Backup_3040S ((LPBYTE)cmd_buffer,&cmd_size);
    
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    self.backString = backupSucess;
    self.timeoutInside = timeout;
    self.operationCancelInside = cancelOperation;
    self.insideCode = error;
    _requestType = deceiveBackUpData;
    self.JMtype = CBCommBackupSOne;
    
    self.backupNumber = progress;
    
    [self sendTheBleData:sendData];
    
    
}



- (void)backUpDataAnaly:(UInt8*)result dataLenth:(UInt32)lenth {
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        
        int8_t     cmd_buffer[BufSize];
        uint32_t   cmd_size = sizeof(cmd_buffer);
        JMD_RESULT  jmd_result;
        uint32_t  	dwRet;
        
        
        dwRet = BTComm_Backup_3040R (result, lenth, &jmd_result);
        
        NSLog(@"解析备份数据..:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析备份数据..:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        if ( jmd_result.ResultSize != 0 || jmd_result.ErrorCode2 == 0x9000) {
            
            [self.contentParsingData appendBytes:jmd_result.ResultData length:jmd_result.ResultSize];
            
            NSLog(@"我是备份长度:-->%lu",(unsigned long)self.contentParsingData.length);
            
            
            
            
            
            if ( jmd_result.ErrorCode2 == 0x6100 ){
                
                _backupNframe ++;
            }else if (jmd_result.ErrorCode2 == 0x9000 ) {
                
                _backupNframe = 0;
                _backupBlockType++;
            }else{
                //貌似不会到这......
            }
            
            
            dwRet = BTComm_Backup_Next_3040S ((LPBYTE)cmd_buffer,&cmd_size,_backupNframe, _backupBlockType, model, version);
            
            
            self.backupNumber(_backupBlockType);
            
            if (dwRet == 0) {
                NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
                
                
                [self sendTheBleData:sendData];
                
            }else if (dwRet == API_BACKUP_ALL_FINISHED ){
                
                if (self.backString) {
                    self.backString(self.contentParsingData.copy);
                }
                self.contentParsingData = nil;
            }
            NSLog(@"------->我是备份循环次数:%d---REsult:%d", _backupBlockType, jmd_result.ResultSize);
            
        }else if (jmd_result.ErrorCode2 == 0x6100 ) {
            
            [self RequestgetResponse:0];
            
            
        } else{
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
            
            
        }
    }
}


#pragma mark - 恢复备份

- (void)restoreBackupTheDeviceData:(NSData*)receviceData  WithResult:(void(^)())restoureSucess exclusiveModeTimeOut:(void(^)())timeout operationCancel:(void(^)())cancelOperation errorBlock:(void(^)(ErrorCode code))error {
    
    NSLog(@"************************恢复备份************************");
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    _receviceData = receviceData;
    
    BTComm_Restore_3040S((LPBYTE)cmd_buffer,&cmd_size,(LPBYTE)receviceData.bytes, (DWORD)receviceData.length,&_backOffse, model, version);
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    self.backUpdata = restoureSucess;
    self.timeoutInside = timeout;
    self.operationCancelInside = cancelOperation;
    self.insideCode = error;
    _requestType = deviceUpData;
    self.JMtype = CBTCommRestoreS;
    
    [self sendTheBleData:sendData];
    
}

- (void)restoreBackupInside {
    
    NSLog(@"************************恢复备份************************");
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    BTComm_Restore_3040S((LPBYTE)cmd_buffer,&cmd_size,(LPBYTE)_receviceData.bytes, (DWORD)_receviceData.length,&_backOffse, model, version);
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    [self sendTheBleData:sendData];
    
    
}


- (void)lastDeviceBackUp:(UInt8*)buffer withDataLength:(int)len {
    
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        JMD_RESULT  jmd_result;
        
        BTComm_Restore_3040R (buffer,(uint32_t)len,&jmd_result);
        
        
        NSLog(@"解析恢复备份数据:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析恢复备份数据:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        
        if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x9000){
            
            
            if (_backOffse < _receviceData.length) {
                
                [self restoreBackupInside];
                
            }else{
                
                if (self.backUpdata) {
                    
                    self.backUpdata();
                }
                
            }
            
        }else if (jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x6100) {
            
            
            
            [self RequestgetResponse:0];
            
            
        } else {
            
            if (jmd_result.ErrorCode1 == 0x6405 && jmd_result.ErrorCode2 == 0x6608){
                
                _backOffse = 0;
            }
            [self errStrWithHexCode:jmd_result.ErrorCode2];
            
        }
        
        
    }else {
        
        
        [self presentControl];
        
    }
    
}



#pragma mark - 固件升级

- (void)deceiveUpdataWithData:(NSData*)updataData Result:(void(^)())updataSucess updataProgress:(void(^)(CGFloat progress))progress exclusiveModeTimeOut:(void(^)())timeout operationCancel:(void(^)())cancelOperation errorBlock:(void(^)(ErrorCode code))error {
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    NSData *data;
    _receviceData = updataData;
    
    _receviceLenthJM = updataData.length;
    _recevice2 = _receviceLenthJM;
    
    if(_receviceLenthJM  > recData){
        
        data = [_receviceData subdataWithRange:NSMakeRange(recData*_sendCountJM, recData)];
        _receviceLenthJM -= recData;
        
    } else {
        
        
        data = [_receviceData subdataWithRange:NSMakeRange(_receviceData.length - _receviceLenthJM, _receviceLenthJM)];
        
        _sendTypeJM = 1;
        
    }
    
    BTComm_upgradeFirmware_3040S ((LPBYTE)cmd_buffer, &cmd_size, _sendTypeJM,  (LPBYTE)data.bytes, (DWORD)data.length, (DWORD)_receviceData.length,_sendCountJM);
    
    
    
    if(JMDeveiceType <= 2){
        
        CGFloat per = 1.00 - (CGFloat)_receviceLenthJM/_receviceData.length;
        
        
        if (self.updataNum) {
            self.updataNum(per);
        }
        
        
    }
    
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    
    self.updataBlackJ = updataSucess;
    self.timeoutInside = timeout;
    self.operationCancelInside = cancelOperation;
    self.insideCode = error;
    self.updataNum = progress;
    _requestType = devieceJMData;
    self.JMtype = CBCommupgradeFirmwareS;
    
    [self sendTheBleData:sendData];
    
    
    _sendCountJM ++;
    
    
}

- (void)deviceUpdataInside {
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    NSData *data;
    
    if(_receviceLenthJM  > recData){
        
        data = [_receviceData subdataWithRange:NSMakeRange(recData*_sendCountJM, recData)];
        _receviceLenthJM -= recData;
        
    } else {
        
        
        data = [_receviceData subdataWithRange:NSMakeRange(_receviceData.length - _receviceLenthJM, _receviceLenthJM)];
        
        _sendTypeJM = 1;
        
    }
    
    BTComm_upgradeFirmware_3040S ((LPBYTE)cmd_buffer, &cmd_size, _sendTypeJM,  (LPBYTE)data.bytes, (DWORD)data.length, (DWORD)_receviceData.length,_sendCountJM);
    
    
    
    if(JMDeveiceType <= 2){
        
        CGFloat per = 1.00 - (CGFloat)_receviceLenthJM/_receviceData.length;
        
        
        if (self.updataNum) {
            self.updataNum(per);
        }
        
        
    }
    
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    
    _requestType = devieceJMData;
    
    [self sendTheBleData:sendData];
    
    
    _sendCountJM ++;
    
    
    
    
    
}


- (void)lastJMUpData:(UInt8*)buffer withDataLength:(int)len{
    
    if ([_numData isEqualToData:_crcData]) {
        
        JMD_RESULT  jmd_result;
        
        BTComm_upgradeFirmware_3040R (buffer,(uint32_t)len,&jmd_result);
        
        
        if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x9000){
            
            if (_sendTypeJM == 0) {
                
                if (JMDeveiceType == 3) {
                    
                    CGFloat per = 1.00 - (CGFloat)_receviceLenthJM/_receviceData.length;
                    
                    
                    if (self.updataNum) {
                        
                        self.updataNum(per);
                    }
                    
                }
                
                [self deviceUpdataInside];
                
            } else {
                
                
                if (self.updataBlackJ) {
                    
                    self.updataBlackJ();
                }
                
            }
            
            
        }else if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x6100){
            
            
            [self RequestgetResponse:0];
            
            
        }else {
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
            
            
        }
        
    }
    
    
}

#pragma mark - 获取设备公钥

- (void)RequestDevPublicKeyWithResult:(void(^)(NSString *publicString))publicString errorBlock:(void(^)(ErrorCode code))error {
    
    NSLog(@"*****************获取设备公钥*******************");
    
    NSData *sendData = [JMCoreCommandCenter commandWithType:DevPublicKey object:NULL];
    
    self.PubData = publicString;
    self.insideCode = error;
    _requestType = devPublicKey;
    
    [self sendTheBleData:sendData];
    
}


- (void)lastAnalyDevPublicKey:(UInt8*)buffer withDataLength:(int)len {
    
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        
        uint8_t     derPublicKey[264];
        uint32_t    derPublicKeySIZE = sizeof(derPublicKey);
        
        int success = BTComm_getDevicePublicKey_3040D(buffer, len, derPublicKey, &derPublicKeySIZE);
        
        WORD ErrorCode1 = (WORD)((success >> 16)&0xFFFF);
        WORD ErrorCode2 = (WORD)(success);
        NSLog(@"解析获取公钥:errorcode1: 0x%x", ErrorCode1);
        NSLog(@"解析获取公钥:errorcode2: 0x%x", ErrorCode2);
        
        if (!success) {
            
            NSString *publicKey = HexStringFromBytes(derPublicKey, derPublicKeySIZE);
            
            
            if (publicKey.length == 136) {
                
                if (self.PubData) {
                    
                    self.PubData(HexStringFromBytes(derPublicKey, derPublicKeySIZE));
                }
            } else {
                
                [self errStrWithHexCode:ErrorCode2];
                
            }
        } else{
            
            [self errStrWithHexCode:ErrorCode2];
            
        }
        
    } else {
        
        
    }
    
}

#pragma mark - 获取联机通道

- (void)RequestSecurityChanelWithBToken:(uint8_t*)bToken bTokenLength:(DWORD)BLength withAToken:(uint8_t*)AToken ATokenLength:(DWORD)ALength WithResult:(void(^)(NSData *sessionKey))sessionKey errorBlock:(void(^)(ErrorCode code))error {
    
    NSLog(@"*****************获取联机通道*******************");
    
    uint8_t     cmd_buffNew[BufSize];
    uint32_t    cmd_sizeNew =sizeof(cmd_buffNew);
    
    
    
    BTComm_requestSecurityChannel_3040S(cmd_buffNew,  &cmd_sizeNew, 0, bToken, BLength, AToken, ALength);
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffNew length:cmd_sizeNew];
    
    self.secureSring = sessionKey;
    self.insideCode = error;
    _requestType = devSecurityCha;
    
    [self sendTheBleData:sendData];
    
}


- (void)lastAnalyDevSecurityCha:(UInt8*)buffer withDataLength:(int)len {
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        uint32_t    _tempRx = arc4random();
        uint8_t     _tempCK[16];
        uint32_t    _tempckSIZE = sizeof(_tempCK);
        
        
        int success = BTComm_requestSecurityChannel_3040D(buffer,len, _tempRx, _tempCK, &_tempckSIZE);
        
        
        WORD ErrorCode1 = (WORD)((success >> 16)&0xFFFF);
        WORD ErrorCode2 = (WORD)(success);
        
        NSLog(@"解析联机通道..:errorcode1: 0x%x", ErrorCode1);
        NSLog(@"解析联机通道...:errorcode2: 0x%x", ErrorCode2);
        NSString *tempCK = HexStringFromBytes(_tempCK, 16);
        NSLog(@"我是tempCK: %@", tempCK);
        
        
        
        if (!success) {
            
            NSData *data = [[NSData alloc] initWithBytes:_tempCK length:_tempckSIZE];
            
            if (self.secureSring) {
                self.secureSring(data);
            }
            
        }else{
            
            
            if (self.secureSring) {
                self.secureSring(nil);
            }
            
            [self errStrWithHexCode:ErrorCode2];
            
        }
        
        
        
    }
}


#pragma mark - 下发联机会话密钥

- (void)RequestSetSessionKey:(NSData*)data WithResult:(void(^)())sucessSessionKey errorBlock:(void(^)(ErrorCode code))error {
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    
    BTComm_setSessionKey_3040S ((LPBYTE)cmd_buffer, &cmd_size,(uint8_t *)data.bytes, (uint32_t)data.length, 0);
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    
    self.Sesskey = sucessSessionKey;
    self.insideCode = error;
    _requestType = devPostKey;
    
    [self sendTheBleData:sendData];
    
}




- (void)lastAnalyPostSessionKey:(UInt8*)buffer withDataLength:(int)len {
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        JMD_RESULT  jmd_result;
        
        
        BTComm_setSessionKey_3040R (buffer,len,&jmd_result);
        
        NSLog(@"解析下发会话密钥:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析下发会话密钥:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        if (jmd_result.ErrorCode1 ==0x9000 && jmd_result.ErrorCode2 == 0x9000) {
            
            
            if (self.Sesskey) {
                self.Sesskey();
            }
            
            
        }
        
        
        
        
    } else {
        
        
        
    }
    
    
    
    
}

#pragma mark - 获取随机数

- (void)RequestRandomNumberWithResult:(void(^)(NSData*random))sucessRandom errorBlock:(void(^)(ErrorCode code))error {
    
    NSData *sendData = [JMCoreCommandCenter commandWithType:DevRandomNum object:nil];
    
    
    self.randomNumber = sucessRandom;
    self.insideCode = error;
    _requestType = devRamNu;
    
    [self sendTheBleData:sendData];
    
}

- (void)lastAnalyRandomNumber:(UInt8*)buffer withDataLength:(int)len {
    
    if ([_numData isEqualToData:_crcData]) {
        
        
        uint8_t     _tempCK[16];
        uint32_t    _tempckSIZE = sizeof(_tempCK);
        
        int success = BTComm_getRandomNumber_3040D (buffer,len,_tempCK, &_tempckSIZE);
        
        
        WORD ErrorCode1 = (WORD)((success >> 16)&0xFFFF);
        WORD ErrorCode2 = (WORD)(success);
        
        NSLog(@"解析随机数..:errorcode1: 0x%x", ErrorCode1);
        NSLog(@"解析随机数...:errorcode2: 0x%x", ErrorCode2);
        
        
        if (!success) {
            
            if (self.randomNumber) {
                self.randomNumber([NSData dataWithBytes:_tempCK length:_tempckSIZE]);
            }
            
            
        }else {
            [self errStrWithHexCode:ErrorCode2];
            
        }
        
        
    } else {
        
        
        
    }
    
    
}


#pragma mark - 申请AToken //验证
- (void)RequestVerifyPINWithType:(DWORD)Type RandomNum:(NSData*)RandomNumber withPin:(NSString*)PIN WithToken:(NSData*)bToken  WithResult:(void(^)(NSData*aTokan))aToaken  passworderrorBlock:(void(^)(int number))number errorBlock:(void(^)(ErrorCode code))error{
    NSLog(@"*****************申请AToken验证*******************");
    
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    
    uint8_t PIN_SHA1[CC_SHA1_DIGEST_LENGTH];
    NSData *PIN_Data  = [PIN dataUsingEncoding: NSUTF8StringEncoding];
    CC_SHA1(PIN_Data.bytes, (unsigned int)PIN_Data.length, PIN_SHA1);
    
    
    BTComm_verifyPIN_3040S ((LPBYTE)cmd_buffer,&cmd_size,Type, (LPBYTE)RandomNumber.bytes,PIN_SHA1,(LPBYTE)bToken.bytes,(DWORD)bToken.length);
    
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    
    self.aToken = aToaken;
    self.insideCode = error;
    self.passError = number;
    _requestType = devVerifyPIN;
    
    [self sendTheBleData:sendData];
    
}




- (void)lastAnalyVerifyPIN:(UInt8*)buffer withDataLength:(int)len {
    
    if ([_numData isEqualToData:_crcData]) {
        
        JMD_RESULT  jmd_result;
        BTComm_verifyPIN_3040D (buffer,len,&jmd_result);
        
        
        NSLog(@"解析验证PIN码:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析验证PIN码:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        
        if (jmd_result.ErrorCode1 ==0x9000 && jmd_result.ErrorCode2 == 0x9000) {
            
            NSData *aToken = [NSData dataWithBytes:jmd_result.ResultData length:jmd_result.ResultSize];
            
            
            if (self.aToken) {
                self.aToken(aToken);
            }
            
            
        } else if ((jmd_result.ErrorCode2&0xFF) == 0x26) {
            
            WORD num = (WORD)(jmd_result.ErrorCode2);
            
            
            num = (BYTE)((num >> 8) & 0xFF);
            
            
            if (self.passError) {
                self.passError(num);
            }
            
            
        }else if (jmd_result.ErrorCode2 == 0x25){
            
            if (self.passError) {
                self.passError(0);
            }
            
            
        }else{
            
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
            
        }
        
    }
    
}



#pragma mark - 下发用户秘钥

- (void)putUserKeyToDevice:(NSString*)userKey  WithResult:(void(^)(BOOL sucess))sucess errorBlock:(void(^)(ErrorCode code))error{
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    NSData *baseDate = [[NSData alloc] initWithBase64EncodedString:userKey options:0];
    
    
    BTComm_setUserData_3040S ((LPBYTE)cmd_buffer,&cmd_size,(LPBYTE)baseDate.bytes,(DWORD)[baseDate length]);
    
    
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    self.userKeyBOOL = sucess;
    self.insideCode = error;
    _requestType = deceivePutUserKey;
    
    [self sendTheBleData:sendData];
    
    
}


- (void)veryBiglastLastAnalyDevceiveSer:(UInt8*)buffer withDataLength:(int)len {
    
    
    if ([_numData isEqualToData:_crcData]) {
        JMD_RESULT  jmd_result;
        
        BTComm_setUserData_3040R (buffer,(uint32_t)len,&jmd_result);
        
        NSLog(@"解析下发用户秘钥:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析下发用户秘钥:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        
        if (jmd_result.ErrorCode1 ==0x9000 && jmd_result.ErrorCode2 == 0x9000) {
            
            
            
            if (self.userKeyBOOL) {
                
                self.userKeyBOOL(YES);
            }
            
            
        } else if (jmd_result.ErrorCode2 != 0x9000) {
            
            if (self.userKeyBOOL) {
                
                self.userKeyBOOL(NO);
            }
            
        }
        
        [self errStrWithHexCode:jmd_result.ErrorCode2];
        
    } else {
        
        _num4++;
        
        if (_num4 <= 3) {
            
            
            
        }
        
    }
}


#pragma mark - 验证+修改 PIN (独占模式)
- (void)requestmodifyPIN_EM:(DWORD)type  WithResult:(void(^)())exclusiveMode exclusiveModeTimeOut:(void(^)())timeout operationCancel:(void(^)())cancelOperation errorBlock:(void(^)(ErrorCode code))error{
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    
    BTComm_verify_modifyPIN_EM_3040S ((LPBYTE)cmd_buffer,&cmd_size,type);
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    self.VerifyPIN = exclusiveMode;
    self.insideCode = error;
    _requestType = devModeifyPINTwo;
    self.JMtype = DEverificationPIN;
    self.timeoutInside = timeout;
    self.operationCancelInside = cancelOperation;
    
    [self sendTheBleData:sendData];
}



- (void)lastAnalyVverify_modifyPIN:(UInt8*)buffer withDataLength:(int)len {
    
    if ([_numData isEqualToData:_crcData]) {
        JMD_RESULT  jmd_result;
        
        
        BTComm_getResponse_3040R (buffer,len,&jmd_result);
        
        NSLog(@"验证设备PIN:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"验证设备PIN:errorcode2: 0x%x", jmd_result.ErrorCode2);
        if(jmd_result.ErrorCode1 ==0x9000 && jmd_result.ErrorCode2 ==0x6100){
            
            if (self.VerifyPIN) {
                
                self.VerifyPIN();
            }
            
        }else {
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
            
        }
        
        
        
        
    }
}

#pragma mark - 发送键盘字符
- (void)RequestSendInput:(LPBYTE)lpChar withSize:(DWORD)size WithResult:(void(^)())success errorBlock:(void(^)(ErrorCode code))error {
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    BTComm_sendInput_3040S ((LPBYTE)cmd_buffer,&cmd_size,lpChar,size);
    
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    
    self.VerificationSuccInside = success;
    self.insideCode = error;
    _requestType = devSendInput;
    
    [self sendTheBleData:sendData];
    
}


- (void)lastAnalySendInput:(UInt8*)buffer withDataLength:(int)len {
    
    if ([_numData isEqualToData:_crcData]) {
        JMD_RESULT  jmd_result;
        
        BTComm_sendInput_3040R (buffer,len,&jmd_result);
        NSLog(@"解析发送键盘字符:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析发送键盘字符:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        if(jmd_result.ErrorCode2 ==0x1081||jmd_result.ErrorCode2 ==0x1082){
            
            if (self.JMtype == CBCommGotoSecurityNoteS) {
                
                
                
                [self OnleReadTheDeviceSecretNote:self.SecurityString];
                
                
            }else if (self.JMtype == CBCommGotoSecurityBookS) {
                
                [self OnleReadTheDeviceSecretBook:self.SecurityString];
                
            }else if (self.JMtype == CBCommupdateSecurityBookS) {
                
                [self EditThePassWord];
            }
            
            
            
        } else if(jmd_result.ErrorCode2 ==0x6100 || jmd_result.ErrorCode2 ==0x9000){
            
            
            
            [self RequestgetResponse:0];
            
            
            
        }
        
    }
}

#pragma mark - 验证设备PIN**********
- (void)RequestVerificationPIN:(NSString*)oldPIN WithResult:(void(^)())success  passworderrorBlock:(void(^)(int number))number {
    
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    NSMutableData * staticPwd = [self modifyPINWithString:oldPIN];
    
    BTComm_sendInput_3040S ((LPBYTE)cmd_buffer,&cmd_size,(LPBYTE)staticPwd.bytes,(DWORD)staticPwd.length);
    
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    
    _requestType = VerificationPIN;
    self.VerificationSuccInside = success;
    self.passError = number;
    
    [self sendTheBleData:sendData];
    
}







#pragma mark - 设备重置
- (void)requestresetFactory:(NSData*)eCloudCMD WithResult:(void(^)())success errorBlock:(void(^)(ErrorCode code))error {
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    BTComm_resetFactory_3040S((LPBYTE)cmd_buffer,&cmd_size,(LPBYTE)eCloudCMD.bytes, (DWORD)eCloudCMD.length);
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    self.VerificationSuccInside = success;
    self.insideCode = error;
    _requestType = devResetFactory;
    self.JMtype = DEvResetFactory;
    
    [self sendTheBleData:sendData];
}


- (void)lastAnalyResetFactory:(UInt8*)buffer withDataLength:(int)len {
    
    if ([_numData isEqualToData:_crcData]) {
        JMD_RESULT  jmd_result;
        
        
        BTComm_setLicense_3040R (buffer,len, &jmd_result);
        
        NSLog(@"解析设备重置..:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析设备重置...:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        if(jmd_result.ErrorCode1 ==0x9000 && jmd_result.ErrorCode2 ==0x9000){
            
            
            if (self.VerificationSuccInside) {
                
                self.VerificationSuccInside();
            }
            
            
            
        }else if ( jmd_result.ErrorCode1 ==0x9000 && jmd_result.ErrorCode2 == 0x6100 ) {
            
            [self RequestgetResponse:0];
            
        }
        
    }
}



#pragma mark - 动态设备参数下发
- (void)requestSetDeviceParamater:(DWORD)Min withMax:(DWORD)Max withTrycount:(DWORD)TryCount withSleep:(DWORD)Sleep withPoweroff:(DWORD)PowerOff withNice:(NSString *)NiceName  WithResult:(void(^)())success errorBlock:(void(^)(ErrorCode code))error {
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    NSMutableData * devname = [self dataWithStringS:NiceName];
    BTComm_setDeviceParamater_3040S ((LPBYTE)cmd_buffer,&cmd_size, Min, Max,TryCount,Sleep, PowerOff, devname.bytes);
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    
    self.changeName = success;
    self.insideCode = error;
    _requestType = devSetParamater;
    
    [self sendTheBleData:sendData];
}



- (void)lastAnalySetDeviceParamater:(UInt8*)buffer withDataLength:(int)len {
    
    if ([_numData isEqualToData:_crcData]) {
        JMD_RESULT  jmd_result;
        
        BTComm_setDeviceParamater_3040R (buffer,len,&jmd_result);
        
        if(jmd_result.ErrorCode1 ==0x9000 && jmd_result.ErrorCode2 ==0x9000){
            
            if (self.changeName) {
                self.changeName();
            }
            
        }else{
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
            
        }
        
    }
}






#pragma mark - 备份密钥显示+重置+输入
- (void)requestBackupKeyType:(DWORD)type withKeyID:(DWORD)bakcupKeyID {
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    
    
    BTComm_backupKey_3040S((LPBYTE)cmd_buffer,&cmd_size,type,bakcupKeyID);
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    //    self.VerifyPIN = sucess;
    //    self.insideCode = error;
    _requestType = devBackUPKey;
    
    [self sendTheBleData:sendData];
}


- (void)lastAnalyBackupKey:(UInt8*)buffer withDataLength:(int)len {
    
    if ([_numData isEqualToData:_crcData]) {
        JMD_RESULT  jmd_result;
        
        BTComm_backupKey_3040R (buffer,len,&jmd_result);
        NSLog(@"解析查看备份密钥...:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析查看备份密钥...:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
    }
}



#pragma mark - 退出独占模式
- (void)requestExitExclusiveMode {
    
    NSData *sendData = [JMCoreCommandCenter commandWithType:DevExitMode object:nil];
    
    //    self.VerifyPIN = sucess;
    //    self.insideCode = error;
    _requestType = devExitMode;
    
    [self sendTheBleData:sendData];
    
}

- (void)lastAnalyExitMode:(UInt8*)buffer withDataLength:(int)len {
    
    if ([_numData isEqualToData:_crcData]) {
        JMD_RESULT  jmd_result;
        BTComm_exitExclusiveMode_3040R (buffer,len,&jmd_result);
        
        NSLog(@"解析退出独占模式:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析退出独占模式:errorcode2: 0x%x", jmd_result.ErrorCode2);
        if(jmd_result.ErrorCode1 ==0x9000 && jmd_result.ErrorCode2 ==0x9000){
            
            if (self.ExitMOde) {
                self.ExitMOde();
            }
            
        }
        
        
    }
}

#pragma mark -  枚举主密钥
- (void)enumMainEncryptKeyType:(DWORD)keyType  WithResult:(void(^)())success errorBlock:(void(^)(ErrorCode code))error {
    
    
    NSLog(@"*****************枚举主密钥*******************");
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    
    BTComm_enumMainEncryptKey_3040S((LPBYTE)cmd_buffer, &cmd_size, MENCKEY_INTERNAL);
    
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    self.enumMainPassword = success;
    self.insideCode = error;
    _requestType = devEncryptKey;
    
    [self sendTheBleData:sendData];
    
    
}

- (void)lastAnalyEnumMainEncryptKey:(UInt8*)buffer withDataLength:(int)len {
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        UInt8 lpHandles[160];
        DWORD lpnkeys;
        
        int success = BTComm_enumMainEncryptKey_3040D (buffer,len,lpHandles, &lpnkeys);
        
        WORD ErrorCode1 = (WORD)((success >> 16)&0xFFFF);
        WORD ErrorCode2 = (WORD)(success);
        NSLog(@"解析枚举密钥:errorcode1: 0x%x", ErrorCode1);
        NSLog(@"解析枚举密钥:errorcode2: 0x%x", ErrorCode2);
        
        if (!success) {
            
            memset(handleInside, 0x00, sizeof(handleInside));
            memcpy(handleInside,lpHandles , 160);
            
            
            if (self.enumMainPassword) {
                
                self.enumMainPassword();
            }
            
            
        } else {
            
            [self errStrWithHexCode:ErrorCode2];
        }
        
        
        
    }
    
    
}

#pragma mark - 加密初始化

- (void)EncryptInit_3040SWithResult:(void(^)())success errorBlock:(void(^)(ErrorCode code))error {
    
    NSLog(@"*****************加密初始化*******************");
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    
    BTComm_EncryptInit_3040S ((LPBYTE)cmd_buffer,&cmd_size,-1,handleInside,0, ALG_SM4_ECB,PADDING_NONE, NULL,SLOTNUM_KDBK);
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    self.encryptInit = success;
    self.insideCode = error;
    _requestType = EncryptInit;
    
    
    [self sendTheBleData:sendData];
    
    
}

- (void)lastAnalyEncryptInit_3040R:(UInt8*)buffer withDataLength:(int)len {
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        JMD_RESULT jmd_result;
        
        BTComm_EncryptInit_3040R (buffer,len, &jmd_result);
        
        NSLog(@"加密初始化:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"加密初始化:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x9000){
            
            
            if (self.encryptInit) {
                
                self.encryptInit();
            }
            
        } else {
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
        }
        
        
    }
    
    
}

#pragma mark - 解密初始化
- (void)DecryptInit_3040SWithResult:(void(^)())success errorBlock:(void(^)(ErrorCode code))error {
    
    NSLog(@"*****************解密初始化*******************");
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    
    
    BTComm_DecryptInit_3040S ((LPBYTE)cmd_buffer,&cmd_size,-1, handleInside,0,ALG_SM4_ECB,PADDING_NONE, NULL,SLOTNUM_KDBK);
    
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    self.DecryptInit = success;
    self.insideCode = error;
    _requestType = DecryptInit;
    
    
    [self sendTheBleData:sendData];
    
    
}

- (void)lastAnalyDecryptInit_3040S:(UInt8*)buffer withDataLength:(int)len {
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        JMD_RESULT jmd_result;
        
        BTComm_DecryptInit_3040R (buffer,len, &jmd_result);
        
        NSLog(@"解密初始化:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解密初始化:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x9000){
            
            
            if (self.DecryptInit) {
                
                self.DecryptInit();
            }
            
        } else {
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
        }
        
        
        
    }
    
    
}

#pragma mark - 加密单帧

- (void)Encrypt_3040SWithData:(NSData*)data WithResult:(void(^)(NSData *data))success errorBlock:(void(^)(ErrorCode code))error {
    
    NSLog(@"*****************加密单帧*******************");
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    
    BTComm_Encrypt_3040S ((LPBYTE)cmd_buffer,&cmd_size, (LPBYTE)data.bytes, (DWORD)data.length);
    
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    self.Encrypt_single = success;
    self.insideCode = error;
    _requestType = Encrypt;
    
    
    [self sendTheBleData:sendData];
    
    
}

- (void)lastAnalyEncrypt_3040S:(UInt8*)buffer withDataLength:(int)len {
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        JMD_RESULT jmd_result;
        
        BTComm_Encrypt_3040R (buffer,len, &jmd_result);
        
        
        
        NSLog(@"加密单帧:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"加密单帧:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        
        if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x9000){
            
            
            NSData *data = [[NSData alloc] initWithBytes:jmd_result.ResultData length:jmd_result.ResultSize];
            
            if (self.Encrypt_single) {
                
                self.Encrypt_single(data);
            }
            
        } else {
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
        }
        
        
        
        
        
        
    }
    
    
}

#pragma mark - 解密单帧

- (void)Decrypt_3040S:(NSData*)data WithResult:(void(^)(NSData *data))success errorBlock:(void(^)(ErrorCode code))error{
    
    NSLog(@"*****************解密单帧*******************");
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    
    BTComm_Decrypt_3040S ((LPBYTE)cmd_buffer,&cmd_size,(LPBYTE)data.bytes,(DWORD)data.length);
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    self.Decrypt_single = success;
    self.insideCode = error;
    _requestType = Decrypt;
    
    
    [self sendTheBleData:sendData];
    
    
}

- (void)lastAnalyDecrypt_3040S:(UInt8*)buffer withDataLength:(int)len {
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        JMD_RESULT jmd_result;
        
        
        
        BTComm_Decrypt_3040R (buffer,len, &jmd_result);
        
        NSLog(@"解密单帧:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解密单帧:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        if(jmd_result.ErrorCode1 == 0x9000 && jmd_result.ErrorCode2 == 0x9000){
            
            
            NSData *data = [[NSData alloc] initWithBytes:jmd_result.ResultData length:jmd_result.ResultSize];
            
            if (self.Decrypt_single) {
                
                self.Decrypt_single(data);
            }
            
        } else {
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
        }
        
        
        
        
        
        
    }
    
    
}
#pragma mark - 下发许可
- (void)requestTheDevice_license:(NSData*)data WithResult:(void(^)())Sucess errorBlock:(void(^)(ErrorCode code))error {
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    BTComm_setLicense_3040S ((LPBYTE)cmd_buffer,&cmd_size,(LPBYTE)data.bytes, (DWORD)data.length);
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    self.setLicese = Sucess;
    self.insideCode = error;
    _requestType = setLicense;
    
    
    [self sendTheBleData:sendData];
    
    
    
    
}


- (void)lastDeviceSetLicese:(UInt8*)buffer withDataLength:(int)len {
    
    
    if ([_numData isEqualToData:_crcData]) {
        
        JMD_RESULT  jmd_result;
        
        BTComm_setLicense_3040R (buffer,(uint32_t)len,&jmd_result);
        
        
        if (jmd_result.ErrorCode2 == 0x9000 ||jmd_result.ErrorCode2 ==  0x9000) {
            
            if (self.setLicese) {
                
                self.setLicese();
            }
            
        }else {
            
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
            
        }
        
        
        
    } else {
        
        _num12++;
        
        if (_num12 <= 3) {
            
            
            
        }
    }
    
}






#pragma mark - *****************我的天啊**************************
-(void)errStrWithHexCode:(int)hexCode{
    
    ErrorCode code = insideCodeVoid;
    switch (hexCode) {
        case 0x10a5:
            code = sercetBookZero;
            break;
        case 0x6803:
            code = sercetBookZero;
            break;
        case 0xd00b:
            code = cancelOperation;
            break;
        case 0x6608:
            code = dveNotLogged;
            break;
        case 0x6801:
            code = serNoteparametErr;
            break;
        case 0x6802:
            code = serNoteExistent;
            break;
        case 0x10a4:
            code = serNoteExistent;
            break;
        case 0x10a2:
            code = serBookNotExistent;
            break;
        case 0x6706:
            code = serBookExistent;
            break;
        case 0x10a1:
            code = serBookExistent;
            break;
        case 0x6711:
            code = serBookNotExistent;
            break;
        case 0x0035:
            code = backupCancel;
            break;
        case 0x0036:
            code = keyTimeout;
            break;
        case 0x6708:
            code = secBookFull;
            break;
        case 0x6804:
            code = secNoteFull;
            break;
        case 0x108F:
            code = inputBackupKey;
            break;
        case 0x1092:
            code = inputBackupKey;
            break;
        case 0x108a:
            code = passagewayNotFulfil;
            break;
        case 0x1096:
            code = passagewayNotFulfil;
            break;
            
        case 0x3330:
            code = titleLengthError;
            break;
        case 0x3331:
            code = descLengthError;
            break;
        case 0x3332:
            code = accountLengthError;
            break;
        case 0x3333:
            code = staticPassLengthError;
            break;
        case 0x3334:
            code = cateNameLengthError;
            break;
        case 0x6100:
            code = requestBlock;
            break;
        case 0x9000:
            code = requestSuccess;
            break;
            
            
            
            
        default:
            break;
    }
    
    
    if (self.insideCode) {
        self.insideCode(code);
    }
    
    
    
}


#pragma mark - 获取响应
- (void)RequestgetResponse:(DWORD)Frame {
    
    int8_t     cmd_buffer[BufSize];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    
    BTComm_getResponse_3040S ((LPBYTE)cmd_buffer,&cmd_size,Frame,_blockType);
    
    
    NSData *sendData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
    
    //    self.VerifyPIN = sucess;
    //    self.insideCode = error;
    _requestType = devGetResponse;
    
    [self sendTheBleData:sendData];
    
}

#pragma mark - ***************************************************
- (void)lastAnalyGetResponse:(UInt8*)buffer withDataLength:(int)len {
    
    if ([_numData isEqualToData:_crcData]) {
        JMD_RESULT  jmd_result;
        
        BTComm_getResponse_3040R (buffer,len,&jmd_result);
        
        
        
        NSLog(@"解析解析读取响应:errorcode1: 0x%x", jmd_result.ErrorCode1);
        NSLog(@"解析解析读取响应:errorcode2: 0x%x", jmd_result.ErrorCode2);
        
        
        if(jmd_result.ErrorCode1 ==0x9000 && jmd_result.ErrorCode2 ==0x6100){
            
            _responeNum++;
            
            sleep(0.3);
            
            if (jmd_result.ResultSize > 0) {
                
                [self.contentParsingData appendBytes:jmd_result.ResultData length:jmd_result.ResultSize];
                
                
                NSLog(@"************我有值啊**************");
            }
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
            
            [self RequestgetResponse:_responeNum];
            
            
            
            
        } else if (jmd_result.ErrorCode1 ==0x9000 && jmd_result.ErrorCode2 ==0x9000){
            
            [self errStrWithHexCode:jmd_result.ErrorCode2];
            _responeNum = 0;
            
            if (self.JMtype == CBCommGetSecurityNoteS) {
                
                [self preectSercetBOOKData:buffer dataLenth:len];
                
            } else if (self.JMtype ==CBCommGetSecurityBookS){
                
                [self preectPassWordData:buffer dataLenth:len];
                
                
            }else if (self.JMtype == CBCommBackupSOne){
                
                
                [self backUpDataAnaly:buffer dataLenth:len];
                
                
                
            }else if (self.JMtype == CBTCommRestoreS){
                
                
                
                [self lastDeviceBackUp:buffer withDataLength:len];
                
                
                
            }else if (self.JMtype ==CBCommupgradeFirmwareS){
                
                
                [self deviceUpdataInside];
                
                
            }else {// 更新版
                
                
                if (self.VerificationSuccInside) {
                    
                    self.VerificationSuccInside();
                }
                
                
            }
            
            
            
        } else if (jmd_result.ErrorCode1 ==0x6405 && jmd_result.ErrorCode2 ==0x35){
            
            _responeNum = 0;
            
            if (self.JMtype == CBTCommRestoreS){
                
                _backOffse = 0;
                
                
            }else if (self.JMtype ==CBCommupgradeFirmwareS){
                
                
                _sendTypeJM = 0;
                _sendCountJM = 0;
                _receviceLenthJM = _recevice2;
                
            }
            
            
            if (self.operationCancelInside) {
                
                self.operationCancelInside();
            }
            
            
            
        } else if (jmd_result.ErrorCode1 ==0x6405 && jmd_result.ErrorCode2 ==0x36){
            _responeNum = 0;
            
            if (self.JMtype == CBTCommRestoreS){
                
                _backOffse = 0;
                
                
            }else if (self.JMtype ==CBCommupgradeFirmwareS){
                
                
                _sendTypeJM = 0;
                _sendCountJM = 0;
                _receviceLenthJM = _recevice2;
                
            }
            
            
            
            if(self.timeoutInside){
                
                self.timeoutInside();
                
            }
            
            
            
            
            
        } else if (jmd_result.ErrorCode1 ==0x6405 && (jmd_result.ErrorCode2&0xFF) == 0x26){
            
            
            WORD num = (WORD)(jmd_result.ErrorCode2);
            
            
            num = (BYTE)((num >> 8) & 0xFF);
            
            
            
            if (self.passError) {
                self.passError(num);
                
            }
            
        }else if (jmd_result.ErrorCode2 == 0x1092 ||jmd_result.ErrorCode2 ==0x108f ){
            
            if (self.backUpdataEnterPwd) {
                
                self.backUpdataEnterPwd();
            }
            
            
        }
    }
    
}







- (NSString *)gbk2utf8:(char*)c_text {
    NSStringEncoding enc = CFStringConvertEncodingToNSStringEncoding(kCFStringEncodingGB_18030_2000);
    unsigned long nLen = strlen(c_text);
    if (nLen <1) {
        return @"";
    }
    NSString *tempText =[[NSString alloc]initWithBytes:c_text length:nLen encoding:enc];
    return tempText;
}

- (NSMutableData *)StringWithGBK:(NSString *)name {
    
    int charByte =0;
    NSStringEncoding enc = CFStringConvertEncodingToNSStringEncoding(kCFStringEncodingGB_18030_2000);
    NSMutableData * tempdata    = (NSMutableData *)[name dataUsingEncoding: enc];
    [tempdata appendBytes:&charByte length:1];
    
    return tempdata;
    
}

- (NSString *)dateInFormat:(time_t)dateTime format:(NSString*) stringFormat {
    char buffer[1000];
    const char *format = [stringFormat UTF8String];
    struct tm * timeinfo;
    timeinfo = localtime(&dateTime);
    strftime(buffer, 80, format, timeinfo);
    return [NSString  stringWithCString:buffer encoding:NSUTF8StringEncoding];
}


- (void)analysisDeviceWithData:(NSData*)data {
    
    
    switch (_requestType) {
        case deceiveStated:{
            
            if (!data) {
                
                
                _num12++;
                
                if (_num12 <= 3) {
                    
                    //                    [self RequestDeviceStated];
                    
                }
                return;
            }
        }
            
            break;
            
        case deceiveInfomation:{
            
            if (!data) {
                
                _num11++;
                
                if (_num11 <= 3) {
                    
                    //                    [self RequestDeviceInformation];
                    
                }
                
                return;
            }
        }
            
            break;
            
        default:
            break;
    }
    
    [self receiveAnalyData:data];
}



- (void)receiveAnalyData:(NSData*)data  {
    
    
    static UInt8 buffer_Delete[3000];
    
    int len = (int)[data length];
    
    
    Byte *point = (UInt8*)data.bytes;
    
    if (point[0] == 0) {
        
        
        
        _numberChange = 30;
        
        _secretB1 = 0;
        
        memcpy(buffer_Delete,point+1 , len-1);
        
        _crcData = [data subdataWithRange:NSMakeRange(data.length - 2, 2)];
        
        _numData = [self CalculateCrcData:buffer_Delete dataLenth:len-3];
        
        
        [self receiveData:buffer_Delete withDataLength:len];
        
    } else {
        
        
        if (point[0] == 1) {
            
            memcpy(buffer_Delete,point+1 , len-1);
            
            _secretB1 += len-1;
            
        } else if (point[0] == 2) {
            
            memcpy(buffer_Delete + _secretB1,point+1 , len-1);
            
            _secretB1 += len-1;
            
        }  else if (point[0] == 3) {
            
            
            memcpy(buffer_Delete + _secretB1,point+1 , len-1);
            
            _crcData = [self CalcuTwoData:buffer_Delete WithdataLenth:_secretB1 + len-1];
            
            _numData = [self CalculateCrcData:buffer_Delete dataLenth:_secretB1 + len-3];
            
            
            [self receiveData:buffer_Delete withDataLength:len];
            
            _secretB1 = 0;
            
        }
    }
}


- (void)receiveData:(UInt8*)buffer_Delete withDataLength:(int)len  {
    
    UInt8* buff;
    int lenth;
    
    if(JMDeveiceType > 2){
        
        buff = buffer_Delete;
        lenth = _secretB1+len-3;
        
        
    } else{
        
        buff = buffer_Delete+2;
        lenth = _secretB1+len-5;
        
    }
    
    switch (_requestType) {
            
        case setLicense:
            
            [self lastDeviceSetLicese:buff withDataLength:lenth];
            
            break;
        case Decrypt:
            
            [self lastAnalyDecrypt_3040S:buff withDataLength:lenth];
            
            break;
        case Encrypt:
            
            [self lastAnalyEncrypt_3040S:buff withDataLength:lenth];
            
            break;
        case DecryptInit:
            
            [self lastAnalyDecryptInit_3040S:buff withDataLength:lenth];
            
            break;
        case EncryptInit:
            
            [self lastAnalyEncryptInit_3040R:buff withDataLength:lenth];
            
            break;
        case devEncryptKey:
            
            [self lastAnalyEnumMainEncryptKey:buff withDataLength:lenth];
            
            break;
            
        case VerificationPIN:
            
            [self lastAnalySendInput:buff withDataLength:lenth];
            
            break;
        case devResetFactory:
            
            [self lastAnalyResetFactory:buff withDataLength:lenth];
            
            break;
            
        case devSetParamater:
            
            [self lastAnalySetDeviceParamater:buff withDataLength:lenth];
            
            break;
        case devUpdateSecurityBook:
            
            [self lastAnalyUpdateSecurityBookItemTitle:buff withDataLength:lenth];
            
            break;
            
        case devModeifyPINTwo:
            
            [self lastAnalyVverify_modifyPIN:buff withDataLength:lenth];
            
            break;
        case devBackUPKey:
            
            [self lastAnalyBackupKey:buff withDataLength:lenth];
            
            break;
            
        case devExitMode:
            
            [self lastAnalyExitMode:buff withDataLength:lenth];
            
            break;
            
        case devSendInput:
            
            [self lastAnalySendInput:buff withDataLength:lenth];
            
            break;
            
        case devGetResponse:
            
            [self lastAnalyGetResponse:buff withDataLength:lenth];
            
            break;
            
        case devVerifyPIN:
            
            [self lastAnalyVerifyPIN:buff withDataLength:lenth];
            
            break;
        case devRamNu:
            
            [self lastAnalyRandomNumber:buff withDataLength:lenth];
            
            break;
            
        case devPublicKey:
            
            [self lastAnalyDevPublicKey:buff withDataLength:lenth];
            
            break;
        case devSecurityCha:
            
            [self lastAnalyDevSecurityCha:buff withDataLength:lenth];
            
            break;
        case devPostKey:
            
            [self lastAnalyPostSessionKey:buff withDataLength:lenth];
            
            break;
            
            
        case deceiveStated:
            
            [self lastAnalyStated:buff withDataLength:lenth ];
            
            break;
            
        case deceiveNum:
            
            [self lastAnalyDevceiveSer:buff withDataLength:lenth];
            
            break;
            
        case deceiveAddSec:
            
            [self lastAddSecretBook:buff withDataLength:lenth];
            
            break;
            
        case deletSecret:
            
            [self lastDeleSecretBook:buff withDataLength:lenth];
            break;
            
        case deceiveEditSec:
            
            [self lastEditSecretBook:buff withDataLength:lenth];
            
            break;
        case deceiveOnlySec:
            
            [self lastONlySecretBook:buff withDataLength:lenth];
            
            break;
            
        case deceiveAddPass:
            
            [self lastAddPassWord:buff withDataLength:lenth];
            
            break;
            
        case deceiveOnlyPass:
            
            [self lastOnlyPassword:buff withDataLength:lenth];
            
            break;
            
        case deceiveDelePass:
            
            [self lastDeletePassword:buff withDataLength:lenth];
            
            break;
            
        case deceiveEditPass:
            
            [self lastEditPassword:buff withDataLength:lenth];
            
            break;
            
        case deceiveNamePass:
            
            [self lastNamePassword:buff withDataLength:lenth];
            
            break;
            
        case deviceActive:
            
            [self lastDeviceActive:buff withDataLength:lenth];
            
            break;
            
        case deviceUpData:
            
            [self lastDeviceBackUp:buff withDataLength:lenth];
            
            break;
            
        case devieceJMData:
            
            [self lastJMUpData:buff withDataLength:lenth];
            
            break;
            
        case deceivePutUserKey:
            
            [self veryBiglastLastAnalyDevceiveSer:buff withDataLength:lenth];
            
            break;
        case deceivePassWord:
            
            [self preectPassWordData:buff dataLenth:lenth];
            break;
        case deceiveSecretBook:
            
            [self preectSercetBOOKData:buff dataLenth:lenth];
            break;
        case deceiveBackUpData:
            
            [self backUpDataAnaly:buff dataLenth:lenth];
            break;
        case deceiveInfomation:
            
            [self lastAnalyDevceiveInfomation:buff withDataLength:lenth];
            break;
        default:
            break;
            
            
    }
    
    
}

#pragma mark - 截取CRC

- (NSData *)CalcuTwoData:(UInt8*)result WithdataLenth:(UInt32)lenth {
    
    
    
    UInt8 buffer1[3];
    
    memset(buffer1, 0x00, sizeof(buffer1));
    
    memcpy(buffer1, result+lenth-2 , 2);
    
    
    NSData *numData = [[NSData alloc] initWithBytes:buffer1 length:2];
    
    return numData;
    
}


#pragma mark - 获得数据的CRC

- (NSData *)CalculateCrcData:(UInt8*)result dataLenth:(UInt32)lenth {
    
    UInt16 computeData = [self CalculateCrc:result dataLenthg:lenth crcNa:0xFFFF];
    
    UInt8 buffer1[3];
    buffer1[0] = computeData>>8;
    buffer1[1] = computeData;
    
    NSData *numData = [[NSData alloc] initWithBytes:buffer1 length:2];
    
    return numData;
    
}



#pragma mark - CRC计算

- (UInt16)CalculateCrc:(UInt8 *)pData dataLenthg:(NSUInteger)dataLen crcNa:(UInt16)crc {
    
    
    
    UInt8    bit;
    while(dataLen--) {
        for(bit=0x80;bit!=0;bit>>=1)
        {
            if(crc & 0x8000)
            {
                crc <<= 1;
                crc ^= 0x8005;
            }
            else
                crc <<= 1;
            if(*pData & bit)
                crc ^= 0x8005;
        }
        pData++;
    }
    return crc;
    
}


#pragma mark - 极密盾断开蓝牙
- (void)JMBLEDisconnectTheDevice {
    
    NSData *data2 = BytesFromHexString(@"2800000C0008800D0000000000000000000000000000");
    
    [self sendTheBleData:data2];
    
    
    
    
    
    
}
NSData *BytesFromHexString(NSString *hexString)
{
    const char *chars = [hexString UTF8String];
    int i = 0, len = (int)hexString.length;
    
    NSMutableData *data = [NSMutableData dataWithCapacity:len / 2];
    char byteChars[3] = {'\0','\0','\0'};
    unsigned long wholeByte;
    
    while (i < len) {
        byteChars[0] = chars[i++];
        byteChars[1] = chars[i++];
        wholeByte = strtoul(byteChars, NULL, 16);
        [data appendBytes:&wholeByte length:1];
    }
    
    return data;
}


//
//-(void)goalertWithControl:(UIViewController*)control{
//    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"提示" message:@"当前极密盾固件版本过低，无法正常使用，请进入官网下载中心（www.jimidun.com），下载windows客户端完成本次固件升级。" preferredStyle:UIAlertControllerStyleAlert];
//    UIAlertAction *altion = [UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
//
////        [self.cbControllerTools disconnectDevice:self.periphralTools];
////        [self.cbControllerTools stopScan];
//        JMMyDevices * devview = [[JMMyDevices alloc]init];
//        [control presentViewController:devview animated:YES completion:nil];
//    }];
//
//    [alert addAction:altion];
//
//    [control presentViewController:alert animated:YES completion:nil];
//
//}

#pragma mark - 保存密条
- (NSMutableData *)contentParsingData {
    
    
    if (!_contentParsingData) {
        
        _contentParsingData = [NSMutableData data];
        
    }
    
    
    return _contentParsingData;
}




-(NSMutableData *)dataWithStringS:(NSString *)name {
    
    int charByte =0;
    NSStringEncoding enc = CFStringConvertEncodingToNSStringEncoding(kCFStringEncodingGB_18030_2000);
    
    NSData *data = [name dataUsingEncoding:enc];
    
    NSMutableData * tempdata  = [[NSMutableData alloc] initWithData:data];
    [tempdata appendBytes:&charByte length:1];
    
    
    return tempdata;
    
}




- (void)presentControl {
    
    
    
    //    UIAlertController *alertVC = [UIAlertController alertControllerWithTitle:@"提示" message:@"备份恢复过程中出现异常，是否尝试重新恢复" preferredStyle:1];
    //
    //
    //
    //    [alertVC addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
    //
    //        _num12++;
    //
    //        if (_num12 <= 3) {
    //
    //
    //            [self restoreBackupInside];
    //
    //        }
    //
    //    }]];
    //
    //    [alertVC addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    //
    //    [_viewControl presentViewController:alertVC animated:YES completion:nil];
}



NSString *HexStringFromBytes(uint8_t *bytes, unsigned int length) {
    
    if (bytes == NULL) {
        return @"";
    }
    
    NSString *hexStr=@"";
    
    for(int i=0;i<length;i++){
        NSString *newHexStr = [NSString stringWithFormat:@"%x",bytes[i]&0xff];///16进制数
        
        if([newHexStr length]==1)
            hexStr = [NSString stringWithFormat:@"%@0%@",hexStr,newHexStr];
        else
            hexStr = [NSString stringWithFormat:@"%@%@",hexStr,newHexStr];
    }
    return hexStr.uppercaseString;
}





//if (_passWord) {
//
//    uint8_t PIN_SHA1[CC_SHA1_DIGEST_LENGTH];
//    NSString *defult_PIN = @"000000";
//    NSData *PIN_Data  = [defult_PIN dataUsingEncoding: NSUTF8StringEncoding];
//    CC_SHA1(PIN_Data.bytes, (unsigned int)PIN_Data.length, PIN_SHA1);
//
//    //  申请aToken
//    [weakself.SecretTools RequestVerifyPINWithType:1 RandomNum:(LPBYTE)weakself.data.bytes withPin:PIN_SHA1 WithToken:(LPBYTE)bToken_Data.bytes tokenLen:(DWORD)bToken_Data.length];
//    _Devtype = DevVerifyPIN;
//    weakself.SecretTools.aToken = ^(){
//
//
//        [weakself bindOneRequest];
//
//
//    };
//
//
//
//}else{


//- (NSMutableArray *)LocalizedIndexedColl:(NSMutableArray *)array {
//
//
//    NSMutableArray *mutArray = [NSMutableArray array];
//    for (NSString *string in array) {
//
//        JMLonging *loing = [[JMLonging alloc] init];
//        loing.password = string;
//        [mutArray addObject:loing];
//
//    }
//
//
//    UILocalizedIndexedCollation *collation = [UILocalizedIndexedCollation currentCollation];
//
//
//    NSInteger sectionTitlesCount = [[collation sectionTitles] count];
//
//    NSMutableArray *newSectionsArray = [[NSMutableArray alloc] initWithCapacity:sectionTitlesCount];
//
//
//    for (NSInteger index = 0; index < sectionTitlesCount; index++) {
//
//        [newSectionsArray addObject:[[NSMutableArray alloc] init]];
//    }
//
//
//    for (JMLonging *loingJ in mutArray) {
//
//        NSInteger sectionNumber = [collation sectionForObject:loingJ collationStringSelector:@selector(password)];
//
//        [newSectionsArray[sectionNumber] addObject:loingJ];
//
//
//    }
//    //NSLog(@"%@",newSectionsArray);
//
//    for (NSInteger index = 0; index < sectionTitlesCount; index++) {
//
//        NSArray *sortedPersonArrayForSection = [collation sortedArrayFromArray:newSectionsArray[index] collationStringSelector:@selector(password)];
//
//        NSMutableArray *mutArray = [NSMutableArray arrayWithArray:sortedPersonArrayForSection];
//
//        newSectionsArray[index] = mutArray;//sortedPersonArrayForSection;
//
//
//
//    }
//
//
//    NSMutableArray *existTitleSections = [NSMutableArray array];
//
//    for (NSMutableArray *section in newSectionsArray) {
//        if ([section count] > 0) {
//            [existTitleSections addObject:section];
//
//        }
//    }
//
//
//    array = existTitleSections;
//
//
//    NSMutableArray *oneArray = [NSMutableArray array];
//    for (int i = 0; i < array.count; i++) {
//
//
//        NSMutableArray *smArray = array[i];
//
//        [oneArray addObjectsFromArray:smArray];
//
//    }
//
//    return oneArray;
//
//
//
//}



//1. if ( 3038 && 固件版本 >= 1.01.008 ){
//    3040 数据备份、数据恢复流程。
//    支持 3038 <=> 3040互相备份恢复。
//}

//#pragma mark - 蓝牙设置
//
//
//- (void)setupBLE {
//#if TARGET_IPHONE_SIMULATOR//模拟器
//
//#elif TARGET_OS_IPHONE//真机
//    CBController *cbc = [CBController shareInstance];
//    self.ConPeripher =  [cbc connectedList][0];
//    self.ConPeripher.transDataDelegate = self;
//
//    self.BLETools = [[JMBlueTools alloc] init];
//    self.BLETools.periphralTools = self.ConPeripher;
//
//    _isaddPassFirst = ISAPASSFIRST;
//#endif
//
//}





- (void)sendTheBleData:(NSData*)sendData {
    
    
    
    UInt8 bufferSE[3000];
    memset(bufferSE, 0x00, sizeof(bufferSE));
    
    
    _lengthInfo++;
    bufferSE[0] = 0x00;
    bufferSE[1] = _lengthInfo>>24;
    bufferSE[2] = _lengthInfo>>16;
    bufferSE[3] = _lengthInfo>>8;
    bufferSE[4] = _lengthInfo;
    memcpy(bufferSE+5, sendData.bytes, sendData.length);
    
    NSUInteger length = sendData.length + 4;
    UInt16 crcData = [self CalculateCrc:bufferSE+1 dataLenthg:length crcNa:0xFFFF];
    bufferSE[length + 1]=crcData>>8;
    bufferSE[length + 2]=crcData;
    
    
    
    if (JMDeveiceType > 1) {
        
        
        static UInt8 buffer_send2[3000];
        memset(buffer_send2, 0x00, sizeof(buffer_send2));
        
        
        NSData *senddata = [NSData dataWithBytes:bufferSE length:length + 3];
        int baolength =(int) [senddata length]-1;
        
        memcpy(buffer_send2, bufferSE+1,baolength );
        
        
        if(baolength >92){
            
            int num1 = baolength/46;
            bufferSE[0]= 0x01;
            memcpy(bufferSE+1, buffer_send2, 46);
            
            NSData *data = [NSData dataWithBytes:bufferSE length:47];
            [self sendDataToPeripheral:data];
            
            NSLog(@"第一包:%@",data);
            
            
            for (int i=1; i<num1; i++) {
                
                bufferSE[0]= 0x02;
                memcpy(bufferSE+1, buffer_send2+46*i, 46);
                data = [NSData dataWithBytes:bufferSE length:47];
                NSLog(@"第%d包:%@", i +1, data);
                [self sendDataToPeripheral:data];
            }
            
            
            
            bufferSE[0]= 0x03;
            memcpy(bufferSE+1, buffer_send2+46*num1, baolength-46*num1);
            data = [NSData dataWithBytes:bufferSE length:baolength-46*num1+1];
            
            [self sendDataToPeripheral:data];
            
            NSLog(@"最后一包:%@",data);
            
        } else if (baolength > 46 && baolength <=92) {
            
            bufferSE[0]= 0x01;
            memcpy(bufferSE+1, buffer_send2, 46);
            
            NSData *data = [NSData dataWithBytes:bufferSE length:47];
            
            [self sendDataToPeripheral:data];
            NSLog(@"第一包:%@",data);
            
            
            bufferSE[0]= 0x03;
            memcpy(bufferSE+1, buffer_send2+46, baolength-46);
            data = [NSData dataWithBytes:bufferSE length:baolength-46+1];
            
            [self sendDataToPeripheral:data];
            NSLog(@"最后一包:%@",data);
            
            
        } else {
            
            [self sendDataToPeripheral:senddata];
            
            //                [periph sendDataToPeripheral:senddata];
            NSLog(@"第一包:%@",senddata);
            
        }
        
        
        
    }else if(JMDeveiceType == 1){
        
        //30
        
        int eighteen = 18 + _numberChange;
        int ninteen = 19 + _numberChange;
        int thSix = 36 + _numberChange * 2;
        int twoteen = 20 + _numberChange;
        int secBuff = 0x12 + _numberChange;
        
        
        static UInt8 buffer_send2[3000];
        memset(buffer_send2, 0x00, sizeof(buffer_send2));
        NSUInteger sendDataLength = sendData.length;
        memcpy(buffer_send2, bufferSE + 1, sendDataLength + 6);
        
        int baolength = (int)sendDataLength + 6;
        
        
        if (baolength <= eighteen) {
            
            
            UInt8 bufferIN2[twoteen];
            memset(bufferIN2, 0x00, sizeof(bufferIN2));
            
            
            bufferIN2[0]= 0x00;
            bufferIN2[1]= baolength;
            memcpy(bufferIN2+2, buffer_send2, baolength);
            
            NSData *data = [NSData dataWithBytes:bufferIN2 length:baolength+2];
            NSLog(@"第一包:%@",data);
            
            [self sendDataToPeripheral:data];
            
        } else if(baolength > eighteen && baolength <= thSix) {
            
            UInt8 bufferIN2[twoteen];
            memset(bufferIN2, 0x00, sizeof(bufferIN2));
            
            
            bufferIN2[0]= 0x01;
            bufferIN2[1]= secBuff;
            memcpy(bufferIN2+2, buffer_send2, eighteen);
            
            NSData *data = [NSData dataWithBytes:bufferIN2 length:twoteen];
            NSLog(@"第一包:%@",data);
            
            
            
            [self sendDataToPeripheral:data];
            
            bufferIN2[0]= 0x03;
            bufferIN2[1]= baolength -eighteen;
            memcpy(bufferIN2+2, bufferSE+ninteen, baolength -eighteen);
            data = [NSData dataWithBytes:bufferIN2 length:baolength - eighteen + 2];
            NSLog(@"第二包:%@",data);
            
            [self sendDataToPeripheral:data];
            
            
        } else if (baolength > thSix) {
            int num1 = baolength/eighteen;
            
            UInt8 bufferIN2[twoteen];
            memset(bufferIN2, 0x00, sizeof(bufferIN2));
            
            bufferIN2[0]= 0x01;
            bufferIN2[1]= secBuff;
            memcpy(bufferIN2+2, buffer_send2, eighteen);
            
            NSData *data = [NSData dataWithBytes:bufferIN2 length:twoteen];
            NSLog(@"第一包:%@",data);
            
            
            [self sendDataToPeripheral:data];
            
            
            for (int i = 1; i < num1; i++) {
                bufferIN2[0] = 0x02;
                bufferIN2[1] = secBuff;
                memcpy(bufferIN2+2, buffer_send2 + i*eighteen, eighteen);
                NSData *data = [NSData dataWithBytes:bufferIN2 length:twoteen];
                NSLog(@"第%d包:%@", i +1, data);
                [self sendDataToPeripheral:data];
                
            }
            
            bufferIN2[0]= 0x03;
            bufferIN2[1]= baolength -eighteen*num1;
            memcpy(bufferIN2+2, buffer_send2+ num1*eighteen , baolength -eighteen*num1);
            
            data = [NSData dataWithBytes:bufferIN2 length:baolength - eighteen*num1 + 2];
            
            NSLog(@"最后一包:%@",data);
            
            
            [self sendDataToPeripheral:data];
        }
        
    } else {
        
        
        
        
    }
    
    
    
    
    
}

- (void)sendDataToPeripheral:(NSData *)data {
    
    
    
    [_BLEPeripheral writeValue:data forCharacteristic:_writeCharcter type:0];
    
    
    
}



- (int)stringLenght:(NSString *)str {
    int abc = 0;
    for(int i=0; i< [str length];i++) {
        
        int a = [str characterAtIndex:i];
        
        
        abc += isascii(a) ? 1 : 2;
        
        
    }
    
    return abc;
}


- (NSMutableData *)modifyPINWithString:(NSString *)string {
    
    NSMutableData *mutData = [NSMutableData data];
    [ mutData appendBytes:string.UTF8String length:string.length];
    
    return mutData;
    
}




@end
