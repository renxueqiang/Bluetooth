//
//  JMPeripheral.h
//  jimidun
//
//  Created by 任雪强 on 17/4/6.
//  Copyright © 2017年 microdone. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <CoreBluetooth/CoreBluetooth.h>
#import "JMCoreCommandCenter.h"
#import "jmd_btcomm.hpp"
#import "JMDeviceModel.h"

typedef NS_ENUM(NSInteger, JMDevType) {
    
    
    DevTypeBLE = 1, // 3032 3026
    DevTypeLGBLE,   // 3038
    DevTypeK2       // K2
    
};

typedef NS_ENUM(NSInteger, ErrorCode) {
    
    insideCodeVoid = 0,
    sercetBookZero,          //密条为零或者不存在
    cancelOperation,         //取消了操作
    dveNotLogged,            //设备未登陆
    serNoteparametErr,       //密条参数错误
    serNoteExistent,         //密条已存在
    serBookNotExistent,       //密码不存在
    serBookExistent,          //密码存在
    backupCancel ,            //取消备份
    keyTimeout ,               //按键超时
    secBookFull,               //密码已满
    secNoteFull,                //密条已满
    inputBackupKey,              //输入备份秘钥
    passagewayNotFulfil,         //通道权限不足
    randomREError,             //随机数RE错误
    
    titleLengthError ,            //标题长度错误
    descLengthError  ,            //描述长度错误
    accountLengthError,            //账号长度错误
    staticPassLengthError,        //静态密码长度错误
    cateNameLengthError,           //分类名长度错误
    requestBlock,
    requestSuccess
};


@protocol JMPeripheralDelegate <NSObject>

@optional



- (void)JMPeripheral:(CBPeripheral *)peripheral didReceiveTransparentData:(NSData *)data;

@end



@interface JMPeripheral : NSObject

@property(nonatomic,strong) CBPeripheral *BLEPeripheral;
@property(nonatomic,strong) CBCharacteristic *writeCharcter;
@property(nonatomic,weak) id<JMPeripheralDelegate> delegate;

//设备类型
@property(nonatomic,assign) JMDevType devType;

//设备模型 (存储设备参数)
@property(nonatomic,strong) JMDeviceModel *devModel;

//设备atoken
@property(nonatomic,strong) NSArray *atokenArr;
//固件升级
@property(nonatomic,strong) NSArray *firmwarArr;
#pragma mark - ***************最新版*******************
/** 1.激活设备   */

- (void)requestTheDeviceActive:(NSData*)data WithResult:(void(^)())activeSucess errorBlock:(void(^)(ErrorCode code))error;

/** 2.获取设备状态    */

- (void)RequestDeviceStatedWithResult:(void(^)(DWORD SW1,DWORD SW2))stated;


/** 3.获取设备信息    */

- (void)RequestDeviceInformationWithResult:(void(^)(JMDeviceModel*devInfomation))devInfomation;

/** 4.获取设备序列号    */

- (void)RequestDeviceSerialNumWithResult:(void(^)(NSString*serialNoS))DeviceSerialNoS;


/** 5.读取密条    */

- (void)readTheDeviceSecretBookWithResult:(void(^)(NSArray* secretBookArray))SecretBookModel errorBlock:(void(^)(ErrorCode code))error;


/**  6.增加密条   */


- (void)addTheDeviceSecretBookItemTitle:(NSString*)itemTitle itemDescData:(NSString*)itemDesc protect:(UInt32)mtProtectLevel ResultSuccess:(void(^)())AddSuccess errorBlock:(void(^)(ErrorCode code))error;


/**  7.编辑密条   */

- (void)EditTheDeviceSecretBookItemTitle:(NSString*)itemTitle itemDescData:(NSString*)itemDesc  ResultSuccess:(void(^)())editSuccess errorBlock:(void(^)(ErrorCode code))error;

/**  8.删除密条   */

- (void)deleteTheDeviceSecretBook:(NSString*)itemTitle ResultSuccess:(void(^)())deleteSuccess exclusiveModeTimeOut:(void(^)())timeout operationCancel:(void(^)())cancelOperation errorBlock:(void(^)(ErrorCode code))error;

/**  9.只读密条   */

- (void)OnleReadTheDeviceSecretNote:(NSString*)securityNote WithResult:(void(^)())readSecretNote ExclusiveMode:(void(^)())exclusiveMode exclusiveModeTimeOut:(void(^)())timeout operationCancel:(void(^)())cancelOperation errorBlock:(void(^)(ErrorCode code))error;


/** 10.读取密码    */

- (void)readTheDevicepasssWordWithResult:(void(^)(NSArray* secretNoteArray))SecretNoteModel errorBlock:(void(^)(ErrorCode code))error;


/** 11.增加密码    */
- (void)addTheDevicePassWordItemTitle:(NSString*)itemTitle itemDescData:(NSString*)itemDesc accData:(NSString*)accName staticData:(NSString*)staticPwd itemCData:(UInt32)itemCataID itemCNaData:(NSString*)itemCataName WithResult:(void(^)())addSuccess errorBlock:(void(^)(ErrorCode code))error;


/**  12.编辑密码    */

- (void)EditThePassWordItemTitle:(NSString*)itemTitle itemDescData:(NSString*)itemDesc accData:(NSString*)accName staticData:(NSString*)staticPwd itemCData:(UInt32)itemCataID itemCNaData:(NSString*)itemCataName editSecurityBookType:(int)editPassType  WithResult:(void(^)())EditSuccess ExclusiveMode:(void(^)())exclusiveMode  exclusiveModeTimeOut:(void(^)())timeout operationCancel:(void(^)())cancelOperation errorBlock:(void(^)(ErrorCode code))error;


/**  13.删除密码    */


- (void)deleteTheDevicePassWord:(NSString*)securityTitleName WithResult:(void(^)())deleteSuccess exclusiveModeTimeOut:(void(^)())timeout operationCancel:(void(^)())cancelOperation errorBlock:(void(^)(ErrorCode code))error;



/**  14.只读密码    */

- (void)OnleReadTheDeviceSecretBook:(NSString*)secyrityBookTitle WithResult:(void(^)())readSecretBook ExclusiveMode:(void(^)())exclusiveMode  exclusiveModeTimeOut:(void(^)())timeout operationCancel:(void(^)())cancelOperation errorBlock:(void(^)(ErrorCode code))error;



/** 15.修改密码标题    */
- (void)requestUpdateSecurityBookItemTitle:(NSString*)old_itemTitle withNewTitle:(NSString*)new_itemTitle WithResult:(void(^)())successEdit errorBlock:(void(^)(ErrorCode code))error;

/**16.修改密码分类    */
- (void)editSecurityBookCategoryWithnewCatalogName:(NSString*)newCatalogName olditemCataID:(UInt32)oldNameID oldCatalogName:(NSString*)oldCatalogName WithResult:(void(^)())successEdit errorBlock:(void(^)(ErrorCode code))error;



/**  17.备份数据    */
- (void)backUpTheDeceiveDataWithResult:(void(^)(NSData* backupData))backupSucess DevProgress:(void(^)(DWORD progress))progress exclusiveModeTimeOut:(void(^)())timeout operationCancel:(void(^)())cancelOperation errorBlock:(void(^)(ErrorCode code))error;


/**  18.恢复备份   */

- (void)restoreBackupTheDeviceData:(NSData*)receviceData  WithResult:(void(^)())restoureSucess exclusiveModeTimeOut:(void(^)())timeout operationCancel:(void(^)())cancelOperation errorBlock:(void(^)(ErrorCode code))error;


/**  19.固件升级   */

- (void)deceiveUpdataWithData:(NSData*)updataData Result:(void(^)())updataSucess updataProgress:(void(^)(CGFloat progress))progress exclusiveModeTimeOut:(void(^)())timeout operationCancel:(void(^)())cancelOperation errorBlock:(void(^)(ErrorCode code))error;



#pragma mark - 3040

/** 20.获取设备公钥    */
- (void)RequestDevPublicKeyWithResult:(void(^)(NSString *publicString))publicString errorBlock:(void(^)(ErrorCode code))error;

/**21.获取联机通道    */

- (void)RequestSecurityChanelWithBToken:(uint8_t*)bToken bTokenLength:(DWORD)BLength withAToken:(uint8_t*)AToken ATokenLength:(DWORD)ALength WithResult:(void(^)(NSData *sessionKey))sessionKey errorBlock:(void(^)(ErrorCode code))error;


/** 22.下发联机会话密钥    */
- (void)RequestSetSessionKey:(NSData*)data WithResult:(void(^)())sucessSessionKey errorBlock:(void(^)(ErrorCode code))error;


/** 23.下发随机数    */

- (void)RequestRandomNumberWithResult:(void(^)(NSData*random))sucessRandom errorBlock:(void(^)(ErrorCode code))error;


/** 24.申请atoken 验证设备PIN    */
- (void)RequestVerifyPINWithType:(DWORD)Type RandomNum:(NSData*)RandomNumber withPin:(NSString*)PIN WithToken:(NSData*)bToken  WithResult:(void(^)(NSData*aTokan))aToaken  passworderrorBlock:(void(^)(int number))number errorBlock:(void(^)(ErrorCode code))error;

/** 24. 验证+修改 设备PIN    */

- (void)requestmodifyPIN_EM:(DWORD)type  WithResult:(void(^)())exclusiveMode exclusiveModeTimeOut:(void(^)())timeout operationCancel:(void(^)())cancelOperation errorBlock:(void(^)(ErrorCode code))error;



- (void)analysisDeviceWithData:(NSData*)data;


#pragma mark - **************分割******************



/** 3040 备份密钥显示+重置+输入    */
- (void)requestBackupKeyType:(DWORD)type withKeyID:(DWORD)bakcupKeyID;



/** 3040 5.验证设备PIN    */
- (void)RequestVerificationPIN:(NSString*)oldPIN WithResult:(void(^)())success  passworderrorBlock:(void(^)(int number))number;




/** 3040 7.发送键盘字符    */
- (void)RequestSendInput:(LPBYTE)lpChar withSize:(DWORD)size WithResult:(void(^)())success errorBlock:(void(^)(ErrorCode code))error;

/** 3040 8.退出独占模式    */
- (void)requestExitExclusiveMode;


/** 3040 9.独占模式    */
- (void)RequestgetResponse:(DWORD)Frame;

/** 3040 10. 断开设备  02    */
- (void)JMBLEDisconnectTheDevice;



/** 3040 10. 动态设备参数下发    */
- (void)requestSetDeviceParamater:(DWORD)Min withMax:(DWORD)Max withTrycount:(DWORD)TryCount withSleep:(DWORD)Sleep withPoweroff:(DWORD)PowerOff withNice:(NSString *)NiceName  WithResult:(void(^)())success errorBlock:(void(^)(ErrorCode code))error;


/** 3040 11.  设备重置    */
- (void)requestresetFactory:(NSData*)eCloudCMD WithResult:(void(^)())success errorBlock:(void(^)(ErrorCode code))error;


/** 下发用户秘钥    */

- (void)putUserKeyToDevice:(NSString*)userKey  WithResult:(void(^)(BOOL sucess))sucess errorBlock:(void(^)(ErrorCode code))error;




/** 3040 11.  枚举密钥    */
- (void)enumMainEncryptKeyType:(DWORD)keyType  WithResult:(void(^)())success errorBlock:(void(^)(ErrorCode code))error;

- (void)EncryptInit_3040SWithResult:(void(^)())success errorBlock:(void(^)(ErrorCode code))error;

- (void)DecryptInit_3040SWithResult:(void(^)())success errorBlock:(void(^)(ErrorCode code))error;

- (void)Encrypt_3040SWithData:(NSData*)data WithResult:(void(^)(NSData *data))success errorBlock:(void(^)(ErrorCode code))error;


- (void)Decrypt_3040S:(NSData*)data WithResult:(void(^)(NSData *data))success errorBlock:(void(^)(ErrorCode code))error;

/** 下发许可    */
- (void)requestTheDevice_license:(NSData*)data WithResult:(void(^)())Sucess errorBlock:(void(^)(ErrorCode code))error;

@end
