//
//  JMDeviceModel.h
//  JMBLE
//
//  Created by 任雪强 on 17/4/13.
//  Copyright © 2017年 任雪强. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface JMDeviceModel : NSObject

/** 设备序列号 */
@property (copy, nonatomic) NSString *devID;

/** 生产日期 32 bits UTC */
@property (copy, nonatomic) NSString *ProductionDate;

/** 每两字节表一个密码长度，格式为min max min max min max，分别为设备密码、保护密码、解锁码 */
@property (copy, nonatomic) NSString *PWDLEN;

/** 每两字节表一个密码错误次数，分别为设备密码、保护密码、解锁码 */
@property (copy, nonatomic) NSString *PWDERR;

/** SPARA */
@property (copy, nonatomic) NSString *SPARA;

/** 自动熄屏秒数 */
@property (copy, nonatomic) NSString *CSCRTO;

/** 自动关机秒数 */
@property (copy, nonatomic) NSString *DOWNTO;

/** 设备型号 */
@property (copy, nonatomic) NSString *DevModel;

/** 0.99.015为固件版本，升级检测使用 */
@property (copy, nonatomic) NSString *devVer;

/** 最大密条许可数量 */
@property (copy, nonatomic) NSString *MaxSecLog;

/** 当前密条存储数量 */
@property (copy, nonatomic) NSString *SecLogNum;

/** 最大口令项许可数量 */
@property (copy, nonatomic) NSString *MaxPwd;

/** 当前口令项数量 */
@property (copy, nonatomic) NSString *PwdNum;

/** 当前组口令数量 */
@property (copy, nonatomic) NSString *gPWDNum;

/** 当前分类数量 */
@property (copy, nonatomic) NSString *CataNum;

/** 电池电量 */
@property (copy, nonatomic) NSString *Battery;

/** 设备时间 32 bits UTC Time */
@property (copy, nonatomic) NSString *devTime;

/**当前版本号*/
@property(nonatomic,retain) NSString *DevCurrVersion;


/** 3040当前密条存储数量 */
@property (copy, nonatomic) NSString *CurSecLog;

/** 3040当前口令项数量 */
@property (copy, nonatomic) NSString *CurPwd;

//密码最长长度
@property (copy, nonatomic) NSString *PwdMaxLen;

//密码最短长度
@property (copy, nonatomic) NSString *PwdMinLen;

@property (copy, nonatomic) NSString *DevName;




@property (copy, nonatomic) NSString *NiceName;

@property (copy, nonatomic) NSString *CurMEncKeyCnt;

@property (copy, nonatomic) NSString *MaxATokenCnt;
@property (copy, nonatomic) NSString *MaxMEncKeyCnt;


- (instancetype)initWithDict:(NSDictionary *)dict;


@end
