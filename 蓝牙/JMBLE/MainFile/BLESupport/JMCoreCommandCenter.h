//
//  JMCoreCommandCenter.h
//  jimidun
//
//  Created by microdone on 16/1/20.
//  Copyright © 2016年 microdone. All rights reserved.
//

#import <Foundation/Foundation.h>
typedef NS_ENUM(NSInteger, CBCommType) {
    CBCommGetDevInfo = 0,
    CBCommGetSecurityBookS,
    CBCommGetSecurityBookSTwo,
    CBCommGotoSecurityBookS,
    CBCommGetSecurityNoteS,
    CBCommGetSecurityNoteSTwo,
    CBCommGotoSecurityNoteS,
    CBCommBackupSOne,
    CBCommBackupSTwo,
    CBCommgetSecurityNoteContentS,
    CBCommdeleteSecurityNoteS,
    CBCommgetDeviceStatusS,
    CBCommgetDeviceInfoS,
    CBCommaddSecurityBookS,
    CBCommaddSecurityNoteS,
    CBCommdeleteSecurityBookS,
    CBCommupdateSecurityNoteS,
    CBCommupdateSecurityBookS,
    CBCommupgradeFirmwareS,
    CBTCommputUserKeyS,
    CBTCommRestoreS,
    CBCommgetDeviceSerialNoS,
    CBCommActivateS,
    DevPublicKey,   //设备公钥
    DevSeChanal,    //联机通道
    DevPostKey,   // 下发联机秘钥
    DevRandomNum, //获取随机数
    DevVerifyPIN,  //验证PIN
    DevModifyPIN,   //修改PIN
    DevputUserKeyS,   //下发用户秘钥
    DevGetRespone,     //获取响应
    DevShowKeyboard,    //暂时安全键盘
    DevSendInput,       //发送键盘字符
    DevExitMode,        //退出独占模式
    DevVerify_modifyPIN,  //修改和验证
    DEVUpdataTitle,       //修改密码标题
    BTCommbackupKey,
    DEvSetMachineName,  //修改标题
    DEvResetFactory ,    //设备重置
    DEverificationPIN   //验证设备PIN
};
@interface JMCoreCommandCenter : NSObject

+ (NSData *)commandWithType:(CBCommType)type object:(NSData *)anObject;

+(NSString *)chooseDeviceStatusSW1:(int)SW1;


@end
