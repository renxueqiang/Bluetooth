//
//  SecurityBookModel.h
//  jmi
//
//  Created by microdone on 15/12/9.
//  Copyright © 2015年 microdone. All rights reserved.
//

#import <Foundation/Foundation.h>
@interface SecurityBookModel : NSObject


@property (nonatomic,copy) NSString *itemTitle;

@property (nonatomic,copy) NSString *itemCataName;

/** 细节描述标题    */
@property (nonatomic,copy) NSString *itemDesc;

@property (nonatomic,copy) NSString *xURL;

@property (nonatomic,copy) NSString *lastDate;


/**分类ID*/
@property(nonatomic,assign)  int itemCataID;


/**密码页保护级别，
                0：开机密码 
                1：保护密码 
                2：应用密码
 
 */
@property (nonatomic, assign) int  ProtectLevel;



/**密条保护级别， 0：可以批量读出内容
                1：按确认键授权读出内容
                2：不能读出内容，只能在设备中查看
 */
@property (nonatomic, assign) int  mtProtectLevel;


/**口令项是否关联了应用 
                0：未关联应用 
                1：关联了应用
 
 */
@property (nonatomic, assign) int appLink;


/**拼音*/
@property (nonatomic,copy) NSString *itemspell;


/**账号*/
@property (nonatomic,copy) NSString *acctName;








@end
