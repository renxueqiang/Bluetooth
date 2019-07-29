//
//  ViewController.h
//  JMBLE
//
//  Created by 任雪强 on 17/4/10.
//  Copyright © 2017年 任雪强. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "JMCentralManager.h"
@interface BaseController : UIViewController

@property (nonatomic,strong)  JMCentralManager *Cbcontrol;
@property (nonatomic,strong) JMPeripheral *BLETools;

@end

