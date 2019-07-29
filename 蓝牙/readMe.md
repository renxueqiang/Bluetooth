
#                     极密科技蓝牙SDK文档



依赖库添加: openssl.framework
libFMCrypto.a
libstdc++.6.0.9.tbd
PassGuardCrypto.hpp


工程build setting 配置 


Apple LLVM 8.0 - Language - c++ -> c++ standard Library 修改为 libstdc++(GUC C++ standard library)


[JMCentralManager类]为蓝牙开发核心类 
    初始化 [JMCentralManager shareManger]获得中心对象



`实现

-(void)viewDidLoad {
[super viewDidLoad];

_Cbcontrol = [JMCentralManager shareManger];
[_Cbcontrol startScanPeripheralWithScanTime:3.0];
_Cbcontrol.delegate = self;

}

- (void)JMController:(JMCentralManager *)cbController didFindPeripheral:(CBPeripheral *)peripheral {

// 1. 扫描结束 已发现设备 存储在属性 PeripModelArray 
    2. connectPeripheralWithIdentifier: 连接外设

}

- (void)JMController:(JMCentralManager *)cbController didConnectedPeripheral:(CBPeripheral *)peripheral {

// 获取当前连接的外设  调用外设的方法

}

[JMPeripheral类]具体功能实现类 所有方法都以block回调方式返回 错误都以错误码方式返回 具体请参照SDK代码实现以及说明


[外设所有方法 都以blockd的形式回调]



