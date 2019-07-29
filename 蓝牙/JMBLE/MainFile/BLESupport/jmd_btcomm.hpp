//
//  jmd_btcomm.hpp
//  BTComm
//
//  Created by 毕卫国 on 15/11/3.
//  Copyright © 2015年 毕卫国. All rights reserved.
//

#ifndef jmd_btcomm_hpp
#define jmd_btcomm_hpp

#include <stdio.h>
#include <time.h>

#define LPBYTE      unsigned char *
#define LPDWORD     unsigned int *
#define BYTE        unsigned char
#define WORD        unsigned short
#define DWORD       unsigned int
#define LPCSTR		const char *
#define _IN
#define _OUT
#define _IN_OUT

//极密盾状态字
#define SW1_CREATED			                    (1<<0)	    //已创建状态
#define SW1_INITED				                (1<<1)	    //已初始化状态
#define SW1_READY								(1<<2)		//已就绪。
#define SW1_ACTIVATED							(1<<3)		//已激活。
#define SW1_BINDED								(1<<4)		//已绑定。
#define SW1_DLOAD_DEVKEY_SUCC					(1<<8)		//下发设备的密钥成功
#define SW1_DLOAD_PARAM_SUCC					(1<<9)		//下发参数成功
#define SW1_SIGNPUBKEY							(1<<10)     //下发通用密钥成功。
#define SW1_CORRECT_TIME						(1<<11)     //正确时间。
#define SW1_RELEASED							(1<<12)     //正式生产设备。

#define	SW2_POWER_ON_LOGINED					(1<<3<<16)	//开机密码已登录。
#define	SW2_PROTECT_LOGINED						(1<<3<<8)	//保护密码已登录。
#define	SW2_UNLOCK_LOCKED						(1<<1)		//解锁密码已锁定（设备已锁定）。
#define	SW2_UNLOCK_LOGINED						(1<<3)		//解锁密码已登录。
#define SW2_PSW_CHANGED							(1<<24)		//开机PIN码已修改。//3040

#define	API_OK									0
#define API_BAD_TLV								0x8003
#define	API_DEVICE_NOT_SUPPORT					0x8008
#define	API_BACKUP_ALL_FINISHED					0x8009
#define	API_INVALID_PARAMETER					0x800A

#define E3001_TRANSFER_BUFFER_SIZE      		2148	//预留缓冲区大小，与硬件定义需相同

#define	MAXDEVID		(17+1)
#define	MAXITEMTITLE	(14+1)
#define	MAXITEMCATANAME	(14+1)
#define MAXITEMDESC		(128+1)
#define	MAXXURL			(128+1)
#define	MAX_SITENAME	(14+1)
#define	MAX_SCRIPTNAME	(24+1)
#define	MAX_ACCOUNTNAME	(32+1)


typedef struct tag_LPJMD_RESULT {
    int     ErrorCode1; //0x9000 正确，其他值为错误码。
    int     ErrorCode2;
    LPBYTE  ResultData; //返回的数据，详见CPP程序中的注释。
    int		ResultSize;
}JMD_RESULT, *LPJMD_RESULT;

typedef struct tag_JMD_SECURITYBOOK {
    char	itemTitle[MAXITEMTITLE];
    char	itemDesc[MAXITEMDESC];
    int		itemCataID;
    char	itemCataName[MAXITEMCATANAME];
    char	acctName[MAX_ACCOUNTNAME];
    char	xURL[MAXXURL];
    time_t  lastDate;
    int     ProtectLevel;       //密码页保护级别，0：开机密码 1：保护密码 2：应用密码
    int     mtProtectLevel;     //密条保护级别，0：可以批量读出内容 1：按确认键授权读出内容 2：不能读出内容，只能在设备中查看
    int     appLink;            //口令项是否关联了应用，0：未关联应用 1：关联了应用
}JMD_SECURITYBOOK, *LPJMD_SECURITYBOOK;

typedef struct tag_JMD_BACKUP_RECORD {
    char				itemTitle[MAXITEMTITLE];	//标题，仅对blockType 1 2有效。
    LPBYTE				recordData;					//本条备份数据
    DWORD				dataSIZE;					//本条备份数据长度
}JMD_BACKUP_RECORD, *LPJMD_BACKUP_RECORD;

typedef struct tag_JMD_BACKUP_FORMAT {
    char				deviceID[MAXDEVID];			//设备序列号，仅对blockType 0有效。
    int					backupKeyID;				//备份密钥序列号，仅对blockType 0有效。
    LPJMD_BACKUP_RECORD	lpRecord;					//BACKUP_RECORD列表
    DWORD				recordCount;				//BACKUP_RECORD数量
}JMD_BACKUP_FORMAT, *LPJMD_BACKUP_FORMAT;

#ifdef __cplusplus
extern "C" {
#endif
    /*
     * 所有函数的返回值为DWORD类型
     *	0为成功
     *	1为失败。
     * 所有输出为LPJMD_SECURITYBOOK *Result的，其中Result需要释放内存。
     */
    
    /*
     * 获取设备信息
     * 此函数已过期，请参考 BTComm_getDeviceInformation_3040
     */
    DWORD BTComm_getDeviceInfoS 		(LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_getDeviceInfoR 		(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /*
     * 枚举密码
     * 此函数已过期，请参考 BTComm_enumSecurityBook_3040 / BTComm_getResponse_3040
     *
     */
    DWORD BTComm_getSecurityBookS 		(DWORD isFirst, LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_getSecurityBookR 		(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    DWORD BTComm_getSecurityBookD 		(LPBYTE recvData, DWORD recvSize, LPJMD_SECURITYBOOK *Result, LPDWORD ResultCount);
    DWORD BTComm_getSecurityBookF 		(LPJMD_SECURITYBOOK Result);
    
    /*
     * 查询密码
     * 此函数已过期，请参考 BTComm_showSecurityBook_3040
     */
    DWORD BTComm_gotoSecurityBookS 		(LPCSTR itemTitle, LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_gotoSecurityBookR 		(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /*
     * 枚举密条标题+内容
     * 此函数已过期，请参考 BTComm_enumSecurityNote_3040 / BTComm_getResponse_3040
     */
    DWORD BTComm_getSecurityNoteS		(DWORD isFirst, LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_getSecurityNoteR 		(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    DWORD BTComm_getSecurityNoteD 		(LPBYTE recvData, DWORD recvSize, LPJMD_SECURITYBOOK *Result, LPDWORD ResultCount);
    DWORD BTComm_getSecurityNoteF 		(LPJMD_SECURITYBOOK Result);
    
    /*
     * 查询密条
     * 此函数已过期，请参考 BTComm_showSecurityNote_3040
     */
    DWORD BTComm_gotoSecurityNoteS		(LPCSTR itemTitle, LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_gotoSecurityNoteR 		(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /*
     * 绑定（下发用户密钥）
     * 此函数已过期，请参考 BTComm_setUserData_3040
     */
    DWORD BTComm_putUserKeyS			(LPBYTE userKey, DWORD userkeySize, LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_putUserKeyR 			(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /*
     * 激活
     * 此函数已过期，请参考 BTComm_Activate_3040
     */
    DWORD BTComm_ActivateS				(LPBYTE activateCode, DWORD codeSize, LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_ActivateR 				(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /*
     * 获取设备序列号
     * 此函数已过期，请参考 BTComm_getDeviceID_3040
     */
    DWORD BTComm_getDeviceSerialNoS		(LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_getDeviceSerialNoR 	(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /*
     * 获取设备状态
     * 此函数已过期，请参考 BTComm_getDeviceStatus_3040
     */
    DWORD BTComm_getDeviceStatusS 		(LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_getDeviceStatusR 		(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    DWORD BTComm_getDeviceStatusD 		(LPBYTE recvData, DWORD recvSize, LPDWORD SW1, LPDWORD SW2);
    
    /*
     * 新增密条
     * 此函数已过期，请参考 BTComm_addSecurityNote_3040
     */
    DWORD BTComm_addSecurityNoteS		(LPCSTR itemTitle, LPCSTR itemDesc, DWORD mtProtectLevel, LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_addSecurityNoteR 		(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /*
     * 删除密条
     * 此函数已过期，请参考 BTComm_deleteSecurityNote_3040
     */
    DWORD BTComm_deleteSecurityNoteS 	(LPCSTR itemTitle, LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_deleteSecurityNoteR 	(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /*
     * 更新密条
     * 此函数已过期，请参考 BTComm_updateSecurityNote_3040
     */
    DWORD BTComm_updateSecurityNoteS 	(LPCSTR itemTitle, LPCSTR itemDesc, LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_updateSecurityNoteR 	(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /*
     * 获取密条内容
     * only for 3026/3032/3038
     * 3040不支持该功能。
     */
    DWORD BTComm_getSecurityNoteContentS(LPCSTR itemTitle, LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_getSecurityNoteContentR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    DWORD BTComm_getSecurityNoteContentD (LPBYTE recvData, DWORD recvSize, LPJMD_SECURITYBOOK Result);
    
    /*
     * 新增密码
     * 此函数已过期，请参考 BTComm_addSecurityBook_3040
     */
    DWORD BTComm_addSecurityBookS 		(LPCSTR itemTitle, LPCSTR itemDesc, LPCSTR acctName, LPCSTR staticPwd, LPCSTR xURL, DWORD itemCataID, LPCSTR itemCataName, LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_addSecurityBookR 		(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /*
     * 删除密码
     * 此函数已过期，请参考 BTComm_deleteSecurityBook_3040
     */
    DWORD BTComm_deleteSecurityBookS	(LPCSTR itemTitle, LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_deleteSecurityBookR 	(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /*
     * 更新密码
     * 此函数已过期，请参考 BTComm_updateSecurityBook_3040
     */
    DWORD BTComm_updateSecurityBookS	(LPCSTR itemTitle, LPCSTR itemDesc, LPCSTR acctName, LPCSTR staticPwd, LPCSTR xURL, DWORD itemCataID, LPCSTR itemCataName, LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_updateSecurityBookR 	(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /*
     * 修改分类名
     * 由于3026/3032/3038新固件参数调整，此函数已废除，请参考 BTComm_updateCatalog_3040。
     */
    //DWORD BTComm_updateCatalogNameS(DWORD itemCataID, LPCSTR itemCataName, LPBYTE cmdBuf, LPDWORD cmdSize);
    //DWORD BTComm_updateCatalogNameR(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /*
     * 重置设备时间
     * only for 3026/3032/3038
     * 3040不支持该功能。
     */
    DWORD BTComm_ResetTimeS(LPBYTE ResetTimeCode, DWORD codeSize, LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_ResetTimeR(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /*
     * 数据备份
     * 此函数已过期，请使用 BTComm_Backup_3040S / BTComm_Backup_Next_3040S
     */
    DWORD BTComm_BackupS(DWORD isFirst, LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_BackupR(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /*
     * 数据恢复
     * 此函数已过期，请使用 BTComm_Restore_3040S
     */
    //DWORD BTComm_RestoreS(DWORD Flag, LPBYTE frameData, DWORD frameSize, DWORD totalSize, DWORD nFrame, LPBYTE cmdBuf, LPDWORD cmdSize);
    /*
     * 参数说明：
     *	Flag
     *		0 第一个数据包
     *		1 还有数据
     *		2 最后一个数据包
     *	frameData
     *		帧数据，帧大小不能超过2048字节。
     *	frameSize
     *		帧数据长度
     *	totalSize
     *		恢复数据总大小
     *	nFrame
     *		帧计数，从0开始计数
     */
    //DWORD BTComm_RestoreR(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /*
     * 固件升级
     * 此函数已过期，请参考 BTComm_upgradeFirmware_3040
     */
    DWORD BTComm_upgradeFirmwareS(DWORD Flag, LPBYTE frameData, DWORD frameSize, DWORD totalSize, DWORD nFrame, LPBYTE cmdBuf, LPDWORD cmdSize);
    DWORD BTComm_upgradeFirmwareR(LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /*
     * 获取重置码随机数
     * only for 3026/3032/3038
     * 3040不支持该功能。
     */
    DWORD BTComm_getResetCodeS(_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize);
    /*
     * 参数说明：
     *	cmdBuf
     *		发送给极密盾的命令。
     *	cmdSize
     *		输入时为cmdBuf缓冲区长度，返回时为极密盾指令长度。
     */
    DWORD BTComm_getResetCodeD (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    /*
     * 参数说明：
     *	recvData
     *		从极密盾接收到的数据。
     *	recvSize
     *		从极密盾接收到的数据长度。
     *	Result->ResultData
     *		重置码随机数。
     *	Result->ResultSize
     *		重置码随机数长度。
     */
    void BTComm_setSEQ_3040(DWORD newSEQ);
    
    /*
     * 以下为E3040协议封装解析指令
     * BTComm_xxx_3040S	构造极密盾指令函数
     * BTComm_xxx_3040R	解析极密盾返回数据函数。
     * BTComm_xxx_3040D	通常出现在经R处理后需再次解析的指令。
     * 返回值：
     *	==0成功，成功后所有标注_OUT及_IN_OUT类型的参数返回了有效数据。
     *  !=0失败，错误码。
     */
    
    /****************************************************************************
     301. 获取设备序列号
     ****************************************************************************/
    DWORD BTComm_getDeviceID_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize);
    /*
     * 参数说明：
     *	cmdBuf
     *		发送给极密盾的命令。
     *	cmdSize
     *		输入时为cmdBuf缓冲区长度，返回时为极密盾指令长度。
     */
    DWORD BTComm_getDeviceID_3040D (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPBYTE lpDeviceID, _IN_OUT LPDWORD lpstrSize);
    /*
     * 参数说明：
     *	recvData
     *		从极密盾接收到的数据。
     *	recvSize
     *		从极密盾接收到的数据长度。
     *	lpDeviceID
     *		返回的设备序列号，此缓冲区要求不少于MAXDEVID字节。
     *	lpstrSize
     *		_IN时表示上面这个参数的缓冲区大小，_OUT时返回实际大小。
     */
    
    /****************************************************************************
     302. 获取设备状态
     ****************************************************************************/
    DWORD BTComm_getDeviceStatus_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize);
    DWORD BTComm_getDeviceStatus_3040D (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPDWORD SW1, _OUT LPDWORD SW2, _OUT LPDWORD Left_Try_Times);
    /*
     * 返回值：
     *	for 3040
     *		SW1 如果不需要解析该状态，可以为NULL。
     *			SW1_READY				TRUE or FALSE;
     *			SW1_ACTIVATED			TRUE or FALSE;
     *			SW1_BINDED				TRUE or FALSE;
     *			SW1_SIGNPUBKEY			TRUE;
     *			SW1_CORRECT_TIME		TRUE;
     *			SW1_RELEASED 			TRUE;
     *		SW2 如果不需要解析该状态，可以为NULL。
     *			SW2_POWER_ON_LOGINED	TRUE or FALSE;
     *			SW2_PROTECT_LOGINED 	FLASE;
     *			SW2_UNLOCK_LOCKED		TRUE or FALSE;
     *			SW2_UNLOCK_LOGINED 		FALSE;
     *			SW2_PSW_CHANGED			TRUE or FALSE;
     *		Left_Try_Times  如果不需要解析该状态，可以为NULL。
     *			缺省值为6，固件1.01.009+为剩余尝试次数。
     *
     *	for 3026/3032/3038
     *		SW1  如果不需要解析该状态，可以为NULL。
     *			SW1_READY				TRUE or FALSE;
     *			SW1_ACTIVATED			TRUE or FALSE;
     *			SW1_BINDED				TRUE or FALSE;
     *			SW1_SIGNPUBKEY			TRUE or FALSE;
     *			SW1_CORRECT_TIME		TRUE or FALSE;
     *			SW1_RELEASED 			TRUE or FALSE;
     *		SW2  如果不需要解析该状态，可以为NULL。
     *			SW2_POWER_ON_LOGINED	TRUE or FALSE;
     *			SW2_PROTECT_LOGINED 	TRUE or FALSE;
     *			SW2_UNLOCK_LOCKED		TRUE or FALSE;
     *			SW2_UNLOCK_LOGINED 		TRUE or FALSE;
     *			SW2_PSW_CHANGED			TRUE;
     *		Left_Try_Times  如果不需要解析该状态，可以为NULL。
     *			缺省值为6。
     *
     * 示例：
     *		uint32_t	Left_Try_Times;
     *
     *		BTComm_getDeviceStatus_3040D((uint8_t *)[recvData bytes], (uint32_t)recvData.length, NULL, NULL, &Left_Try_Times);
     */
    
    /****************************************************************************
     303. 获取设备信息
     ****************************************************************************/
    DWORD BTComm_getDeviceInformation_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize);
    DWORD BTComm_getDeviceInformation_3040D (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    /*
     * 参数说明：
     * recvData
     *		从极密盾接收到的数据。
     * recvSize
     *		从极密盾接收到的数据长度。
     * Result->ResultData
     *		返回数据为JSON结构，由APP自行解析。
     *
     *		//3040 JSON 格式
     *		{
     *			"devID": "0123456701234561",			//设备序列号
     *			"ProductionDate": 1479099890,			//生产日期 32 bits UTC Time
     *			"PwdMinLen": 4,							//密码最短长度
     *			"PwdMaxLen": 16,						//密码最长长度
     *			"PWDERR": 5,							//密码最多允许错误次数
     *			"CSCRTO": 60,                           //自动熄屏秒数
     *			"DOWNTO": 60,                           //自动关机秒数
     *			"DevModel": "JM2A",						//设备型号
     *			"devVer": "E3040V1.01.001-1.01.001",	//固件版本号
     *			"MaxSecLog": 100,						//密条许可数量
     *			"MaxPwd": 100,							//密码许可数量
     *			"MaxATokenCnt": 100,					//最大aToken有效次数
     *			"MaxMEncKeyCnt": 10,					//主密钥许可数量
     *			"CurSecLog": 0,							//当前密条数量
     *			"CurPwd": 0,							//当前密码数量
     *			"CurMEncKeyCnt": 0,						//当前主密钥数量
     *			"NiceName": "",							//用于自定义的极密盾名称，可选项。
     *			"Language": 0							//极密盾当前语言，参见设置语言定义。1.01.011+支持。
     *		}
     *
     *		//3026/3032/3038 JSON 格式
     *		{
     *			"devID": "0123456701234567",			//设备序列号
     *			"ProductionDate": 1440580728,			//生产日期 32 bits UTC Time
     *			"PWDLEN": "041604160416",               //每两字节表一个密码长度，格式为min max min max min max，分别为设备密码、保护密码、解锁码
     *			"PWDERR": "050505",                     //每两字节表一个密码错误次数，分别为设备密码、保护密码、解锁码
     *			"SPARA": "0003",
     *			"CSCRTO": 60,                           //自动熄屏秒数
     *			"DOWNTO": 60,                           //自动关机秒数
     *			"DevModel": "JM1A",						//设备型号
     *			"devVer": "E3001V1.01.005-0.99.015",	//0.99.015为固件版本，升级检测使用
     *			"MaxSecLog": 500,                       //最大密条许可数量
     *			"SecLogNum": 0,                         //当前密条存储数量
     *			"MaxPwd": 500,                          //最大口令项许可数量
     *			"PwdNum": 0,                            //当前口令项数量
     *			"gPWDNum": 0,                           //当前组口令数量
     *			"CataNum": 1,                           //当前分类数量
     *			"Battery": 100,							//电池电量
     *			"devTime": 1442248496,					//设备时间 32 bits UTC Time
     *			"NiceName": ""							//用于自定义的极密盾名称，可选项。
     *		}
     */
    
    /****************************************************************************
     304. 获取设备公钥
     ****************************************************************************/
    enum{
        PUBLIC_KEY_NONE = 0,
        PUBLIC_KEY_SM2 = 0,
        PUBLIC_KEY_RSA1024 = 1,
        PUBLIC_KEY_RSA2048 = 2,
        PUBLIC_KEY_SM2TKEY = 3
    };
    
    DWORD BTComm_getDevicePublicKey_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD keyIndex);
    /*
     * 参数说明：
     *	keyIndex
     *		PUBLIC_KEY_SM2
     *		PUBLIC_KEY_RSA1024
     *		PUBLIC_KEY_RSA2048
     *		PUBLIC_KEY_SM2TKEY
     *
     * 使用说明：
     * 目前只支持SM2。
     * PublicKey 每个极密盾都不同。
     */
    DWORD BTComm_getDevicePublicKey_3040D (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPBYTE publicKey, _IN_OUT LPDWORD keySize);
    /*
     * 参数说明：
     *	publicKey
     *		返回的公钥结构体，此缓冲区要求不少于264字节。
     *
     *		RSA公钥结构体：
     *			BitLen：4字节；小端格式；公钥的模长；
     *			Modules：BitLen / 8；模数N；
     *			PublicExponent：4字节；公开密钥E,固定为65537；
     *
     *		SM2公钥结构体：
     *			BitLen：4字节；小端格式；公钥的模长；
     *			XCoordinate：BitLen / 8；公钥的X坐标；
     *			YCoordinate：BitLen / 8；公钥的Y坐标；
     *	keySize
     *		_IN时表示上面这个参数的缓冲区大小，_OUT时返回实际大小。
     */
    
    /****************************************************************************
     305. 请求联机通道
     ****************************************************************************/
    DWORD BTComm_requestSecurityChannel_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD keyIndex, _IN LPBYTE bToken, _IN DWORD bTokenSize, _IN LPBYTE aToken, _IN DWORD aTokenSize);
    /*
     * 参数说明：
     *	keyIndex
     *		PUBLIC_KEY_NONE     0
     *		PUBLIC_KEY_SM2      0
     *		PUBLIC_KEY_RSA1024  1
     *		PUBLIC_KEY_RSA2048  2
     *		PUBLIC_KEY_SM2TKEY  3
     *	bToken
     *		!=NULL && bTokenSize != 0 认为有bToken。
     *	bTokenSize
     *		bToken的长度。
     *	aToken
     *		!=NULL && aTokenSize != 0 认为有aToken。
     *	aTokenSize
     *		aToken的长度。
     * 使用说明：
     * for 3040 < 1.01.010
     *		keyIndex = PUBLIC_KEY_NONE
     * 		aToken / bToken为明文。
     * for 3040 >= 1.01.010
     *		keyIndex = PUBLIC_KEY_SM2
     *		aToken / bToken为SM2公钥加密的密文。
     * for 3026/3032/3038
     *		必须keyIndex = PUBLIC_KEY_NONE
     *		必须aToken = NULL, bToken = NULL;
     */
    DWORD BTComm_requestSecurityChannel_3040D (_IN LPBYTE recvData, _IN DWORD recvSize, _IN DWORD Rx, _OUT LPBYTE lpCK, _IN_OUT LPDWORD CKSize);
    /*
     * 参数说明：
     *	Rx
     *		由APP产生的32位随机数。用于计算CK。
     *
     * 返回值：
     *	CK
     *		返回的会话密钥的数据。
     *		此缓冲区要求16字节。
     *		CK每次都不同。
     *	CKSize
     *		_IN时表示上面这个参数的缓冲区大小，_OUT时返回实际大小。
     
     * 返回值：
     * 		包含ErrorCode1 & ErrorCode2。
     *
     * 使用说明：
     * 参照 精简版流程.html / 安全通道A / 普通通道 流程。
     */
    
    /****************************************************************************
     306. 下发联机会话密钥
     ****************************************************************************/
    DWORD BTComm_setSessionKey_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE EncCK, _IN DWORD EncCKSize, _IN DWORD keyIndex);
    /*
     * 参数说明：
     *	EncCK
     *		使用publicKey加密的CK，被加密数据为CK由 BTComm_requestSecurityChannel_3040 获得，公钥由 BTComm_getDevicePublicKey_3040 获得。
     *	EncCKSize
     *		EncCK的数据长度。
     *	keyIndex
     *		同调用 BTComm_getDevicePublicKey_3040 时的keyIndex。
     *
     * 使用说明：
     * 参照 精简版流程.html / 安全通道A / 普通通道 流程。
     * 以SM2为例：
     * 1）获取设备公钥 时的keyIndex = 0。
     * 2）获取设备公钥 返回的公钥数据为 00 10 00 00 || X (32 字节) || Y (32字节)。
     * 3）将公钥数据的X,Y取出，转换为HexString格式，作为MicrodoneGMSM2Enc函数的参数3和参数4。
     * 4）将CK转换成Base64格式，作为MicrodoneGMSM2Enc函数的参数1。
     * 5）MicrodoneGMSM2Enc函数的参数2为""。
     * 6）将MicrodoneGMSM2Enc函数的返回结果，经Base64解码后，作为本函数的参数 EncCK 和 EncCKSize传入。
     * 7）keyIndex此处与1）相同=0。
     */
    DWORD BTComm_setSessionKey_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     307. 关闭安全通道
     ****************************************************************************/
    DWORD BTComm_closeSecurityChannel_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize);
    DWORD BTComm_closeSecurityChannel_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     308. 激活
     ****************************************************************************/
    DWORD BTComm_Activate_3040S(_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE eCloudCMD, _IN DWORD _CMDSize);
    /*
     * 参数说明：
     *	eCloudCMD
     *		从服务器拿到的指令经base64解码后得到。
     *	_CMDSize
     *		activateCMD的数据长度。
     */
    DWORD BTComm_Activate_3040R	(_IN LPBYTE recvData, _IN DWORD recvSize, LPJMD_RESULT Result);
    
    /****************************************************************************
     309. 获取随机数
     ****************************************************************************/
    DWORD BTComm_getRandomNumber_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD nBytes);
    /*
     * 参数说明：
     * nBytes
     *		需要获取的随机数长度，单位字节。
     *		目前只支持16/32。为区分3040和3038。
     *
     * 使用说明：
     * 此命令目前只用于BTComm_verifyPIN_3040使用，且每次调用BTComm_verifyPIN_3040之前都必须调用。
     */
    DWORD BTComm_getRandomNumber_3040D (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPBYTE lpRandomNumber, _IN_OUT LPDWORD bufSIZE);
    /*
     * 参数说明：
     *	RandomNumber
     *		返回获取到的随机数，此缓冲区要求不少于nBytes字节。
     *	bufSIZE
     *		_IN时表示上面这个参数的缓冲区大小，_OUT时返回实际大小。
     */
    
    /****************************************************************************
     310. 验证设备PIN (包含 申请aToken)
     ****************************************************************************/
    DWORD BTComm_verifyPIN_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD Type, _IN LPBYTE RandomNumber, _IN LPBYTE PIN_SHA1, _IN LPBYTE bToken, _IN DWORD bTokenSIZE);
    /*
     * 参数说明：
     *	Type
     *		0 验证PIN
     *		1 验证PIN，并且申请aToken
     *	RandomNumber
     *		获取到的随机数，16字节
     *	PIN_SHA1
     *		对用户输入的PIN码计算SHA1得到的结果。
     *	bToken
     *		由云端返回的bToken。Type == 0 时，允许bToken = NULL，Type == 1时必须包含此项;
     *	bTokenSIZE
     *		bToken的长度。Type == 0 时，允许bTokenSIZE = 0，Type == 1时此项必须为正确的长度;
     *
     * 使用说明：
     * 		必须先调用BTComm_getRandomNumber_3040获取随机数。
     */
    DWORD BTComm_verifyPIN_3040D(_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    /*
     * 参数说明：
     * 当用于验证PIN，即Type == 0 时，返回数据只有Result.ErrorCode1和Result.ErrorCode2有效。
     * 当用于申请aToken，即Type == 1 时，并且ErrorCode1、ErrorCode2为正确的情况下，另外还包含：
     *	Result.ResultData
     *		aToken数据
     *	Result.ResultSize
     *		aToken数据的长度。
     */
    
    /****************************************************************************
     311. 绑定（下发用户密钥）
     ****************************************************************************/
    DWORD BTComm_setUserData_3040S(_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE eCloudCMD, _IN DWORD _CMDSize);
    /*
     * 参数说明：
     *	eCloudCMD
     *		由云端返回的绑定指令，经base64解码后得到。
     *	_CMDSize
     *		userDataCMD长度。
     */
    
    DWORD BTComm_setUserData_3040R (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /****************************************************************************
     312. 枚举密条 (独占模式)
     ****************************************************************************/
    DWORD BTComm_enumSecurityNote_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize);
    /*
     * 使用说明：
     * 1) 连续读，全部读完再解析(原3026/3032/3038流程)。
     *  BTComm_enumSecurityNote_3040S
     *  (APP发送数据给极密盾)
     *  (极密盾返回数据给APP)
     *  BTComm_getResponse_3040R                <--返回9000 6100，可继续。
     *  while {
     *      BTComm_getResponse_3040S(nFrame)
     *      (APP发送数据给极密盾)
     *      (极密盾返回数据给APP)               <--如出现CRC错误等情况，可再次请求本帧数据。
     *      BTComm_getResponse_3040R            <--返回9000 6100表明后续还有，继续循环，并把JMD_Result.ResultData数据追加到上一帧尾部。
     *                                             返回9000 9000标明全部读完，终止循环。
     *                                             其他返回值为错误代码(超时等)。
     *      nFrame ++
     *  }
     *  BTComm_enumSecurityNote_3040D           <--解析所有读取的数据（TLV翻译到java class）
     *
     * 2) 全部读，边读边解析边显示，并提示用户剩余数据完成时间(3040 only)。
     *  BTComm_enumSecurityNote_3040S
     *  (APP发送数据给极密盾)
     *  (极密盾返回数据给APP)
     *  BTComm_getResponse_3040R                <--返回9000 6100，可继续。
     *  while {
     *      BTComm_getResponse_3040S(nFrame)
     *      (APP发送数据给极密盾)
     *      (极密盾返回数据给APP)               <--如出现CRC错误等情况，可再次请求本帧数据。
     *      BTComm_getResponse_3040R            <--返回9000 6100表明后续还有，继续循环。
     *                                             返回9000 9000标明全部读完，终止循环。
     *                                             其他返回值为错误代码(超时等)。
     *      BTComm_enumSecurityNote_3040D       <--非错误时，可直接解析并显示（TLV翻译到java class）
     *                                          <--由nFrame==0时返回的条目数和设备信息返回的总条目数，可估算剩余时间。
     *      nFrame ++
     *  }
     *
     * 3) 分页读(3040 only)。
     *  BTComm_enumSecurityNote_3040S
     *  (APP发送数据给极密盾)
     *  (极密盾返回数据给APP)
     *  BTComm_getResponse_3040R                <--返回9000 6100，可继续。
     *  BTComm_getResponse_3040S(nFrame)
     *  (APP发送数据给极密盾)
     *  (极密盾返回数据给APP)                   <--如出现CRC错误等情况，可再次请求本帧数据。
     *  BTComm_getResponse_3040R                <--返回9000 6100表明后续还有，可继续滑动翻页。
     *                                             返回9000 9000标明全部读完，继续滑动翻页时可提示用户已全部读完。
     *                                             其他返回值为错误代码。
     *  BTComm_enumSecurityNote_3040D           <--非错误时, 可直接解析并显示（TLV翻译到java class）
     *  nFrame ++                               <--nFrame, 类变量。
     *
     *  3026/3032/3038请使用专用函数。
     */
    //	DWORD BTComm_enumSecurityNote_3040R(_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    /*
     * 请使用BTComm_getResponse_3040R。
     */
    DWORD BTComm_enumSecurityNote_3040D (_IN LPBYTE ResultData, _IN DWORD ResultSize, _OUT LPJMD_SECURITYBOOK *Result, _OUT LPDWORD ResultCount);
    /*
     * 参数说明：
     *	ResultData
     *		R函数返回的Result.ResultData，允许NULL，但同时ResultSize必须=0。
     *	ResultSize
     *		R函数返回的Result.ResultSize。
     *
     * 输出：
     *	Result
     *		for 3040
     *		{
     *			itemTitle       //标题
     *			lastDate		//更新时间
     *		}
     *	ResultCount
     *		密条数量
     *
     * Result 需要调用BTComm_enumSecurityNoteFree释放内存。
     */
    DWORD BTComm_enumSecurityNoteFree (_IN LPJMD_SECURITYBOOK Result);
    
    /****************************************************************************
     313. 新增密条
     ****************************************************************************/
    DWORD BTComm_addSecurityNote_3040S(_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPCSTR itemTitle, _IN LPCSTR itemDesc, _IN DWORD utcTime, _IN DWORD mtProtectLevel);
    /*
     * 参数说明：
     *	itemTitle
     *		标题，必须， 4-14字节（英文算一个字节，中文算两个字节）。
     *	itemDesc
     *		内容，4-128字节（英文算一个字节，中文算两个字节）***。
     *		==NULL 或者 ""时，认为此项不存在。
     *	utcTime
     *		更新时间
     *		==0 时，认为此项不存在。
     *	mtProtectLevel
     *		密条保护级别
     *		==0 时，认为此项不存在。
     *
     * 使用说明：
     * for 3040
     *		itemDesc 为可选。
     *		mtProtectLevel 必须为0。
     *		此指令为非独占模式，无需等待按键。
     * for 3026/3032/3038
     *		itemDesc 为必选。
     *		utcTime 必须为0。
     *		此指令需等待极密盾按键。
     */
    DWORD BTComm_addSecurityNote_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     314. 更新密条
     ****************************************************************************/
    DWORD BTComm_updateSecurityNote_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPCSTR itemTitle, _IN LPCSTR itemDesc, _IN DWORD utcTime);
    /*
     * 参数说明：
     *	itemTitle
     *		标题，必须， 4-14字节（英文算一个字节，中文算两个字节）。
     *	itemDesc
     *		内容，可选，4-128字节（英文算一个字节，中文算两个字节）。
     *		当为NULL 或者 ""时，认为此项不存在。
     *	utcTime
     *		更新时间
     *		==0 时，认为此项不存在。
     *
     * 使用说明：
     * for 3040
     *		此指令为非独占模式，无需等待按键。
     * for 3026/3032/3038
     *		utcTime 必须为0。
     *		此指令需等待极密盾按键。
     */
    DWORD BTComm_updateSecurityNote_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     315. 查询密条 (独占模式)
     ****************************************************************************/
    DWORD BTComm_showSecurityNote_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPCSTR itemTitle);
    /*
     * 参数说明：
     *	itemTitle
     *		标题，必须， 4-14字节（英文算一个字节，中文算两个字节）。
     *
     * 使用说明：
     *	3040
     *		执行成功后，R函数ErrorCode1和ErrorCode2分别返回0x9000 0x6100，表明此时出于独占模式。
     *	    此时可初始化键盘，并发送上下控制键。可调用退出独占模式终止键盘输入。
     *	3026/3032/3038
     *		执行成功后，返回0x9000 0x9000，无后续操作。
     */
    DWORD BTComm_showSecurityNote_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     316. 删除密条 (独占模式)
     ****************************************************************************/
    DWORD BTComm_deleteSecurityNote_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPCSTR itemTitle);
    /*
     * 参数说明：
     *	itemTitle
     *		标题，必须， 4-14字节（英文算一个字节，中文算两个字节）。
     *
     * 使用说明：
     * for 3040
     *		此指令为独占模式，需调用BTComm_getResponse_3040判断用户按键状态或超时。
     * for 3026/3032/3038
     *		此指令需等待极密盾按键。
     */
    DWORD BTComm_deleteSecurityNote_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     318. 发送键盘字符（串）
     ****************************************************************************/
    DWORD BTComm_sendInput_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE lpChar, _IN DWORD _SIZE);
    /*
     * 参数说明：
     *	lpChar
     *		要发送的字符串。
     *	_SIZE
     *		长度。
     *
     * 键值定义：
     * 	字符：
     *		0x20 - 0x7E
     *	映射字符，对应映射键盘的0-15号位置
     *		0xA0 - 0xAF
     * 	回退；单键下发
     *		0x08
     *	清空内容：
     *		0x12
     *	显示映射键盘：
     *		0x11
     *	隐藏映射键盘：
     *		0x13
     * 	上翻页：
     *		0x18
     * 	下翻页：
     *		0x19
     *	第n段用Chars填充：
     *		输入备份密钥使用，n 1-8，Chars固定长度4字节。
     *		ESC | 'L' | n | Chars
     *		例如第1段用"1234"填充，\x1B\x4C\x01\x31\x32\x33\x34
     *	第n段清空：
     *		输入备份密钥使用，n 1-8。
     *		ESC | 'L' | n | "Clear"，Clear不分大小写。
     *		例如第2段清空，\x1B\x4C\x02\x43\x6C\x65\x61\x72
     *
     * 	使用说明：
     *		for 3038该指令模拟的用户按物理按键动作，不可连续发送，至少间隔10毫秒，否则会出错。
     */
    DWORD BTComm_sendInput_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     319. 读取响应 Get Response
     ****************************************************************************/
    DWORD BTComm_getResponse_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD nFrame, _IN DWORD blockType);
    /*
     * 参数说明：
     *	nFrame
     *		帧序列，对枚举密码、枚举密条、备份数据有用，其他情况=0。
     *	blockType
     *		数据备份时使用，其他情况=0。
     *
     * 使用说明：
     *		本函数超时时间4秒，如果4秒内无getResponse下发，极密盾自动退出独占模式。
     * 适用于 安全键盘操作/按键确认/交易签名/枚举密码/枚举密条/数据备份；
     */
    DWORD BTComm_getResponse_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    /*
     * 不识别的数据，返回原数据。
     * 国密数据，返回去除第一层TLV的数据。
     * 枚举密码、枚举密条、备份数据，返回去除第一层TLV的数据，可用于拼包或者解调用响应D函数解析。
     * 按键状态、指令执行状态 会返回到 Result.ErrorCode1 和 Result.ErrorCode2上。
     */
    
    /****************************************************************************
     320. 退出独占模式
     ****************************************************************************/
    DWORD BTComm_exitExclusiveMode_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize);
    /*
     * for 3040
     *		退出独占模式。实际效果是使当前出于独占模式的指令终止执行。
     * for 3038
     *		无意义，但可以用于终止上一条命令。从1.01.007开始支持，老版本固件同3026。
     * for 3026/3032
     *		会报错，截止2016/11/30固件不支持此指令。
     */
    DWORD BTComm_exitExclusiveMode_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     321. 下发许可设置
     ****************************************************************************/
    DWORD BTComm_setLicense_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE eCloudCMD, _IN DWORD _CMDSize);
    /*
     * 参数说明：
     *	eCloudCMD
     *		由云端返回的设置许可指令，经base64解码后得到。
     *	_CMDSize
     *		LicenseCMD长度。
     */
    DWORD BTComm_setLicense_3040R (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /****************************************************************************
     322. 设备重置
     ****************************************************************************/
    DWORD BTComm_resetFactory_3040S(_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE eCloudCMD, _IN DWORD _CMDSize);
    /*
     * 参数说明：
     *	eCloudCMD
     *		由云端返回的设备重置指令，经base64解码后得到。
     *	_CMDSize
     *		LicenseCMD长度。
     */
    DWORD BTComm_setLicense_3040R (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    
    /****************************************************************************
     323. 枚举密码 (独占模式)
     ****************************************************************************/
    DWORD BTComm_enumSecurityBook_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize);
    /*
     * 参考 枚举密条使用说明。
     */
    //  DWORD BTComm_enumSecurityBook_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    /*
     * 请使用BTComm_getResponse_3040R。
     */
    DWORD BTComm_enumSecurityBook_3040D (_IN LPBYTE ResultData, _IN DWORD ResultSize, _OUT LPJMD_SECURITYBOOK *Result, _OUT LPDWORD ResultCount);
    /*
     * 参数说明：
     *	ResultData
     *		R函数返回的Result.ResultData。
     *	ResultSize
     *		R函数返回的Result.ResultSize。
     * 输出：
     *	Result
     *		//3040
     *		{
     *			itemTitle       //标题
     *			itemDesc        //内容
     *			itemCataName	//分类名称
     *			acctName		//账号名
     *			lastDate		//更新时间
     *		}
     *
     *		//3026/3032/3038
     *		{
     *			itemTitle		//标题
     *			itemCataID		//
     *			itemCataName	//分类名称
     *			itemDesc		//
     *			xURL			//(已过期结构项)
     *			lastDate		//更新时间
     *			protectLevel	//
     *			appLink			//
     *		}
     *	ResultCount
     *		密码数量
     */
    DWORD BTComm_enumSecurityBookFree (_IN LPJMD_SECURITYBOOK Result);
    
    /****************************************************************************
     324. 新增密码
     ****************************************************************************/
    DWORD BTComm_addSecurityBook_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPCSTR itemTitle, _IN LPCSTR itemDesc, _IN LPCSTR acctName, _IN LPCSTR staticPwd, _IN DWORD itemCataID, _IN LPCSTR itemCataName, _IN DWORD utcTime);
    /*
     * 参数说明：
     *	itemTitle
     *		标题，必须，4-14字节（英文算一个字节，中文算两个字节）。
     *	itemDesc
     *		内容，可选，4-128字节（英文算一个字节，中文算两个字节）。
     *		==NULL 或者 ""时，认为此项不存在。
     *	acctName
     *		账户名，1-32字节（英文算一个字节，中文算两个字节）。
     *		==NULL 或者 ""时，认为此项不存在。
     *	staticPwd
     *		密码，1-32字节（英文，[0-9][a-z][A-Z][ !"#$%&'()*+,-./:;<=>?@[\]^_`{|}]）。
     *		==NULL 或者 ""时，认为此项不存在。
     *	itemCataID
     *		分类ID。参见下文使用说明。
     *	itemCataName
     *		分类名称，4-14字节（英文算一个字节，中文算两个字节）。参见下文使用说明。
     *	utcTime
     *		更新时间
     *		==0时，认为此项不存在。
     *
     * 使用说明：
     * for 3040
     *		itemCataID != 0, itemCataName="默认分类" || "自定义分类"。
     *		此指令为非独占模式，无需等待按键。
     *		以1.4版APP需求为例，新增密码：
     *
     *		第一个页面除静态口令外用户全部可设置。
     *		BTComm_addSecurityBook_3040S(
     *			itemTitle			//必选
     *			itemDesc 			//可选
     *			acctName 			//可选
     *			itemCataID = 1
     *			itemCataName		//最好让用户写上，不建议可选。
     *			utcTime				//32位系统时间
     *		)
     *		(发送到极密盾)
     *		(极密盾返回状态)			//添加成功 (&& 有acctName继续设置密码)。
     *
     *		第二个页面设置静态口令。
     *		BTComm_updateSecurityBook_3040S(
     *			itemTitle			//必选
     *			staticPwdType = 1	//由映射键盘修改静态口令。
     *		)
     *		(发送到极密盾)
     *		(极密盾返回状态)			//正常为0x6100表示进入独占模式，可接收键盘输入。
     *		BTComm_sendInput_3040S(
     *			staticPwd			//用户输入的静态口令
     *		)
     *		(发送到极密盾)
     *		(极密盾返回状态)			//依然是独占模式
     *		BTComm_sendInput_3040R
     *		while ( 独占模式 ){
     *			BTComm_getResponse_3040S
     *			(发送到极密盾)
     *			(极密盾返回状态)	//OK | C | TIMEOUT
     *			BTComm_getResponse_3040R
     *		}
     *		if OK ...
     *		if C ...
     *		if TIMEOUT ...
     *
     * for 3026/3032/3038
     *		默认分类
     *			itemCataID = 0, itemCataName="默认分类"。
     *		自定义分类
     *			itemCataID != 0, itemCataName="自定义分类"。
     *		此指令需等待极密盾按键。
     *
     * 程序实现，for ALL
     *	if ( (JMDType==JM1A || JMDType==JM1Ax || JMDType==JM1B) && itemCataName == "默认分类" )
     *		itemCataID = 0;
     *	else if ( itemCataID == 0 )
     *		itemCataID = 1;
     */
    DWORD BTComm_addSecurityBook_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     325. 更新密码 (独占模式)
     ****************************************************************************/
    DWORD BTComm_updateSecurityBook_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPCSTR itemTitle, _IN LPCSTR itemDesc, _IN LPCSTR acctName, _IN LPCSTR staticPwd, _IN DWORD itemCataID, _IN LPCSTR itemCataName, _IN DWORD staticPwdType, _IN DWORD utcTime);
    /*
     * 参数说明：
     *	itemTitle
     *		标题，必须， 4-14字节（英文算一个字节，中文算两个字节）。
     *	itemDesc
     *		内容，可选，4-128字节（英文算一个字节，中文算两个字节）。
     *		==NULL 或者 ""时，认为此项不存在。
     *		*** 此项不存在，极密盾会删除已有内容。
     *	acctName
     *		账户名，1-32字节（英文算一个字节，中文算两个字节）。
     *		==NULL 或者 ""时，认为此项不存在。
     *	staticPwd
     *		密码，1-32字节（英文，[0-9][a-z][A-Z][ !"#$%&'()*+,-./:;<=>?@[\]^_`{|}]）。
     *		==NULL 或者 ""时，认为此项不存在。
     *	itemCataID
     *		分类ID。参见下文使用说明。
     *	itemCataName
     *		分类名称，4-14字节（英文算一个字节，中文算两个字节）。参见下文使用说明。
     *	staticPwdType
     *		0 由App端修改口令项。
     *		1 由映射键盘修改静态口令；由APP修改其他参数。
     *	utcTime
     *		更新时间
     *		==0时，认为此项不存在。
     *
     *
     * 使用说明：
     * for 3040
     *		itemCataID != 0, itemCataName="默认分类" || "自定义分类"。
     *		BTComm_updateSecurityBook_3040S(staticPwdType=1) 时，该指令应进入独占模式。
     *		staticPwdType=1时，可通过BTComm_sendInput_3040S 将staticPwd发下去。
     *		staticPwdType=1时，其他修改项依然生效。
     *		BTComm_getResponse_3040S/R 等待极密盾响应，OK | C | TIMEOUT。
     *		此指令在staticPwdType=1时为独占模式。
     * for 3026/3032/3038
     *		默认分类
     *			itemCataID = 0, itemCataName="默认分类"。
     *		自定义分类
     *			itemCataID != 0, itemCataName="自定义分类"。
     *		此指令需等待极密盾按键。
     *		staticPwdType必须=0。
     *		utcTime必须=0。
     *		此指令需等待极密盾按键。
     *
     * 程序实现，for ALL
     *	if ( (JMDType==JM1A || JMDType==JM1Ax || JMDType==JM1B) && itemCataName == "默认分类" )
     *		itemCataID = 0;
     *	else if ( itemCataID == 0 )
     *		itemCataID = 1;
     */
    DWORD BTComm_updateSecurityBook_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     326. 查询密码 (独占模式)
     ****************************************************************************/
    DWORD BTComm_showSecurityBook_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPCSTR itemTitle);
    /*
     * 参数说明：
     * itemTitle
     *	标题，必须， 4-14字节（英文算一个字节，中文算两个字节）。
     *
     * 使用说明：
     *	3040
     *		执行成功后，R函数ErrorCode1和ErrorCode2分别返回0x9000 0x6100，表明此时出于独占模式。
     *	    此时可初始化键盘，并发送上下控制键。可调用退出独占模式终止键盘输入。
     *	3026/3032/3038
     *		执行成功后，返回0x9000 0x9000，无后续操作。
     */
    DWORD BTComm_showSecurityBook_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     327. 删除密码 (独占模式)
     ****************************************************************************/
    DWORD BTComm_deleteSecurityBook_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPCSTR itemTitle);
    /*
     * 参数说明：
     *	itemTitle
     *		标题，必须， 4-14字节（英文算一个字节，中文算两个字节）。
     *
     * 使用说明：
     * for 3040
     *		此指令为独占模式，需调用BTComm_getResponse_3040判断用户按键状态或超时。
     * for 3026/3032/3038
     *		此指令需等待极密盾按键。
     */
    DWORD BTComm_deleteSecurityBook_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     328. 数据备份 (独占模式)
     ****************************************************************************/
    DWORD BTComm_Backup_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize);
    DWORD BTComm_Backup_Next_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD nFrame, _IN DWORD blockType, _IN LPCSTR deviceModel, _IN LPCSTR armVersion);
    /*
     * 参数说明：
     *	nFrame
     *		帧号，每种blockType都从0计数。
     *	blockType
     *		备份数据种类，详见下文 备份数据格式 BLOCK定义。
     *	deviceModel
     *		源设备de设备型号。例如："JM1A"/"JM1Ax"/"JM1B"/"K2"。
     *	armVersion
     *		源设备de固件版本。例如："1.01.008"。
     *
     * 备份数据格式：
     *
     * BLOCK 0					//设备号+备份密钥ID
     * {
     *		DeviceID			//设备序列号
     *		BackupKeyID			//备份密钥ID
     * }
     *
     * BLOCK 1					//密码数据
     *		BKREC 0
     *		{
     *			recordID		//==itemTitle
     *			encryptedData	//密文数据
     *			clearMAC		//明文的MAC
     *		}
     *		...
     *		BKREC N
     * BLOCK 2					//密条数据
     *		BKREC 0
     *		{
     *			recordID		//==itemTitle
     *			encryptedData	//密文数据
     *			clearMAC		//明文的MAC
     *		}
     *		...
     *		BKREC N
     * BLOCK 3					//主加密密钥数据
     *		BKREC 0
     *		{
     *			recordID		//二进制数据，含义未知。
     *			encryptedData	//密文数据
     *			clearMAC		//明文的MAC
     *		}
     *		...
     *		BKREC N
     *
     * 使用说明：
     * for 3040 || 3026 >=0.99.030 || 3032 >=1.01.005 || 3038 >=1.01.008
     * 每种BLOCK单独循环处理。每种BLOCK不会交叉。
     * 每种BLOCK 依次递增，不可乱序。
     * 对于3038 & 3040 BLOCK 0 3必须包含，BLOCK 3完成时自动退出独占模式。
     * 备份文件存储时，如需以下信息，请APP自行记录：
     *		备份日期
     *		每种BLOCK的数量/存储位置
     *		设备序列号
     *		描述
     * 数据备份/数据恢复时，用户可选择BLOCK进行备份/恢复。
     * 数据备份/数据恢复支持断线续传。
     * 当 BTComm_Backup_Next_3040S 返回错误码 API_BACKUP_ALL_FINISHED时，备份结束。
     *
     * 数据备份流程如下：
     *		BTComm_Backup_3040S
     *		(发送到极密盾)
     *		(收到极密盾返回数据)
     *		BTComm_Backup_3040R								//此处只会返回状态字，没有数据。
     *														//9000:6100 进入独占模式。
     *														//6405:6608 设备未登录
     *														//6405:108A 通道权限不满足
     *														//错误代码  其他。
     *
     *		if ( 0x6608 == errorCode2 ) {
     *			show message								//提示用户去极密盾登录
     *			do {
     *				获取设备状态
     *				等待200毫秒
     *			} while (用户未登录 && 未超时);
     *			hide message								//取消提示
     *			if ( 用户已登录 )
     *				重新执行 备份操作。
     *			else
     *				终止。
     *		}
     *		if ( 0x6100 == errorCode2 ) {
     *			show error message							//提示用户去极密盾登录
     *			goto All_Finished;
     *		}
     *
     *		blockType = 0									//备份BLOCK X的数据，可选，可分别对BLOCK 0 1 2 3进行备份。
     * NextBlock:
     *		nFrame = 0										//每种BLOCK都从第0帧开始。
     *		do {
     *			dwRet = BTComm_Backup_Next_3040S (nFrame, blockType, "K2", "1.01.009")
     *			if ( API_BACKUP_ALL_FINISHED == dwRet )
     *				goto All_Finished;
     *			(发送到极密盾)
     *			(收到极密盾返回数据)
     *			BTComm_Backup_3040R							//9000 6100 等待用户按键 || 后续还有数据。
     *														//9000 9000 此BLOCK数据全部完成（可能为空数据）。
     *														//6405 0035 用户按了C键。
     *														//6405 0036 超时错误。
     *														//6405 10A0 密码已满。
     *														//6405 10A3 密条已满。
     *														//6405 0036 超时错误。
     *														//其他 错误码。
     *			if ( ResultSize != 0 ){
     *				nFrame ++								//有数据返回，保存返回的备份数据，继续下一帧。
     *														//如果计算传输时间，需要解析当前返回条目数（暂不支持）。
     *			}
     *			else if ( 0x6100 == errorCode2 ) {
     *				等待 200毫秒							//目前为等待按键状态，可稍加延迟。
     *			}
     *		} while ( 0x6100 == errorCode2 )
     *		blockType ++;
     *		goto NextBlock;
     * All_Finished:
     *		...
     */
    DWORD BTComm_Backup_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    /*
     * 等效于 BTComm_getResponse_3040R
     */
    
    
    /****************************************************************************
     329. 数据恢复 (独占模式)
     ****************************************************************************/
    DWORD BTComm_Restore_3040S(_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE backupData, _IN DWORD backupSize, _IN_OUT LPDWORD backupOffset, _IN LPCSTR deviceModel, _IN LPCSTR armVersion);
    /*
     * 参数说明：
     * 	cmdBuf
     *		极密盾指令缓冲区，要求最小2148字节。
     *	backupData
     *		备份数据。
     *	backupSize
     *		备份数据长度。
     *	backupOffset
     *		备份数据当前处理位置。
     *	deviceModel
     *		目标设备de设备型号，例如："JM1A"/"JM1Ax"/"JM1B"/"K2"。
     *	armVersion
     *		目标设备de固件版本，例如："1.01.008"。
     *
     * 使用说明：
     * 自动识别备份数据格式，无需关心备份时固件版本。
     * 当目标设备不支持此数据备份恢复时，返回API_DEVICE_NOT_SUPPORT。
     * for 3040 || 3026 >=0.99.030 || 3032 >=1.01.005 || 3038 >=1.01.008
     * 	数据恢复可直接恢复任意条数据。
     * 	数据恢复为增量恢复，不会覆盖已有数据。
     * 	数据恢复采用即时处理方式，每条指令的执行时间稍长。
     * 	最后一帧恢复数据API会自动添加结束标记，极密盾返回9000同时会自动退出独占模式。
     * for 3026/3032/3038 <1.01.008
     *	自动生成相应分包和恢复数据指令。
     *
     * 数据恢复流程如下（与固件升级类似）：
     *		backupOffset = 0					//读入备份数据，并设置backupOffset = 0
     *		while ( backupOffset < backupSize ) {
     *			BTComm_Restore_3040S(backupOffset)
     *			(发送到极密盾)
     *			(极密盾返回状态)
     *			BTComm_Restore_3040R			//9000:6100 独占模式，等待按键。
     *											//9000:9000	数据恢复正确，继续。
     *											//6405:6608 设备未登录，恢复失败，提示在极密盾上数据开机密码。
     *											//6405:10A0 密码已满。
     *											//6405:10A3 密条已满。
     *											//6405:108E 主密钥已满。
     *											//其他错误  数据恢复失败。
     *											//任意时间可调用退出独占模式终止数据恢复。
     *			while ( 0x6100 == errorCode2 ) {
     *				BTComm_getResponse_3040S
     *				(发送到极密盾)
     *				(极密盾返回状态)
     *				BTComm_getResponse_3040R
     *											//9000:6100 用户未按键继续等待。
     *											//9000:9000 用户按了OK，且数据恢复正确，可继续。
     *											//当errorCode1 == 0x6405 时，终止恢复，极密盾主动退出独占模式。
     *											//6405:0035 用户按了C。
     *											//6405:0036 TIMEOUT。
     *											//6405:1092	数据恢复MAC错误，恢复失败，需要用户输入备份密钥。
     *											//6405:108F	备份密钥不存在，恢复失败，需要用户输入备份密钥。
     *											//6405:10A0 密码已满。
     *											//6405:10A3 密条已满。
     *											//6405:108E 主密钥已满。
     *											//其他错误  数据恢复失败。
     *			}
     *		}
     *
     *		if ( 0x1092 || 0x108F ){		//输入备份密钥。
     *			BTComm_backupKey_3040(2)
     *			BTComm_sendInput_3040(XON)	//如果要显示映射键盘，自己开启下
     *			BTComm_sendInput_3040		//分段输入方式 ESC | L | n | "1234"
     *										//1B4CxxXXXXXXXX, xx为第几段，XXXXXXXX为4个字节字符。
     *										//例如第一段密码"1234"，发送键盘指令为1B4C0131323334。
     *										//分段清除 ESC | L | n | Clear
     *										//"\x1B\x4C\x01\x43\x6C\x65\x61\x72"
     *			BTComm_getResponse_3040		//用户OK后，重启数据恢复流程。
     *		}
     *
     */
    DWORD BTComm_Restore_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    /*
     * 等效于 BTComm_getResponse_3040R
     */
    
    /****************************************************************************
     330. 固件升级 (独占模式)
     ****************************************************************************/
    DWORD BTComm_upgradeFirmware_3040S(_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD Flag, _IN LPBYTE frameData, _IN DWORD frameSize, _IN DWORD totalSize, _IN DWORD nFrame);
    /*
     * 参数说明：
     *	Flag
     *		0 后续还有。
     *		1 最后一包。
     *	frameData
     *		固件升级数据每帧数据，除最后一帧外每帧必须1024字节。
     *	frameSize
     *		frameData大小。
     *	totalSize
     *		固件总大小。
     *	nFrame
     *		第几帧，从0计数。
     *
     * 使用说明：
     *	for 3040
     *		BTComm_upgradeFirmware_3040S(nFrame = 0 | X)	//支持断线续传，续传时X为4的整倍数(数据以4096为边界)。
     *		(发送到极密盾)
     *		(极密盾返回状态)
     *		BTComm_getResponse_3040R			//errorCode2 可能为：
     *											//==0x6100 	进入独占模式，等待用户按键。
     *											//==0x9000	3026/3032/3038才会出现。
     *											//others	其他错误，比如通道错误等，终止升级。
     *		while ( 0x6100 == errorCode2 ) {
     *			BTComm_getResponse_3040S
     *			(发送到极密盾)
     *			(极密盾返回状态)
     *			BTComm_getResponse_3040R		//当errorCode1 == 0x9000 时，errorCode2 可能为：
     *											//==0x6100 	用户未按键继续等待。
     *											//==0x9000 	用户按了OK，且数据正确(xData==0x0000 SW=0x9000)，可继续。
     *											//当errorCode1 == 0x6405 时，终止升级，极密盾主动退出独占模式，errorCode2 可能为：
     *											//==0x0035 	用户按了C。(xData==0x0035 SW=0x9000)
     *											//==0x0036 	TIMEOUT。(xData==0x0036 SW=0x9000)
     *											//others	其他错误，比如数据错误，TLV错误，CRC错误等等。
     *		}
     *		;									//OK且数据正确时，依然处于独占模式。
     *		for ( ++nFrame < totalFrame ) {
     *			BTComm_upgradeFirmware_3040S(nFrame)
     *			(发送到极密盾)
     *			(极密盾返回状态)
     *			BTComm_getResponse_3040R		//errorCode2 可能为：
     *											//==0x6100 	依然处于独占模式，可继续。
     *											//==0x9000	出现在最后一包，表明数据正确且退出独占模式，终止循环。
     *											//others	其他错误，比如数据错误，TLV错误，CRC错误等等，终止循环。
     *		}
     *
     *		除最后一帧外每帧必须1024字节。
     *	for 3026/3032/3038
     *		无固定大小限制，但要求<=2048。
     */
    DWORD BTComm_upgradeFirmware_3040R (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result);
    /*
     * 等效于 BTComm_getResponse_3040R
     */
    
    /****************************************************************************
     331. 修改设备PIN (由上位机输入)
     ****************************************************************************/
    DWORD BTComm_modifyPIN_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE oldPIN_SHA1, _IN LPBYTE newPIN, _IN DWORD newPIN_SIZE);
    /*
     * 参数说明：
     *	oldPIN_SHA1
     *		对用户输入的oldPIN码计算SHA1得到的结果。
     *	newPIN
     *		用户输入的新开机密码。
     *	newPIN_SIZE
     *		newPIN长度
     */
    DWORD BTComm_modifyPIN_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     332. 验证PIN管理+修改设备PIN (独占模式)
     ****************************************************************************/
    DWORD BTComm_verify_modifyPIN_EM_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD Type);
    /*
     * 参数说明：
     *	Type
     *		0 修改
     *		1 验证
     */
    //DWORD BTComm_verify_modifyPIN_EM_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    /*
     * 请使用BTComm_getResponse_3040R。
     */
    /*
     * 使用说明：
     * 	ErrorCode1:ErrorCode2
     *		0x9000:0x9000	用户确认，并且PIN正确。
     *		0x6405:0x0035	用户点击了C键。
     *		0x6405:0x0036	TIMEOUT。
     *		0x6405:0xXX26	PIN不正确，XX代表剩余次数。
     *
     * 使用示例：
     * 申请aToken时输入的开机PIN要在极密盾上显示并经用户确认。
     *		BTComm_getDevicePublicKey_3040				//读取设备公钥
     *		BTComm_getDeviceID_3040						//获取设备序列号
     *		BTComm_getDeviceStatus_3040					//获取剩余尝试次数
   	 *		(得到该DeviceID的bToken)
     *		BTComm_requestSecurityChannel_3040(bToken)	//含bToken方式的请求联机通道
     *		BTComm_setSessionKey_3040					//下发联机会话密钥，此时进入不可信通道
     *		BTComm_verify_modifyPIN_EM_3040S(1)			//验证PIN
     *		BTComm_getResponse_3040R					//正确返回0x6100(独占模式)
     *		BTComm_sendInput_3040(PIN)					//发送键盘字符（串）
     *		if ( 剩余尝试次数 <= 2 ) {
     *			//此时极密盾在等待确认，需要提示用户。
     *			Show MessageBox
     *		}
     *		else{
     *			//此时无需提示用户，极密盾会在2秒后自动确认。
     *		}
     *		while (独占模式) {
     *			BTComm_getResponse_3040S
     *			BTComm_getResponse_3040R
     *		}
     *													//退出独占模式后，返回的错误码见使用说明
     *		BTComm_getRandomNumber_3040					//获取随机数
     *		BTComm_verifyPIN_3040(PIN)					//申请aToken，再次使用刚才验证通过的PIN
     *													//成功后进入可信通道
     */
    
    /****************************************************************************
     333. 备份密钥显示+重置+输入 (独占模式)
     *****************************************************************************/
    DWORD BTComm_backupKey_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD Type, _IN DWORD bakcupKeyID);
    /*
     * 参数说明：
     *	Type
     *		0 显示备份密钥，显示备份密钥ID和备份密钥。
     *		1 重置备份密钥，需要用户按键确认，然后显示新的备份密钥ID和备份密钥。
     *		2 输入备份密钥，极密盾需要显示输入界面，用于数据恢复操作。
     *	bakcupKeyID
     *		当Type==0时才有效。
     *
     * for 3040
     * for 3038 1.01.008+
     */
    DWORD BTComm_backupKey_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     334. 安全通道初始化
     *****************************************************************************/
    void BTComm_InitSecurityChannel_3040 (int bEnable);
    /*
     * 参数说明：
     *	bEnable
     *		0 关闭数据加密
     *		1 开启数据加密
     * 使用说明：
     * 每次连接极密盾之前必须调用一次，开启安全通道后禁止调用。
     * 也可以在每次收到断开连接消息后调用一次。
     */
    
    /****************************************************************************
     337. 断开蓝牙连接
     *****************************************************************************/
    /*
     * 使用说明：
     * 	for 3040 直接发送如下指令，HexString格式需要转换为bytes。
     * 		"2800000C0008800D0000000000000000000000000000"
     */
    
    /****************************************************************************
     338. 修改分类名
     *****************************************************************************/
    DWORD BTComm_updateCatalog_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD olditemCataID, _IN LPCSTR oldCatalogName, _IN LPCSTR newCatalogName, _IN LPCSTR deviceModel, _IN LPCSTR armVersion);
    /*
     * 参数说明：
     *	olditemCataID（必须）
     *		分类ID
     *	oldCatalogName（必须不可以为NULL或者""）
     *		旧分类名
     *	newCatalogName（必须不可以为NULL或者""）
     *		新分类名
     *	deviceModel
     *		当前连接设备de设备型号。例如："JM1A"/"JM1Ax"/"JM1B"/"K2"。
     *	armVersion
     *		当前连接设备de固件版本。例如："1.01.008"。
     * 使用说明：
     *		API会根据设备型号及固件版本自动调整生成的指令。
     */
    DWORD BTComm_updateCatalog_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     339. 修改密码标题
     *****************************************************************************/
    DWORD BTComm_updateSecurityBookItemTitle_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPCSTR old_itemTitle, _IN LPCSTR new_itemTitle);
    /*
     * 参数说明：
     *	old_itemTitle
     *		旧标题名称
     *	new_itemTitle
     *		新标题名称
     * 使用说明：
     * 	for 3040
     */
    DWORD BTComm_updateSecurityBookItemTitle_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     340. 动态设备参数下发
     *****************************************************************************/
    DWORD BTComm_setDeviceParamater_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD Min, _IN DWORD Max, _IN DWORD TryCount, _IN DWORD Sleep, _IN DWORD PowerOff, _IN LPCSTR NiceName);
    /*
     * 参数说明：
     *	Min
     *		设备PIN输入最短长度，==0忽略此项与Max。
     *	Max
     *		设备PIN输入最长长度，==0忽略此项与Min。
     *	TryCount
     *		设备PIN最大尝试次数，==0忽略此项。
     *	Sleep
     *		自动熄屏秒数，==0忽略此项。
     *	PowerOff
     *		自动关机秒数，==0忽略此项。
     *	NiceName
     *		设备名，4-14字节（英文算一个字节，中文算两个字节）。
     *
     * 使用说明：
     * 	for 3040
     *	for 3038 1.01.007+。
     */
    DWORD BTComm_setDeviceParamater_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     341. 导入 非本机主密钥
     ****************************************************************************/
    
    /****************************************************************************
     342. 导出 非本机主密钥
     ****************************************************************************/
    
    /****************************************************************************
     343. 删除 非本机的主密钥
     ****************************************************************************/
    
    /****************************************************************************
     344. 枚举主密钥
     ****************************************************************************/
    enum{
        MENCKEY_EXTERNAL = 0,
        MENCKEY_INTERNAL = 1,
    };
    
    DWORD BTComm_enumMainEncryptKey_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD KeyType);
    /*
     * 参数说明：
     *	KeyType
     *		MENCKEY_INTERNAL	本机
     *		MENCKEY_EXTERNAL	非本机
     *
     * 使用说明：
     * 	only for 3040.
     */
    DWORD BTComm_enumMainEncryptKey_3040D (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPBYTE lpHandles, _OUT LPDWORD lpnKeys);
    /*
     * 返回值：
     *		0x9000  正确，并且nKeys & Handles有效。
     *		其他     错误代码。
     *  lpHandles
     *      主密钥句柄，需要160字节。
     *  lpnKeys
     *      Handles的数量
     */
    
    /****************************************************************************
     345. 导入 会话密钥
     ****************************************************************************/
    
    /****************************************************************************
     347. 加密初始化
     ****************************************************************************/
#define		SESSION_ID_NONE	0xFFFFFFFF
    //对称算法ID 3040
#define		ALG_SM1_ECB		0x00000101
#define		ALG_SM1_CBC		0x00000102
#define		ALG_SM1_MAC		0x00000110
#define		ALG_SM4_ECB		0x00000401
#define		ALG_SM4_CBC		0x00000402
#define		ALG_SM4_MAC		0x00000410
#define		ALG_DES_ECB		0x00000801
#define		ALG_DES_CBC		0x00000802
#define		ALG_DES_MAC		0x00000810
#define		ALG_DES3_ECB	0x00001001
#define		ALG_DES3_CBC	0x00001002
#define		ALG_DES3_MAC	0x00001010
    //填充算法
#define		PADDING_PKCS_5	1
#define		PADDING_NONE	0
    /*
     * 通道编号
     */
#define 	SLOTNUM_KDBK 		63   //
#define		SLOTNUM_KSK 		62   //
#define		SLOTNUM_KFENC 		61   //
    
    enum{
        FUNC_ENCRYPT = 0,
        FUNC_DECRYPT = 1,
        FUNC_MAC = 2,
        FUNC_HASH = 3
    };
    
    enum{
        CMD_INIT = 0,
        CMD_ONE_FRAME = 1,
        CMD_MORE_FRAME = 2,
        CMD_FINISH = 3
    };
    
    DWORD BTComm_EncryptInit_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD SessionID, _IN LPBYTE lpHandles, _IN DWORD indexOfHandles, _IN DWORD ALG_ID, _IN DWORD paddingType, _IN LPBYTE IV, _IN DWORD slotNum);
    /*
     * 参数说明：
     *	SessionID
     *      由导入会话密钥生成，SESSION_ID_NONE(-1)为不使用。
     *  lpHandles
     *      由枚举主密钥生成，lpHandles。
     *  indexOfHandles
     *      使用第几个主密钥，indexOfHandles必须<nKeys。
     *      == -1 为不使用主密钥，同时Handles被忽略。
     *  ALG_ID
     *      详见对称算法ID定义。
     *  paddingType
     *      详见填充算法定义。
     *  IV
     *      只有CBC/MAC算法模式时存在。
     *      NULL = 不存在。
     *  slotNum
     *      详见通道编号定义。
     *
     * 使用说明：
     * 	only for 3040.
     * 	会话密钥与主密钥仅可使用一种方式，且必须存在一种有效方式。
     */
    DWORD BTComm_EncryptInit_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     348. 加密单帧
     ****************************************************************************/
    DWORD BTComm_Encrypt_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE srcData, _IN DWORD srcDataSIZE);
    /*
     * 参数说明：
     *	srcData
     *      明文数据。
     *  srcDataSIZE
     *      明文数据长度，最大1024，超长数据请使用多帧加密方式。
     *
     * 使用说明：
     * 	only for 3040.
     */
    DWORD BTComm_Encrypt_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    /*
     * 返回值：
     * 	JMD_Result.ErrorCode2
     *		0x9000  正确，且ResultData有效。
     *		其他     错误代码。
     *  ResultData
     *      密文数据。
     */
    
    /****************************************************************************
     349. 加密（多帧起始帧/中间帧）
     ****************************************************************************/
    
    /****************************************************************************
     350. 加密（多帧结束帧）
     ****************************************************************************/
    
    /****************************************************************************
     351. 解密初始化
     ****************************************************************************/
    DWORD BTComm_DecryptInit_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD SessionID, _IN LPBYTE Handles, _IN DWORD indexOfHandles, _IN DWORD ALG_ID, _IN DWORD paddingType, _IN LPBYTE IV, _IN DWORD slotNum);
    /*
     * 参数说明：
     *	SessionID
     *      由导入会话密钥生成，SESSION_ID_NONE(-1)为不使用。
     *  Handles
     *      由枚举主密钥生成，Handles。
     *  indexOfHandles
     *      使用第几个主密钥，indexOfHandles必须<nKeys。
     *      == -1 为不使用主密钥，同时Handles被忽略。
     *  ALG_ID
     *      详见对称算法ID定义。
     *  paddingType
     *      详见填充算法定义。
     *  IV
     *      只有CBC/MAC算法模式时存在。
     *      NULL = 不存在。
     *  slotNum
     *      详见通道编号定义。
     *
     * 使用说明：
     * 	only for 3040.
     * 	会话密钥与主密钥仅可使用一种方式，且必须存在一种有效方式。
     */
    DWORD BTComm_DecryptInit_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    
    /****************************************************************************
     352. 解密单帧
     ****************************************************************************/
    DWORD BTComm_Decrypt_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE srcData, _IN DWORD srcDataSIZE);
    /*
     * 参数说明：
     *	srcData
     *      密文数据。
     *  srcDataSIZE
     *      密文数据长度，最大1024，超长数据请使用多帧解密方式，数据长度必须是16的整数倍。
     *
     * 使用说明：
     * 	only for 3040.
     */
    DWORD BTComm_Decrypt_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    /*
     * 返回值：
     * 	JMD_Result.ErrorCode2
     *		0x9000  正确，且ResultData有效。
     *		其他     错误代码。
     *  ResultData
     *      明文数据。
     */
    
    /****************************************************************************
     353. 解密（多帧起始帧/中间帧）
     ****************************************************************************/
    
    /****************************************************************************
     354. 解密（多帧结束帧）
     ****************************************************************************/
    
    /* #902加解密示例：
     *	0) 名词解释
     *	KSK         加解密软盾de密钥
     *	KSKT_S      软盾加密的KSK密文
     *	KSKT_H      硬盾加密的KSK密文
     *	EKSK        加解密KSK的软盾密钥
     *	KFENC       加解密文件de密钥
     *	KFENCT_S    软盾加密KFENC的密文
     *	KFENCT_H    硬盾加密KFENC的密文
     *	KDBK        加解密SDO数据库de密钥
     *	KDBKT_S     软盾加密KDBK的密文
     *	KDBKT_H     硬盾加密KDBK的密文
     *
     * 	1) KSK -> KSKT_H
     *	BTComm_enumMainEncryptKey_3040S(MENCKEY_INTERNAL)
     *	BTComm_EncryptInit_3040S(-1, lpHandles, 0, ALG_SM4_ECB, PADDING_NONE, SLOTNUM_KSK)
     *	BTComm_Encrypt_3040S(KSK)
     *	BTComm_Encrypt_3040R() 返回de密文数据即KSKT_H。
     *
     * 	2) KSKT_H -> KSK
     *	BTComm_enumMainEncryptKey_3040S(MENCKEY_INTERNAL)
     *	BTComm_DecryptInit_3040S(-1, lpHandles, 0, ALG_SM4_ECB, PADDING_NONE, SLOTNUM_KSK)
     *	BTComm_Decrypt_3040S(KSKT_H)
     *	BTComm_Decrypt_3040R() 返回de明文数据即KSK。
     *
     * 	3) KFENC -> KFENCT_H
     *	BTComm_enumMainEncryptKey_3040S(MENCKEY_INTERNAL)
     *	BTComm_EncryptInit_3040S(-1, lpHandles, 0, ALG_SM4_ECB, PADDING_NONE, SLOTNUM_KFENC)
     *	BTComm_Encrypt_3040S(KFENC)
     *	BTComm_Encrypt_3040R() 返回de密文数据即KFENCT_H。
     *
     * 	4) KSKT_H -> KSK
     *	BTComm_enumMainEncryptKey_3040S(MENCKEY_INTERNAL)
     *	BTComm_DecryptInit_3040S(-1, lpHandles, 0, ALG_SM4_ECB, PADDING_NONE, SLOTNUM_KFENC)
     *	BTComm_Decrypt_3040S(KFENCT_H)
     *	BTComm_Decrypt_3040R() 返回de明文数据即KFENC。
     *
     * 	5) KDBK -> KDBKT_H
     *	BTComm_enumMainEncryptKey_3040S(MENCKEY_INTERNAL)
     *	BTComm_EncryptInit_3040S(-1, lpHandles, 0, ALG_SM4_ECB, PADDING_NONE, SLOTNUM_KDBK)
     *	BTComm_Encrypt_3040S(KDBK)
     *	BTComm_Encrypt_3040R() 返回de密文数据即KDBK_H。
     *
     * 	6) KDBKT_H -> KDBK
     *	BTComm_enumMainEncryptKey_3040S(MENCKEY_INTERNAL)
     *	BTComm_DecryptInit_3040S(-1, lpHandles, 0, ALG_SM4_ECB, PADDING_NONE, SLOTNUM_KDBK)
     *	BTComm_Decrypt_3040S(KDBKT_H)
     *	BTComm_Decrypt_3040R() 返回de明文数据即KDBK。
     *
     */
    /****************************************************************************
     355. 设置语言
     ****************************************************************************/
    enum{
        LANG_SIMPLIFIED_CHINESE = 0,
        LANG_TRADITIONAL_CHINESE = 1,
        LANG_ENGLISH = 2
    };
    
    DWORD BTComm_setLanguage_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD Language);
    /*
     * 参数说明：
     *	Language
     *		LANG_SIMPLIFIED_CHINESE
     *		LANG_TRADITIONAL_CHINESE
     *		LANG_ENGLISH
     *
     */
    DWORD BTComm_setLanguage_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result);
    /*
     * 返回值：
     * 	JMD_Result.ErrorCode2
     *		0x9000  正确，且ResultData有效。
     *		其他    错误代码。
     */
    
#ifdef __cplusplus
}
#endif

#endif /* jmd_btcomm_hpp */
