//
//  jmd_btcomm.cpp
//  BTComm
//
//  Created by 毕卫国 on 15/11/3.
//  Copyright © 2015年 毕卫国. All rights reserved.
//

#include <memory.h>
#include "jmd_btcomm.hpp"
#include "_sm3.h"
#include "_sm4.h"
#include "_calcsortvalue.h"

#define LOBYTE(w)               ((BYTE)(((DWORD)(w)) & 0xff))
#define HIBYTE(w)               ((BYTE)((((DWORD)(w)) >> 8) & 0xff))
#define LOWORD(_dw)             ((WORD)(((DWORD)(_dw)) & 0xffff))
#define HIWORD(_dw)             ((WORD)((((DWORD)(_dw)) >> 16) & 0xffff))
#define MAKEWORD(low, high)     ((WORD)(((BYTE)(((DWORD)(low)) & 0xff)) | ((WORD)((BYTE)(((DWORD)(high)) & 0xff))) << 8))
#define MAKEDWORD(low, high)    ((DWORD)(((WORD)(((DWORD)(low)) & 0xffff)) | ((DWORD)((WORD)(((DWORD)(high)) & 0xffff))) << 16))

#define DLL_LOCAL

#pragma pack (1)

typedef struct tagMINFO{
    BYTE	ChNum : 3;	//安全通道号
    BYTE	MTYPE : 5;	//报文类型
    BYTE	CFLAG : 1;	//安全通道启用标记
    BYTE	FRU   : 7;	//保留
}MINFO;

typedef struct tagHCP_HEAD{
    MINFO	MPARA;
    WORD	FN;				//功能接口编号
    WORD	PLEN;			//报文数据长度
}HCP_HEAD;

typedef struct tagHCP_BODY{
    BYTE	CLA;
    BYTE	INS;
    BYTE	P1;
    BYTE	P2;
    WORD	LC;
}HCP_BODY;

#pragma pack ()

//指令计数器
DLL_LOCAL unsigned int     SEQ = 1;

//临时保存的ChNum / CK，直到 下发联机会话密钥 成功才作为正式使用，并清除临时保存数据。
DLL_LOCAL BYTE	__temp_ChNum = 0;
DLL_LOCAL BYTE	__temp_CK[16] = {0};
//使用__temp_CK加密的Re，临时保存，作为 下发联机会话密钥 时使用。
DLL_LOCAL BYTE	__tempEncRe[16] = {0};

//联机会话密钥发送成功 保存的正式 ChNum / CK。
DLL_LOCAL BYTE	__internal_ChNum = 0;
DLL_LOCAL BYTE	__internal_CK[16] = {0};
DLL_LOCAL DWORD __internal_CFLAG = 0;

DLL_LOCAL BYTE	PMAC_IV[16] = { 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31
};

void pkcs_5_padding(LPBYTE src, DWORD srcSIZE, LPBYTE dest, LPDWORD destSIZE)
{
    DWORD	fixedSIZE = 16 - srcSIZE % 16;
    
    memcpy(dest, src, srcSIZE);
    for (DWORD i = srcSIZE; i<srcSIZE + fixedSIZE; i++){
        dest[i] = (BYTE)fixedSIZE;
    }
    *destSIZE = srcSIZE + fixedSIZE;
}

/*
 * @Key 密钥
 * @Input 需要计算MAC的数据
 * @InputLen 需要计算MAC的数据长度
 * @_IV IV
 *
 * Input 处理为16自己的整倍数，不足填0
 * SM4 CBC加密Input, 需复制IV, CBC加密时会改变IV
 * 取加密结果的最后一组数据的前4字节为MAC
 */
DLL_LOCAL DWORD _SM4_CBC_MAC4(LPBYTE Key, LPBYTE Input, DWORD InputLen, LPBYTE _IV)
{
    BYTE	    IV[16];
    BYTE        PlainBuf[E3001_TRANSFER_BUFFER_SIZE];
    BYTE        EncBuf[E3001_TRANSFER_BUFFER_SIZE];
    sm4_context	ctx;
    
    DWORD	NewLen = (InputLen + 15) / 16 * 16;
    
    memset(PlainBuf, 0, NewLen);
    memcpy(PlainBuf, Input, InputLen);
    memcpy(IV, _IV, 16);
    
    sm4_setkey_enc(&ctx, Key);
    sm4_crypt_cbc(&ctx, SM4_ENCRYPT, NewLen, IV, PlainBuf, EncBuf);
    DWORD	MAC = ((DWORD)EncBuf[NewLen - 16] << 24) + ((DWORD)EncBuf[NewLen - 15] << 16) + ((DWORD)EncBuf[NewLen - 14] << 8) + (DWORD)EncBuf[NewLen - 13];
    
    return MAC;
}

/*
 * ==0 OK
 * ==1 PMAC 错误
 * ==2 解密错误
 * ==3 参数错误
 * ==4 destB 数据区太不足
 */
DWORD _decode_recvDATA(LPBYTE srcB, DWORD srcLen, LPBYTE destB, LPDWORD destLen)
{
    if (NULL == srcB || srcLen < 16 || NULL == destB || *destLen < srcLen)
        return 3;
    
    DWORD CFLAG = (DWORD)(srcB[1] & 0x01);
    
    if (0 != CFLAG){
        DWORD calcPMAC = _SM4_CBC_MAC4(__internal_CK, srcB, srcLen - 4, PMAC_IV);
        DWORD recvPMAC = ((DWORD)srcB[srcLen - 4] << 24) + ((DWORD)srcB[srcLen - 3] << 16) + ((DWORD)srcB[srcLen - 2] << 8) + (DWORD)srcB[srcLen - 1];
        
        if (calcPMAC == recvPMAC){
            //first 8 bytes
            memcpy(destB, srcB, 8);
            
            //decode cipher data
            sm4_context	ctx;
            
            sm4_setkey_dec(&ctx, __internal_CK);
            sm4_crypt_ecb(&ctx, SM4_DECRYPT, srcLen - 16, srcB + 8, destB + 8);
            
            //last 8 bytes
            WORD	plainLen = (WORD)(((DWORD)srcB[6] << 8) + (DWORD)srcB[7]);
            
            memcpy(destB + 8 + plainLen, srcB + srcLen - 8, 8);
            *destLen = 16 + plainLen;
            return 0;
        }
        else
            return 1;
    }
    else{
        memcpy(destB, srcB, srcLen);
        *destLen = srcLen;
        return 0;
    }
}

DWORD _nbuild_cmd_with_body(LPBYTE CmdBuf, LPDWORD CmdLen, BYTE ChNum, BYTE MTYPE, WORD FN, BYTE CFLAG, BYTE CLA, BYTE INS, BYTE P1, BYTE P2, LPBYTE Pbody_TLV, WORD LC)
{
    HCP_HEAD	_head;
    DWORD		PMAC = 0;
    DWORD	    code_len;
    BYTE	    code_buff[E3001_TRANSFER_BUFFER_SIZE];
    
    if (*CmdLen < (DWORD)LC + 14)   //14 = MPARA 2 bytes + FN 2 bytes + LC 2 bytes + SEQ 4 bytes + CRC 4 bytes
        return 1;
    _head.MPARA.ChNum = ChNum;
    _head.MPARA.MTYPE = MTYPE;
    _head.MPARA.FRU = 0x00;
    _head.MPARA.CFLAG = CFLAG;
    _head.FN = FN;
    _head.PLEN = sizeof(HCP_BODY) + LC;
    
    code_len = 0;
    *(MINFO *)(CmdBuf+code_len) = _head.MPARA;
    code_len += sizeof(MINFO);
    CmdBuf[code_len++] = HIBYTE(_head.FN);
    CmdBuf[code_len++] = LOBYTE(_head.FN);
    CmdBuf[code_len++] = HIBYTE(_head.PLEN);
    CmdBuf[code_len++] = LOBYTE(_head.PLEN);
    CmdBuf[code_len++] = CLA;
    CmdBuf[code_len++] = INS;
    CmdBuf[code_len++] = P1;
    CmdBuf[code_len++] = P2;
    CmdBuf[code_len++] = HIBYTE(LC);
    CmdBuf[code_len++] = LOBYTE(LC);
    
    if (0 != LC) {
        memcpy(CmdBuf + code_len, Pbody_TLV, LC);
        code_len += LC;
    }
    
    if (0 != CFLAG) {
        pkcs_5_padding(CmdBuf + 6, code_len - 6, code_buff, CmdLen);
        
        sm4_context	ctx;
        
        sm4_setkey_enc(&ctx, __internal_CK);
        sm4_crypt_ecb(&ctx, SM4_ENCRYPT, *CmdLen, code_buff, CmdBuf + 6);
        code_len = *CmdLen + 6;
    }
    
    CmdBuf[code_len++] = HIBYTE(HIWORD(SEQ));
    CmdBuf[code_len++] = LOBYTE(HIWORD(SEQ));
    CmdBuf[code_len++] = HIBYTE(SEQ);
    CmdBuf[code_len++] = LOBYTE(SEQ);
    SEQ ++;
    
    if (0 != CFLAG) {
        PMAC = _SM4_CBC_MAC4(__internal_CK, CmdBuf, code_len, PMAC_IV);
    }
    CmdBuf[code_len++] = HIBYTE(HIWORD(PMAC));
    CmdBuf[code_len++] = LOBYTE(HIWORD(PMAC));
    CmdBuf[code_len++] = HIBYTE(PMAC);
    CmdBuf[code_len++] = LOBYTE(PMAC);
    
    *CmdLen = code_len;
    return 0;
}

DWORD _nbuild_cmd(LPBYTE CmdBuf, LPDWORD CmdLen, BYTE ChNum, BYTE MTYPE, WORD FN, BYTE CFLAG, BYTE CLA, BYTE INS, BYTE P1, BYTE P2)
{
    return _nbuild_cmd_with_body(CmdBuf, CmdLen, ChNum, MTYPE, FN, CFLAG, CLA, INS, P1, P2, NULL, 0);
}

DWORD _parseRecvData (_IN_OUT LPBYTE recvB, _IN DWORD recvLen, _OUT LPJMD_RESULT Result)
{
    DWORD       PLEN;
    BYTE		_recvB[E3001_TRANSFER_BUFFER_SIZE];
    
    Result->ErrorCode1 = 0x6405;
    Result->ErrorCode2 = 0x6405;
    Result->ResultData = NULL;
    Result->ResultSize = 0;
    
    if ( recvB == NULL || Result == NULL || recvLen > E3001_TRANSFER_BUFFER_SIZE )
        return API_INVALID_PARAMETER;
    
    memcpy(_recvB, recvB, recvLen);
    _decode_recvDATA(_recvB, recvLen, recvB, &recvLen);
    
    /*
     * 接收到的数据最短为16字节
     * 信息头  4字节
     * Status  2字节
     * PLEN    2字节
     * SEQ     4字节
     * CRC     4字节
     */
    if ( recvLen >= 16 ) {
        /* 大端数据 */
        Result->ErrorCode1 = MAKEWORD(recvB[5], recvB[4]);
        /* 大端数据 */
        PLEN = MAKEWORD( recvB[7], recvB[6] );
        
        if ( PLEN < 2 ) {
            Result->ErrorCode2 = Result->ErrorCode1;
        }
        else if ( 16 + PLEN == recvLen ) {
            /* 大端数据 */
            Result->ErrorCode2 = MAKEWORD( recvB[8 + PLEN - 1], recvB[8 + PLEN - 2]);
            /* 当PLEN == 2 时，只返回了SW，无数据，ResultData长度为0 */
            Result->ResultSize = PLEN - 2;
            Result->ResultData = recvB + 8;
        }
        else{
            Result->ErrorCode1 = 0x6405;
        }
        return API_OK;
    }
    else
        return API_INVALID_PARAMETER;
}

DWORD BTComm_getDeviceInfoS (LPBYTE cmdBuf, LPDWORD cmdSize)
{
    return BTComm_getDeviceInformation_3040S(cmdBuf, cmdSize);
}

DWORD BTComm_getDeviceInfoR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getDeviceInformation_3040D(recvData, recvSize, Result);
}

DWORD BTComm_getSecurityBookS (DWORD isFirst, LPBYTE cmdBuf, LPDWORD cmdSize)
{
    if ( isFirst )
        return BTComm_enumSecurityBook_3040S(cmdBuf, cmdSize);
    else{
        DWORD	code_len;
        
        if ( cmdBuf == NULL)
            return API_INVALID_PARAMETER;
        
        code_len = *cmdSize;
        if (_nbuild_cmd(cmdBuf, &code_len,
                        __internal_ChNum,	//ChNum
                        0x06,				//MTYPE
                        0x000D,				//FN
                        __internal_CFLAG,	//CFLAG
                        0x00,				//CLA
                        0xC0,				//INS
                        0x00,
                        0x00
                        ))
            return API_INVALID_PARAMETER;
        
        *cmdSize = code_len;
        
        return 0;
    }
}

DWORD BTComm_getSecurityBookR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R(recvData, recvSize, Result);
}

DWORD BTComm_getSecurityBookD (LPBYTE recvB, DWORD recvLen, LPJMD_SECURITYBOOK *Result, LPDWORD ResultCount)
{
    return BTComm_enumSecurityBook_3040D(recvB, recvLen, Result, ResultCount);
}

DWORD BTComm_getSecurityBookF (LPJMD_SECURITYBOOK Result)
{
    return BTComm_enumSecurityBookFree(Result);
}

DWORD BTComm_gotoSecurityBookS (const char *mb_itemTitle, LPBYTE cmdBuf, LPDWORD cmdSize)
{
    return BTComm_showSecurityBook_3040S(cmdBuf, cmdSize, mb_itemTitle);
}

DWORD BTComm_gotoSecurityBookR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_getSecurityNoteS (DWORD isFirst, LPBYTE cmdBuf, LPDWORD cmdSize)
{
    if (isFirst)
        return BTComm_enumSecurityNote_3040S(cmdBuf, cmdSize);
    else{
        DWORD	code_len;
        
        if ( cmdBuf == NULL)
            return API_INVALID_PARAMETER;
        
        code_len = *cmdSize;
        if (_nbuild_cmd(cmdBuf, &code_len,
                        __internal_ChNum,	//ChNum
                        0x06,				//MTYPE
                        0x000D,				//FN
                        __internal_CFLAG,	//CFLAG
                        0x00,				//CLA
                        0xC0,				//INS
                        0x00,				//P1
                        0x00				//P2
                        ))
            return API_INVALID_PARAMETER;
        
        *cmdSize = code_len;
        
        return 0;
    }
}

DWORD BTComm_getSecurityNoteR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_getSecurityNoteD (LPBYTE recvData, DWORD recvSize, LPJMD_SECURITYBOOK *Result, LPDWORD ResultCount)
{
    return BTComm_enumSecurityBook_3040D(recvData, recvSize, Result, ResultCount);
}

DWORD BTComm_getSecurityNoteF (LPJMD_SECURITYBOOK Result)
{
    return BTComm_enumSecurityBookFree(Result);
}

DWORD BTComm_gotoSecurityNoteS (const char *mb_itemTitle, LPBYTE cmdBuf, LPDWORD cmdSize)
{
    return BTComm_showSecurityNote_3040S(cmdBuf, cmdSize, mb_itemTitle);
}

DWORD BTComm_gotoSecurityNoteR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_upgradeFirmwareS(DWORD Flag, LPBYTE frameData, DWORD frameSize, DWORD totalSize, DWORD nFrame, LPBYTE cmdBuf, LPDWORD cmdSize)
{
    return BTComm_upgradeFirmware_3040S(cmdBuf, cmdSize, Flag, frameData, frameSize, totalSize, nFrame);
}

DWORD BTComm_upgradeFirmwareR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R(recvData, recvSize, Result);
}

DWORD BTComm_putUserKeyS (LPBYTE userKey, DWORD userkeySize, LPBYTE cmdBuf, LPDWORD cmdSize)
{
    return BTComm_setUserData_3040S(cmdBuf, cmdSize, userKey, userkeySize);
}

DWORD BTComm_putUserKeyR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_BackupS (DWORD isFirst, LPBYTE cmdBuf, LPDWORD cmdSize)
{
    if ( isFirst )
        return BTComm_Backup_3040S(cmdBuf, cmdSize);
    else{
        DWORD	code_len;
        
        if ( cmdBuf == NULL )
            return API_INVALID_PARAMETER;
        
        code_len = *cmdSize;
        if (_nbuild_cmd(cmdBuf, &code_len,
                        __internal_ChNum,	//ChNum
                        0x03,				//MTYPE
                        0x0001,				//FN
                        0x00,				//CFLAG
                        0x00,				//CLA
                        0xC0,				//INS
                        0x00,				//P1
                        0x00				//P2
                        ))
            return API_INVALID_PARAMETER;
        
        *cmdSize = code_len;
        
        return 0;
    }
}

DWORD BTComm_BackupR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_RestoreS (DWORD Flag, LPBYTE frameData, DWORD frameSize, DWORD totalSize, DWORD Count, LPBYTE cmdBuf, LPDWORD cmdSize)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    
    if ( cmdBuf == NULL )
        return API_INVALID_PARAMETER;
    
    LC = 0;
    //FFLEN
    BodyBuf[LC++] = HIBYTE(HIWORD(totalSize));
    BodyBuf[LC++] = LOBYTE(HIWORD(totalSize));
    BodyBuf[LC++] = HIBYTE(totalSize);
    BodyBuf[LC++] = LOBYTE(totalSize);
    //FPNUM
    BodyBuf[LC++] = HIBYTE(Count);
    BodyBuf[LC++] = LOBYTE(Count);
    //FDATA
    memcpy(BodyBuf + LC , frameData, frameSize);
    LC += frameSize;
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              0x00,	        //ChNum
                              0x03,			//MTYPE
                              0x0001,		//FN
                              0x00,		    //CFLAG
                              0x01,			//CLA
                              0x51,			//INS
                              0x00,			//P1
                              Flag,			//P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_RestoreR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_ActivateS (LPBYTE activateCode, DWORD codeSize, LPBYTE cmdBuf, LPDWORD cmdSize)
{
    return BTComm_Activate_3040S(cmdBuf, cmdSize, activateCode, codeSize);
}

DWORD BTComm_ActivateR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_addSecurityNoteS (const char *itemTitle, const char *itemDesc, DWORD mtProtectLevel, LPBYTE cmdBuf, LPDWORD cmdSize)
{
    return BTComm_addSecurityNote_3040S(cmdBuf, cmdSize, itemTitle, itemDesc, 0, mtProtectLevel);
}

DWORD BTComm_addSecurityNoteR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_deleteSecurityNoteS (const char *itemTitle, LPBYTE cmdBuf, LPDWORD cmdSize)
{
    return BTComm_deleteSecurityNote_3040S(cmdBuf, cmdSize, itemTitle);
}

DWORD BTComm_deleteSecurityNoteR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_updateSecurityNoteS (const char *itemTitle, const char *itemDesc, LPBYTE cmdBuf, LPDWORD cmdSize)
{
    return BTComm_updateSecurityNote_3040S(cmdBuf, cmdSize, itemTitle, itemDesc, 0);
}

DWORD BTComm_updateSecurityNoteR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_addSecurityBookS (const char *itemTitle, const char *itemDesc, const char *acctName, const char *staticPwd, const char *xURL, DWORD itemCataID, const char *itemCataName, LPBYTE cmdBuf, LPDWORD cmdSize)
{
    return BTComm_addSecurityBook_3040S(cmdBuf, cmdSize, itemTitle, itemDesc, acctName, staticPwd, itemCataID, itemCataName, 0);
}

DWORD BTComm_addSecurityBookR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_deleteSecurityBookS (const char *itemTitle, LPBYTE cmdBuf, LPDWORD cmdSize)
{
    return BTComm_deleteSecurityBook_3040S(cmdBuf, cmdSize, itemTitle);
}

DWORD BTComm_deleteSecurityBookR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_updateSecurityBookS (const char *itemTitle, const char *itemDesc, const char *acctName, const char *staticPwd, const char *xURL, DWORD itemCataID, const char *itemCataName, LPBYTE cmdBuf, LPDWORD cmdSize)
{
    return BTComm_updateSecurityBook_3040S(cmdBuf, cmdSize, itemTitle, itemDesc, acctName, staticPwd, itemCataID, itemCataName, 0, 0);
}

DWORD BTComm_updateSecurityBookR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_updateSecurityBook_3040R(recvData, recvSize, Result);
}

DWORD BTComm_getDeviceSerialNoS (LPBYTE cmdBuf, LPDWORD cmdSize)
{
    return BTComm_getDeviceID_3040S(cmdBuf, cmdSize);
}

DWORD BTComm_getDeviceSerialNoR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_getDeviceStatusS (LPBYTE cmdBuf, LPDWORD cmdSize)
{
    return BTComm_getDeviceStatus_3040S(cmdBuf, cmdSize);
}

DWORD BTComm_getDeviceStatusR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

//3040D是RD二合一，无法替换。
DWORD BTComm_getDeviceStatusD (LPBYTE recvData, DWORD recvSize, LPDWORD SW1, LPDWORD SW2)
{
    //is devStatus TLV TAG = 0x800D LENGTH == 0x05
    if ( recvData[0] == 0x80 && recvData[1] == 0x0D && recvData[2] == 0x05) {
        if ( SW1 != NULL )
            *SW1 = MAKEWORD(recvData[4], recvData[3]);
        if ( SW2 != NULL )
            *SW2 = MAKEDWORD(MAKEWORD(recvData[7], recvData[6]), MAKEWORD(recvData[5], 0));
        return 0;
    }
    else{
        if ( SW1 != NULL )
            *SW1 = 0;
        if ( SW2 != NULL )
            *SW2 = 0;
        return 1;
    }
}

DWORD BTComm_getSecurityNoteContentS (const char *itemTitle, LPBYTE cmdBuf, LPDWORD cmdSize)
{
    DWORD	code_len;
    DWORD   stringLen;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    
    if (cmdBuf == NULL ||itemTitle == NULL)
        return API_INVALID_PARAMETER;
    
    LC = 0;
    
    BodyBuf[LC++] = 28;		//itemTitle
    stringLen = (DWORD)strlen(itemTitle);
    BodyBuf[LC++] = LOBYTE(stringLen);
    memcpy(BodyBuf + LC, itemTitle, stringLen);
    LC += stringLen;
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x06,				//MTYPE
                              0x000D,			//FN
                              __internal_CFLAG,	//CFLAG
                              0x04,				//CLA
                              0x11,				//INS
                              0x00,				//P1
                              0x00,				//P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_getSecurityNoteContentR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_getSecurityNoteContentD (LPBYTE recvB, DWORD recvLen, LPJMD_SECURITYBOOK Result)
{
    WORD        LENGTH;
    WORD        i;
    DWORD		TAG;
    
    Result->itemDesc[0] = 0;
    if ( recvB == NULL )
        return 1;
    
    i = 0;
    
    while ( i < recvLen ) {
        if ( (recvB[i] & 0xFF) < 128 ){  //TAG
            TAG =recvB[i];
            i ++;
        }
        else{
            TAG = MAKEWORD(recvB[i+1], recvB[i]);
            i += 2;
        }
        if ( (recvB[i] & 0xFF) < 128){   //LENGTH
            LENGTH = recvB[i];
            i ++;
        }
        else{
            LENGTH = MAKEWORD(recvB[i+1], recvB[i]&0x7F);
            i += 2;
        }
        switch ( TAG ){
            case 0x1A:	    //itemDesc
                memcpy(Result->itemDesc, recvB+i, LENGTH);
                Result->itemDesc[LENGTH] = 0;
                i += LENGTH;
                break;
            default:    //不识别的TAG
                i = recvLen;
                break;
        }
    }
    
    return 0;
}

DWORD BTComm_ResetTimeS (LPBYTE eCloudCMD, DWORD _CMDSize, LPBYTE cmdBuf, LPDWORD cmdSize)
{
    return BTComm_Activate_3040S(cmdBuf, cmdSize, eCloudCMD, _CMDSize);
}

DWORD BTComm_ResetTimeR (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_getResetCodeS (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize)
{
    DWORD	code_len;
    
    if ( cmdBuf == NULL)
        return API_INVALID_PARAMETER;
    
    code_len = *cmdSize;
    if (_nbuild_cmd(cmdBuf, &code_len,
                    0x00,	    //ChNum
                    0x03,	    //MTYPE
                    0x0001,	    //FN
                    0x00,	    //CFLAG
                    0x01,	    //CLA
                    0x07,	    //INS
                    0x00,	    //P1
                    0x00    	//P2
                    ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_getResetCodeD (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R(recvData, recvSize, Result);
}

//ChNum = 0，CFLAG = 0，无通道差异
DWORD BTComm_getDeviceID_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize)
{
    DWORD	code_len;
    
    if ( cmdBuf == NULL)
        return API_INVALID_PARAMETER;
    
    code_len = *cmdSize;
    if (_nbuild_cmd(cmdBuf, &code_len,
                    0x00,	    //ChNum
                    0x02,	    //MTYPE
                    0x0000,	    //FN
                    0x00,	    //CFLAG
                    0x01,	    //CLA
                    0x04,	    //INS
                    0x00,	    //P1
                    0x00    	//P2
                    ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_getDeviceID_3040D (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPBYTE lpDeviceID, _IN_OUT LPDWORD lpstrSize)
{
    JMD_RESULT	Result;
    DWORD		dwRet;
    
    dwRet = BTComm_getResponse_3040R (recvData, recvSize, &Result);
    if ( dwRet != 0 )
        return dwRet;
    
    if ( Result.ErrorCode1 != 0x9000 || Result.ErrorCode2 != 0x9000 )
        return MAKEDWORD(Result.ErrorCode2, Result.ErrorCode1);
    
    if ( lpDeviceID == NULL || lpstrSize == NULL || *lpstrSize < MAXDEVID )
        return API_INVALID_PARAMETER;
    
    if ( Result.ResultSize != 0x10 )
        return API_BAD_TLV;
    
    memcpy(lpDeviceID, Result.ResultData, 0x10);
    lpDeviceID[0x10] = 0;
    *lpstrSize = 0x10;
    return API_OK;
}

//ChNum = x，通道差异
DWORD BTComm_getDeviceStatus_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize)
{
    DWORD	code_len;
    
    if ( cmdBuf == NULL)
        return API_INVALID_PARAMETER;
    code_len = *cmdSize;
    if (_nbuild_cmd(cmdBuf, &code_len,
                    __internal_ChNum,	//ChNum
                    0x03,	    		//MTYPE
                    0x01,	    		//FN
                    0x00,    			//CFLAG
                    0x01,	    		//CLA
                    0xDD,	    		//INS
                    0x00,	    		//P1
                    0x00    			//P2
                    ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

//设备状态标志：2字节
#define FLAG_DEV_CREATED			(1 << 0)	//已创建状态
#define FLAG_DEV_INITED				(1 << 1)	//已初始化状态
#define FLAG_DEV_READY				(1 << 2)	//已就绪状态
#define FLAG_DEV_ACTIVE				(1 << 3)	//已激活状态
#define FLAG_DEV_BONDED				(1 << 4)	//已绑定状态
#define FLAG_DEV_DLOAD_DEVKEY_SUCC	(1 << 8)	//下发设备的密钥成功
#define FLAG_DEV_DLOAD_PARAM_SUCC	(1 << 9)	//下发参数成功

//密码状态标志：1字节
#define FLAG_PSW_NOT_SET			(1 << 0)	//密码未设置
#define FLAG_PSW_LOCKED				(1 << 1)	//密码已锁定
#define FLAG_PSW_CHANGED			(1 << 2)	//密码已修改(非默认值)
#define FLAG_PSW_APPPIN				(1 << 3)	//0---设备PIN保护, 1---应用PIN保护

//安全通道的状态：1字节
#define FLAG_CHAN_DEV_AUTH			(1 << 0）	//设备认证 验证成功标志
#define FLAG_CHAN_VER_DEVPIN		(1 << 1)	//设备PIN 验证成功标志

DWORD BTComm_getDeviceStatus_3040D (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPDWORD SW1, _OUT LPDWORD SW2, _OUT LPDWORD Left_Try_Times)
{
    JMD_RESULT	Result;
    DWORD		dwRet;
    WORD		FLAG_DEV;
    BYTE		FLAG_PSW;
    BYTE		FLAG_CHAN;
    DWORD		LC = 0;
    
    dwRet = _parseRecvData (recvData, recvSize, &Result);
    if ( dwRet != 0 )
        return dwRet;
    if ( Result.ErrorCode1 != 0x9000 || Result.ErrorCode2 != 0x9000 )
        return MAKEDWORD(Result.ErrorCode2, Result.ErrorCode1);
    
    if ( SW1 != NULL )
        *SW1 = 0;
    if ( SW2 != NULL )
        *SW2 = 0;
    if ( Left_Try_Times != NULL )
        *Left_Try_Times = 0;
    
    while (Result.ResultSize > LC ){
        DWORD	TAG = MAKEWORD( Result.ResultData[LC + 1], Result.ResultData[LC] );
        WORD	LENGTH = Result.ResultData[LC + 2];
        
        if ( TAG == 0x800D && LENGTH == 4 ){
            ////3040 TAG_DEVSTATUS
            if ( SW1 != NULL ){
                FLAG_DEV = MAKEWORD(Result.ResultData[LC + 4], Result.ResultData[LC + 3]);
                *SW1 = SW1_SIGNPUBKEY | SW1_CORRECT_TIME | SW1_RELEASED;
                if (FLAG_DEV & FLAG_DEV_READY )
                    *SW1 |= SW1_READY;
                if ( FLAG_DEV & FLAG_DEV_ACTIVE )
                    *SW1 |= SW1_ACTIVATED;
                if ( FLAG_DEV & FLAG_DEV_BONDED )
                    *SW1 |= SW1_BINDED;
                if ( FLAG_DEV & FLAG_DEV_CREATED )
                    *SW1 |= SW1_CREATED;
                if ( FLAG_DEV & FLAG_DEV_INITED )
                    *SW1 |= SW1_INITED;
                if ( FLAG_DEV & FLAG_DEV_DLOAD_DEVKEY_SUCC )
                    *SW1 |= SW1_DLOAD_DEVKEY_SUCC;
                if ( FLAG_DEV & FLAG_DEV_DLOAD_PARAM_SUCC )
                    *SW1 |= SW1_DLOAD_PARAM_SUCC;
            }
            if ( SW2 != NULL ){
                FLAG_PSW = Result.ResultData[LC + 5];
                FLAG_CHAN = Result.ResultData[LC + 6];
                *SW2 = 0;
                if ( FLAG_CHAN & FLAG_CHAN_VER_DEVPIN )
                    *SW2 |= SW2_POWER_ON_LOGINED;
                if ( FLAG_PSW & FLAG_PSW_LOCKED )
                    *SW2 |= SW2_UNLOCK_LOCKED;
                if ( FLAG_PSW & FLAG_PSW_CHANGED )
                    *SW2 |= SW2_PSW_CHANGED;
            }
            LC += 7;
        }
        else if ( TAG == 0x87EE && LENGTH == 1 ){
            //3040 TAG_LEFT_TRY_TIMES
            if ( Left_Try_Times != NULL )
                *Left_Try_Times = Result.ResultData[LC + 3];
            LC += 4;
        }
        else if ( TAG == 0x800D && LENGTH == 5 ) {
            //3026/3032/3038 TAG_DEVSTATUS
            if (SW1 != NULL)
                *SW1 = MAKEWORD(Result.ResultData[LC + 4], Result.ResultData[LC + 3]);
            if (SW2 != NULL)
                *SW2 = MAKEDWORD(MAKEWORD(Result.ResultData[LC + 7], Result.ResultData[LC + 6]), MAKEWORD(Result.ResultData[LC + 5], 0));
            LC += 8;
        }
    }
    return 0;
}

//ChNum = 0，CFLAG = 0，无通道差异
DWORD BTComm_getDeviceInformation_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize)
{
    DWORD	code_len;
    
    if ( cmdBuf == NULL)
        return API_INVALID_PARAMETER;
    
    code_len = *cmdSize;
    if (_nbuild_cmd(cmdBuf, &code_len,
                    0x00,	            //ChNum
                    0x03,				//MTYPE
                    0x0001,				//FN
                    0x00,				//CFLAG
                    0x01,				//CLA
                    0x42,				//INS
                    0x01,				//P1, 1: Jason格式的设备信息
                    0x00				//P2
                    ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_getDeviceInformation_3040D (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R(recvData, recvSize, Result);
}

DWORD BTComm_getDevicePublicKey_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD keyIndex)
{
    DWORD	code_len;
    
    if ( cmdBuf == NULL)
        return API_INVALID_PARAMETER;
    code_len = *cmdSize;
    if (_nbuild_cmd(cmdBuf, &code_len,
                    0x00,	    //ChNum
                    0x02,	    //MTYPE
                    0x0000,		//FN
                    0x00,	    //CFLAG
                    0x01,	    //CLA
                    0x01,	    //INS
                    0x00,	    //P1
                    keyIndex   //P2
                    ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_getDevicePublicKey_3040D (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPBYTE publicKey, _IN_OUT LPDWORD keySize)
{
    JMD_RESULT	Result;
    DWORD 		dwRet;
    
    dwRet = BTComm_getResponse_3040R (recvData, recvSize, &Result);
    if ( dwRet != 0 )
        return dwRet;
    
    if ( Result.ErrorCode1 != 0x9000 || Result.ErrorCode2 != 0x9000 )
        return MAKEDWORD(Result.ErrorCode2, Result.ErrorCode1);
    
    if ( publicKey == NULL || keySize == NULL || *keySize < Result.ResultSize )
        return API_INVALID_PARAMETER;
    
    memcpy(publicKey, Result.ResultData, Result.ResultSize);
    *keySize = Result.ResultSize;
    return API_OK;
}

DWORD BTComm_requestSecurityChannel_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD keyIndex, _IN LPBYTE bToken, _IN DWORD bTokenSize, _IN LPBYTE aToken, _IN DWORD aTokenSize)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    
    if ( cmdBuf == NULL)
        return API_INVALID_PARAMETER;
    
    LC = 0;
    
    if ( aToken != NULL && aTokenSize != 0 ){
        BodyBuf[LC++] = 0x87;		//aToken TAG
        BodyBuf[LC++] = 0xDA;		//aToken TAG
        if ( aTokenSize <= 127 ) {
            BodyBuf[LC++] = LOBYTE(aTokenSize);
        }
        else{
            BodyBuf[LC++]   = HIBYTE(aTokenSize) | 0x80;
            BodyBuf[LC++] = LOBYTE(aTokenSize);
        }
        memcpy(BodyBuf + LC, aToken, aTokenSize);
        LC += aTokenSize;
    }
    if ( bToken != NULL && bTokenSize != 0 ){
        BodyBuf[LC++] = 0x87;		//bToken TAG
        BodyBuf[LC++] = 0xDB;		//bToken TAG
        if ( bTokenSize <= 127 ) {
            BodyBuf[LC++] = LOBYTE(bTokenSize);
        }
        else{
            BodyBuf[LC++]   = HIBYTE(bTokenSize) | 0x80;
            BodyBuf[LC++] = LOBYTE(bTokenSize);
        }
        memcpy(BodyBuf + LC, bToken, bTokenSize);
        LC += bTokenSize;
    }
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              0x00,     //ChNum
                              0x02,     //MTYPE
                              0x0000,	//FN
                              0x00,     //CFLAG
                              0x01,     //CLA
                              0x02,     //INS
                              0x00,     //P1
                              keyIndex, //P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_requestSecurityChannel_3040D (_IN LPBYTE recvData, _IN DWORD recvSize, _IN DWORD Rx, _OUT LPBYTE lpCK, _IN_OUT LPDWORD CKSize)
{
    JMD_RESULT	Result;
    BYTE		_Re[16];
    DWORD 		dwRet;
    
    dwRet = _parseRecvData (recvData, recvSize, &Result);
    if ( dwRet != 0 )
        return dwRet;
    if ( Result.ErrorCode1 != 0x9000 || Result.ErrorCode2 != 0x9000 )
        return MAKEDWORD(Result.ErrorCode2, Result.ErrorCode1);
    if ( lpCK == NULL || *CKSize < 16 )
        return API_INVALID_PARAMETER;
    
    //TLV TAG = 0x87D4 LENGTH = 0x10 3040
    if ( Result.ResultSize == 0x13 && Result.ResultData[0] == 0x87 && Result.ResultData[1] == 0xD4 ) {
        WORD    LENGTH;
        LPBYTE  VALUE;
        
        if ( (Result.ResultData[2] & 0xFF) < 128 ){
            LENGTH = Result.ResultData[2];
            VALUE = Result.ResultData + 3;
        }
        else{
            LENGTH = MAKEWORD(Result.ResultData[3], Result.ResultData[2] & 0x7F);
            VALUE = Result.ResultData + 4;
        }
        //Re
        memcpy(_Re, VALUE, 0x10);
        
        //ChNum
        __temp_ChNum = recvData[0] & 0x07;
        
        //UK = Rx | Re | ChNum
        BYTE	_UK[4 + 16 + 1];
        
        _UK[0] = HIBYTE(HIWORD(Rx));
        _UK[1] = LOBYTE(HIWORD(Rx));
        _UK[2] = HIBYTE(Rx);
        _UK[3] = LOBYTE(Rx);
        memcpy(_UK + 4, _Re, 0x10);
        _UK[0x14] = __temp_ChNum;
        
        //SM3(UK)
        BYTE UK_SM3HASH[32];
        
        sm3(_UK, 0x15, UK_SM3HASH);
        
        //CK
        memcpy(__temp_CK, UK_SM3HASH, 0x10);
        
        //EncRe
       	sm4_context	ctx;
        
        sm4_setkey_enc(&ctx, __temp_CK);
        sm4_crypt_ecb(&ctx, SM4_ENCRYPT, 0x10, _Re, __tempEncRe);
        
        //return CK for EncCK
        memcpy(lpCK, __temp_CK, 0x10);
        *CKSize = 0x10;
        
        return 0;
    }
    //3026/3032/3038
    else if ( Result.ResultSize == 0x10 ) {
        
        //Re
        memcpy(_Re, Result.ResultData, 0x10);
        
        //ChNum
        __temp_ChNum = recvData[0] & 0x07;
        
        //UK = Rx | Re | ChNum
        BYTE	_UK[4 + 16 + 1];
        
        _UK[0] = HIBYTE(HIWORD(Rx));
        _UK[1] = LOBYTE(HIWORD(Rx));
        _UK[2] = HIBYTE(Rx);
        _UK[3] = LOBYTE(Rx);
        memcpy(_UK + 4, _Re, 0x10);
        _UK[0x14] = __temp_ChNum;
        
        //SM3(UK)
        BYTE UK_SM3HASH[32];
        
        sm3(_UK, 0x15, UK_SM3HASH);
        
        //CK
        memcpy(__temp_CK, UK_SM3HASH, 0x10);
        
        //EncRe
       	sm4_context	ctx;
        
        sm4_setkey_enc(&ctx, __temp_CK);
        sm4_crypt_ecb(&ctx, SM4_ENCRYPT, 0x10, _Re, __tempEncRe);
        
        //return CK for EncCK
        memcpy(lpCK, __temp_CK, 0x10);
        *CKSize = 0x10;
        
        return 0;
    }
    else{
        return API_BAD_TLV;
    }
}

DWORD BTComm_setSessionKey_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE EncCK, _IN DWORD EncCKSize, _IN DWORD keyIndex)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    
    if ( cmdBuf == NULL || EncCK == NULL )
        return API_INVALID_PARAMETER;
    
    LC = 0;
    
    BodyBuf[LC++] = 0x3F;		//EncCK TAG
    if ( EncCKSize <= 127 ){
        BodyBuf[LC++] = LOBYTE(EncCKSize);
    }
    else{
        BodyBuf[LC++] = HIBYTE(EncCKSize) | 0x80;
        BodyBuf[LC++] = LOBYTE(EncCKSize);
    }
    memcpy(BodyBuf + LC, EncCK, EncCKSize);
    LC += EncCKSize;
    
    BodyBuf[LC++] = 0x40;		//EncRe TAG
    BodyBuf[LC++] = 0x10;
    memcpy(BodyBuf + LC, __tempEncRe, 0x10);
    LC += 0x10;
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __temp_ChNum,		//ChNum
                              0x02,      		//MTYPE
                              0x0000,			//FN
                              0x00,      		//CFLAG
                              0x01,      		//CLA
                              0x03,      		//INS
                              0x00,      		//P1
                              LOBYTE(keyIndex),	//P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    memset(__tempEncRe, 0, 0x10);
    
    return 0;
}

DWORD BTComm_setSessionKey_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    DWORD dwRet = _parseRecvData (recvData, recvSize, Result);
    if ( dwRet != 0 )
        return dwRet;
    if ( Result->ErrorCode1 != 0x9000 || Result->ErrorCode2 != 0x9000 )
        return dwRet;
    memcpy(__internal_CK, __temp_CK, 0x10);
    __internal_ChNum = __temp_ChNum;
    
    //安全通道开启成功，清除临时保存的数据
    memset(__temp_CK, 0, 0x10);
    __temp_ChNum = 0;
    
    return dwRet;
}

DWORD BTComm_closeSecurityChannel_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize)
{
    DWORD	code_len;
    
    if ( cmdBuf == NULL)
        return API_INVALID_PARAMETER;
    
    code_len = *cmdSize;
    if (_nbuild_cmd(cmdBuf, &code_len,
                    __internal_ChNum,	//ChNum
                    0x02,	    		//MTYPE
                    0x0000,				//FN
                    __internal_CFLAG,	//CFLAG
                    0x01,	    		//CLA
                    0x05,	    		//INS
                    0x00,	    		//P1
                    0x00		   		//P2
                    ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    //安全通道关闭，清除数据
    memset(__internal_CK, 0, 0x10);
    __internal_ChNum = 0;
    
    return 0;
}

DWORD BTComm_closeSecurityChannel_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_Activate_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE eCloudCMD, _IN DWORD _CMDSize)
{
    DWORD	code_len;
    
    if (cmdBuf == NULL || eCloudCMD == NULL)
        return API_INVALID_PARAMETER;
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	    //ChNum
                              0x03,					//MTYPE
                              0x01,					//FN
                              0x00,					//CFLAG
                              eCloudCMD[0],	    	//CLA
                              eCloudCMD[1],	    	//INS
                              eCloudCMD[2],	    	//P1
                              eCloudCMD[3],	    	//P2
                              eCloudCMD + 6,
                              MAKEWORD(eCloudCMD[5], eCloudCMD[4])
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_Activate_3040R	(_IN LPBYTE recvData, _IN DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_getRandomNumber_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD nBytes)
{
    DWORD	code_len;
    
    if ( cmdBuf == NULL)
        return API_INVALID_PARAMETER;
    code_len = *cmdSize;
    if (_nbuild_cmd(cmdBuf, &code_len,
                    __internal_ChNum, 	//ChNum
                    0x06,	           	//MTYPE
                    0x0001,		       	//FN
                    __internal_CFLAG,	//CFLAG
                    0x02,	           	//CLA
                    0x01,	           	//INS
                    nBytes,           	//P1
                    0x00              	//P2
                    ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_getRandomNumber_3040D (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPBYTE lpRandomNumber, _IN_OUT LPDWORD bufSIZE)
{
    JMD_RESULT	Result;
    DWORD 		dwRet;
    
    dwRet = BTComm_getResponse_3040R (recvData, recvSize, &Result);
    if ( dwRet != 0 )
        return dwRet;
    
    if ( Result.ErrorCode1 != 0x9000 || Result.ErrorCode2 != 0x9000 )
        return MAKEDWORD(Result.ErrorCode2, Result.ErrorCode1);
    
    if ( lpRandomNumber == NULL || bufSIZE == NULL || *bufSIZE < Result.ResultSize )
        return API_INVALID_PARAMETER;
    
    memcpy(lpRandomNumber, Result.ResultData, Result.ResultSize);
    *bufSIZE = Result.ResultSize;
    return API_OK;
}

DWORD BTComm_verifyPIN_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD Type, _IN LPBYTE RandomNumber, _IN LPBYTE PIN_SHA1, _IN LPBYTE bToken, _IN DWORD bTokenSIZE)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    BYTE	EncRand[16];
    WORD	LC;
    
    //	0---验证PIN
    //	1---验证PIN，并且申请AToken
    if ( cmdBuf == NULL || (Type == 1 && bToken == NULL) || RandomNumber == NULL || PIN_SHA1 == NULL )
        return API_INVALID_PARAMETER;
    
   	sm4_context	ctx;
    
    sm4_setkey_enc(&ctx, PIN_SHA1);
    sm4_crypt_ecb(&ctx, SM4_ENCRYPT, 0x10, RandomNumber, EncRand);
    
    LC = 0;
    
    BodyBuf[LC++] = 0x87;		//EncRand TAG
    BodyBuf[LC++] = 0xD3;		//EncRand TAG
    BodyBuf[LC++] = 0x10;
    memcpy(BodyBuf + LC, EncRand, 0x10);
    LC += 0x10;
    
    if ( bToken != NULL ){
        BodyBuf[LC++] = 0x87;		//tName TAG
        BodyBuf[LC++] = 0xDC;		//tName TAG
        BodyBuf[LC++] = 0x10;
        memcpy(BodyBuf + LC, bToken + 4, 0x10);
        LC += 0x10;
    }
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x03,      		//MTYPE
                              0x0001,			//FN
                              __internal_CFLAG,	//CFLAG
                              0x01,      		//CLA
                              0x46,      		//INS
                              Type,      		//P1
                              0x00,      		//P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    memset(__tempEncRe, 0, 0x10);
    
    return 0;
}

DWORD BTComm_verifyPIN_3040D (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R(recvData, recvSize, Result);
}

DWORD BTComm_setUserData_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE eCloudCMD, _IN DWORD _CMDSize)
{
    return BTComm_Activate_3040S(cmdBuf, cmdSize, eCloudCMD, _CMDSize);
}

DWORD BTComm_setUserData_3040R (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_addSecurityNote_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPCSTR itemTitle, _IN LPCSTR itemDesc, _IN DWORD utcTime, _IN DWORD mtProtectLevel)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    DWORD   stringLen;
    DWORD	SortValue = 0;
    
    if ( cmdBuf == NULL )
        return API_INVALID_PARAMETER;
    
    LC = 0;
    
    BodyBuf[LC++] = 28;		//itemTtile
    stringLen = (DWORD)strlen(itemTitle);
    BodyBuf[LC++] = LOBYTE(stringLen);
    memcpy(BodyBuf + LC, itemTitle, stringLen);
    LC += stringLen;
    
    CalcSortValue(itemTitle, &SortValue);
    BodyBuf[LC++] = 27;		//ItemSortValue
    BodyBuf[LC++] = 4;
    BodyBuf[LC++] = HIBYTE(HIWORD(SortValue));
    BodyBuf[LC++] = LOBYTE(HIWORD(SortValue));
    BodyBuf[LC++] = HIBYTE(SortValue);
    BodyBuf[LC++] = LOBYTE(SortValue);
    
    if (itemDesc != NULL && (stringLen = (DWORD)strlen(itemDesc)) != 0 ){
        BodyBuf[LC++] = 26;		//itemDesc
        stringLen = (DWORD)strlen(itemDesc);
        if ( stringLen <= 127 ){
            BodyBuf[LC++] = LOBYTE(stringLen);
        }
        else{
            BodyBuf[LC++] = HIBYTE(stringLen) | 0x80;
            BodyBuf[LC++] = LOBYTE(stringLen);
        }
        memcpy(BodyBuf + LC, itemDesc, stringLen);
        LC += stringLen;
    }
    
    //for 3040 创建时间
    if ( utcTime != 0 ){
        BodyBuf[LC++] = 50;		//utcTime
        BodyBuf[LC++] = 4;
        BodyBuf[LC++] = HIBYTE(HIWORD(utcTime));
        BodyBuf[LC++] = LOBYTE(HIWORD(utcTime));
        BodyBuf[LC++] = HIBYTE(utcTime);
        BodyBuf[LC++] = LOBYTE(utcTime);
    }
    
    //for 3026/3032/3038 密条保护级别
    if ( mtProtectLevel != 0 ){
        BodyBuf[LC++] = HIBYTE(32784);		//mtProtectLevel
        BodyBuf[LC++] = LOBYTE(32784);
        BodyBuf[LC++] = 1;
        BodyBuf[LC++] = LOBYTE(mtProtectLevel);
    }
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x06,			    //MTYPE
                              0x000D,		    //FN
                              __internal_CFLAG,	//CFLAG
                              0x04,			    //CLA
                              0x01,			    //INS
                              0x00,			    //P1
                              0x00,			    //P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_addSecurityNote_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_updateSecurityNote_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPCSTR itemTitle, _IN LPCSTR itemDesc, _IN DWORD utcTime)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    DWORD   stringLen;
    
    if (cmdBuf == NULL || itemTitle == NULL)
        return API_INVALID_PARAMETER;
    
    LC = 0;
    
    BodyBuf[LC++] = 28;		//itemTtile
    stringLen = (DWORD)strlen(itemTitle);
    BodyBuf[LC++] = LOBYTE(stringLen);
    memcpy(BodyBuf + LC, itemTitle, stringLen);
    LC += stringLen;
    
    if (itemDesc != NULL && (stringLen = (DWORD)strlen(itemDesc)) != 0 ){
        BodyBuf[LC++] = 26;		//itemDesc
        stringLen = (DWORD)strlen(itemDesc);
        if ( stringLen <= 127 ){
            BodyBuf[LC++] = LOBYTE(stringLen);
        }
        else{
            BodyBuf[LC++] = HIBYTE(stringLen) | 0x80;
            BodyBuf[LC++] = LOBYTE(stringLen);
        }
        memcpy(BodyBuf + LC, itemDesc, stringLen);
        LC += stringLen;
    }
    
    if ( utcTime != 0 ){
        BodyBuf[LC++] = 50;		//utcTime
        BodyBuf[LC++] = 4;
        BodyBuf[LC++] = HIBYTE(HIWORD(utcTime));
        BodyBuf[LC++] = LOBYTE(HIWORD(utcTime));
        BodyBuf[LC++] = HIBYTE(utcTime);
        BodyBuf[LC++] = LOBYTE(utcTime);
    }
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x06,			    //MTYPE
                              0x000D,		    //FN
                              __internal_CFLAG,	//CFLAG
                              0x04,			    //CLA
                              0x03,			    //INS
                              0x00,			    //P1
                              0x00,			    //P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_updateSecurityNote_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_showSecurityNote_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPCSTR itemTitle)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    DWORD   stringLen;
    
    if (cmdBuf == NULL || itemTitle == NULL)
        return API_INVALID_PARAMETER;
    
    LC = 0;
    
    BodyBuf[LC++] = 28;		//itemTtile
    stringLen = (DWORD)strlen(itemTitle);
    BodyBuf[LC++] = LOBYTE(stringLen);
    memcpy(BodyBuf + LC, itemTitle, stringLen);
    LC += stringLen;
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x06,			    //MTYPE
                              0x000D,		    //FN
                              __internal_CFLAG,	//CFLAG
                              0x04,			    //CLA
                              0x04,			    //INS
                              0x00,			    //P1
                              0x00,			    //P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_showSecurityNote_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_deleteSecurityNote_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPCSTR itemTitle)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    DWORD   stringLen;
    
    if (cmdBuf == NULL || itemTitle == NULL)
        return API_INVALID_PARAMETER;
    
    LC = 0;
    
    BodyBuf[LC++] = 28;		//itemTtile
    stringLen = (DWORD)strlen(itemTitle);
    BodyBuf[LC++] = LOBYTE(stringLen);
    memcpy(BodyBuf + LC, itemTitle, stringLen);
    LC += stringLen;
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x06,			    //MTYPE
                              0x000D,		    //FN
                              __internal_CFLAG,	//CFLAG
                              0x04,			    //CLA
                              0x02,			    //INS
                              0x00,			    //P1
                              0x00,			    //P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_deleteSecurityNote_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_sendInput_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE lpChar, _IN DWORD _SIZE)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    
    if ( cmdBuf == NULL || lpChar == NULL )
        return API_INVALID_PARAMETER;
    
    LC = 0;
    BodyBuf[LC++] = 0x87;		//TAG_SEKBD_VALUE
    BodyBuf[LC++] = 0xD6;		//TAG_SEKBD_VALUE
    BodyBuf[LC++] = (BYTE)_SIZE;
    memcpy(BodyBuf + LC, lpChar, _SIZE);
    LC += _SIZE;
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x03,			    //MTYPE
                              0x0001,			//FN
                              __internal_CFLAG, //CFLAG
                              0x04,			    //CLA
                              0x02,			    //INS
                              0x00,			    //P1
                              0x00,			    //P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_sendInput_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

/*
 * 319. 读取响应 Get Response
 */
DWORD BTComm_getResponse_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD nFrame, _IN DWORD blockType)
{
    DWORD	code_len;
    
    if ( cmdBuf == NULL)
        return API_INVALID_PARAMETER;
    
    code_len = *cmdSize;
    if (_nbuild_cmd(cmdBuf, &code_len,
                    __internal_ChNum,		//ChNum
                    0x06,	                //MTYPE
                    0x0001,	            	//FN
                    0x00,	                //CFLAG
                    0x01,	                //CLA
                    0xC0,	                //INS
                    LOBYTE(blockType), 		//P1
                    LOBYTE(nFrame)     		//P2
                    ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_getResponse_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    DWORD	dwRet;
    
    dwRet = _parseRecvData(recvData, recvSize, Result);
    if ( dwRet != 0)
        return dwRet;
    
    if (Result->ErrorCode1 == 0x9000 && ((Result->ErrorCode2 == 0x9000) || ((Result->ErrorCode2 & 0xFF00) == 0x6100))) {
        DWORD	TAG, TAG2;
        WORD    LENGTH, LENGTH2;
        LPBYTE  VALUE;
        DWORD	LC;
        WORD	SW3;
        
        if ( Result->ResultSize >= 4 ){
            //可能是TLV数据
            LC = 0;
            
            if ( (Result->ResultData[LC] & 0xFF) <= 127 ){  //TAG
                TAG =Result->ResultData[LC];
                LC ++;
            }
            else{
                TAG = MAKEWORD(Result->ResultData[LC + 1], Result->ResultData[LC]);
                LC += 2;
            }
            if ((Result->ResultData[LC] & 0xFF) <= 127){	//LENGTH
                LENGTH = Result->ResultData[LC];
                LC ++;
                VALUE = Result->ResultData + LC;
            }
            else{
                LENGTH = MAKEWORD(Result->ResultData[LC + 1], Result->ResultData[LC] & 0x7F);
                LC += 2;
                VALUE = Result->ResultData + LC;
            }
            
            if ( LENGTH + LC == Result->ResultSize ){
                //只支持单包TLV
                if (TAG == 0x61) {
                    //xData 数据，需继续分析
                    if ( LENGTH == 5 ){
                        //可能是3040状态，需要进一步判断是否是3038枚举密条、密码数据
                        TAG2 = MAKEWORD(Result->ResultData[LC + 1], Result->ResultData[LC]);
                        LC += 2;
                        
                        LENGTH2 = Result->ResultData[LC];
                        LC ++;
                        
                        SW3 = MAKEWORD(Result->ResultData[LC + 1], Result->ResultData[LC]);
                        
                        if ((TAG2 == 0x87D7) && LENGTH2 == 2 && ((SW3 & 0xFF00) <= 0x1000)){
                            //TAG_USER_KEY_RESULT_SW //用户按键后,指令返回状态值
                            //LENGTH == 2
                            //VALUE 属于3040错误码范围
                            if ( SW3 == 0x0000 ){
                                Result->ErrorCode1 = 0x9000;
                                Result->ErrorCode2 = 0x9000;
                            }
                            else if (SW3 == 0x1084){
                                Result->ErrorCode1 = 0x9000;
                                Result->ErrorCode2 = 0x6100;
                            }
                            else{
                                Result->ErrorCode1 = 0x6405;
                                Result->ErrorCode2 = SW3;
                            }
                            LENGTH = 0;
                        }
                        else{
                            //非3040状态字，返回去除第一层TLV的数据
                        }
                    }
                    else{
                        //非3040状态字，返回去除第一层TLV的数据
                    }
                }
                else{
                    //非xData数据，返回去除第一层TLV的数据
                }
            }
            else{
                //非TLV数据，返回原数据
                LENGTH = Result->ResultSize;
                VALUE = Result->ResultData;
            }
            Result->ResultData = VALUE;
            Result->ResultSize = LENGTH;
            return API_OK;
        }
        else{
            //无TLV数据，之后SW的情况
            Result->ResultSize = 0;
            return API_OK;
        }
    }
    else{
        return API_OK;
    }
}

DWORD BTComm_exitExclusiveMode_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize)
{
    DWORD	code_len;
    
    if ( cmdBuf == NULL)
        return API_INVALID_PARAMETER;
    
    code_len = *cmdSize;
    if (_nbuild_cmd(cmdBuf, &code_len,
                    __internal_ChNum,          //ChNum
                    0x06,	                    //MTYPE
                    0x0001,	                //FN
                    0x00,	                    //CFLAG
                    0x01,	                    //CLA
                    0x01,	                    //INS
                    0x00,                      //P1
                    0x00                       //P2
                    ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_exitExclusiveMode_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_setLicense_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE eCloudCMD, _IN DWORD _CMDSize)
{
    return BTComm_Activate_3040S(cmdBuf, cmdSize, eCloudCMD, _CMDSize);
}

DWORD BTComm_setLicense_3040R (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_resetFactory_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE eCloudCMD, _IN DWORD _CMDSize)
{
    return BTComm_Activate_3040S(cmdBuf, cmdSize, eCloudCMD, _CMDSize);
}

DWORD BTComm_resetFactory_3040R (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_enumSecurityNote_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize)
{
    DWORD	code_len;
    
    if ( cmdBuf == NULL)
        return API_INVALID_PARAMETER;
    
    code_len = *cmdSize;
    if (_nbuild_cmd(cmdBuf, &code_len,
                    __internal_ChNum,	//ChNum
                    0x06,				//MTYPE
                    0x000D,				//FN
                    __internal_CFLAG,	//CFLAG
                    0x04,				//CLA
                    0x12,				//INS
                    0x01,				//P1
                    0x00				//P2
                    ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_enumSecurityNote_3040D (_IN LPBYTE ResultData, _IN DWORD ResultSize, _OUT LPJMD_SECURITYBOOK *Result, _OUT LPDWORD ResultCount)
{
    return BTComm_enumSecurityBook_3040D(ResultData, ResultSize, Result, ResultCount);
}

DWORD BTComm_enumSecurityNoteFree (_IN LPJMD_SECURITYBOOK Result)
{
    return BTComm_enumSecurityBookFree(Result);
}

DWORD BTComm_enumSecurityBook_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize)
{
    DWORD	code_len;
    
    if ( cmdBuf == NULL)
        return API_INVALID_PARAMETER;
    
    code_len = *cmdSize;
    if (_nbuild_cmd(cmdBuf, &code_len,
                    __internal_ChNum,	//ChNum
                    0x06,				//MTYPE
                    0x000D,				//FN
                    __internal_CFLAG,	//CFLAG
                    0x03,				//CLA
                    0x12,				//INS
                    0x01,				//P1，0---读口令项的标题 1---读口令项的所有内容
                    0x00				//P2
                    ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_enumSecurityBook_3040D (_IN LPBYTE recvB, _IN DWORD recvLen, _OUT LPJMD_SECURITYBOOK *Result, _OUT LPDWORD ResultCount)
{
    WORD        LENGTH, itemCount = 0;
    DWORD       i;
    DWORD		TAG;
    
    *Result = NULL;
    *ResultCount = 0;
    if (recvB == NULL && recvLen != 0)
        return API_INVALID_PARAMETER;
    
    i = 0;
    while (i < recvLen){
        if ((recvB[i] & 0xFF) < 128){  //TAG
            TAG = recvB[i];
            i++;
        }
        else{
            TAG = MAKEWORD(recvB[i + 1], recvB[i]);
            i += 2;
        }
        if ((recvB[i] & 0xFF) < 128){   //LENGTH
            LENGTH = recvB[i];
            i++;
        }
        else{
            LENGTH = MAKEWORD(recvB[i + 1], recvB[i] & 0x7F);
            i += 2;
        }
        switch (TAG){
            case 0x1C:		//itemTtile, start one item
                itemCount ++;
            case 0x01:		//acctName
            case 0x1A:	    //itemDesc
            case 0x18:      //itemCataName
            case 0x71:      //itemCataID
            case 0x33:	    //xURL
            case 0x32:	    //lastDate
            case 0x800E:    //protectLevel
            case 0x800F:    //appLink
            case 0x8010:    //mtProtectLevel
                i += LENGTH;
                break;
            default:    //不识别的TAG
                itemCount = 0;
                i = recvLen;
                break;
        }
    }
    
    LPJMD_SECURITYBOOK  jmd_sb = new JMD_SECURITYBOOK[itemCount];
    memset(jmd_sb, 0, sizeof(JMD_SECURITYBOOK)*itemCount);
    i = 0;
    int	index = -1;
    DWORD   dwValue;
    
    while ((index < itemCount) && (i < recvLen)) {
        if ((recvB[i] & 0xFF) < 128){  //TAG
            TAG = recvB[i];
            i++;
        }
        else{
            TAG = MAKEWORD(recvB[i + 1], recvB[i]);
            i += 2;
        }
        if ((recvB[i] & 0xFF) < 128){   //LENGTH
            LENGTH = recvB[i];
            i++;
        }
        else{
            LENGTH = MAKEWORD(recvB[i + 1], recvB[i] & 0x7F);
            i += 2;
        }
        switch (TAG){
            case 0x1C:  //itemTtile, start one item
                index++;
                memcpy(jmd_sb[index].itemTitle, recvB + i, LENGTH);
                jmd_sb[index].itemTitle[LENGTH] = 0;
                i += LENGTH;
                break;
            case 0x01:
                memcpy(jmd_sb[index].acctName, recvB + i, LENGTH);
                jmd_sb[index].acctName[LENGTH] = 0;
                i += LENGTH;
                break;
            case 0x71:      //itemCataID
                dwValue = MAKEDWORD(MAKEWORD(recvB[i + 3], recvB[i + 2]), MAKEWORD(recvB[i + 1], recvB[i]));
                jmd_sb[index].itemCataID = dwValue;
                i += LENGTH;
                break;
            case 0x18:      //itemCataName
                memcpy(jmd_sb[index].itemCataName, recvB + i, LENGTH);
                jmd_sb[index].itemCataName[LENGTH] = 0;
                i += LENGTH;
                break;
            case 0x1A:	    //itemDesc
                memcpy(jmd_sb[index].itemDesc, recvB + i, LENGTH);
                jmd_sb[index].itemDesc[LENGTH] = 0;
                i += LENGTH;
                break;
            case 0x33:	    //xURL
                memcpy(jmd_sb[index].xURL, recvB + i, LENGTH);
                jmd_sb[index].xURL[LENGTH] = 0;
                i += LENGTH;
                break;
            case 0x32:	    //lastDate
                dwValue = MAKEDWORD(MAKEWORD(recvB[i + 3], recvB[i + 2]), MAKEWORD(recvB[i + 1], recvB[i]));
                jmd_sb[index].lastDate = dwValue;
                i += LENGTH;
                break;
            case 0x800E:    //ProtectLevel
                dwValue = recvB[i];
                jmd_sb[index].ProtectLevel = dwValue;
                i += LENGTH;
                break;
            case 0x800F:    //appLink
                dwValue = recvB[i];
                jmd_sb[index].appLink = dwValue;
                i += LENGTH;
                break;
            case 0x8010:    //mtProtectLevel
                dwValue = recvB[i];
                jmd_sb[index].mtProtectLevel = dwValue;
                i += LENGTH;
                break;
            default:    //不识别的TAG
                itemCount = 0;
                i = recvLen;
                break;
        }
    }
    
    *Result = jmd_sb;
    *ResultCount = index + 1;
    
    return 0;
}

DWORD BTComm_enumSecurityBookFree (_IN LPJMD_SECURITYBOOK Result)
{
    if (Result != nullptr)
        delete Result;
    return 0;
}

DWORD BTComm_addSecurityBook_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPCSTR itemTitle, _IN LPCSTR itemDesc, _IN LPCSTR acctName, _IN LPCSTR staticPwd, _IN DWORD itemCataID, _IN LPCSTR itemCataName, _IN DWORD utcTime)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    DWORD   stringLen;
    DWORD	SortValue = 0;
    
    if (cmdBuf == NULL || itemTitle == NULL || (itemCataID != 0 && itemCataName == NULL))
        return API_INVALID_PARAMETER;
    
    LC = 0;
    
    stringLen = (DWORD)strlen(itemTitle);
    BodyBuf[LC++] = 28;		//itemTtile
    BodyBuf[LC++] = LOBYTE(stringLen);
    memcpy(BodyBuf + LC, itemTitle, stringLen);
    LC += stringLen;
    
    CalcSortValue(itemTitle, &SortValue);
    BodyBuf[LC++] = 27;		//ItemSortValue
    BodyBuf[LC++] = 4;
    BodyBuf[LC++] = HIBYTE(HIWORD(SortValue));
    BodyBuf[LC++] = LOBYTE(HIWORD(SortValue));
    BodyBuf[LC++] = HIBYTE(SortValue);
    BodyBuf[LC++] = LOBYTE(SortValue);
    
    if (itemDesc != NULL && (stringLen = (DWORD)strlen(itemDesc)) != 0 ){
        BodyBuf[LC++] = 26;		//itemDesc
        if ( stringLen <= 127 ){
            BodyBuf[LC++] = LOBYTE(stringLen);
        }
        else{
            BodyBuf[LC++] = HIBYTE(stringLen) | 0x80;
            BodyBuf[LC++] = LOBYTE(stringLen);
        }
        memcpy(BodyBuf + LC, itemDesc, stringLen);
        LC += stringLen;
    }
    
    if (acctName != NULL && (stringLen = (DWORD)strlen(acctName)) != 0 ){
        BodyBuf[LC++] = 1;		//acctName
        BodyBuf[LC++] = LOBYTE(stringLen);
        memcpy(BodyBuf + LC, acctName, stringLen);
        LC += stringLen;
    }
    
    if (staticPwd != NULL && (stringLen = (DWORD)strlen(staticPwd)) != 0 ){
        BodyBuf[LC++] = 40;		//staticPwd
        BodyBuf[LC++] = LOBYTE(stringLen);
        memcpy(BodyBuf + LC, staticPwd, stringLen);
        LC += stringLen;
    }
    
    if (itemCataID != 0){
        BodyBuf[LC++] = 113;		//itemCataID
        BodyBuf[LC++] = 4;
        BodyBuf[LC++] = HIBYTE(HIWORD(itemCataID));
        BodyBuf[LC++] = LOBYTE(HIWORD(itemCataID));
        BodyBuf[LC++] = HIBYTE(itemCataID);
        BodyBuf[LC++] = LOBYTE(itemCataID);
        
        BodyBuf[LC++] = 24;		//itemCataName
        stringLen = (DWORD)strlen(itemCataName);
        BodyBuf[LC++] = LOBYTE(stringLen);
        memcpy(BodyBuf + LC, itemCataName, stringLen);
        LC += stringLen;
        
        CalcSortValue(itemCataName, &SortValue);
        BodyBuf[LC++] = 25;		//ItemCataSortValue
        BodyBuf[LC++] = 4;
        BodyBuf[LC++] = HIBYTE(HIWORD(SortValue));
        BodyBuf[LC++] = LOBYTE(HIWORD(SortValue));
        BodyBuf[LC++] = HIBYTE(SortValue);
        BodyBuf[LC++] = LOBYTE(SortValue);
    }
    
    if (utcTime != 0){
        BodyBuf[LC++] = 50;		//utcTime
        BodyBuf[LC++] = 4;
        BodyBuf[LC++] = HIBYTE(HIWORD(utcTime));
        BodyBuf[LC++] = LOBYTE(HIWORD(utcTime));
        BodyBuf[LC++] = HIBYTE(utcTime);
        BodyBuf[LC++] = LOBYTE(utcTime);
    }
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x06,			    //MTYPE
                              0x000D,		    //FN
                              __internal_CFLAG,	//CFLAG
                              0x03,			    //CLA
                              0x01,			    //INS
                              0x00,			    //P1
                              0x01,			    //P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_addSecurityBook_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_updateSecurityBook_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPCSTR itemTitle, _IN LPCSTR itemDesc, _IN LPCSTR acctName, _IN LPCSTR staticPwd, _IN DWORD itemCataID, _IN LPCSTR itemCataName, _IN DWORD staticPwdType, _IN DWORD utcTime)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    DWORD   stringLen;
    DWORD	SortValue;
    
    if (cmdBuf == NULL || itemTitle == NULL)
        return API_INVALID_PARAMETER;
    
    LC = 0;
    BodyBuf[LC++] = 28;		//itemTtile
    stringLen = (DWORD)strlen(itemTitle);
    BodyBuf[LC++] = LOBYTE(stringLen);
    memcpy(BodyBuf + LC, itemTitle, stringLen);
    LC += stringLen;
    
    CalcSortValue(itemTitle, &SortValue);
    BodyBuf[LC++] = 27;		//ItemSortValue
    BodyBuf[LC++] = 4;
    BodyBuf[LC++] = HIBYTE(HIWORD(SortValue));
    BodyBuf[LC++] = LOBYTE(HIWORD(SortValue));
    BodyBuf[LC++] = HIBYTE(SortValue);
    BodyBuf[LC++] = LOBYTE(SortValue);
    
    if (itemDesc != NULL && (stringLen = (DWORD)strlen(itemDesc)) != 0 ){
        BodyBuf[LC++] = 26;		//itemDesc
        if ( stringLen <= 127 ){
            BodyBuf[LC++] = LOBYTE(stringLen);
        }
        else{
            BodyBuf[LC++] = HIBYTE(stringLen) | 0x80;
            BodyBuf[LC++] = LOBYTE(stringLen);
        }
        memcpy(BodyBuf + LC, itemDesc, stringLen);
        LC += stringLen;
    }
    
    if (acctName != NULL && (stringLen = (DWORD)strlen(acctName)) != 0 ){
        BodyBuf[LC++] = 1;		//acctName
        BodyBuf[LC++] = LOBYTE(stringLen);
        memcpy(BodyBuf + LC, acctName, stringLen);
        LC += stringLen;
    }
    
    if (staticPwd != NULL && (stringLen = (DWORD)strlen(staticPwd)) != 0 ){
        BodyBuf[LC++] = 40;		//staticPwd
        BodyBuf[LC++] = LOBYTE(stringLen);
        memcpy(BodyBuf + LC, staticPwd, stringLen);
        LC += stringLen;
    }
    
    if (itemCataName == NULL){
        //nothing
    }
    else if (itemCataID == 0){
        BodyBuf[LC++] = 113;		//itemCataID
        BodyBuf[LC++] = 4;
        BodyBuf[LC++] = HIBYTE(HIWORD(itemCataID));
        BodyBuf[LC++] = LOBYTE(HIWORD(itemCataID));
        BodyBuf[LC++] = HIBYTE(itemCataID);
        BodyBuf[LC++] = LOBYTE(itemCataID);
    }
    else{
        BodyBuf[LC++] = 113;		//itemCataID
        BodyBuf[LC++] = 4;
        BodyBuf[LC++] = HIBYTE(HIWORD(itemCataID));
        BodyBuf[LC++] = LOBYTE(HIWORD(itemCataID));
        BodyBuf[LC++] = HIBYTE(itemCataID);
        BodyBuf[LC++] = LOBYTE(itemCataID);
        
        BodyBuf[LC++] = 24;		//itemCataName
        stringLen = (DWORD)strlen(itemCataName);
        BodyBuf[LC++] = LOBYTE(stringLen);
        memcpy(BodyBuf + LC, itemCataName, stringLen);
        LC += stringLen;
        
        
        CalcSortValue(itemCataName, &SortValue);
        BodyBuf[LC++] = 25;		//ItemCataSortValue
        BodyBuf[LC++] = 4;
        BodyBuf[LC++] = HIBYTE(HIWORD(SortValue));
        BodyBuf[LC++] = LOBYTE(HIWORD(SortValue));
        BodyBuf[LC++] = HIBYTE(SortValue);
        BodyBuf[LC++] = LOBYTE(SortValue);
    }
    
    if (utcTime != 0){
        BodyBuf[LC++] = 50;		//utcTime
        BodyBuf[LC++] = 4;
        BodyBuf[LC++] = HIBYTE(HIWORD(utcTime));
        BodyBuf[LC++] = LOBYTE(HIWORD(utcTime));
        BodyBuf[LC++] = HIBYTE(utcTime);
        BodyBuf[LC++] = LOBYTE(utcTime);
    }
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x06,			    //MTYPE
                              0x000D,		    //FN
                              __internal_CFLAG,	//CFLAG
                              0x03,			    //CLA
                              0x03,			    //INS
                              staticPwdType,	//P1
                              0x01,			    //P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_updateSecurityBook_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_showSecurityBook_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPCSTR itemTitle)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    DWORD   stringLen;
    
    if (cmdBuf == NULL || itemTitle == NULL)
        return API_INVALID_PARAMETER;
    
    LC = 0;
    BodyBuf[LC++] = 28;		//itemTtile
    stringLen = (DWORD)strlen(itemTitle);
    BodyBuf[LC++] = LOBYTE(stringLen);
    memcpy(BodyBuf + LC, itemTitle, stringLen);
    LC += stringLen;
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x06,			    //MTYPE
                              0x000D,			    //FN
                              __internal_CFLAG,	//CFLAG
                              0x03,			    //CLA
                              0x05,			    //INS
                              0x00,			    //P1
                              0x00,			    //P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_showSecurityBook_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_deleteSecurityBook_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPCSTR itemTitle)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    DWORD   stringLen;
    
    if (cmdBuf == NULL || itemTitle == NULL)
        return API_INVALID_PARAMETER;
    
    LC = 0;
    BodyBuf[LC++] = 28;		//itemTtile
    stringLen = (DWORD)strlen(itemTitle);
    BodyBuf[LC++] = LOBYTE(stringLen);
    memcpy(BodyBuf + LC, itemTitle, stringLen);
    LC += stringLen;
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x06,			    //MTYPE
                              0x000D,			    //FN
                              __internal_CFLAG,	//CFLAG
                              0x03,			    //CLA
                              0x02,			    //INS
                              0x00,			    //P1
                              0x00,			    //P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_deleteSecurityBook_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_Backup_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize)
{
    DWORD	code_len;
    
    if ( cmdBuf == NULL )
        return API_INVALID_PARAMETER;
    
    code_len = *cmdSize;
    if (_nbuild_cmd(cmdBuf, &code_len,
                    __internal_ChNum,	//ChNum
                    0x03,				//MTYPE
                    0x0001,				//FN
                    0x00,				//CFLAG
                    0x01,				//CLA
                    0x50,				//INS
                    0x00,				//P1
                    0x00				//P2
                    ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_Backup_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

/****************************************************************************
 329. 恢复数据 (独占模式)
 *****************************************************************************/
DWORD BTComm_Restore_3040S(_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE backupData, _IN DWORD backupSize, _IN_OUT LPDWORD _backupOffset, _IN LPCSTR deviceModel, _IN LPCSTR armVersion)
{
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC = 0;
    BYTE	P2 = 0;
    DWORD	testTAG;
    WORD	testLENGTH;
    WORD	tlvSIZE;
    DWORD	backupOffset = *_backupOffset;
    /*
     * for 3040 1.01.008 BUG, 每次恢复时条目数太多超过8秒导致极密盾重启。
     * 密码新建大约0.9秒。
     * 密条新建大约0.6秒。
     * 主加密密钥按照密条计算。
     */
    WORD	nBKREC = 0;
    
    if ( cmdBuf == NULL || cmdSize == NULL || backupData == NULL || backupOffset >= backupSize || deviceModel == NULL || armVersion == NULL)
        return API_INVALID_PARAMETER;
    
    bool	isDataNewFormat;
    bool	isDeviceSupportNewFormat;
    
    if ( backupData[0x00] == 0x39 && backupData[0x01] == 0x10 && backupData[0x12] == 0x87 && backupData[0x13] == 0xE4 && backupData[0x14] == 0x01 )
        isDataNewFormat = true;
    else
        isDataNewFormat = false;
    
    if (   (strcmp(deviceModel, "JM1A")  == 0 && strcmp(armVersion, "0.99.030") >=0)
        || (strcmp(deviceModel, "JM1Ax") == 0 && strcmp(armVersion, "1.01.005") >=0)
        || (strcmp(deviceModel, "JM1B")  == 0 && strcmp(armVersion, "1.01.008") >=0)
        || (strcmp(deviceModel, "K2")    == 0)
        )
        isDeviceSupportNewFormat = true;
    else
        isDeviceSupportNewFormat = false;
    
    if ( isDataNewFormat != isDeviceSupportNewFormat )
        return API_DEVICE_NOT_SUPPORT;
    
    if (isDataNewFormat){
        while (backupOffset < backupSize){
            tlvSIZE = 0;
            if (backupData[backupOffset + tlvSIZE] & 0x80){
                testTAG = MAKEWORD(backupData[backupOffset + tlvSIZE + 1], backupData[backupOffset + tlvSIZE]);
                tlvSIZE += 2;
            }
            else{
                testTAG = backupData[backupOffset + tlvSIZE];
                tlvSIZE += 1;
            }
            if (backupData[backupOffset + tlvSIZE] & 0x80){
                testLENGTH = MAKEWORD(backupData[backupOffset + tlvSIZE + 1], backupData[backupOffset + tlvSIZE] & 0x7F);
                tlvSIZE += 2;
            }
            else{
                testLENGTH = backupData[backupOffset + tlvSIZE];
                tlvSIZE += 1;
            }
            tlvSIZE += testLENGTH;
            
            if ( testTAG == 0x87E5 ){
                //密码数据
                nBKREC += 3;
            }
            else if (testTAG == 0x87E6 || testTAG == 0x87E7){
                //密条数据 || 主加密密钥数据
                nBKREC += 2;
            }
            
            if ((nBKREC < 18) && (LC + tlvSIZE < 2048)){
                memcpy(BodyBuf + LC, backupData + backupOffset, tlvSIZE);
                LC += tlvSIZE;
                backupOffset += tlvSIZE;
            }
            else
                break;
        }
        if (backupOffset >= backupSize)
            P2 = 1;	//最后一个数据包
    }
    else{
        //FFLEN
        BodyBuf[LC++] = HIBYTE(HIWORD(backupSize));
        BodyBuf[LC++] = LOBYTE(HIWORD(backupSize));
        BodyBuf[LC++] = HIBYTE(backupSize);
        BodyBuf[LC++] = LOBYTE(backupSize);
        
        //FPNUM
        BodyBuf[LC++] = HIBYTE((backupOffset + 2047) / 2048);
        BodyBuf[LC++] = LOBYTE((backupOffset + 2047) / 2048);
        
        //FDATA
        if (backupOffset + 2048 < backupSize){
            if (backupOffset == 0)
                P2 = 0;	//首个数据包
            else
                P2 = 1;	//中间数据包
            memcpy(BodyBuf + LC, backupData + backupOffset, 2048);
            LC += 2048;
            backupOffset += 2048;
        }
        else{
            P2 = 2;	//最后一个数据包
            memcpy(BodyBuf + LC, backupData + backupOffset, backupSize - backupOffset);
            LC += (WORD)(backupSize - backupOffset);
            backupOffset = backupSize;
        }
    }
    if (_nbuild_cmd_with_body(cmdBuf, cmdSize,
                              __internal_ChNum,	//ChNum
                              0x03,				//MTYPE
                              0x0001,			//FN
                              0x00,				//CFLAG
                              0x01,				//CLA
                              0x51,				//INS
                              0x00,				//P1=0: 下发备份文件, P1=1: 放弃下发
                              P2,				//P2=0: 还有数据下发, P2=1: 最后一个数据包
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *_backupOffset = backupOffset;
    
    return 0;
}

DWORD BTComm_Restore_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_upgradeFirmware_3040S(_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD Flag, _IN LPBYTE frameData, _IN DWORD frameSize, _IN DWORD totalSize, _IN DWORD nFrame)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    
    if ( cmdBuf == NULL || frameData == NULL || frameSize > 1024 )
        return API_INVALID_PARAMETER;
    
    LC = 0;
    //FID
    memcpy(BodyBuf, "12345678", 8);
    LC += 8;
    //FFLEN
    BodyBuf[LC++] = HIBYTE(HIWORD(totalSize));
    BodyBuf[LC++] = LOBYTE(HIWORD(totalSize));
    BodyBuf[LC++] = HIBYTE(totalSize);
    BodyBuf[LC++] = LOBYTE(totalSize);
    //FPNUM
    BodyBuf[LC++] = HIBYTE(nFrame);
    BodyBuf[LC++] = LOBYTE(nFrame);
    //FDATA
    memcpy(BodyBuf + LC, frameData, frameSize);
    LC += frameSize;
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x03,				//MTYPE
                              0x0001,			//FN
                              0x00,			    //CFLAG
                              0x01,				//CLA
                              0x40,				//INS
                              0x00,				//P1
                              Flag,				//P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_upgradeFirmware_3040R (LPBYTE recvData, DWORD recvSize, LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_modifyPIN_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE oldPIN_SHA1, _IN LPBYTE newPIN, _IN DWORD newPIN_SIZE)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    BYTE	newPIN_PKCS[48];
    DWORD	newPIN_SIZE_PKCS = sizeof(newPIN_PKCS);
    BYTE	encPIN[48];
    WORD	LC;
    
    if ( cmdBuf == NULL || oldPIN_SHA1 == NULL || newPIN == NULL || newPIN_SIZE > 32 )
        return API_INVALID_PARAMETER;
    
    pkcs_5_padding(newPIN, newPIN_SIZE, newPIN_PKCS, &newPIN_SIZE_PKCS);
    
    sm4_context	ctx;
    
    sm4_setkey_enc(&ctx, oldPIN_SHA1);
    sm4_crypt_ecb(&ctx, SM4_ENCRYPT, newPIN_SIZE_PKCS, newPIN_PKCS, encPIN);
    
    
    LC = 0;
    
    BodyBuf[LC] = 0x87;		//TAG_ENC_PIN
    LC++;
    BodyBuf[LC] = 0xD2;		//TAG_ENC_PIN
    LC++;
    BodyBuf[LC] = newPIN_SIZE_PKCS;
    LC++;
    memcpy(BodyBuf + LC, encPIN, newPIN_SIZE_PKCS);
    LC += newPIN_SIZE_PKCS;
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x03,      		//MTYPE
                              0x0001,			//FN
                              __internal_CFLAG,	//CFLAG
                              0x01,      		//CLA
                              0x45,      		//INS
                              0x00,      		//P1
                              0x00,      		//P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    memset(__tempEncRe, 0, 0x10);
    
    return 0;
}

DWORD BTComm_modifyPIN_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_verify_modifyPIN_EM_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD Type)
{
    DWORD	code_len;
    
    if ( cmdBuf == NULL )
        return API_INVALID_PARAMETER;
    
    code_len = *cmdSize;
    if ( _nbuild_cmd(cmdBuf, &code_len,
                     __internal_ChNum,  //ChNum
                     0x03,				//MTYPE
                     0x0001,			//FN
                     __internal_CFLAG,	//CFLAG
                     0x01,				//CLA
                     0x47,				//INS
                     Type,				//P1
                     0x00				//P2
                     ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_backupKey_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD Type, _IN DWORD bakcupKeyID)
{
    DWORD	code_len;
    
    if ( cmdBuf == NULL )
        return API_INVALID_PARAMETER;
    
    code_len = *cmdSize;
    if (_nbuild_cmd(cmdBuf, &code_len,
                    __internal_ChNum,  //ChNum
                    0x03,				//MTYPE
                    0x0001,				//FN
                    0x00,				//CFLAG
                    0x01,				//CLA
                    0x10,				//INS
                    Type,				//P1
                    bakcupKeyID			//P2
                    ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_backupKey_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

/****************************************************************************
 334. 安全通道初始化
 ****************************************************************************/
void BTComm_InitSecurityChannel_3040 (int bEnable)
{
    __temp_ChNum = 0;
    memset(__temp_CK, 0, 0x10);
    memset(__tempEncRe, 0, 0x10);
    
    __internal_ChNum = 0;
    memset(__internal_CK, 0, 0x10);
    
    __internal_CFLAG = bEnable;
}

/****************************************************************************
 338. 修改分类名
 ****************************************************************************/
DWORD BTComm_updateCatalog_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD olditemCataID, _IN LPCSTR oldCatalogName, _IN LPCSTR newCatalogName, _IN LPCSTR deviceModel, _IN LPCSTR armVersion)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    DWORD   stringLen;
    DWORD	SortValue;
    
    if (cmdBuf == NULL || newCatalogName == NULL || oldCatalogName == NULL || deviceModel == NULL || armVersion == NULL)
        return API_INVALID_PARAMETER;
    
    bool	isDeviceSupportNewFormat;
    
    if (   (strcmp(deviceModel, "JM1A" ) == 0 && strcmp(armVersion, "0.99.030") >= 0)
        || (strcmp(deviceModel, "JM1Ax") == 0 && strcmp(armVersion, "1.01.005") >= 0)
        || (strcmp(deviceModel, "JM1B" ) == 0 && strcmp(armVersion, "1.01.008") >= 0)
        || (strcmp(deviceModel, "K2"   ) == 0)
        ){
        isDeviceSupportNewFormat = true;
    }
    else{
        isDeviceSupportNewFormat = false;
    }
    
    LC = 0;
    
    if ( isDeviceSupportNewFormat == true ){
        BodyBuf[LC++] = 31;		//oldCatalogName
        stringLen = (DWORD)strlen(oldCatalogName);
        BodyBuf[LC++] = LOBYTE(stringLen);
        memcpy(BodyBuf + LC, oldCatalogName, stringLen);
        LC += stringLen;
    }
    else{
        BodyBuf[LC++] = 113;	//itemCataID
        BodyBuf[LC++] = 4;
        BodyBuf[LC++] = HIBYTE(HIWORD(olditemCataID));
        BodyBuf[LC++] = LOBYTE(HIWORD(olditemCataID));
        BodyBuf[LC++] = HIBYTE(olditemCataID);
        BodyBuf[LC++] = LOBYTE(olditemCataID);
    }
    
    BodyBuf[LC++] = 24;		//itemCataName
    stringLen = (DWORD)strlen(newCatalogName);
    BodyBuf[LC++] = LOBYTE(stringLen);
    memcpy(BodyBuf + LC, newCatalogName, stringLen);
    LC += stringLen;
    
    CalcSortValue(newCatalogName, &SortValue);
    BodyBuf[LC++] = 25;		//ItemCataSortValue
    BodyBuf[LC++] = 4;
    BodyBuf[LC++] = HIBYTE(HIWORD(SortValue));
    BodyBuf[LC++] = LOBYTE(HIWORD(SortValue));
    BodyBuf[LC++] = HIBYTE(SortValue);
    BodyBuf[LC++] = LOBYTE(SortValue);
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x06,				//MTYPE
                              0x000D,			//FN
                              __internal_CFLAG,	//CFLAG
                              0x03,				//CLA
                              0x06,				//INS
                              0x00,				//P1
                              0x00,				//P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_updateCatalog_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

/****************************************************************************
 339. 修改密码标题
 ****************************************************************************/
DWORD BTComm_updateSecurityBookItemTitle_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPCSTR old_itemTitle, _IN LPCSTR new_itemTitle)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    DWORD   stringLen;
    DWORD	SortValue;
    
    if (cmdBuf == NULL ||old_itemTitle == NULL || new_itemTitle == NULL )
        return API_INVALID_PARAMETER;
    
    LC = 0;
    
    BodyBuf[LC++] = 32;		//oldItemTitle
    stringLen = (DWORD)strlen(old_itemTitle);
    BodyBuf[LC++] = LOBYTE(stringLen);
    memcpy(BodyBuf + LC, old_itemTitle, stringLen);
    LC += stringLen;
    
    BodyBuf[LC++] = 28;		//itemTtile
    stringLen = (DWORD)strlen(new_itemTitle);
    BodyBuf[LC++] = LOBYTE(stringLen);
    memcpy(BodyBuf + LC, new_itemTitle, stringLen);
    LC += stringLen;
    
    CalcSortValue(new_itemTitle, &SortValue);
    BodyBuf[LC++] = 27;		//ItemSortValue
    BodyBuf[LC++] = 4;
    BodyBuf[LC++] = HIBYTE(HIWORD(SortValue));
    BodyBuf[LC++] = LOBYTE(HIWORD(SortValue));
    BodyBuf[LC++] = HIBYTE(SortValue);
    BodyBuf[LC++] = LOBYTE(SortValue);
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x06,				//MTYPE
                              0x000D,			//FN
                              __internal_CFLAG,	//CFLAG
                              0x03,				//CLA
                              0x07,				//INS
                              0x00,				//P1
                              0x00,				//P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_updateSecurityBookItemTitle_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

/****************************************************************************
 340. 动态设备参数下发
 ****************************************************************************/
DWORD BTComm_setDeviceParamater_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD Min, _IN DWORD Max, _IN DWORD TryCount, _IN DWORD Sleep, _IN DWORD PowerOff, _IN LPCSTR NiceName)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    DWORD   stringLen;
    
    if (cmdBuf == NULL)
        return API_INVALID_PARAMETER;
    
    LC = 0;
    
    if ( Min != 0 && Max != 0 ){
        BodyBuf[LC++] = 69;		//TAG_PWDLEN
        BodyBuf[LC++] = 2;
        BodyBuf[LC++] = Min;
        BodyBuf[LC++] = Max;
    }
    
    if ( TryCount != 0 ){
        BodyBuf[LC++] = 68;		//TAG_PWDERR
        BodyBuf[LC++] = 1;
        BodyBuf[LC++] = TryCount;
    }
    
    if ( Sleep != 0 ){
        BodyBuf[LC++] = 56;		//TAG_CSCRTO
        BodyBuf[LC++] = 1;
        BodyBuf[LC++] = Sleep;
    }
    
    if ( PowerOff != 0 ){
        BodyBuf[LC++] = 62;		//TAG_DOWNTO
        BodyBuf[LC++] = 2;
        BodyBuf[LC++] = HIBYTE(PowerOff);
        BodyBuf[LC++] = LOBYTE(PowerOff);
    }
    
    if ( NiceName != NULL && (stringLen = (DWORD)strlen(NiceName)) != 0 ){
        BodyBuf[LC++] = 0x87;	//TAG_DEVNAME
        BodyBuf[LC++] = 0xED;	//TAG_DEVNAME
        BodyBuf[LC++] = LOBYTE(stringLen);
        memcpy(BodyBuf + LC, NiceName, stringLen);
        LC += stringLen;
    }
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x03,				//MTYPE
                              0x0001,			//FN
                              __internal_CFLAG,	//CFLAG
                              0x01,				//CLA
                              0x08,				//INS
                              0x00,				//P1
                              0x01,				//P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_setDeviceParamater_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

/****************************************************************************
 328. 数据备份 (独占模式)
 ****************************************************************************/
DWORD BTComm_Backup_Next_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD nFrame, _IN DWORD blockType, _IN LPCSTR deviceModel, _IN LPCSTR armVersion)
{
    DWORD	code_len;
    
    if ( cmdBuf == NULL || deviceModel == NULL || armVersion == NULL )
        return API_INVALID_PARAMETER;
    
    bool	isDeviceSupportNewFormat;
    DWORD	_maxblockType = 0;
    
    if (   (strcmp(deviceModel, "JM1A" ) == 0 && strcmp(armVersion, "0.99.030") >= 0)
        || (strcmp(deviceModel, "JM1Ax") == 0 && strcmp(armVersion, "1.01.005") >= 0)
        || (strcmp(deviceModel, "JM1B" ) == 0 && strcmp(armVersion, "1.01.008") >= 0)
        || (strcmp(deviceModel, "K2"   ) == 0)
        ){
        _maxblockType = 3;
        isDeviceSupportNewFormat = true;
    }
    else{
        _maxblockType = 0;
        isDeviceSupportNewFormat = false;
    }
    
    if ( blockType > _maxblockType )
        return API_BACKUP_ALL_FINISHED;
    
    code_len = *cmdSize;
    
    if ( isDeviceSupportNewFormat ){
        if (_nbuild_cmd(cmdBuf, &code_len,
                        __internal_ChNum,		//ChNum
                        0x06,	                //MTYPE
                        0x0001,	            	//FN
                        0x00,	                //CFLAG
                        0x01,	                //CLA
                        0xC0,	                //INS
                        LOBYTE(blockType), 		//P1
                        LOBYTE(nFrame)     		//P2
                        ))
            return API_INVALID_PARAMETER;
    }
    else{
        if (_nbuild_cmd(cmdBuf, &code_len,
                        __internal_ChNum,	//ChNum
                        0x03,				//MTYPE
                        0x0001,				//FN
                        0x00,				//CFLAG
                        0x00,				//CLA
                        0xC0,				//INS
                        0x00,				//P1
                        0x00				//P2
                        ))
            return API_INVALID_PARAMETER;
    }
    
    *cmdSize = code_len;
    
    return 0;
}

void BTComm_setSEQ_3040(DWORD newSEQ)
{
    SEQ = newSEQ;
}

DWORD BTComm_enumMainEncryptKey_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD KeyType)
{
    DWORD	code_len;
    
    if ( cmdBuf == NULL )
        return API_INVALID_PARAMETER;
    
    code_len = *cmdSize;
    
    if (_nbuild_cmd(cmdBuf, &code_len,
                    __internal_ChNum,		//ChNum
                    0x06,	                //MTYPE
                    0x0001,	            	//FN
                    __internal_CFLAG,       //CFLAG
                    0x02,	                //CLA
                    0x04,	                //INS
                    LOBYTE(KeyType), 		//P1
                    0     					//P2
                    ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_enumMainEncryptKey_3040D (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPBYTE lpHandles, _OUT LPDWORD lpnKeys)
{
    JMD_RESULT	Result;
    DWORD		dwRet;
    
    dwRet = BTComm_getResponse_3040R (recvData, recvSize, &Result);
    if ( dwRet != 0 )
        return dwRet;
    
    if ( Result.ErrorCode1 != 0x9000 || Result.ErrorCode2 != 0x9000 )
        return MAKEDWORD(Result.ErrorCode2, Result.ErrorCode1);
    
    if ( lpHandles == NULL || lpnKeys == NULL )
        return API_INVALID_PARAMETER;
    
    if ( Result.ResultSize > 160 || Result.ResultSize % 0x10 != 0 )
        return API_BAD_TLV;
    
    memcpy(lpHandles, Result.ResultData, Result.ResultSize);
    *lpnKeys = Result.ResultSize / 0x10;
    return API_OK;
}

DWORD BTComm_EncryptInit_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD SessionID, _IN LPBYTE lpHandles, _IN DWORD indexOfHandles, _IN DWORD ALG_ID, _IN DWORD paddingType, _IN LPBYTE IV, _IN DWORD slotNum)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    
    if ( cmdBuf == NULL || (NULL != lpHandles && indexOfHandles > 10))
        return API_INVALID_PARAMETER;
    
    LC = 0;
    
    if (SESSION_ID_NONE != SessionID) {
        BodyBuf[LC++] = 0x87;	//TAG_SESSION_ID
        BodyBuf[LC++] = 0xDE;
        BodyBuf[LC++] = 2;
        BodyBuf[LC++] = HIBYTE(SessionID);
        BodyBuf[LC++] = LOBYTE(SessionID);
    }
    
    if (NULL != lpHandles ) {
        BodyBuf[LC++] = 0x87;	//TAG_MKHANDLE
        BodyBuf[LC++] = 0xE1;
        BodyBuf[LC++] = 0x10;
        memcpy(BodyBuf + LC, lpHandles + indexOfHandles * 0x10, 0x10);
        LC += 0x10;
    }
    BodyBuf[LC++] = 0x87;	//TAG_ALG_ID
    BodyBuf[LC++] = 0xE8;
    BodyBuf[LC++] = 4;
    BodyBuf[LC++] = HIBYTE(HIWORD(ALG_ID));
    BodyBuf[LC++] = LOBYTE(HIWORD(ALG_ID));
    BodyBuf[LC++] = HIBYTE(ALG_ID);
    BodyBuf[LC++] = LOBYTE(ALG_ID);
    
    BodyBuf[LC++] = 0x87;	//TAG_ALG_PAD_TYPE
    BodyBuf[LC++] = 0xE9;
    BodyBuf[LC++] = 1;
    BodyBuf[LC++] = LOBYTE(paddingType);
    
    if (NULL != IV) {
        BodyBuf[LC++] = 0x87;	//TAG_ALG_INIT_IV
        BodyBuf[LC++] = 0xEA;
        BodyBuf[LC++] = 0x10;
        memcpy(BodyBuf + LC, IV, 0x10);
        LC += 0x10;
    }
    
    BodyBuf[LC++] = 0x87;	//TAG_SLOT_NUM
    BodyBuf[LC++] = 0xE2;
    BodyBuf[LC++] = 1;
    BodyBuf[LC++] = LOBYTE(slotNum);
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x06,				//MTYPE
                              0x0001,			//FN
                              __internal_CFLAG,	//CFLAG
                              0x02,				//CLA
                              0x07,				//INS
                              FUNC_ENCRYPT,		//P1
                              CMD_INIT,			//P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_EncryptInit_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_DecryptInit_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD SessionID, _IN LPBYTE lpHandles, _IN DWORD indexOfHandles, _IN DWORD ALG_ID, _IN DWORD paddingType, _IN LPBYTE IV, _IN DWORD slotNum)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    
    if ( cmdBuf == NULL || (NULL != lpHandles && indexOfHandles > 10))
        return API_INVALID_PARAMETER;
    
    LC = 0;
    
    if (SESSION_ID_NONE != SessionID) {
        BodyBuf[LC++] = 0x87;	//TAG_SESSION_ID
        BodyBuf[LC++] = 0xDE;
        BodyBuf[LC++] = 2;
        BodyBuf[LC++] = HIBYTE(SessionID);
        BodyBuf[LC++] = LOBYTE(SessionID);
    }
    
    if (NULL != lpHandles ) {
        BodyBuf[LC++] = 0x87;	//TAG_MKHANDLE
        BodyBuf[LC++] = 0xE1;
        BodyBuf[LC++] = 0x10;
        memcpy(BodyBuf + LC, lpHandles + indexOfHandles * 0x10, 0x10);
        LC += 0x10;
    }
    BodyBuf[LC++] = 0x87;	//TAG_ALG_ID
    BodyBuf[LC++] = 0xE8;
    BodyBuf[LC++] = 4;
    BodyBuf[LC++] = HIBYTE(HIWORD(ALG_ID));
    BodyBuf[LC++] = LOBYTE(HIWORD(ALG_ID));
    BodyBuf[LC++] = HIBYTE(ALG_ID);
    BodyBuf[LC++] = LOBYTE(ALG_ID);
    
    BodyBuf[LC++] = 0x87;	//TAG_ALG_PAD_TYPE
    BodyBuf[LC++] = 0xE9;
    BodyBuf[LC++] = 1;
    BodyBuf[LC++] = LOBYTE(paddingType);
    
    if (NULL != IV) {
        BodyBuf[LC++] = 0x87;	//TAG_ALG_INIT_IV
        BodyBuf[LC++] = 0xEA;
        BodyBuf[LC++] = 0x10;
        memcpy(BodyBuf + LC, IV, 0x10);
        LC += 0x10;
    }
    
    BodyBuf[LC++] = 0x87;	//TAG_SLOT_NUM
    BodyBuf[LC++] = 0xE2;
    BodyBuf[LC++] = 1;
    BodyBuf[LC++] = LOBYTE(slotNum);
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x06,				//MTYPE
                              0x0001,			//FN
                              __internal_CFLAG,	//CFLAG
                              0x02,				//CLA
                              0x07,				//INS
                              FUNC_DECRYPT,		//P1
                              CMD_INIT,			//P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_DecryptInit_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_Encrypt_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE srcData, _IN DWORD srcDataSIZE)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    
    if ( cmdBuf == NULL || srcData == NULL || srcDataSIZE > 1024 )
        return API_INVALID_PARAMETER;
    
    LC = 0;
    
    BodyBuf[LC++] = 0x87;	//TAG_DATA
    BodyBuf[LC++] = 0xEB;
    if (srcDataSIZE <= 127){
        BodyBuf[LC++] = LOBYTE(srcDataSIZE);
    }
    else{
        BodyBuf[LC++] = HIBYTE(srcDataSIZE) | 0x80;
        BodyBuf[LC++] = LOBYTE(srcDataSIZE);
    }
    memcpy(BodyBuf + LC, srcData, srcDataSIZE);
    LC += (WORD)srcDataSIZE;
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x06,				//MTYPE
                              0x0001,			//FN
                              __internal_CFLAG,	//CFLAG
                              0x02,				//CLA
                              0x07,				//INS
                              FUNC_ENCRYPT,		//P1
                              CMD_ONE_FRAME,	//P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_Encrypt_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_Decrypt_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN LPBYTE srcData, _IN DWORD srcDataSIZE)
{
    DWORD	code_len;
    BYTE	BodyBuf[E3001_TRANSFER_BUFFER_SIZE];
    WORD	LC;
    
    if ( cmdBuf == NULL || srcData == NULL || srcDataSIZE > 1024 )
        return API_INVALID_PARAMETER;
    
    LC = 0;
    
    BodyBuf[LC++] = 0x87;	//TAG_DATA
    BodyBuf[LC++] = 0xEB;
    if (srcDataSIZE <= 127){
        BodyBuf[LC++] = LOBYTE(srcDataSIZE);
    }
    else{
        BodyBuf[LC++] = HIBYTE(srcDataSIZE) | 0x80;
        BodyBuf[LC++] = LOBYTE(srcDataSIZE);
    }
    memcpy(BodyBuf + LC, srcData, srcDataSIZE);
    LC += (WORD)srcDataSIZE;
    
    code_len = *cmdSize;
    if (_nbuild_cmd_with_body(cmdBuf, &code_len,
                              __internal_ChNum,	//ChNum
                              0x06,				//MTYPE
                              0x0001,			//FN
                              __internal_CFLAG,	//CFLAG
                              0x02,				//CLA
                              0x07,				//INS
                              FUNC_DECRYPT,		//P1
                              CMD_ONE_FRAME,	//P2
                              BodyBuf,
                              LC
                              ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_Decrypt_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}

DWORD BTComm_setLanguage_3040S (_OUT LPBYTE cmdBuf, _IN_OUT LPDWORD cmdSize, _IN DWORD Language)
{
    DWORD	code_len;
    
    if ( cmdBuf == NULL)
        return API_INVALID_PARAMETER;
    code_len = *cmdSize;
    if (_nbuild_cmd(cmdBuf, &code_len,
                    0x00,	    //ChNum
                    0x03,	    //MTYPE
                    0x0001,		//FN
                    0x00,	    //CFLAG
                    0x01,	    //CLA
                    0x61,	    //INS
                    0x00,	    //P1
                    Language	//P2
                    ))
        return API_INVALID_PARAMETER;
    
    *cmdSize = code_len;
    
    return 0;
}

DWORD BTComm_setLanguage_3040R (_IN LPBYTE recvData, _IN DWORD recvSize, _OUT LPJMD_RESULT Result)
{
    return BTComm_getResponse_3040R (recvData, recvSize, Result);
}
