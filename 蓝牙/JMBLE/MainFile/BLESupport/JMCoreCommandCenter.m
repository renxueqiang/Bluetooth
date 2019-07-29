//
//  JMCoreCommandCenter.m
//  jimidun
//
//  Created by microdone on 16/1/20.
//  Copyright © 2016年 microdone. All rights reserved.
//

#import "JMCoreCommandCenter.h"
#import "jmd_btcomm.hpp"
#import "JMPeripheral.h"


@implementation JMCoreCommandCenter
+ (NSData *)commandWithType:(CBCommType)type object:(NSData *)anObject{
    int8_t     cmd_buffer[E3001_TRANSFER_BUFFER_SIZE];
    uint32_t   cmd_size =sizeof(cmd_buffer);
    NSData *commData;
    
    
    uint8_t     cmd_buffNew[E3001_TRANSFER_BUFFER_SIZE];
    uint32_t    cmd_sizeNew =sizeof(cmd_buffer);

    
    switch (type) {
            
            
        case DevExitMode:
            BTComm_exitExclusiveMode_3040S (cmd_buffNew, &cmd_sizeNew);
            
            commData = [[NSData alloc] initWithBytes:cmd_buffNew length:cmd_sizeNew];
            break;
            
        case DevRandomNum:
          BTComm_getRandomNumber_3040S (cmd_buffNew, &cmd_sizeNew, 16);

            commData = [[NSData alloc] initWithBytes:cmd_buffNew length:cmd_sizeNew];
            break;
            
        case DevPublicKey:
             BTComm_getDevicePublicKey_3040S(cmd_buffNew, &cmd_sizeNew, 0);
            commData = [[NSData alloc] initWithBytes:cmd_buffNew length:cmd_sizeNew];
            break;
        
        
        case CBCommActivateS:
            if (JMDeveiceType > 2) {
                
            BTComm_Activate_3040S ((LPBYTE)cmd_buffer,&cmd_size, (LPBYTE)anObject.bytes,(DWORD)[anObject length]);
                
            }else{
                
            BTComm_ActivateS ((LPBYTE)anObject.bytes, (DWORD)[anObject length],(LPBYTE)cmd_buffer, &cmd_size);
            }
            
            commData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
            break;

        case CBCommGetDevInfo:
            BTComm_getDeviceInfoS((LPBYTE)cmd_buffer, &cmd_size);
            commData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
            break;
        case CBCommGetSecurityBookS:
            
            BTComm_enumSecurityBook_3040S ((LPBYTE)cmd_buffer,&cmd_size);
            commData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
            break;
        case CBCommGetSecurityBookSTwo:
            BTComm_getSecurityBookS(0, (LPBYTE)cmd_buffer, &cmd_size);
            commData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
            break;
        case CBCommGotoSecurityBookS:
            
            BTComm_showSecurityBook_3040S ((LPBYTE)cmd_buffer,&cmd_size,anObject.bytes);
                
            commData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
            break;
        case CBCommGetSecurityNoteS:
            
            if(JMDeveiceType >2){
          
            BTComm_enumSecurityNote_3040S ((LPBYTE)cmd_buffer, &cmd_size);
            
            }else{
            
             BTComm_getSecurityNoteS(1, (LPBYTE)cmd_buffer, &cmd_size);
            }
            
           
            commData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
            break;
        case CBCommGetSecurityNoteSTwo:
            BTComm_getSecurityNoteS(0, (LPBYTE)cmd_buffer, &cmd_size);
            commData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
            break;
        case CBCommGotoSecurityNoteS:
            
   
            BTComm_showSecurityNote_3040S ((LPBYTE)cmd_buffer,&cmd_size,anObject.bytes);
                
            commData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
            break;
        case CBCommBackupSOne:
            
            if (JMDeveiceType >2) {
                
            BTComm_Backup_3040S ((LPBYTE)cmd_buffer,&cmd_size);
          
            }else {
                
             
                  BTComm_BackupS(1, (LPBYTE)cmd_buffer, &cmd_size);
            
            }
            commData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
            break;
        case CBCommBackupSTwo:
            BTComm_BackupS(0, (LPBYTE)cmd_buffer, &cmd_size);
            commData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
            break;            
        case CBCommgetSecurityNoteContentS:
            BTComm_getSecurityNoteContentS(anObject.bytes, (LPBYTE)cmd_buffer, &cmd_size);
            commData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
            break;
        case CBCommdeleteSecurityNoteS:
            
            BTComm_deleteSecurityNote_3040S ((LPBYTE)cmd_buffer, &cmd_size, anObject.bytes);
                
                
            commData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
            break;
        case CBCommgetDeviceStatusS:
            
            BTComm_getDeviceStatusS((LPBYTE)cmd_buffer, &cmd_size);
                

            commData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
            break;
        case CBCommgetDeviceInfoS:
                            
             BTComm_getDeviceInformation_3040S ((LPBYTE)cmd_buffer, &cmd_size);
            
            
            commData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
            break;
            
        case CBCommdeleteSecurityBookS:
             
            BTComm_deleteSecurityBook_3040S ((LPBYTE)cmd_buffer, &cmd_size,anObject.bytes);
                
           
            commData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
            break;
        case CBCommgetDeviceSerialNoS:
            
            BTComm_getDeviceID_3040S ((LPBYTE)cmd_buffer,&cmd_size);
                
            commData = [[NSData alloc] initWithBytes:cmd_buffer length:cmd_size];
            break;
            
        default:
            break;
    }

    return commData;
}



+(NSString *)chooseDeviceStatusSW1:(int)SW1 {
    NSString * status ;
    
    if (SW1 & SW1_ACTIVATED) {
        
        status = @"已激活";
       
        if (!(SW1 & SW1_BINDED)) {
            status = @"未绑定";
        }
        
    }else {
        
        status = @"未激活";
    }
    
    return status;
}


@end
