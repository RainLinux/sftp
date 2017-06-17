
/* *****************************************************************************************
*    文 件 名：dba_sftp_client.h
*    说    明：dba_sftp_client.c文件中函数声明
*    版本记录：
*    提交日期   版本  提交人  提交原因及内容
*******************************************************************************************/


#ifndef  __DBA_SFTP_CLIENT_H
#define  __DBA_SFTP_CLIENT_H

/******************************************************************************************/

DWORD dba_sftp_mkdir(const CHAR *remote_path);

DWORD dba_sftp_up_file(const CHAR *local_file_path,
                            const CHAR *remote_file_path);
DWORD dba_sftp_get_file(const CHAR *remote_file_path,
                             const CHAR *local_file_path);


#endif




