
/* *****************************************************************************************
*    �� �� ����dba_sftp_client.h
*    ˵    ����dba_sftp_client.c�ļ��к�������
*    �汾��¼��
*    �ύ����   �汾  �ύ��  �ύԭ������
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




