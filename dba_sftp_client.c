/*******************************************************************************
 * 版权所有 (C)2017, 深圳市中兴通讯股份有限公司。
 *
 * 文件名称： dba_sftp.c
 * 文件标识：
 * 内容摘要： 本文件提供dba模块sftp功能实现
 * 其它说明：
 * 完成日期：
 
 *******************************************************************************/

#include "pub_div.h"
#include "tcfs_log.h"

#include "libssh2_config.h"
#include "libssh2.h"
#include "libssh2_sftp.h"

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>

#include "dba_define.h"
#include "dba_struct.h"
#include "dba_func.h"
#include "dba_sftp_client.h"

/*******************************************************************************/

/**********************************************************************
* 函数名称：dba_sftp_create_socket
* 功能描述：
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：
* 修改日期     版本号     修改人      修改内容
* 
************************************************************************/
DWORD dba_sftp_create_socket(INT *s_socket,
                                     const CHAR *ip,
                                     const WORD port)
{
    struct sockaddr_in serv_addr;

    DBA_NULLPOINTER_CHK_RTVALUE(s_socket);
    DBA_NULLPOINTER_CHK_RTVALUE(ip);

    *s_socket = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = inet_addr(ip);
    /*lint -e740 */
    if (connect(*s_socket, (struct sockaddr*)(&serv_addr),sizeof(struct sockaddr_in)) != 0)
    {
        DBA_PRN_ERROR("failed to connect(ip=%s,port=%d).",ip,port);
        return DBA_RC_SFTP_CONNECT_FAIL;
    }
    /*lint +e740 */

    return DBA_RC_OK;
}
/**********************************************************************
* 函数名称：dba_sftp_close_socket
* 功能描述：
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：
* 修改日期     版本号     修改人      修改内容
* 
************************************************************************/
VOID dba_sftp_close_socket(INT s_socket)
{
    dba_close_ftp_socket(s_socket);
}
/**********************************************************************
* 函数名称：dba_sftp_close_session
* 功能描述：
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：
* 修改日期     版本号     修改人      修改内容
* 
************************************************************************/
VOID dba_sftp_close_session(LIBSSH2_SESSION *session,LIBSSH2_SFTP *sftp_session)
{
    if(!session)
    {
        libssh2_session_disconnect(session, "Normal Shutdown, Thank you for playing");
        libssh2_session_free(session);
    }

    if(!sftp_session)
    {
        libssh2_sftp_shutdown(sftp_session);
    }

    return ;
}

/**********************************************************************
* 函数名称：dba_sftp_close
* 功能描述：
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：
* 修改日期     版本号     修改人      修改内容
* 
************************************************************************/
VOID dba_sftp_close(INT s_socket,
                         LIBSSH2_SESSION *session,
                         LIBSSH2_SFTP *sftp_session)
{
    dba_sftp_close_socket(s_socket);
    dba_sftp_close_session(session);

    return ;
}

/**********************************************************************
* 函数名称：dba_sftp_init_session
* 功能描述：
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：
* 修改日期     版本号     修改人      修改内容
* 
************************************************************************/
DWORD dba_sftp_init_session(INT socket,
                                   const CHAR *user_name,
                                   const CHAR *password,
                                   LIBSSH2_SESSION **p_session,
                                   LIBSSH2_SFTP **p_sftp_session)
{
    DBA_NULLPOINTER_CHK_RTVALUE(user_name);
    DBA_NULLPOINTER_CHK_RTVALUE(password);
    DBA_NULLPOINTER_CHK_RTVALUE(p_session);
    DBA_NULLPOINTER_CHK_RTVALUE(p_sftp_session);
    
    int ret = 0;
    ret = libssh2_init(0);
    if (ret != 0) 
    {
        DBA_PRN_ERROR("libssh2 initialization failed (%d)", ret);
        return DBA_RC_SFTP_SSH2_INIT_FAIL;   
    }
    /* Create a session instance */ 
    LIBSSH2_SESSION *session = NULL;
    session = libssh2_session_init();    
    if(!session)        
    {
        DBA_PRN_ERROR("libssh2 Create a session failed (%d)",ret);
        return DBA_RC_SFTP_SSH2_CREATE_SEEION_FAIL;   
    }
    /* Since we have set non-blocking, tell libssh2 we are blocking */
    libssh2_session_set_blocking(session, 1);
    
    /* start it up. This will trade welcome banners, exchange keys,
    * and setup crypto, compression, and MAC layers */ 
    ret = libssh2_session_handshake(session, socket);    
    if(ret)
    {
        DBA_PRN_ERROR("libssh2 handshake failed (%d)",ret);
        return DBA_RC_SFTP_SSH2_HAND_SHAKE_FAIL;   
    }
    /* At this point we havn't yet authenticated.  The first thing to do
    * is check the hostkey's fingerprint against our known hosts Your app
    * may have it hard coded, may go to a file, may present it to the
    * user, that's your call     */
    const char *fingerprint;
    fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
    DBA_PRN_DEBUG("Fingerprint: ");
    WORD i = 0;
    for(i = 0; i < 20; i++)
    {
        DBA_PRN_DEBUG("%02X ", (unsigned char)fingerprint[i]);
    }
    /* We could authenticate via password */
    if (libssh2_userauth_password(session, user_name, password))
    {
        DBA_PRN_ERROR("Authentication by password failed(user=%s,pwd=%s).",user_name,password);
        return DBA_RC_SFTP_SSH2_AUTH_FAIL;
    }
    
    DBA_PRN_ERROR("libssh2_sftp_init()");
    LIBSSH2_SFTP *sftp_session = NULL;
    sftp_session = libssh2_sftp_init(session);
    if (!sftp_session)
    {
        DBA_PRN_ERROR("Unable to init SFTP session\n");
        return DBA_RC_SFTP_SSH2_INTI_SFTP_SESSION_FAIL;
    }
    *p_sftp_session = sftp_session;
    *p_session = session;

    return DBA_RC_OK;
}
/**********************************************************************
* 函数名称：dba_sftp_init
* 功能描述：
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：
* 修改日期     版本号     修改人      修改内容
* 
************************************************************************/
DWORD dba_sftp_init(INT *p_socket,
                        LIBSSH2_SESSION **p_session,
                        LIBSSH2_SFTP **p_sftp_session)
{
    DBA_NULLPOINTER_CHK_RTVALUE(p_socket);
    DBA_NULLPOINTER_CHK_RTVALUE(p_session);
    DBA_NULLPOINTER_CHK_RTVALUE(p_sftp_session);
    
    CHAR user_name[NAMELEN]   = {0};
    CHAR passwd[PASSWDLEN]    = {0};
    CHAR ip[IPLEN] = {0};
    WORD port = SFTP_PORT;

    dba_get_ftp_info(ip,&port,user_name,passwd);
    
    INT socket = INVALID_SOCKET;
    DBA_NOK_CHK_RTCODE(dba_sftp_create_socket(&socket,ip,port));
    
    DBA_NOK_CHK_RTCODE(dba_sftp_init_session(socket,user_name,passwd,p_session,p_sftp_session));

    *p_socket = socket;

    return DBA_RC_OK;
}

/**********************************************************************
* 函数名称：dba_sftp_up_file
* 功能描述：sftp上传文件
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：
* 修改日期     版本号     修改人      修改内容
* 
************************************************************************/
DWORD dba_sftp_up_file(const CHAR *local_file_path,
                            const CHAR *remote_file_path)
{
    DBA_PRN_ERROR("dba_sftp_up_file() start.");
    DBA_NULLPOINTER_CHK_RTVALUE(local_file_path);
    DBA_NULLPOINTER_CHK_RTVALUE(remote_file_path);

    INT  socket     = INVALID_SOCKET;
    LIBSSH2_SFTP *sftp_session;
    LIBSSH2_SESSION *session;
    
    if(DBA_RC_OK != dba_sftp_init(&socket,&session,&sftp_session))
    {
        DBA_PRN_ERROR("dba_sftp_init() failed.");
        dba_sftp_close(socket,session,sftp_session);
        return DBA_RC_SFTP_ERR_BEGIN;
    }

    FILE *local_f_handle;
    local_f_handle = fopen(local_file_path, "rb");
    if (NULL == local_f_handle) 
    {
        DBA_PRN_ERROR("Can't open local file(%s)", local_file_path);
        dba_sftp_close(socket,session,sftp_session);
        return DBA_RC_SFTP_SSH2_OPEN_L_FILE_FAIL;
    }
    DBA_PRN_ERROR("libssh2_sftp_open()");
    /* Request a file via SFTP */
    LIBSSH2_SFTP_HANDLE *sftp_handle;
    sftp_handle = libssh2_sftp_open(sftp_session, remote_file_path, 
                                    LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT|LIBSSH2_FXF_TRUNC,
                                    LIBSSH2_SFTP_S_IRUSR|LIBSSH2_SFTP_S_IWUSR|
                                    LIBSSH2_SFTP_S_IRGRP|LIBSSH2_SFTP_S_IROTH);
    if (!sftp_handle) 
    {
        DBA_PRN_ERROR("Unable to open remote file(%s) with SFTP.",remote_file_path);
        dba_sftp_close(socket,session,sftp_session);
        return DBA_RC_SFTP_SSH2_OPEN_R_FILE_FAIL;
    }
    DBA_PRN_ERROR("start send data");
    int rc = 0;
    char mem[BACKUP_READ_WRITE_BUFFER_LEN];
    do 
    {
        size_t nread = 0;
        nread = fread(mem, 1, sizeof(mem), local_f_handle);
        if (nread <= 0) 
        {/* end of file */
            break;
        }
        char *ptr = NULL;
        ptr = mem;
        do
        {/* write data in a loop until we block */
            rc = libssh2_sftp_write(sftp_handle, ptr, nread);
            if(rc < 0)
                break;
            ptr = ptr + rc;
            nread = nread - rc;
         } while (nread);
    } while (rc > 0);

    libssh2_sftp_close(sftp_handle);
    dba_sftp_close(socket,session,sftp_session);

    if(local_f_handle)
    {
        fclose(local_f_handle);
    }
    DBA_PRN_ERROR("dba_sftp_up_file() all done");
    libssh2_exit();
    
    return DBA_RC_OK;
}

/**********************************************************************
* 函数名称：dba_sftp_mkdir
* 功能描述：
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：
* 修改日期     版本号     修改人      修改内容
* 
************************************************************************/
DWORD dba_sftp_mkdir(const CHAR *remote_path)
{
    DBA_PRN_ERROR("dba_sftp_mkdir() start.");
    DBA_NULLPOINTER_CHK_RTVALUE(remote_path);

    INT  socket     = INVALID_SOCKET;
    LIBSSH2_SFTP *sftp_session;
    LIBSSH2_SESSION *session;
    
    if(DBA_RC_OK != dba_sftp_init(&socket,&session,&sftp_session))
    {
        DBA_PRN_ERROR("dba_sftp_init() failed.");
        dba_sftp_close(socket,session,sftp_session);
        return DBA_RC_SFTP_ERR_BEGIN;
    }
    /* Make a directory via SFTP */
    int rc = 0;
    rc = libssh2_sftp_mkdir(sftp_session, remote_path,
                            LIBSSH2_SFTP_S_IRWXU|
                            LIBSSH2_SFTP_S_IRGRP|LIBSSH2_SFTP_S_IXGRP|
                            LIBSSH2_SFTP_S_IROTH|LIBSSH2_SFTP_S_IXOTH);
    if(rc)
    {
        DBA_PRN_ERROR("libssh2_sftp_mkdir failed(%d)", rc);
        dba_sftp_close(socket,session,sftp_session);
        //return DBA_RC_SFTP_SSH2_MKDIR_FAIL;
    }
    
    dba_sftp_close(socket,session,sftp_session);
    
    DBA_PRN_ERROR("dba_sftp_mkdir() all done");
    libssh2_exit();

    return DBA_RC_OK;
}

/**********************************************************************
* 函数名称：dba_sftp_up_file
* 功能描述：sftp上传文件
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：
* 修改日期     版本号     修改人      修改内容
* 
************************************************************************/
DWORD dba_sftp_get_file(const CHAR *remote_file_path,
                             const CHAR *local_file_path)
{
    DBA_PRN_ERROR("dba_sftp_get_file() start.");
    DBA_NULLPOINTER_CHK_RTVALUE(remote_file_path);
    DBA_NULLPOINTER_CHK_RTVALUE(local_file_path);

    INT  socket     = INVALID_SOCKET;
    LIBSSH2_SFTP *sftp_session;
    LIBSSH2_SESSION *session;
    
    if(DBA_RC_OK != dba_sftp_init(&socket,&session,&sftp_session))
    {
        DBA_PRN_ERROR("dba_sftp_init() failed.");
        dba_sftp_close(socket,session,sftp_session);
        return DBA_RC_SFTP_ERR_BEGIN;
    }

    FILE *local_f_handle;
    local_f_handle = fopen(local_file_path, "wb");
    if (NULL == local_f_handle) 
    {
        DBA_PRN_ERROR("Can't open local file(%s)", local_file_path);
        dba_sftp_close(socket,session,sftp_session);
        return DBA_RC_SFTP_SSH2_OPEN_L_FILE_FAIL;
    }
    
    /* Request a file via SFTP */
    LIBSSH2_SFTP_HANDLE *sftp_handle;
    sftp_handle = libssh2_sftp_open(sftp_session, remote_file_path, LIBSSH2_FXF_READ, 0);
    if (!sftp_handle) 
    {        
        DBA_PRN_ERROR("Unable to open file(%s) with SFTP  err=%ld", 
                      remote_file_path,
                      libssh2_sftp_last_error(sftp_session));
        dba_sftp_close(socket,session,sftp_session);
        return DBA_RC_SFTP_SSH2_OPEN_R_FILE_FAIL;  
    }

    DBA_PRN_ERROR("libssh2_sftp_open() is done, now receive data.");
    int rc = 0;
    do 
    {        
        char mem[BACKUP_READ_WRITE_BUFFER_LEN];        
        /* loop until we fail */
        rc = libssh2_sftp_read(sftp_handle, mem, BACKUP_READ_WRITE_BUFFER_LEN);
        if (rc > 0)
        {
            fwrite(mem, rc, 1, local_f_handle);
        }
        else
        {
            break;
        }
    } while (1);

    libssh2_sftp_close(sftp_handle);
    dba_sftp_close(socket,session,sftp_session);

    if(local_f_handle)
    {
        fclose(local_f_handle);
    }
    DBA_PRN_ERROR("dba_sftp_get_file() all done");
    libssh2_exit();
    
    return DBA_RC_OK;
}


