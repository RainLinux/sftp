## sftp


### 1. 编译openssl(1.0.2l)
 下载地址[openssl.org](https://www.openssl.org/source/)

##### 编译方法

[参考](http://blog.csdn.net/gengxiaoming7/article/details/50957275)

 1. 解压
 2. ./config --prefix=/usr/local/openssl shared (*注意用shared选 项，否则libssh2编译报错*)
 3. ./config -t
 4. make depend
 5. make
 6. make install
 7. 建ssl的软链接
 8. 修改环境变量


### 2. 编译libssh2

 下载地址[libssh2.org](https://www.libssh2.org/)

##### 编译方法
 1. 解压
 2. ./configure CPPFLAGS="-I/usr/local/ssl/include" LDFLAGS="-L/usr/local/ssl/lib"
 3. make
 4. 静/动态库生成在 ./src/.libs/

### 3. sftp client使用方法

 1. 依赖库：
 
    [libssh2](./inlcude)

 2. 接口

    [dba\\_sftp_client.h](./dba_sftp_client.h)

    [dba\\_sftp_client.c](./dba_sftp_client.c)