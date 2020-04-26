# HMAC认证SDK使用说明

Python版本的SDK，用于生成Orchsym API Gateway HMAC 认证所需的请求头。

支持 Python2.7+。

### HMAC简介

* hmac是Hashing for Message Authentication的简写，可以用来保证数据的完整，客户端把内容通过散列/哈希算法算出一个摘要，并把算法和内容以及摘要传送给服务端，服务端按照这个算法也算一遍，和摘要比一下如果一样就认为内容是完整的，如果不一样就认为内容被篡改了。

### 计算签名

1. 生成 `X-Date`、`Content-md5` 参数

2. 构建待签名报文字符串 

```
sig_list.append("X-Date: ")
sig_list.append(signature_headers["X-Date"])
sig_list.append("\n")
sig_list.append("Content-md5: ")
sig_list.append(signature_headers["Content-md5"].decode("utf8"))
sig_list.append("\n")
sig_list.append(signature_headers["request-line"])
"".join(sig_list)
```

3. 对签名字符串使用SHA256算法进行HMAC加密

```
h = hmac.new(bytes(secret.decode("utf8")), (string_to_hash).encode("utf-8"), hashlib.sha256)
return base64.b64encode(h.digest())
```



### 构建请求头报文

设置header:

```
  Authorization:hmac username="userhmac", algorithm="hmac-sha256", headers="X-Date Content-md5 request-line", signature="p4sGy3B+J/Zqt7gaLJVZCzVY5/Y="
  X-Date:Mon, 31 Jul 2017 07:25:07 GMT
  Content-md5:IgWlVHazOsGgHGVlcKvQDA==
```

### 方法说明

#### generate_request_headers(username, secret, request_method, url)

描述：根据给定请求信息以及HMAC用户名、秘钥，生成HMAC认证所需的请求头。

参数：

- username: HMAC 认证用户名

- secret: HMAC 认证秘钥

- request_method: 请求方法

- url: 请求完整路径，比如: `http://www.example.com/a/b/c?type=1`


返回:

```
{
  'Content-md5': '98mUgq1pd7snmumXmFAtLQ==',
  'Authorization': 'hmac username="user_tom",algorithm="hmac-sha256",headers="X-Date Content-md5 request-line",signature="Pzsm3qYCnnuq+ZKz7rJ84Gl83ZRM/Sb6RQ2XiUPZWxc="',
  'X-Date': 'Sun, 26 Apr 2020 06:56:08 GMT'
}
```

### 使用示例

```
    url = "https://172.18.28.240/env-101/por-1/test/api/users/2"
    headers = generate_request_headers("user_tom", "password", "GET", url)

    import requests
    r = requests.get(url, verify=False, headers=headers)
    print(r.text)
```


