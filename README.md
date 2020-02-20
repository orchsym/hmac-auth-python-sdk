# HMAC认证SDK使用说明

hmac认证 implemented by python.

### 简介  
* hmac是Hashing for Message Authentication的简写，可以用来保证数据的完整，客户端把内容通过散列/哈希算法算出一个摘要，并把算法和内容以及摘要传送给服务端，服务端按照这个算法也算一遍，和摘要比一下如果一样就认为内容是完整的，如果不一样就认为内容被篡改了。

### 计算签名
1). 计算queryParam Content-md5.  
2). 构建待签名报文String 
    sig_list.append("X-Date: ")
    sig_list.append(signature_headers["X-Date"])
    sig_list.append("\n")
    sig_list.append("Content-md5: ")
    sig_list.append(str(signature_headers["Content-md5"], encoding = "utf8"))
    sig_list.append("\n")
    sig_list.append(signature_headers["request-line"])
    "".join(sig_list)  
3). 构建签名     h = hmac.new(bytes(secret, encoding = "utf8"), (string_to_hash).encode("utf-8"), hashlib.sha256)
    return base64.b64encode(h.digest())

### 构建request报文：
设置header：  

```   
  Authorization:hmac username="userhmac", algorithm="hmac-sha256", headers="X-Date Content-md5 request-line", signature="p4sGy3B+J/Zqt7gaLJVZCzVY5/Y="
  X-Date:Mon, 31 Jul 2017 07:25:07 GMT
  Content-md5:IgWlVHazOsGgHGVlcKvQDA==
```
### 方法说明：
获取请求必要头信息:  
方法：`generate_request_headers`
|  参数名称  | 说明  |
|  ----  | ----  |  
| username  | hmac用户名 |  
| secret  | hmac秘钥 |  
| request_method  | 请求方法 |  
| url  | 请求path |   
