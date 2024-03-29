# goDomain

> Windows活动目录中的LDAP信息收集工具

文章：[Windows活动目录中的LDAP](https://payloads.online/archivers/2021-08-11/1)

## 使用示例

![get-computers](./images/img_6.png)

### 自定义过滤器

```bash
$ goDomain -username <Username> -password <Password> -base-dn <BaseDN> -host <LDAP-Server> -filter '(&(objectCategory=person)(objectClass=user))' -columns distinguishedName,sAMAccountName -csv
```

### 获取域内所有机器DN、操作系统、版本号

```
$ goDomain -username <Username> -password <Password> -base-dn <BaseDN> -host <LDAP-Server> -get-computers
```

![get-computers](./images/img_6.png)

### 获取域内所有非约束委派机器DN、操作系统、版本号

```
$ goDomain -username <Username> -password <Password> -base-dn <BaseDN> -host <LDAP-Server> -get-unconstrained-delegation-computers
```

![get-computers](./images/img_5.png)

### 获取域内所有约束委派机器DN、操作系统、版本号、约束信息


```
$ goDomain -username <Username> -password <Password> -base-dn <BaseDN> -host <LDAP-Server> -get-delegation-computers
```

![get-computers](./images/img_3.png)

### 获取域内所有用户


```
$ goDomain -username <Username> -password <Password> -base-dn <BaseDN> -host <LDAP-Server> -get-delegation-computers
```

![get-computers](./images/img_4.png)

### 结果输出

- [x] -csv
- [x] -html
- [x] -markdown

**-html**

```bash
$ goDomain -username <Username> -password <Password> -base-dn <BaseDN> -host <LDAP-Server> -get-users -html > /tmp/result.html
```

**-csv**

```bash
$ goDomain -username <Username> -password <Password> -base-dn <BaseDN> -host <LDAP-Server> -get-users -csv > /tmp/result.csv
```

**-markdown**

```bash
$ goDomain -username <Username> -password <Password> -base-dn <BaseDN> -host <LDAP-Server> -get-users -markdown > /tmp/result.md
```
