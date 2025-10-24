Запуск

```
sudo neo4j console
```

```
cd ~/standoff365/BloodHound/BloodHound-Tools/DBCreator/
python DBCreator.py
```

```
/home/kali/tools/BloodHound-linux-x64/BloodHound --disable-gpu-sandbox
```
Username: neo4j
Password: kali

web: admin/admin
```bash
cd ~/tools
./bloodhound-cli containers start
```

## 🔍 Аудит Active Directory / BloodHound Queries

### 🎯 **Атаки на делегацию**

#### Неограниченная делегация до контроллеров домена

```cypher
MATCH (unconstrainedHost:Computer {unconstraineddelegation: true})
MATCH (dc:Computer {name: "DC$.DOMAIN.LOCAL"})
MATCH path = shortestPath((unconstrainedHost)-[r:MemberOf|HasSession|AdminTo|AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|TrustedBy*1..10]->(dc))
WHERE NONE(rel IN relationships(path) WHERE TYPE(rel) = "MemberOf" AND NOT rel.isacl)
RETURN path, unconstrainedHost.name AS UnconstrainedHost, dc.name AS DomainController
```

#### Все системы с неограниченной делегацией

```cypher
MATCH (u:User {unconstraineddelegation:true})
RETURN u.name, u.enabled,
datetime({epochseconds:toInteger(u.whencreated)}) as whencreated, 
u.pwdneverexpires,
datetime({epochseconds:toInteger(u.lastlogontimestamp)}) as lastlogontimestamp,
datetime({epochseconds:toInteger(u.pwdlastset)}) as pwdlastset,
u.description
ORDER BY u.pwdlastset ASC
```

### 🔐 **Kerberoasting & AS-REP Roasting**

#### Kerberoastable пользователи

```cypher
MATCH (u:User)
WHERE u.hasspn=true
AND u.enabled = true
AND NOT u.objectid ENDS WITH '-502'
AND NOT COALESCE(u.gmsa, false) = true
AND NOT COALESCE(u.msa, false) = true
RETURN u
LIMIT 100
```

#### Старые пароли сервисных аккаунтов

```cypher
MATCH (u:User {hasspn:true})
WHERE u.enabled = true AND u.pwdlastset < 1704153599 AND u.whencreated < 1704153599
RETURN u.name, u.serviceprincipalnames, u.pwdlastset, u.whencreated
ORDER BY u.pwdlastset ASC
```

#### AS-REP Roastable пользователи

```cypher
MATCH (u:User)
WHERE u.dontreqpreauth = true
AND u.enabled = true
RETURN u
LIMIT 100
```

### 👥 **Анализ групп и членства**

#### Поиск групп пользователя

```cypher
MATCH (u:User {name:"USER@DOMAIN_NAME"})-[:MemberOf*1..]->(g:Group)
RETURN u.name, g.name, g.objectid
```

#### Пользователи в >50 группах

```cypher
MATCH (u:User)-[:MemberOf]->(g:Group)
WITH u, COLLECT (g.name) as groups, COUNT(g) as groupCount
WHERE groupCount >50
RETURN u.name, groups, groupCount
```

#### Пустые группы

```cypher
MATCH (g:Group)
WHERE NOT (g)<-[:MemberOf]-()
RETURN g.name, g.objectid
```

### 🗺️ **Пути атаки**

#### Путь к Domain Admins

```cypher
MATCH p=shortestPath((t:Group)<-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|GPLink|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteGPLink|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|SyncedToEntraUser|CoerceAndRelayNTLMToSMB|CoerceAndRelayNTLMToADCS|WriteOwnerLimitedRights|OwnsLimitedRights|CoerceAndRelayNTLMToLDAP|CoerceAndRelayNTLMToLDAPS|Contains|DCFor|SameForestTrust|SpoofSIDHistory|AbuseTGTDelegation*1..]-(s:Base))
WHERE t.objectid ENDS WITH '-512' AND s<>t
RETURN p
LIMIT 10
```

#### Прямые назначения прав

```cypher
MATCH p=(n:Base)-[r:GenericAll|GenericWrite|WriteOwner|WriteDacl|ForceChangePassword|AllExtendedRights|AddMember|AllowedToDelegate|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteGPLink|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13]->(:Base)
WHERE (n:User OR n:Computer)  
RETURN p
LIMIT 1000
```

### ⚠️ **Уязвимые конфигурации**

#### Устаревшие ОС

```cypher
MATCH (c:Computer)
WHERE c.operatingsystem =~ '(?i).*Windows.* (2000|2003|2008|2012|xp|vista|7|8|me|nt).*'
RETURN c
LIMIT 100
```

#### Компьютеры без LAPS

```cypher
MATCH (c:Computer)
WHERE c.operatingsystem =~ '(?i).*WINDOWS (SERVER)? ?(10|11|2019|2022|2025).*'
AND c.haslaps = false
AND c.enabled = true
RETURN c
LIMIT 100
```

#### Пароли без срока действия

```cypher
MATCH (u:User)
WHERE u.enabled = true
AND u.pwdneverexpires = true
RETURN u
LIMIT 100
```

### 🔍 **Обнаружение аномалий**

#### Привилегии DCSync

```cypher
MATCH p=(:Base)-[:DCSync|AllExtendedRights|GenericAll]->(:Domain)
RETURN p
LIMIT 1000
```

#### Аккаунты с SID History

```cypher
MATCH p=(:Base)-[:HasSIDHistory]->(:Base)
RETURN p
```

#### Неактивные компьютеры (180 дней)

```cypher
WITH 180 as inactive_days
MATCH (n:Computer)
WHERE n.enabled = true
AND n.lastlogontimestamp < (datetime().epochseconds - (inactive_days * 86400))
AND n.lastlogon < (datetime().epochseconds - (inactive_days * 86400))
AND n.whencreated < (datetime().epochseconds - (inactive_days * 86400))
RETURN n
LIMIT 1000
```

### 🏗️ **Структура домена**

#### Карта OU

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(:OU)
RETURN p
LIMIT 1000
```

#### Доверительные отношения

```cypher
MATCH p = (:Domain)-[:SameForestTrust|CrossForestTrust]->(:Domain)
RETURN p
LIMIT 1000
```

### 📊 **Политики паролей**

#### Пароли не менялись >1 года

```cypher
WITH 365 as days_since_change
MATCH (u:User)
WHERE u.pwdlastset < (datetime().epochseconds - (days_since_change * 86400))
AND NOT u.pwdlastset IN [-1.0, 0.0]
RETURN u
LIMIT 100
```

#### Слабые методы шифрования

```cypher
MATCH (n:Base)
WHERE n.pwdlastset < 1204070400
RETURN n
LIMIT 100
```

### 🎭 **ADCS атаки**

#### Все ESC привилегии ADCS

```cypher
MATCH p=(:Base)-[:ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|GoldenCert|CoerceAndRelayNTLMToADCS]->(:Base)
RETURN p
```

#### Уязвимые шаблоны сертификатов ESC1

```cypher
MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)
WHERE ct.enrolleesuppliessubject = True
AND ct.authenticationenabled = True
AND ct.requiresmanagerapproval = False
AND (ct.authorizedsignatures = 0 OR ct.schemaversion = 1)
RETURN p
LIMIT 1000
```

### ☁️ **Azure/Entra ID**

#### Глобальные администраторы

```cypher
MATCH p = (:AZBase)-[:AZGlobalAdmin*1..]->(:AZTenant)
RETURN p
LIMIT 1000
```

#### Привилегированные роли

```cypher
MATCH p=(t:AZRole)<-[:AZHasRole|AZMemberOf*1..2]-(:AZBase)
WHERE t.name =~ '(?i)Global Administrator|User Administrator|Cloud Application Administrator|Authentication Policy Administrator|Exchange Administrator|Helpdesk Administrator|Privileged Authentication Administrator'
RETURN p
LIMIT 1000
```