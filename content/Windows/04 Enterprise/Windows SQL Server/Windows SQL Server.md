---
title: "SQL Server in Windows Enterprise"
aliases: []
tags: [windows, x4]
domain: windows
phase: "X4"
type: tech
status: draft
pair: "[[Windows SQL Server Security]]"
updated: 2026-11-03
---
# SQL Server in Windows Enterprise

> [!abstract] TL;DR
> Trace Windows service identity -> authentication transport -> server login -> database user/role -> object permission. Linked-server identity and host administration are additional boundaries, not automatic consequences of database access.

> [!info] Agent scope
> Service identity; Windows authentication; logins and roles; linked servers; delegation; administrative features; link Web SQL Server for application queries.

## Prerequisites

- Windows services/ACLs, AD/Kerberos/SPNs, TLS and basic T-SQL. Application parameterization/transactions belong in [[Web SQL Server]].
- Reference baseline and native lab: SQL Server 2022 (16.x) Developer edition on an existing isolated Windows instance, current servicing, and SSMS 19+ or an existing compatible query client. No installation, service start, VM or AD provisioning is required by these notes.
- Native lab needs permission to create/drop its single database and create users/roles within it. A complete offline alternative is also included for readers without an engine. Author executed neither path.

## Learn

```text
Teach SQL Server in Windows enterprise at expert infrastructure/identity depth.
Assume T-SQL basics, Windows services, AD/Kerberos and TLS. Separate Database
Engine service identity, service SID, network identity, login, database user,
role and securable. Compare virtual accounts, domain identities and gMSAs; use
Configuration Manager and supported permissions, not manual secret changes.
Trace Windows authentication, MSSQLSvc SPNs, remote TCP versus local transport,
aliases/listeners, auth_scheme and double-hop requirements. Explain TLS server
validation separately from Kerberos. Work through login/user SID mapping,
metadata visibility, fixed roles and narrow GRANT/REVOKE/DENY with caveats.
Cover linked-server self/explicit mappings, data access versus RPC OUT,
delegation scope, Agent jobs/proxies and disabled administrative features.
Give read-only inventory, precise secure configuration and failure evidence,
including SQL 2022 versus 2025/provider changes. Provide complete native T-SQL
labs with synthetic data, WITHOUT LOGIN users, expected allow/deny tests and
cleanup; no AD or service provisioning. Include an offline evidence alternative.
No OS execution, credential retrieval, unsafe feature enablement, abuse or
bypass recipes. Cite Microsoft sources. Teach here without editing files.
```

## Cheatsheet

### Identity Stack

| Layer | Concrete identity | What it does not imply |
|---|---|---|
| Service logon | Engine account such as `LAB\SqlEngine$` gMSA or a virtual account | A connecting user's SQL role does not change this Windows identity. |
| Service SID | Per-service Windows security principal used in local ACLs | It is not necessarily the identity used to authenticate to a remote file server. |
| Network access | Domain service identity or computer account for applicable virtual/built-in service accounts | Access to local data files does not establish access to a backup share. |
| Server login | Windows user/group or SQL-authenticated principal | A login does not automatically create a user in every database. |
| Database user | SID-mapped login, contained identity, or `WITHOUT LOGIN` user | A database-only user cannot normally open an external Windows-authenticated connection. |
| Role/securable | Server/database role, schema, object/column permission | Membership is only one part of effective permission; ownership and implicit rights matter. |

Prefer a supported low-privilege service identity, commonly gMSA for appropriate domain workloads. A virtual account is managed locally and accesses domain resources using the computer account where applicable. A gMSA's password management does not remove the need to constrain which hosts can use it, SPN registration rights, file/share ACLs and service logon rights. Use SQL Server Configuration Manager for service-account changes so required configuration/permissions are handled; do not casually edit the service in Services or assign Domain Admin to make a connection work. Availability groups/clusters add identity/SPN/backup dependencies that require their own supported design.

### Windows Authentication and TLS

Client chooses endpoint/protocol -> SSPI negotiates Windows authentication -> KDC locates the service SPN when Kerberos is available -> SQL maps the authenticated principal/group SIDs to a login -> database mapping and permissions decide access. For TCP, the common SPN is `MSSQLSvc/sql01.lab.example:1433`, tied to the actual SQL service identity. Named instances using TCP still use the TCP port in this format; other transports have different forms.

Aliases/listeners must align with DNS, intended SPN ownership and TLS certificate names. A missing SPN can lead to NTLM; an SPN registered to the wrong account can cause failure. Duplicates also need investigation. A local connection is not a valid test of remote Kerberos; use evidence from the intended client-to-server TCP path. Windows authentication is not always Kerberos, and Kerberos is not a substitute for encrypting/validating the SQL transport.

Use a supported TLS certificate with Server Authentication purpose, a private key accessible to the service, correct DNS SANs and a chain trusted by clients. Configure the instance's supported encryption settings in Configuration Manager and use clients with certificate validation enabled. `Encrypt=True;TrustServerCertificate=False` states the client intent explicitly; a server setting cannot prove every client validates the certificate. ODBC Driver 18 and modern SqlClient defaults differ from older drivers, so record exact driver versions. Do not repair a name/chain error by turning validation off.

### Read-Only Identity and Transport Evidence

Run the following on an authorized instance in an existing query window. Some DMVs require `VIEW SERVER STATE` on older versions or `VIEW SERVER PERFORMANCE STATE` on SQL Server 2022+; request approved read access rather than grant sysadmin. Metadata visibility can hide rows.

```sql
SELECT SERVERPROPERTY('ProductVersion') AS product_version,
	   SERVERPROPERTY('Edition') AS edition,
	   SERVERPROPERTY('IsIntegratedSecurityOnly') AS windows_auth_only;
SELECT ORIGINAL_LOGIN() AS original_login, SUSER_SNAME() AS execution_login,
	   USER_NAME() AS database_user, DB_NAME() AS database_name;
SELECT net_transport, auth_scheme, encrypt_option, client_net_address
FROM sys.dm_exec_connections
WHERE session_id = @@SPID;
SELECT servicename, service_account, startup_type_desc, status_desc
FROM sys.dm_server_services;
```

Read-only SPN lookup on an authorized domain workstation with ordinary directory visibility:

```powershell
setspn.exe -Q MSSQLSvc/sql01.lab.example:1433
```

Do not register/delete SPNs until the actual service identity, endpoints and duplicates are reviewed. Successful lookup alone does not establish the connection used Kerberos. `encrypt_option=TRUE` establishes transport encryption for that connection, not proof of client certificate-name validation.

### Login, User, Role and Ownership

Windows group logins reduce individual grants; use narrowly maintained groups. Server roles such as sysadmin carry broad authority; database `db_owner` is not a read-only role. Prefer custom roles with object-level permissions when workload scope is small. A login and database user usually map by SID, not display name. After moving/restoring a database, review mapping; supported `ALTER USER ... WITH LOGIN = ...` repair requires an intentionally chosen matching login, not arbitrary name reuse.

`GRANT` allows, `REVOKE` removes an explicit permission, `DENY` adds an explicit denial. REVOKE does not cancel access inherited from another role. DENY has important exceptions involving sysadmin/ownership and column-level behavior; do not teach it as a universal barrier against a privileged owner. Metadata visibility means an empty permission query does not prove no effective rights. Stored-module ownership chaining and signing can provide intentional least-privilege interfaces but require careful design; do not use database-owner privileges as the application's ordinary identity.

### Linked Servers and Delegation

| Setting | Meaning / review requirement |
|---|---|
| Self mapping | Attempts to use caller context; Windows remote identity forwarding depends on authentication/delegation and provider support. |
| Explicit remote mapping | Connects as a configured remote identity; grants can differ from caller privileges. Inventory without revealing stored secrets. |
| Default mapping (`local_principal_id=0`) | Applies broadly to logins not otherwise mapped; review intentionally, not just named mappings. |
| Data access | Enables distributed data queries; independent of RPC OUT. |
| RPC OUT | Permits outgoing remote procedure calls; leave disabled unless an approved workload needs it. |

Client -> SQL-A -> SQL-B is a separate authentication hop. First-hop Kerberos alone does not authorize delegation to B. Constrain supported delegation to required services/identities and inspect actual SQL-B evidence; no blanket unconstrained delegation. If forwarding user identity is unnecessary, an explicitly designed narrow service identity can be simpler, but introduces its own credential/role lifecycle. Links are directional and each mapping is independent.

Microsoft documents linked-server pass-through support with constrained delegation starting at SQL Server 2017 CU17; resource-based constrained delegation is not supported for that linked-server path. Do not equate general Windows Kerberos feature support with SQL/provider support.

SQL Server 2025 (17.x) linked-server provider behavior differs: MSOLEDBSQL 19 introduces encryption-parameter requirements and stricter connection defaults. Keep the 2022 lab pinned; do not cargo-cult a 2022 provider string or disable certificate checks after an upgrade. Follow the current provider documentation for supported explicit encryption and trusted certificates.

### Administrative Features and Errors

Inventory Agent job owners/proxies/subsystems, backup destinations, credentials, CLR/external scripts, OLE Automation, ad hoc distributed queries and `xp_cmdshell` configuration without invoking any execution feature. A configured feature and permission to use it are separate facts. Leave unneeded features disabled, restrict admin roles, protect backup keys/media, and audit changes. SQL Agent is a separate service; its job context is not always the interactive submitter.

| Error/evidence | First interpretation |
|---|---|
| 18456 | Login failure; server error-log state distinguishes causes. Do not infer password failure from the client message alone. |
| 4060 / 916 | Requested database unavailable/inaccessible or principal lacks access; review mapping/default database and state. |
| 229 | Permission denied on the named securable; identify effective user and grant scope. |
| Cannot generate SSPI context | DNS/SPN/account/time/authentication investigation; do not respond with broad privilege. |
| ANONYMOUS LOGON on second hop | Missing/unsupported identity delegation or wrong context; not proof the first hop failed. |
| TLS certificate-chain/name error | Trust/name/provider-version problem; fix the certificate/endpoint design instead of trusting arbitrary certificates. |

## Gotchas

- TDE protects data files/backups at rest according to its scope; it is not transport TLS or row authorization. Back up required encryption keys separately.
- SQL authentication mode changes do not fix SPNs, and enabling a Windows login does not grant filesystem access to that user through SQL.
- A contained database permission test cannot certify Windows authentication or second-hop identity.

## Labs

### Native Database Identity Lab

Use only an existing disposable SQL Server 2022 Developer instance and SSMS 19+; no engine installation or service start is part of this exercise. Connect with Windows authentication using an authorized lab administrator. Verify the server name and `SERVERPROPERTY('Edition')` before continuing; never use a shared/production instance. Create three local files from the blocks, or execute their complete contents in separate SSMS query tabs in the stated order. `GO` is a query-client batch separator. All data is synthetic; users are `WITHOUT LOGIN`, not Windows accounts.

### File: setup.sql

```sql
USE master;
GO
IF DB_ID(N'X4SqlIdentityLab') IS NOT NULL
	THROW 51000, 'Lab database already exists; stop and inspect ownership.', 1;
GO
CREATE DATABASE X4SqlIdentityLab;
GO
USE X4SqlIdentityLab;
GO
EXEC sys.sp_addextendedproperty @name=N'X4LabMarker', @value=N'identity-20261103';
GO
CREATE SCHEMA reporting AUTHORIZATION dbo;
GO
CREATE TABLE reporting.Inventory (
	AssetId int NOT NULL PRIMARY KEY,
	Label nvarchar(40) NOT NULL
);
INSERT reporting.Inventory VALUES (1,N'Training workstation'),(2,N'Training server');
CREATE USER LabReader WITHOUT LOGIN;
CREATE USER LabUnassigned WITHOUT LOGIN;
CREATE ROLE InventoryReaders AUTHORIZATION dbo;
GRANT SELECT ON OBJECT::reporting.Inventory TO InventoryReaders;
ALTER ROLE InventoryReaders ADD MEMBER LabReader;
GO
```

If the initial guard raises an error, stop; SSMS can continue later batches if submitted blindly. Run the preflight batch separately, then the remaining setup only after confirming absence. Setup creates only this database and its internal objects; it creates no login, endpoint, linked server, job or OS identity.

### File: verify.sql

```sql
USE X4SqlIdentityLab;
GO
EXECUTE AS USER = 'LabReader';
SELECT USER_NAME() AS current_database_user,
	   HAS_PERMS_BY_NAME(N'reporting.Inventory', N'OBJECT', N'SELECT') AS can_read,
	   HAS_PERMS_BY_NAME(N'reporting.Inventory', N'OBJECT', N'UPDATE') AS can_update;
SELECT AssetId, Label FROM reporting.Inventory ORDER BY AssetId;
REVERT;
GO
DECLARE @denied bit = 0;
EXECUTE AS USER = 'LabUnassigned';
BEGIN TRY
	SELECT AssetId FROM reporting.Inventory;
END TRY
BEGIN CATCH
	IF ERROR_NUMBER() = 229 SET @denied = 1;
	ELSE BEGIN
		REVERT;
		THROW;
	END;
END CATCH;
REVERT;
IF @denied <> 1 THROW 51001, 'Unassigned user was not denied.', 1;
PRINT 'PASS: unassigned database user denied SELECT';
GO
SELECT principal.name, principal.type_desc, role_member.name AS role_name
FROM sys.database_principals AS principal
LEFT JOIN sys.database_role_members AS membership
	ON membership.member_principal_id = principal.principal_id
LEFT JOIN sys.database_principals AS role_member
	ON role_member.principal_id = membership.role_principal_id
WHERE principal.name IN (N'LabReader', N'LabUnassigned');
```

The scoped `EXECUTE AS USER` tests only these newly created, unprivileged database users; it is not Windows impersonation, a login change or a delegation test.

### File: cleanup.sql

```sql
USE X4SqlIdentityLab;
GO
IF NOT EXISTS (SELECT 1 FROM sys.extended_properties
			   WHERE class = 0 AND name = N'X4LabMarker'
				 AND CONVERT(nvarchar(100), value) = N'identity-20261103')
	THROW 51002, 'Unexpected database marker; do not clean up.', 1;
GO
USE master;
GO
DROP DATABASE X4SqlIdentityLab;
GO
```

Run the marker-check batch separately and stop on failure before the drop batches. Close other lab query windows or change them to master if the database is in use; do not forcibly disconnect unrelated sessions.

### Objectives, Hints and Solution

1. Run setup after the preflight check, then verification. Explain why LabReader has a database identity but no external login.
2. Expected manual acceptance: current user LabReader, `can_read=1`, `can_update=0`, exactly two synthetic rows, and PASS for LabUnassigned's 229 denial. Role inventory shows only LabReader in InventoryReaders.
3. If permitted SELECT fails, inspect the active database, role membership and object name. If denial does not occur, stop and inspect grants; do not add DENY simply to hide an unexpected broad grant.
4. Run verification again without changes: results must remain the same. Run cleanup after inspecting the marker. In master, `SELECT DB_ID(N'X4SqlIdentityLab');` should return NULL.

### Complete Offline Alternative

No SQL instance is necessary for this source-review case. All evidence is below; create no files or resources. Treat it as synthetic reported metadata, not measured output:

```text
service_account=LAB\SqlEngine$
connection=remote TCP to sql01.lab.example:1433
auth_scheme=NTLM
encrypt_option=TRUE
spn_lookup=MSSQLSvc/sql01.lab.example:1433 not found
login=LAB\InventoryReaders
database_user=InventoryReaders
role=report_reader
grant=SELECT on reporting.Inventory
linked_server=none
```

Task: identify the authentication defect, preserve the legitimate database grant, and state two unproven properties. Hint: encryption and Kerberos are independent. Answer: investigate missing SPN ownership/registration under the supported service-account workflow; leave narrow SELECT unchanged. The record does not prove client certificate validation or absence of other permissions hidden by metadata visibility. Manual test: your conclusion must not recommend enabling mixed authentication, disabling TLS validation or granting sysadmin. Repaired evidence would show the correct unique SPN and remote `KERBEROS`, with TLS and narrow grant still intact. This is a complete offline reasoning exercise, not a live authentication test; cleanup is none.

### Verification and Limits

Neither native SQL nor offline checks were executed by the author. All files/setup/data/checks/cleanup for the native lab are printed above, but an existing isolated engine/query client remains an external prerequisite. No Python dependencies. Native success proves database authorization only, not Windows login mapping, SPNs, TLS validation or delegation. Preserve the original live-practice checklist below without marking it complete.

- [ ] Local Windows SQL Server exercise: In an isolated lab, run SQL Server under a limited service identity and map two synthetic Windows users to different database roles. Inspect linked-server and delegation configuration without enabling unnecessary features.
- [ ] Boundary check: Verify a read-only synthetic login cannot change server configuration, impersonate a privileged login, or access an unapproved linked server.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[Web SQL Server]]
- [[Windows Lateral Movement]]
- [[Windows SQL Server Security]]

## References

- [Configure Windows service accounts and permissions](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions)
- [Register SPNs for Kerberos connections](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/register-a-service-principal-name-for-kerberos-connections)
- [SQL Server permissions](https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine)
- [CREATE USER](https://learn.microsoft.com/en-us/sql/t-sql/statements/create-user-transact-sql)
- [Linked servers](https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine)
- [Configure encrypted connections](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-sql-server-encryption)
