---
title: "SQL Server in Windows Enterprise Security"
aliases: []
tags: [windows, x4, security]
domain: windows
phase: "X4"
type: security
status: draft
pair: "[[Windows SQL Server]]"
updated: 2026-11-03
---
# SQL Server in Windows Enterprise Security

> [!abstract] TL;DR
> Keep application/database permissions narrower than server, host and remote-service administration. Review effective grants, service identities, default linked mappings, enabled features and audit evidence without exercising administrative execution paths.

> [!info] Agent scope
> Security of: Service identity; Windows authentication; logins and roles; linked servers; delegation; administrative features; link Web SQL Server for application queries. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Windows service/host administration, SQL roles/ownership, login-user mapping, linked-server identities/delegation, Agent jobs/proxies, administrative features, TLS, backups and audit configuration.
- Examples are defensive inspection and harmless synthetic SELECT tests. No credential extraction, OS command execution, unsafe feature enablement, relay, privileged impersonation, evasion or persistence procedures.

## Learn

```text
Teach defensive SQL Server security in Windows enterprise at expert depth.
Assume Windows services, AD/Kerberos/TLS and T-SQL. Map service identity, SQL
server login, database user/roles/owners, linked-server mappings and Windows
privileges separately. Explain fixed/custom roles, implicit permission paths,
metadata visibility, GRANT/REVOKE/DENY and ownership caveats without abuse recipes.
Review gMSA/virtual accounts, SPN ownership, encryption/certificate validation,
constrained delegation requirements, Agent/proxy scope and optional features.
Provide safe inventory queries that never execute remote or OS commands.
Show a concrete overly broad schema SELECT grant, narrow object-level repair,
permitted and denied retests using only new WITHOUT LOGIN users and synthetic
data. Include every SQL file, setup, expected results, troubleshooting and
cleanup plus a fully specified offline evidence alternative. Explain audit
specifications, coverage/retention, false positives and SQL 2022/2025/provider
version differences. Cite Microsoft documentation. No secret retrieval,
privileged impersonation, exploitation or bypass. Teach here, not by file edits.
```

## Cheatsheet

### Privilege Review Matrix

| Surface | Root cause | Defensive target |
|---|---|---|
| Engine service | Domain/local administrative account used for convenience | Supported low-privilege virtual/domain/gMSA identity; restrict logon rights, host eligibility, SPN writes and file/share access. |
| Server authority | App in sysadmin/securityadmin or granted broad server control | Named administration roles; applications get only required database access. Security-management capabilities are themselves sensitive. |
| Database authority | `db_owner`, broad schema grants or ownership used to avoid defining permissions | Custom role with exact object/actions or reviewed module interface; separate deployment from runtime identities. |
| Linked server | Default mapping connects many callers as one overprivileged remote account | Remove unneeded links/mappings; restrict intended local principals and remote grants; preserve required workflows through pilot validation. |
| Delegation | Broad identity forwarding rather than a documented second-hop need | No delegation if not needed; otherwise supported narrowly scoped services and protected administering identities. |
| Agent/proxy | Job owners or proxy subsystem access exceeds task | Separate job operation from job creation/credential administration; review service/proxy context and msdb role memberships. |
| Optional features | Administrative execution enabled but unused/unreviewed | Keep unneeded features disabled; restrict who can change configuration. Do not invoke a feature simply to prove it is enabled. |
| Backup/recovery | Readable backups or missing encryption-key recovery | Separate backup/media/key access and tested recovery; TDE does not replace permissions/TLS. |

`sysadmin` effectively controls the instance and is not constrained by ordinary object DENY. Database owners can alter database authorization. `REVOKE` removes one grant but does not neutralize membership in another granting role. Column-level and ownership exceptions make simplistic "DENY always wins" claims wrong. Inspect principals, memberships, owners and explicit permissions together, then perform harmless tests under a correctly scoped synthetic identity.

### Concrete Secure Configuration

For `InventoryAPI`, runtime needs SELECT on `reporting.Inventory`, not all current/future objects in `reporting`. Use a custom InventoryReaders role with an object grant and a separate deployment identity. Do not grant `db_datareader` or schema SELECT when sensitive future objects can enter that scope. New users should not inherit business access merely through public grants. `WITHOUT LOGIN` users in the lab isolate the SQL authorization mechanism; live Windows group/login mapping must be reviewed independently.

Windows-authenticated clients should use the expected remote TCP endpoint, unique MSSQLSvc SPN on the actual service identity, trusted TLS server certificate and explicit certificate validation. Verify `auth_scheme` and `encrypt_option` for that connection; encryption alone does not prove client hostname validation. Use Configuration Manager for service/certificate changes and planned maintenance where restart is required. Never add Domain Admin membership or turn off certificate checking as a connectivity fix.

Linked-server review must include `local_principal_id=0` default mappings, self-credential behavior, explicit remote identity, Data Access and RPC OUT independently. A visible link with no needed workload should be retired under change control, not tested with remote queries. First-hop Kerberos does not prove second-hop delegation. SQL Server 2025/MSOLEDBSQL 19 changes encryption requirements; repair provider/certificate configuration instead of restoring weak historical defaults.

### Read-Only Inventory

On an authorized SQL Server 2022+ instance, these queries do not execute linked queries or administrative features and do not return credential secrets. Visibility depends on permissions; an empty result from a low-privileged account is not a clean bill of health. Some server metadata needs approved server-level viewing rights. Capture version/edition first.

```sql
SELECT SERVERPROPERTY('ProductVersion') AS product_version,
	   SERVERPROPERTY('Edition') AS edition;
SELECT role_principal.name AS role_name, member_principal.name AS member_name
FROM sys.server_role_members AS membership
JOIN sys.server_principals AS role_principal
	ON role_principal.principal_id = membership.role_principal_id
JOIN sys.server_principals AS member_principal
	ON member_principal.principal_id = membership.member_principal_id;

SELECT name, value, value_in_use
FROM sys.configurations
WHERE name IN ('xp_cmdshell', 'Ole Automation Procedures',
			   'Ad Hoc Distributed Queries', 'clr enabled',
			   'external scripts enabled', 'cross db ownership chaining');

SELECT server_id, name, provider, is_data_access_enabled, is_rpc_out_enabled
FROM sys.servers WHERE is_linked = 1;
SELECT server_id, local_principal_id, uses_self_credential, remote_name
FROM sys.linked_logins;

SELECT name, is_trustworthy_on, is_db_chaining_on
FROM sys.databases;
SELECT state_desc, permission_name, class_desc,
	   USER_NAME(grantee_principal_id) AS grantee
FROM sys.database_permissions;
```

Interpret pending `value` versus active `value_in_use` separately. `clr enabled` is not itself proof of arbitrary native execution; assembly trust/strict-security/version and actual permissions matter. Keep `TRUSTWORTHY` and cross-database ownership chaining off unless a narrowly reviewed supported requirement exists; note system-database defaults rather than mass-changing everything. Use signing/explicit permissions for legitimate modules where appropriate, with expert review rather than weakening a whole database boundary.

### Safe Remediation Workflow

Inventory -> identify runtime operation -> capture grants/memberships and rollback -> remove excess permission at its actual source -> grant exact required operation -> test permitted and denied synthetic cases -> monitor. Removing a role member from one group does not remove nested Windows group access. New connections/tokens may be required to observe Windows membership changes; pooled connections can preserve old context.

Do not test "cannot change server configuration" by enabling a dangerous feature. Use effective permission metadata and an approved isolated review instead. Database readers should lack server-control and privileged impersonation rights; the supplied lab proves a narrower object boundary and clearly does not certify every server-level permission.

### Failure and Version Evidence

SQL 229 is expected for a denied object operation; 18456 needs server-side state analysis; 916/4060 can reflect database access/default-database problems; TLS name/chain failures belong to transport validation; second-hop ANONYMOUS LOGON belongs to identity forwarding. Avoid granting broader permissions until the failing layer is identified. DMV access requirements changed for SQL Server 2022+, and provider encryption defaults can change independently of the engine version.

## Detection and Defense

SQL Server Audit needs an enabled server audit target plus relevant enabled server/database audit specifications. A defined-but-disabled specification records nothing. Select actions according to the installed version, such as server-role membership changes, server/database permission changes, audit changes, and narrowly scoped SELECT on sensitive objects. Successful/failed login auditing, error logs and Extended Events have different coverage and retention; a default session is not a complete permission audit.

Read-only inventory for an approved administrator:

```sql
SELECT name, type_desc, is_state_enabled FROM sys.server_audits;
SELECT name, is_state_enabled FROM sys.server_audit_specifications;
SELECT name, is_state_enabled FROM sys.database_audit_specifications;
```

Correlate UTC time, original/session/execution principal, database/object, statement/action and success with the change record. An elevated deployment job can be legitimate; scope any suppression to its approved action/object/window. Failed SELECT can be a healthy regression test, not an incident by itself. Protect audit destination access and collector availability; audit text may contain personal data or literals, so avoid secret-bearing statements and public raw-log exports.

## Labs

### Native Schema-Grant Regression Lab

Prerequisites: an already running, isolated SQL Server 2022 Developer instance; SSMS 19+ or compatible existing client; authorized rights to create/drop only the named lab database and manage its internal objects. No install/service/VM/domain actions. Confirm the instance/edition first. This lab uses only local SELECT against synthetic data and impersonates only its newly created unprivileged `WITHOUT LOGIN` user inside the database.

### File: setup.sql

```sql
USE master;
GO
IF DB_ID(N'X4SqlSecurityLab') IS NOT NULL
	THROW 51000, 'Lab database exists; stop and inspect ownership.', 1;
GO
CREATE DATABASE X4SqlSecurityLab;
GO
USE X4SqlSecurityLab;
GO
EXEC sys.sp_addextendedproperty @name=N'X4LabMarker', @value=N'security-20261103';
GO
CREATE SCHEMA reporting AUTHORIZATION dbo;
GO
CREATE TABLE reporting.Inventory (AssetId int PRIMARY KEY, Label nvarchar(40));
CREATE TABLE reporting.InternalReview (ReviewId int PRIMARY KEY, Marker nvarchar(40));
INSERT reporting.Inventory VALUES (1,N'Synthetic asset');
INSERT reporting.InternalReview VALUES (1,N'Synthetic review only');
CREATE USER LabReader WITHOUT LOGIN;
CREATE ROLE InventoryReaders AUTHORIZATION dbo;
ALTER ROLE InventoryReaders ADD MEMBER LabReader;
GRANT SELECT ON SCHEMA::reporting TO InventoryReaders;
GO
```

Run the initial existence-check batch separately; if it fails, do not continue to later `GO` batches. Never reuse an existing database merely because its name matches.

### File: baseline.sql

```sql
USE X4SqlSecurityLab;
GO
EXECUTE AS USER = 'LabReader';
SELECT AssetId, Label FROM reporting.Inventory;
SELECT ReviewId, Marker FROM reporting.InternalReview;
SELECT HAS_PERMS_BY_NAME(N'reporting.InternalReview',N'OBJECT',N'SELECT') AS excessive_read;
REVERT;
GO
```

### File: fix.sql

```sql
USE X4SqlSecurityLab;
GO
REVOKE SELECT ON SCHEMA::reporting FROM InventoryReaders;
GRANT SELECT ON OBJECT::reporting.Inventory TO InventoryReaders;
GO
```

### File: verify.sql

```sql
USE X4SqlSecurityLab;
GO
DECLARE @allowedRows int = 0, @denied bit = 0;
EXECUTE AS USER = 'LabReader';
BEGIN TRY
	SELECT @allowedRows = COUNT(*) FROM reporting.Inventory;
	BEGIN TRY
		SELECT ReviewId FROM reporting.InternalReview;
	END TRY
	BEGIN CATCH
		IF ERROR_NUMBER() = 229 SET @denied = 1;
		ELSE THROW;
	END CATCH;
END TRY
BEGIN CATCH
	REVERT;
	THROW;
END CATCH;
REVERT;
IF @allowedRows <> 1 THROW 51001, 'Permitted inventory read failed.', 1;
IF @denied <> 1 THROW 51002, 'Internal review read was not denied.', 1;
PRINT 'PASS: inventory remains readable; internal review denied';
GO
```

### File: cleanup.sql

```sql
USE X4SqlSecurityLab;
GO
IF NOT EXISTS (SELECT 1 FROM sys.extended_properties
			   WHERE class = 0 AND name = N'X4LabMarker'
				 AND CONVERT(nvarchar(100), value) = N'security-20261103')
	THROW 51003, 'Unexpected marker; do not clean up.', 1;
GO
USE master;
GO
DROP DATABASE X4SqlSecurityLab;
GO
```

Run the marker-check batch separately and stop if it fails. Close/change the database context of other lab windows before dropping; do not force termination of unrelated sessions.

### Objectives and Baseline

1. Execute setup then baseline. Expected baseline: both one-row datasets are visible and `excessive_read=1`. This deliberately overbroad grant is created by the lab; it is not the default permission of every SQL user.
2. Run verify before fixing. Expected failure is 51002 after the unapproved synthetic SELECT succeeds. This failing baseline is intentional; the script reverts context first.
3. Run fix and rerun the identical verify file. Expected PASS means inventory still returns one row and InternalReview SELECT fails with 229.
4. Run verify again for repeatability. Inspect the role's permissions: only object SELECT on Inventory should remain. Cleanup removes only the marked lab database.

### Hints and Solution

Schema SELECT grants access to all relevant objects in that schema, including future ones. The fix removes that broad source before adding the narrow object grant. Adding the narrow grant without REVOKE would leave the defect. Do not add DENY as a substitute for understanding all permission paths. A failure before/after `EXECUTE AS` can leave a query session in unexpected context; use `SELECT USER_NAME();` and the supplied REVERT/error handling, or close the dedicated lab connection before restarting.

### Complete Offline Alternative

No engine/dependencies/files required. Review this complete synthetic normalized evidence and produce a pass/fail decision for each invariant:

```text
Intended operation: SELECT reporting.Inventory only
Baseline role InventoryReaders: SELECT on SCHEMA reporting
Baseline user LabReader: member of InventoryReaders, no other role grants
Baseline Inventory SELECT: success, 1 row
Baseline InternalReview SELECT: success, 1 row
Proposed fix: REVOKE schema SELECT; GRANT object SELECT on reporting.Inventory
Post-fix Inventory SELECT: success, 1 row
Post-fix InternalReview SELECT: error 229
Server features changed: none
```

Objectives: identify root cause, retain allowed behavior, reject unrelated access and avoid unnecessary server changes. Hint: scope of a schema grant includes future objects. Solution/manual tests: baseline fails least privilege; proposed fix removes the actual broad grant; post-fix positive and negative observations satisfy this object-boundary case; no server-feature change is necessary. A proposed fix that only adds the object grant fails because the schema grant remains. No real SQL/Windows authentication, role expansion or audit configuration is verified by this supplied report. Cleanup is none.

### Verification, Troubleshooting, and Limits

Author executed no SQL/tests. Missing instance/client is a prerequisite, not a reason to provision one during review; use the complete offline alternative. Setup denial means insufficient approved lab permissions; do not elevate a real application login. Unexpected error numbers require investigation, not treating every exception as a successful denial. After cleanup in master, `SELECT DB_ID(N'X4SqlSecurityLab');` should return NULL. Neither lab tests OS identity, real Windows logins, delegation, linked-server access or server-level impersonation/configuration rights. Original optional live checklist remains uncompleted.

- [ ] Local Windows SQL Server exercise: In an isolated lab, run SQL Server under a limited service identity and map two synthetic Windows users to different database roles. Inspect linked-server and delegation configuration without enabling unnecessary features.
- [ ] Boundary check: Verify a read-only synthetic login cannot change server configuration, impersonate a privileged login, or access an unapproved linked server.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[Web SQL Server]]
- [[Windows Lateral Movement]]
- [[Windows SQL Server]]

## References

- [SQL Server security best practices](https://learn.microsoft.com/en-us/sql/relational-databases/security/sql-server-security-best-practices)
- [Permissions hierarchy](https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-hierarchy-database-engine)
- [GRANT schema permissions](https://learn.microsoft.com/en-us/sql/t-sql/statements/grant-schema-permissions-transact-sql)
- [SQL Server Audit](https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine)
- [Linked server login mappings](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addlinkedsrvlogin-transact-sql)
- [Configure Windows service identities](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions)
