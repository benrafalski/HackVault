---
title: "SQL Server for Web Applications Security"
aliases: []
tags: [web, w3, security]
domain: web
phase: "W3"
type: security
status: draft
pair: "[[Web SQL Server]]"
updated: 2026-11-03
---
# SQL Server for Web Applications Security

> [!abstract] TL;DR
> Injection, overprivileged application logins, and unsafe dynamic stored procedures can expose data beyond the intended query.

> [!info] Agent scope
> Security of: T-SQL; application connectivity; logins and database users; parameterization; transactions; least privilege; link enterprise administration to Windows SQL Server. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Injection, overprivileged application logins, and unsafe dynamic stored procedures can expose data beyond the intended query.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive SQL Server 2022 security for web applications. Assume T-SQL
and HTTP knowledge. Explain login/user mapping, fixed roles, object permissions,
ownership chaining, typed parameters, safe sp_executesql and dynamic identifier
allowlists. Contrast a stored procedure API with broad table DML. Include TLS
verification, pooling, transaction cleanup, resource budgets and audit evidence.
Build an independent synthetic policy lab: excessive UPDATE baseline, narrow
EXECUTE fix, identical denial tests plus successful literal-value reads. Keep
bootstrap admin credentials separate; no exploitation, theft or escalation.
Use Microsoft primary sources and version caveats. Teach, do not edit or invent
test results. Keep enterprise administration outside this application lesson.
```

## Cheatsheet

### Data, Grammar, and Identity

Never concatenate request values into SQL or into a stored procedure's dynamic command. A procedure containing concatenation is still unsafe. Bind typed values with explicit lengths; select sort/table identifiers from fixed mappings. `QUOTENAME` delimits an identifier but does not authorize which identifier the caller may use. A syntactically valid table choice can still violate policy.

```sql
DECLARE @label nvarchar(80)=N'O''Reilly';
EXEC sys.sp_executesql N'SELECT id FROM dbo.notes WHERE label=@value',
 N'@value nvarchar(80)', @value=@label;
```

This fragment is safe for the value boundary, not a tenant authorization system. Include a trusted tenant predicate or reviewed row-level security where needed; a tenant supplied by the request is not automatically trusted. Pagination and exact column projections also constrain disclosure and workload.

### Narrow Procedure Contracts

Static statements in a procedure can access same-owner objects through ownership chaining without giving callers direct table access. Dynamic SQL ordinarily breaks that chain and changes permission requirements. Do not repair a failing dynamic procedure by adding `db_owner`. Use static statements, or a separately reviewed module-signing design when truly required. Avoid unnecessary `EXECUTE AS OWNER` and cross-database trust settings.

| Identity/control | Application requirement |
|---|---|
| Bootstrap `sa` / migration login | Never in runtime configuration. |
| Runtime login + database user | CONNECT to intended DB, EXECUTE on specific procedures or narrow DML only. |
| `db_datareader` / `db_datawriter` | Broad access to user tables, including future ones; often too broad for a small app. |
| `Encrypt=True;TrustServerCertificate=False` | Verify CA and hostname; encryption without verification can authenticate the wrong endpoint. |
| Command timeout + bounded page size | Different controls; connection timeout alone cannot bound query execution. |
| Request budget + concurrency cap | Prevent many individually permitted queries exhausting the pool. |

Default encryption behavior changes across driver majors; make the intended policy explicit. Resource Governor capabilities are edition/version dependent and do not replace app limits. Use `SET LOCK_TIMEOUT` deliberately and reset session state. Always rollback on failed units of work before returning connections to a pool.

## Detection and Defense

Use SQL Server Audit or appropriately scoped Extended Events for login failures, permission errors, DDL and membership changes. Query Store diagnoses workload/plan behavior, not a complete authorization audit. Correlate request IDs without logging secrets or every sensitive parameter. Review `sys.database_permissions`, role memberships and `HAS_PERMS_BY_NAME` as the actual app. A successful connection as `sa` says nothing about runtime least privilege. Enterprise administration remains in [[Windows SQL Server]].

## Labs

### Environment and Complete Files

PowerShell and Docker Linux containers with SQL Server 2022 Developer, adequate memory and supported architecture. Record image digest and `@@VERSION`. Recent `2022-latest` images supply `/opt/mssql-tools18/bin/sqlcmd`; absence is a client-provisioning prerequisite, not a permission failure. **Not executed here.** No published port or mounts; `-C` is restricted to this self-signed disposable fixture.

### File: setup.sql
```sql
CREATE DATABASE PolicyLab;
GO
CREATE LOGIN policyapp WITH PASSWORD='App-lab-only-2022!',CHECK_POLICY=OFF;
GO
USE PolicyLab;
CREATE USER policyapp FOR LOGIN policyapp;
CREATE TABLE dbo.notes(id int PRIMARY KEY,label nvarchar(80) NOT NULL);
INSERT dbo.notes VALUES(1,N'O''Reilly');
GO
CREATE PROCEDURE dbo.FindNote @label nvarchar(80)
AS
BEGIN
 SET NOCOUNT ON;
 SELECT id,label FROM dbo.notes WHERE label=@label;
END;
GO
GRANT EXECUTE ON dbo.FindNote TO policyapp;
GRANT UPDATE ON dbo.notes TO policyapp;
GO
```

### File: test.sql
```sql
SELECT ORIGINAL_LOGIN() AS login_name,USER_NAME() AS user_name;
IF HAS_PERMS_BY_NAME('dbo.notes','OBJECT','UPDATE')=1
 THROW 50000,'Read-only policy violated',1;
IF HAS_PERMS_BY_NAME(NULL,NULL,'ALTER ANY LOGIN')=1
 THROW 50000,'Server privilege present',1;
BEGIN TRY
 UPDATE dbo.notes SET label=N'temporary';
 THROW 50000,'Unexpected update success',1;
END TRY
BEGIN CATCH
 IF ERROR_NUMBER()<>229 THROW;
END CATCH;
DECLARE @actual TABLE(id int,label nvarchar(80));
INSERT @actual EXEC dbo.FindNote @label=N'O''Reilly';
IF (SELECT COUNT(*) FROM @actual)<>1 THROW 50000,'Allowed read failed',1;
IF NOT EXISTS(SELECT 1 FROM @actual WHERE id=1 AND label=N'O''Reilly')
 THROW 50000,'Literal mismatch',1;
SELECT * FROM @actual;
```

### Baseline and Hints

```powershell
docker run --name w3-sql-sec -d -e ACCEPT_EULA=Y -e MSSQL_PID=Developer -e MSSQL_SA_PASSWORD=Admin-lab-only-2022! mcr.microsoft.com/mssql/server:2022-latest
docker exec -e SQLCMDPASSWORD=Admin-lab-only-2022! w3-sql-sec /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -C -b -Q 'SELECT 1'
Get-Content -Raw setup.sql | docker exec -i -e SQLCMDPASSWORD=Admin-lab-only-2022! w3-sql-sec /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -C -b
Get-Content -Raw test.sql | docker exec -i -e SQLCMDPASSWORD=App-lab-only-2022! w3-sql-sec /opt/mssql-tools18/bin/sqlcmd -S localhost -U policyapp -d PolicyLab -C -b
```

Retry readiness manually. Baseline fails at `Read-only policy violated` before changing any data. Objective: retain the procedure API but remove direct mutation. Hint: EXECUTE is independent from UPDATE, and both table/procedure are owned by `dbo`.

### Solution and Fixed Retest

```powershell
docker exec -e SQLCMDPASSWORD=Admin-lab-only-2022! w3-sql-sec /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -d PolicyLab -C -b -Q 'REVOKE UPDATE ON dbo.notes FROM policyapp;'
Get-Content -Raw test.sql | docker exec -i -e SQLCMDPASSWORD=App-lab-only-2022! w3-sql-sec /opt/mssql-tools18/bin/sqlcmd -S localhost -U policyapp -d PolicyLab -C -b
```

Fixed test exits zero: direct UPDATE raises exactly error 229, while the procedure returns `1,O'Reilly`. The test rethrows unrelated errors, so a connection/schema failure cannot masquerade as authorization success. Inspect `$LASTEXITCODE` after each invocation. No server-administration capability is exercised.

### Troubleshooting and Cleanup

Unexpected UPDATE permission can come from role membership as well as a direct grant; REVOKE does not cancel every inherited grant. Incorrect procedure ownership can break the allowed path. Keep bootstrap credentials out of production app settings. Remove only the lab container:

```powershell
docker rm -f -v w3-sql-sec
```

- [ ] Local Web SQL Server exercise: Create a limited database user and parameterized CRUD operation for synthetic notes. Test rollback, a quote-containing value, and denied access to another database.
- [ ] Boundary check: Submit a harmless SQL-looking string as a value and verify literal handling. Confirm the runtime identity cannot alter logins, configuration, or unrelated tables.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W3 Data|W3 Data]]
- [[SQL Injection]]
- [[Windows SQL Server]]
- [[Web SQL Server]]

## References

- [SQL parameterization guidance](https://learn.microsoft.com/en-us/sql/relational-databases/security/sql-injection)
- [Database permissions](https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine)
- [SQL Server Audit](https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine)
