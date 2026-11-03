---
title: "SQL Server for Web Applications"
aliases: []
tags: [web, w3]
domain: web
phase: "W3"
type: tech
status: draft
pair: "[[Web SQL Server Security]]"
updated: 2026-11-03
---
# SQL Server for Web Applications

> [!abstract] TL;DR
> Prefer parameters over concatenation; separate migration and runtime identities; enforce TLS validation. See Windows SQL Server for enterprise service and linked-server concerns.

> [!info] Agent scope
> T-SQL; application connectivity; logins and database users; parameterization; transactions; least privilege; link enterprise administration to Windows SQL Server.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me SQL Server 2022 for web applications assuming SQL and HTTP knowledge.
Explain T-SQL schemas, indexes, plans, logins versus users, roles, typed driver
parameters, sp_executesql and ownership chaining. Trace transactions, XACT_ABORT,
TRY/CATCH, locking versus row-versioned read committed, deadlocks and pool reset.
Build a limited-login application with Unicode CRUD, rollback, uniqueness and
cross-database denial tests. Explain TLS validation, driver-version defaults,
parameter length/type inference and migration identity separation. Keep enterprise
administration out of scope. Use public Microsoft sources, complete code and
worked failure cases. Teach here without file edits or fabricated execution.
```

## Cheatsheet

### Query Shape and Types

T-SQL uses `TOP (@limit)` or `ORDER BY ... OFFSET ... FETCH` for bounded results; stable pagination needs a unique tie-breaker. `nvarchar` stores Unicode; prefix SQL literals with `N`. Use `decimal(p,s)` for exact numeric quantities and `datetime2`/`datetimeoffset` deliberately. A `rowversion` is an automatically changing binary concurrency token, not wall-clock time.

```sql
DECLARE @label nvarchar(80)=N'O''Reilly';
EXEC sys.sp_executesql
 N'SELECT id FROM dbo.notes WHERE label=@value',
 N'@value nvarchar(80)', @value=@label;
```

The table is supplied in the lab. Declare types and sizes that match the columns. In .NET, use `command.Parameters.Add("@value", SqlDbType.NVarChar, 80).Value = label`; avoid relying on `AddWithValue` inference. Implicit conversions can defeat seeks, and varying parameter metadata can fragment plan reuse. A cached plan may suit one cardinality poorly; inspect actual plans and Query Store before adding hints or recompilation. Parameterization fixes syntax/data separation, not all plan instability.

### Transactions and Connections

```sql
SET XACT_ABORT ON;
BEGIN TRY
 BEGIN TRAN;
 UPDATE dbo.notes SET label=N'edited' WHERE id=1;
 IF @@ROWCOUNT<>1 THROW 50001,'Expected one row',1;
 COMMIT;
END TRY
BEGIN CATCH
 IF XACT_STATE()<>0 ROLLBACK;
 THROW;
END CATCH;
```

`XACT_STATE()=-1` means uncommittable; rollback is required. `XACT_ABORT` does not replace error handling for every error category. The usual on-premises read-committed default uses locks; `READ_COMMITTED_SNAPSHOT` changes read behavior at database level, while snapshot isolation has a separate enablement. `NOLOCK` permits inconsistent results and is not a general latency fix. Retry deadlock victims as whole idempotent transactions, with bounded backoff.

Pool lifetime is not request lifetime. Dispose/close connections, finish transactions explicitly and avoid assuming arbitrary session state is safely reset by every provider. Use request cancellation and command timeouts, not just connection timeouts. Optimistic updates should include the expected `rowversion` in the WHERE clause and check affected rows.

### Authentication and Authorization

A server login authenticates; a database user maps its SID into a database; roles and grants govern objects. Restores/migrations can produce SID mismatches. Contained users and managed-identity deployments use different connection arrangements. The app should not be `sa`, `sysadmin`, `db_owner` or `db_ddladmin`. Grant table DML or specific procedure EXECUTE; use a distinct migration identity.

Production connection intent: `Encrypt=True;TrustServerCertificate=False` with a trusted certificate whose name matches the server. Microsoft.Data.SqlClient and ODBC encryption defaults vary by major version; declare policy explicitly. The local lab's `sqlcmd -C` accepts its disposable self-signed certificate and is not production guidance. Enterprise service accounts, linked servers and administration belong in [[Windows SQL Server]].

## Gotchas

A stored procedure is not automatically injection-safe. Parameter placeholders cannot stand in for arbitrary table names or sort expressions.

## Labs

### Environment and Complete Files

Requires PowerShell, Docker Linux containers on a SQL Server-supported architecture with sufficient memory, and Microsoft's SQL Server 2022 Developer container (nonproduction licensing). The `2022-latest` tag is mutable; record `@@VERSION` and image digest. Recent images include `/opt/mssql-tools18/bin/sqlcmd`; if absent, provision a documented Microsoft sqlcmd client before proceeding. **Unexecuted environment requirement.** No port or host mount is used.

### File: setup.sql
```sql
CREATE DATABASE WebLab;
GO
CREATE LOGIN webapp WITH PASSWORD='App-lab-only-2022!', CHECK_POLICY=OFF;
GO
USE WebLab;
CREATE USER webapp FOR LOGIN webapp;
CREATE TABLE dbo.notes (
 id int NOT NULL PRIMARY KEY,
 label nvarchar(80) NOT NULL,
 version rowversion NOT NULL
);
INSERT dbo.notes(id,label) VALUES(1,N'seed');
GRANT SELECT,INSERT,UPDATE,DELETE ON dbo.notes TO webapp;
GO
```

### File: test.sql
```sql
SET XACT_ABORT ON;
SELECT @@VERSION AS version, ORIGINAL_LOGIN() AS login_name, USER_NAME() AS user_name;
BEGIN TRAN;
EXEC sys.sp_executesql
 N'INSERT dbo.notes(id,label) VALUES(@id,@label)',
 N'@id int,@label nvarchar(80)', @id=2,@label=N'O''Reilly';
IF NOT EXISTS(SELECT 1 FROM dbo.notes WHERE id=2 AND label=N'O''Reilly')
 THROW 50000,'Literal round trip failed',1;
UPDATE dbo.notes SET label=N'revised' WHERE id=2;
DELETE dbo.notes WHERE id=2;
ROLLBACK;
IF (SELECT COUNT(*) FROM dbo.notes)<>1 THROW 50000,'Rollback failed',1;
IF HAS_PERMS_BY_NAME(NULL,NULL,'ALTER ANY LOGIN')=1
 THROW 50000,'Excessive server privilege',1;
SELECT id,label FROM dbo.notes;
```

```powershell
docker run --name w3-sql-tech -d -e ACCEPT_EULA=Y -e MSSQL_PID=Developer -e MSSQL_SA_PASSWORD=Admin-lab-only-2022! mcr.microsoft.com/mssql/server:2022-latest
docker exec -e SQLCMDPASSWORD=Admin-lab-only-2022! w3-sql-tech /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -C -b -Q 'SELECT 1'
Get-Content -Raw setup.sql | docker exec -i -e SQLCMDPASSWORD=Admin-lab-only-2022! w3-sql-tech /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -C -b
Get-Content -Raw test.sql | docker exec -i -e SQLCMDPASSWORD=App-lab-only-2022! w3-sql-tech /opt/mssql-tools18/bin/sqlcmd -S localhost -U webapp -d WebLab -C -b
docker exec -e SQLCMDPASSWORD=App-lab-only-2022! w3-sql-tech /opt/mssql-tools18/bin/sqlcmd -S localhost -U webapp -d model -C -b -Q 'SELECT 1'
```

### Objectives, Hints, and Solution

Retry the readiness query manually. Show CRUD under typed parameters and rollback, distinguish login from user, and require denial opening `model` as the app. Hint: a database user in WebLab does not automatically grant CONNECT to every other database. Expected: test exits zero and returns only `1,seed`; the separate `model` connection fails with nonzero exit. If model is accessible, inspect customized guest/CONNECT grants: that is not a passing least-privilege result.

### Verification, Troubleshooting, and Cleanup

Inspect `$LASTEXITCODE` after each command; `-b` turns SQL errors into failing exits. Login failure before reaching the fixture is not a successful policy test. Inspect container logs for startup/memory/password errors. Cleanup affects only this disposable database container:

```powershell
docker rm -f -v w3-sql-tech
```

- [ ] Local Web SQL Server exercise: Create a limited database user and parameterized CRUD operation for synthetic notes. Test rollback, a quote-containing value, and denied access to another database.
- [ ] Boundary check: Submit a harmless SQL-looking string as a value and verify literal handling. Confirm the runtime identity cannot alter logins, configuration, or unrelated tables.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W3 Data|W3 Data]]
- [[SQL Injection]]
- [[Windows SQL Server]]
- [[Web SQL Server Security]]

## References

- [sp_executesql](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-executesql-transact-sql)
- [SET XACT_ABORT](https://learn.microsoft.com/en-us/sql/t-sql/statements/set-xact-abort-transact-sql)
- [SQL Server containers](https://learn.microsoft.com/en-us/sql/linux/quickstart-install-connect-docker)
