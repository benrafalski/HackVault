---
title: "MySQL Security"
aliases: []
tags: [web, w3, security]
domain: web
phase: "W3"
type: security
status: draft
pair: "[[MySQL]]"
updated: 2026-11-03
---
# MySQL Security

> [!abstract] TL;DR
> String-built SQL and excessive database privileges can turn a query defect into broad data or host access.

> [!info] Agent scope
> Security of: SQL schema and queries; users and grants; transactions; prepared statements; network and file privileges. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- String-built SQL and excessive database privileges can turn a query defect into broad data or host access.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive MySQL 8.4 security assuming SQL, transactions and web APIs.
Trace client identity, TLS, user@host account selection, grants, SQL parsing,
prepared parameters and InnoDB execution. Contrast value binding with identifier
allowlists and tenant authorization. Explain FILE, LOCAL INFILE, backup access,
DDL implicit commits, connection budgets and statement timeout limitations.
Build a synthetic local policy-regression lab with separate admin/app identities,
a deliberately excessive table grant, a harmless rolled-back baseline, a grant
fix, and identical negative/positive tests. No injection payloads, data theft or
host-access exercises. Include monitoring, false positives, version caveats and
primary sources. Teach here; do not edit files or invent execution evidence.
```

## Cheatsheet

### Query and Authorization Boundaries

An authenticated connection authorizes SQL execution, not an HTTP user's ownership of a row. A runtime account shared by tenants can read every row its grants permit unless SQL predicates or a separate architecture enforce isolation. MySQL has no PostgreSQL-style native row-level policies. Use scoped repository methods, constrained views where appropriate, or separate schemas/accounts, and test alternate query paths.

Unsafe construction is `sql = "... WHERE label='" + label + "'"`; replacing quotes manually depends on character set and SQL mode. Pass the value through the connector binding API. Native SQL equivalent:

```sql
PREPARE scoped FROM 'SELECT id FROM appdb.items WHERE tenant_id=? AND label=? LIMIT 20';
SET @tenant=7, @label='O''Reilly';
EXECUTE scoped USING @tenant, @label;
DEALLOCATE PREPARE scoped;
```

Tenant `7` must come from authenticated server-side context, not a writable request field. Map sort identifiers to fixed fragments, enforce an integer maximum page size, and remember `%`/`_` still have pattern semantics in a bound `LIKE` value.

### Capability Matrix

| Control | What it prevents / what remains |
|---|---|
| Table-specific DML grants | Limits operations; does not add row authorization. |
| Separate migration account | Removes runtime DDL; migration credentials must not be in the app environment. |
| No `FILE`, no account administration | Reduces server capabilities; SQL binding remains necessary. |
| `local_infile=OFF` and client local-file disablement | Closes unused client-file import path; server `FILE` is a different permission. |
| TLS verification and `REQUIRE SSL` remotely | Encrypts transport and verifies identity when the client checks CA/name; `REQUIRE SSL` alone does not verify the server to the client. |
| `MAX_USER_CONNECTIONS` | Caps account concurrency; not query cost, data volume, or total HTTP concurrency. |
| `MAX_EXECUTION_TIME` | Bounds eligible read-only SELECTs in milliseconds; not a universal write/lock timeout. |

```sql
ALTER USER 'app'@'%' WITH MAX_USER_CONNECTIONS 3;
SET SESSION max_execution_time=1000;
SELECT /*+ MAX_EXECUTION_TIME(500) */ id FROM appdb.items LIMIT 20;
SHOW VARIABLES LIKE 'local_infile';
SHOW VARIABLES LIKE 'secure_file_priv';
```

Password storage uses MySQL authentication plugins, not plaintext tables visible to the app. In 8.4, use a modern connector supporting the default authentication; do not enable obsolete plugins just to accommodate an old client. Backups and replicas need equivalent access control because database grants do not protect copied files.

## Detection and Defense

Track failed logins, account/grant changes, connection saturation, lock waits and normalized statement digests. Performance Schema provides workload evidence, not a complete security audit trail. General logs may expose sensitive parameters and add overhead; audit-plugin availability differs by distribution/edition. Alert on unexpected DDL by runtime identities, but distinguish migrations and health probes. Redact credentials and parameter data in application logs.

## Labs

### Environment and Complete Files

Requires PowerShell, Docker Linux containers and `mysql:8.4`; record the actual digest/version. **Unexecuted authoring fixture.** No port is published or host filesystem mounted. The administrator bootstraps permissions; tests authenticate independently as app. All passwords and records are synthetic.

### File: setup.sql
```sql
CREATE DATABASE appdb;
CREATE TABLE appdb.items (
 id INT PRIMARY KEY, tenant_id INT NOT NULL, label VARCHAR(100) NOT NULL
) ENGINE=InnoDB;
INSERT INTO appdb.items VALUES (1,7,'O''Reilly'),(2,8,'other fixture');
CREATE USER 'app'@'%' IDENTIFIED BY 'App-lab-only-84!'
 WITH MAX_USER_CONNECTIONS 3;
GRANT SELECT, UPDATE ON appdb.items TO 'app'@'%';
```

### File: policy.sql
```sql
START TRANSACTION;
UPDATE appdb.items SET label='temporary' WHERE id=1;
ROLLBACK;
```

### File: allowed.sql
```sql
SELECT CURRENT_USER(), VERSION();
SHOW GRANTS;
PREPARE scoped FROM 'SELECT id FROM appdb.items WHERE tenant_id=? AND label=? LIMIT 20';
SET @tenant=7, @label='O''Reilly';
EXECUTE scoped USING @tenant, @label;
DEALLOCATE PREPARE scoped;
SELECT COUNT(*) AS unchanged FROM appdb.items WHERE id=1 AND label='O''Reilly';
```

### Baseline and Objectives

The intended application is read-only. Prove the initial UPDATE grant violates that policy without retaining a modification. Then remove only UPDATE and preserve allowed bound reads.

```powershell
docker run --name w3-mysql-sec -d -e MYSQL_ROOT_PASSWORD=Root-lab-only-84! mysql:8.4 --local-infile=OFF
docker exec -e MYSQL_PWD=Root-lab-only-84! w3-mysql-sec mysqladmin -uroot ping
Get-Content -Raw setup.sql | docker exec -i -e MYSQL_PWD=Root-lab-only-84! w3-mysql-sec mysql -uroot
Get-Content -Raw policy.sql | docker exec -i -e MYSQL_PWD=App-lab-only-84! w3-mysql-sec mysql -h127.0.0.1 -uapp
$LASTEXITCODE
Get-Content -Raw allowed.sql | docker exec -i -e MYSQL_PWD=App-lab-only-84! w3-mysql-sec mysql -h127.0.0.1 -uapp
```

Retry the readiness command manually until initialization finishes. Baseline `policy.sql` exits zero even though policy says read-only; rollback leaves the label unchanged. Hint: SQL parsing controls and database grants are independent defenses.

### Solution and Fixed Retest

```powershell
docker exec -e MYSQL_PWD=Root-lab-only-84! w3-mysql-sec mysql -uroot -e "REVOKE UPDATE ON appdb.items FROM 'app'@'%';"
Get-Content -Raw policy.sql | docker exec -i -e MYSQL_PWD=App-lab-only-84! w3-mysql-sec mysql -h127.0.0.1 -uapp
$LASTEXITCODE
Get-Content -Raw allowed.sql | docker exec -i -e MYSQL_PWD=App-lab-only-84! w3-mysql-sec mysql -h127.0.0.1 -uapp
docker exec -e MYSQL_PWD=App-lab-only-84! w3-mysql-sec mysql -h127.0.0.1 -uapp -e 'CREATE DATABASE forbidden_lab;'
```

Require UPDATE denial/nonzero exit, bound read returning only id `1`, `unchanged=1`, and CREATE DATABASE denial. An app still able to update indicates the wrong matched account or another grant; inspect `CURRENT_USER()` and `SHOW GRANTS`. The new connection prevents ambiguity about privilege cache timing. This fixture does not establish row isolation against arbitrary SQL: app SELECT covers both tenants, so the scoped query must remain mandatory.

### Troubleshooting and Cleanup

If the baseline fails, verify initialization and grants before declaring the control effective. A connection error is not an authorization denial. Do not mount host files or test file import/export. Record expected vs actual output and remove only this fixture:

```powershell
docker rm -f -v w3-mysql-sec
```

- [ ] Local MySQL exercise: Create a disposable database and limited app account. Implement a parameterized insert/read and a rollback test; prove the app account cannot create users or access unrelated schemas.
- [ ] Boundary check: Submit an apostrophe-containing marker through a bound query and verify literal storage. Attempt an administrative operation with the app account and require denial.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W3 Data|W3 Data]]
- [[SQL Injection]]
- [[MySQL]]

## References

- [MySQL security](https://dev.mysql.com/doc/refman/8.4/en/security.html)
- [Privileges](https://dev.mysql.com/doc/refman/8.4/en/privileges-provided.html)
- [LOCAL data loading considerations](https://dev.mysql.com/doc/refman/8.4/en/load-data-local-security.html)
