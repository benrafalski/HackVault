---
title: "MySQL"
aliases: []
tags: [web, w3]
domain: web
phase: "W3"
type: tech
status: draft
pair: "[[MySQL Security]]"
updated: 2026-11-03
---
# MySQL

> [!abstract] TL;DR
> Bind values; allowlist identifiers; use explicit transactions and least-privilege grants. Inspect query plans before adding indexes blindly.

> [!info] Agent scope
> SQL schema and queries; users and grants; transactions; prepared statements; network and file privileges.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me MySQL 8.4 application engineering, assuming SQL and HTTP knowledge.
Cover InnoDB schemas, constraints, composite indexes, EXPLAIN, MVCC, repeatable
read versus read committed, locking reads, deadlocks, autocommit and implicit
commits. Trace native prepared statements versus driver-side parameterization.
Explain user@host matching, authentication, TLS, grants, FILE and LOCAL INFILE.
Work through a complete order reservation transaction and rollback, including
concurrent writers and connection-pool reset. Contrast migration and runtime
identities. Supply executable SQL, expected results, failure cases and tests;
do not assume small-table plans generalize. Use public MySQL documentation,
identify version-dependent behavior, and end with worked diagnostic questions.
Teach here, without editing files; do not claim examples were executed.
```

## Cheatsheet

### Schema, Access Paths, and Constraints

InnoDB clusters table data by the primary key; secondary index leaves contain that key. Wide primary keys increase every secondary index. A composite `(tenant_id, created_at, id)` index supports tenant equality plus a time range, not arbitrary searches by `id` alone. Check `EXPLAIN FORMAT=TREE SELECT ...`; `EXPLAIN ANALYZE` executes the query, so use it only when execution is acceptable.

Use `DECIMAL(12,2)` for bounded decimal prices, integer smallest units where suitable, and explicit UTC conversion for timestamps. `TIMESTAMP` is session-time-zone sensitive; `DATETIME` records a calendar value. Collations determine equality and uniqueness, including case/accent handling. Foreign-key columns need compatible definitions. MySQL 8.4 enforces `CHECK`; old pre-8.0.16 behavior is not equivalent.

```sql
CREATE TABLE inventory (
	sku VARCHAR(32) PRIMARY KEY,
	available INT NOT NULL CHECK (available >= 0)
) ENGINE=InnoDB;
INSERT INTO inventory VALUES ('book', 3);
START TRANSACTION;
UPDATE inventory SET available = available - 1
 WHERE sku = 'book' AND available >= 1;
SELECT ROW_COUNT() AS reserved;
COMMIT;
```

This conditional write avoids a read-then-write race. Require `reserved=1` before creating the matching order in the same transaction. An idempotency key with a unique constraint prevents duplicate order creation after ambiguous network failures.

### Transactions and Binding

| Mechanism | Consequence |
|---|---|
| Default InnoDB repeatable read | Consistent reads share a transaction snapshot; locking reads observe current versions. Mixing them needs care. |
| `SELECT ... FOR UPDATE` | Locks encountered rows/index ranges; keep transactions short and acquire locks in consistent order. |
| Deadlock / lock timeout | Retry a bounded, idempotent whole unit of work after explicit rollback; do not blindly retry individual statements. |
| DDL and account management | Many operations implicitly commit; an outer rollback is not a migration undo plan. |
| Autocommit | Each standalone statement commits; pooled connections must not retain an abandoned transaction. |

Native SQL preparation binds data separately from grammar:

```sql
PREPARE lookup FROM 'SELECT sku, available FROM inventory WHERE sku = ?';
SET @sku = 'book';
EXECUTE lookup USING @sku;
DEALLOCATE PREPARE lookup;
```

Driver placeholder spelling and whether preparation is server-side are driver-specific. Never substitute identifiers through value placeholders; map a requested sort key to a fixed SQL fragment. Binding alone does not impose tenant predicates or cap result sizes.

### Accounts and Transport

`'app'@'localhost'` and `'app'@'%'` are different accounts. Inspect `USER()` (client identity) and `CURRENT_USER()` (matched account) when grants appear wrong. Grant runtime DML on named tables; keep DDL, `GRANT OPTION`, `FILE`, account management, and plugin administration with a migration/operator identity. MySQL 8.4 disables `mysql_native_password` by default; use current compatible clients rather than weakening authentication.

For remote clients use `--ssl-mode=VERIFY_IDENTITY --ssl-ca=ca.pem` and a matching certificate hostname. `secure_file_priv` restricts server file import/export locations but is not a substitute for withholding `FILE`. `LOAD DATA LOCAL` involves the client filesystem and a distinct client/server enablement boundary; disable it when unnecessary.

## Gotchas

Escaping depends on encoding and SQL mode; binding is preferable. Transaction guarantees depend on the storage engine and operation.

## Labs

### Environment and Complete Files

Requires Docker with Linux containers and PowerShell, internet/image access, and MySQL `8.4` (real release series, mutable tag). Record the resolved image digest and `SELECT VERSION()` before interpreting results. **Not executed during authoring.** This container has no published port and no host mounts. Passwords below are disposable fixtures, not production credentials.

Create an empty working directory and the following file.

### File: setup.sql
```sql
CREATE DATABASE shop;
CREATE TABLE shop.orders (
	id BIGINT PRIMARY KEY,
	tenant_id INT NOT NULL,
	label VARCHAR(100) NOT NULL,
	amount DECIMAL(12,2) NOT NULL CHECK (amount >= 0),
	INDEX tenant_orders (tenant_id, id)
) ENGINE=InnoDB;
INSERT INTO shop.orders VALUES (1, 7, 'seed', 12.50);
CREATE USER 'app'@'%' IDENTIFIED BY 'App-lab-only-84!';
GRANT SELECT, INSERT, UPDATE ON shop.orders TO 'app'@'%';
```

### File: exercise.sql
```sql
SELECT VERSION(), USER(), CURRENT_USER();
SHOW GRANTS;
START TRANSACTION;
PREPARE add_order FROM
 'INSERT INTO shop.orders (id, tenant_id, label, amount) VALUES (?, ?, ?, ?)';
SET @id=2, @tenant=7, @label='O''Reilly', @amount=4.25;
EXECUTE add_order USING @id, @tenant, @label, @amount;
SELECT label, amount FROM shop.orders WHERE id=2;
ROLLBACK;
SELECT COUNT(*) AS after_rollback FROM shop.orders;
DEALLOCATE PREPARE add_order;
START TRANSACTION;
INSERT INTO shop.orders VALUES (3, 7, 'committed', 1.00);
COMMIT;
SELECT SUM(amount) AS total FROM shop.orders WHERE tenant_id=7;
EXPLAIN FORMAT=TREE SELECT * FROM shop.orders WHERE tenant_id=7 ORDER BY id;
```

Start, wait until the readiness command succeeds (retry manually), initialize as administrator, then exercise as app:

```powershell
docker run --name w3-mysql-tech -d -e MYSQL_ROOT_PASSWORD=Root-lab-only-84! mysql:8.4
docker exec -e MYSQL_PWD=Root-lab-only-84! w3-mysql-tech mysqladmin -uroot ping
Get-Content -Raw setup.sql | docker exec -i -e MYSQL_PWD=Root-lab-only-84! w3-mysql-tech mysql -uroot
Get-Content -Raw exercise.sql | docker exec -i -e MYSQL_PWD=App-lab-only-84! w3-mysql-tech mysql -h127.0.0.1 -uapp shop
docker exec -e MYSQL_PWD=App-lab-only-84! w3-mysql-tech mysql -h127.0.0.1 -uapp -e 'CREATE DATABASE forbidden_lab;'
```

### Objectives and Hints

Explain the query plan, confirm the literal apostrophe round-trip, distinguish committed from rolled-back rows, and prove that the app cannot create a database. Hint: a scan on two rows is not evidence that the index is broken. Account-management statements in setup are deliberately outside the runtime transaction.

### Solution and Expected Results

The bound label is `O'Reilly`, rollback leaves one row, and committed total is `13.50`. The final administrative command must fail with access denied and nonzero exit; inspect `$LASTEXITCODE` immediately. `SHOW GRANTS` must contain table DML but no global administrative grants. Running the exercise twice is intentionally not idempotent: id `3` already exists. Recreate only this container to reset.

### Verification, Troubleshooting, and Cleanup

Compare each printed result, not merely the client's last exit status. Startup refusal means wait for initialization and inspect `docker logs w3-mysql-tech`. Authentication failure can mean wrong account/host, not a missing table grant. No remote TLS claim is made by this in-container lab. Remove only the lab container and its anonymous data volume:

```powershell
docker rm -f -v w3-mysql-tech
```

- [ ] Local MySQL exercise: Create a disposable database and limited app account. Implement a parameterized insert/read and a rollback test; prove the app account cannot create users or access unrelated schemas.
- [ ] Boundary check: Submit an apostrophe-containing marker through a bound query and verify literal storage. Attempt an administrative operation with the app account and require denial.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W3 Data|W3 Data]]
- [[SQL Injection]]
- [[MySQL Security]]

## References

- [MySQL 8.4 security](https://dev.mysql.com/doc/refman/8.4/en/security.html)
- [InnoDB transaction model](https://dev.mysql.com/doc/refman/8.4/en/innodb-transaction-model.html)
- [Prepared statements](https://dev.mysql.com/doc/refman/8.4/en/sql-prepared-statements.html)
