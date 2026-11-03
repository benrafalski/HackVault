---
title: "PostgreSQL"
aliases: []
tags: [web, w3]
domain: web
phase: "W3"
type: tech
status: draft
pair: "[[PostgreSQL Security]]"
updated: 2026-11-03
---
# PostgreSQL

> [!abstract] TL;DR
> Parameterize values; secure search_path; separate migration ownership from runtime access. Test row-level policies using the actual runtime role.

> [!info] Agent scope
> SQL schema and queries; roles; schemas and search_path; transactions; extensions; prepared statements; row-level security.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me PostgreSQL application storage assuming relational SQL and HTTP.
Use PostgreSQL 17-compatible examples. Explain MVCC snapshots, read committed,
repeatable read and serializable retries; constraints, indexes, plans, vacuum,
prepared statements and connection pools. Trace role membership, object ownership,
schema USAGE/CREATE, search_path, extensions and SECURITY DEFINER. Work through
an order schema with rollback, uniqueness and row-level security under a nonowner
login. Show direct and joined reads, USING versus WITH CHECK, owner bypass and
trusted identity selection. Include complete SQL, failure evidence, tradeoffs,
version caveats and primary references. Teach rather than edit files; no invented
execution results or confidential examples. End with worked concurrency questions.
```

## Cheatsheet

### MVCC and Schema Design

Each statement at the default read-committed isolation gets a fresh snapshot. Repeatable read keeps a transaction snapshot but is not fully serializable. Serializable uses dependency tracking and can abort a transaction with SQLSTATE `40001`; retry the entire idempotent unit. Deadlocks (`40P01`) likewise need bounded whole-transaction retries. After an error, a transaction remains aborted until rollback or rollback to a prior savepoint.

```sql
BEGIN;
UPDATE app.stock SET quantity=quantity-1 WHERE sku='book' AND quantity>0
 RETURNING sku, quantity;
COMMIT;
```

This fragment needs a `stock(sku text primary key, quantity integer check(quantity>=0))` table. Zero returned rows means no reservation, not success. Put order insertion in the same transaction. Use `numeric`, not floating point, for exact monetary arithmetic; `timestamptz` represents an instant displayed in the session timezone. Uniqueness, foreign keys and CHECK constraints are concurrency-safe invariants, unlike a preceding application SELECT.

Indexes accelerate selective access at write/storage cost. A B-tree `(tenant, id)` serves tenant-filtered pagination; foreign keys do not automatically index referencing columns. `EXPLAIN (ANALYZE, BUFFERS)` executes its statement; inspect writes inside a disposable transaction, remembering triggers/external effects may not roll back. Dead tuples require vacuum; long snapshots can prevent cleanup.

### Binding and Names

```sql
PREPARE find_order(integer, bigint) AS
 SELECT id, label FROM app.orders WHERE tenant=$1 AND id=$2;
EXECUTE find_order(7, 1);
DEALLOCATE find_order;
```

SQL PREPARE is session-local; driver binding uses its protocol/API and placeholder syntax. Transaction-pooling proxies may require specific prepared-statement support. Generic and parameter-specific plans can differ for skewed tenants. Parameters are values, not table or sort identifiers: choose identifiers from an allowlist and use the driver's identifier-composition API.

### Privilege and Resolution Model

Database CONNECT, schema USAGE, table privileges and sometimes sequence privileges are separate gates. `GENERATED ... AS IDENTITY` is preferable to manually assembling sequence access assumptions. Object owners can alter/drop their objects; runtime roles should not own them. `ALTER DEFAULT PRIVILEGES` affects future objects created by the specified owner, not existing objects or every creator.

```sql
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER ROLE runtime SET search_path = pg_catalog, app;
GRANT USAGE ON SCHEMA app TO runtime;
GRANT SELECT, INSERT ON app.orders TO runtime;
```

Use explicit schema qualification in sensitive code. A trusted `search_path` must not contain schemas writable by untrusted roles. Privileged functions should use a fixed path with `pg_temp` last, schema-qualified objects, narrow EXECUTE grants, and reviewed ownership. Extensions install database code and may need elevated privileges; some are trusted, but that is not a blanket authorization to let the app install them.

RLS restricts rows after ordinary privileges permit the operation. `USING` filters existing rows; `WITH CHECK` validates new row values. With RLS enabled and no applicable policy, access is default-deny. Owners normally bypass RLS; `FORCE ROW LEVEL SECURITY` subjects owners, but superusers and BYPASSRLS roles still bypass. A custom tenant setting is not a secure boundary against a client that can set it arbitrarily.

## Gotchas

Table owners and BYPASSRLS roles can bypass ordinary row-level policy behavior; testing only as an administrator gives misleading results.

## Labs

### Environment and Complete Files

Requires PowerShell, Docker Linux containers and the official `postgres:17` image. Record the resolved digest and server version; the major tag moves. **Not executed here.** No port or host mount is needed. The bootstrap superuser is not the application account.

### File: setup.sql
```sql
CREATE ROLE runtime LOGIN PASSWORD 'App-lab-only-17!';
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA app;
CREATE TABLE app.orders (
 id bigint PRIMARY KEY,
 tenant integer NOT NULL,
 label text NOT NULL,
 amount numeric(12,2) NOT NULL CHECK(amount>=0),
 UNIQUE(tenant,label)
);
INSERT INTO app.orders VALUES (1,7,'seed',12.50),(2,8,'other',99);
CREATE INDEX ON app.orders(tenant,id);
GRANT USAGE ON SCHEMA app TO runtime;
GRANT SELECT, INSERT ON app.orders TO runtime;
ALTER ROLE runtime SET search_path=pg_catalog,app;
ALTER TABLE app.orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant7 ON app.orders TO runtime
 USING (tenant=7) WITH CHECK (tenant=7);
```

### File: test.sql
```sql
SELECT version(), current_user;
BEGIN;
PREPARE add_order(bigint,text) AS
 INSERT INTO app.orders VALUES ($1,7,$2,4.25);
EXECUTE add_order(3,'O''Reilly');
SELECT id,label FROM app.orders ORDER BY id;
ROLLBACK;
DEALLOCATE add_order;
DO $$ BEGIN
 IF (SELECT count(*) FROM app.orders) <> 1 THEN
  RAISE EXCEPTION 'rollback or row policy failed';
 END IF;
 BEGIN
  INSERT INTO app.orders VALUES(4,7,'seed',1);
  RAISE EXCEPTION 'uniqueness missing';
 EXCEPTION WHEN unique_violation THEN NULL;
 END;
END $$;
EXPLAIN (ANALYZE,BUFFERS) SELECT * FROM app.orders WHERE tenant=7;
SELECT has_schema_privilege(current_user,'public','CREATE') AS can_shadow;
```

```powershell
docker run --name w3-pg-tech -d -e POSTGRES_PASSWORD=Admin-lab-only-17! -e POSTGRES_DB=lab postgres:17
docker exec w3-pg-tech pg_isready -U postgres -d lab
Get-Content -Raw setup.sql | docker exec -i w3-pg-tech psql -U postgres -d lab -v ON_ERROR_STOP=1
Get-Content -Raw test.sql | docker exec -i -e PGPASSWORD=App-lab-only-17! w3-pg-tech psql -h127.0.0.1 -U runtime -d lab -v ON_ERROR_STOP=1
```

Retry readiness manually until ready. Objectives: trace snapshot/rollback behavior, explain why uniqueness still works with RLS, and show that the app cannot create a shadow object in `public`. Hint: SQL PREPARE persists for the session even when the transaction that prepared it rolls back.

### Solution and Expected Results

The in-transaction read shows ids `1,3`, including literal `O'Reilly`, but never tenant 8. The assertion after rollback sees one row. The duplicate raises `unique_violation`, caught by the nested block's subtransaction. `can_shadow` is false. A small sequential scan is reasonable. A passing run exits zero; `ON_ERROR_STOP` makes an uncaught SQL failure nonzero.

### Troubleshooting and Cleanup

Running setup twice produces existing-object errors: reset this container, not the host PostgreSQL service. If tenant 8 appears, confirm `current_user` is `runtime`, not `postgres`; admin results cannot validate RLS. Socket admin authentication here is container bootstrap convenience, not a production recommendation. Remove only the lab volume/container:

```powershell
docker rm -f -v w3-pg-tech
```

- [ ] Local PostgreSQL exercise: Build a small transactional table under a nonowner app role. Test rollback, uniqueness, and tenant filtering; inspect a query plan and verify unrelated-schema denial.
- [ ] Boundary check: With two synthetic tenants, query both direct and joined paths under the app role and verify isolation. Confirm that an untrusted schema cannot shadow an object used by privileged code.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W3 Data|W3 Data]]
- [[SQL Injection]]
- [[PostgreSQL Security]]

## References

- [Row security](https://www.postgresql.org/docs/17/ddl-rowsecurity.html)
- [Transaction isolation](https://www.postgresql.org/docs/17/transaction-iso.html)
- [Schemas and search paths](https://www.postgresql.org/docs/17/ddl-schemas.html)
