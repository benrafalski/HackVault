---
title: "PostgreSQL Security"
aliases: []
tags: [web, w3, security]
domain: web
phase: "W3"
type: security
status: draft
pair: "[[PostgreSQL]]"
updated: 2026-11-03
---
# PostgreSQL Security

> [!abstract] TL;DR
> Unsafe SQL, writable schemas in trusted resolution paths, and misconfigured privileged functions or RLS can expose other tenants' data.

> [!info] Agent scope
> Security of: SQL schema and queries; roles; schemas and search_path; transactions; extensions; prepared statements; row-level security. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Unsafe SQL, writable schemas in trusted resolution paths, and misconfigured privileged functions or RLS can expose other tenants' data.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me PostgreSQL 17 defensive application security: binding, role inheritance,
ownership, schema resolution, RLS, extension installation and privileged functions.
Assume SQL/MVCC knowledge. Explain USING and WITH CHECK, permissive policy ORs,
owner/BYPASSRLS exemptions, referential-integrity side channels and pool context
reset. Compare database-authenticated tenant roles with mutable session settings.
Provide a local two-tenant policy fixture with direct/join reads, denied writes,
safe search_path and least-privilege app logins, separate from bootstrap admin.
Use harmless records, no exploitation or privilege escalation. Include resource
limits, logging, primary sources, version caveats and worked review questions.
Teach here without edits or claims of execution.
```

## Cheatsheet

### Independent Boundaries

Binding preserves SQL grammar; it neither chooses a tenant nor prevents excessive reads. Use explicit columns, fixed identifiers, bounded pagination and a trusted identity. `WHERE tenant=$1` only helps when `$1` is bound from authenticated context. Prefer native constraints to application-only checks for consistency.

RLS is enforced for ordinary roles after table privileges. A policy `USING (tenant=current_user)` can tie rows to a database-authenticated role. It is not appropriate if that role can assume another tenant role. A shared role with `current_setting('app.tenant')` needs a trusted gateway that exclusively controls SQL and transaction-local settings; any client allowed arbitrary SQL can set that custom value itself.

| Policy detail | Review consequence |
|---|---|
| No policy on an RLS-enabled table | Default deny; distinguish a broken app from healthy isolation. |
| Permissive policies | Combined with OR; an additional broad policy can reopen rows. Restrictive policies combine with AND but need a permissive policy to admit rows. |
| `USING` / `WITH CHECK` | Existing-row visibility / allowed inserted or updated state. Test both. |
| Owner / superuser / BYPASSRLS | Owner generally bypasses unless forced; superuser/BYPASSRLS remain exempt. |
| Referential integrity | Constraint checks may reveal conflicts involving hidden rows; do not promise absence of existence side channels. |
| Views/functions | Definer ownership can change effective access. PostgreSQL 15+ security-invoker views are an explicit option, not every view's default. |

### Name Resolution and Privileged Code

```sql
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER ROLE app7 SET search_path=pg_catalog,app;
ALTER ROLE app7 SET statement_timeout='2s';
ALTER ROLE app7 SET lock_timeout='500ms';
ALTER ROLE app7 SET idle_in_transaction_session_timeout='10s';
```

Role-level timeout settings are operational defaults, not immutable quotas against arbitrary SQL. Enforce request deadlines/concurrency too. Qualify objects and trust every schema in the path. Review `SECURITY DEFINER` functions with a fixed `search_path=pg_catalog,app,pg_temp`; revoke default PUBLIC EXECUTE and grant only intended callers. Never give the app schema CREATE or ownership of objects a privileged function resolves. Fresh database defaults changed in PostgreSQL 15; upgraded databases may retain older `public` grants.

Extensions execute code with installation-dependent privileges. Inventory `pg_extension`, restrict CREATE on databases and schemas, and review extension upgrades as code deployments. Use SCRAM and verified TLS for remote connections; local container authentication below does not exercise transport security.

## Detection and Defense

Audit role membership, `rolsuper`/`rolbypassrls`, schema ownership, `pg_policies`, extension changes and function security settings. RLS-denied SELECTs can return zero rows without an error, so test exact row sets rather than counting permission failures. Avoid logging sensitive bind values. Monitor long transactions and aborted connections; denial spikes can also indicate a bad deployment or stale pool state.

## Labs

### Environment and Complete Files

PowerShell, Docker Linux containers and `postgres:17`; no published ports or mounts. Record actual image digest/version. **Not executed during authoring.** This fixture maps distinct authenticated logins to tenants; it does not rely on an attacker-writable session setting.

### File: setup.sql
```sql
CREATE ROLE app7 LOGIN PASSWORD 'Tenant7-lab-only!';
CREATE ROLE app8 LOGIN PASSWORD 'Tenant8-lab-only!';
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA app;
CREATE TABLE app.documents(id integer PRIMARY KEY, tenant text NOT NULL, label text NOT NULL);
CREATE TABLE app.notes(id integer PRIMARY KEY, document_id integer REFERENCES app.documents(id), tenant text NOT NULL);
INSERT INTO app.documents VALUES(1,'app7','O''Reilly'),(2,'app8','synthetic');
INSERT INTO app.notes VALUES(10,1,'app7'),(20,2,'app8');
GRANT USAGE ON SCHEMA app TO app7,app8;
GRANT SELECT,INSERT,UPDATE ON app.documents TO app7,app8;
GRANT SELECT ON app.notes TO app7,app8;
ALTER TABLE app.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.notes ENABLE ROW LEVEL SECURITY;
ALTER ROLE app7 SET search_path=pg_catalog,app;
ALTER ROLE app8 SET search_path=pg_catalog,app;
```

### File: test.sql
```sql
SELECT current_user, version();
DO $$ BEGIN
 IF (SELECT count(*) FROM app.documents) <> 1 THEN
  RAISE EXCEPTION 'expected one visible document';
 END IF;
 IF EXISTS(SELECT 1 FROM app.documents WHERE tenant<>current_user) THEN
  RAISE EXCEPTION 'wrong tenant visible';
 END IF;
 IF (SELECT count(*) FROM app.documents AS documents JOIN app.notes AS notes
	  ON notes.document_id=documents.id) <> 1 THEN
  RAISE EXCEPTION 'join policy failed';
 END IF;
 BEGIN
  INSERT INTO app.documents VALUES(99,'unassigned','rejected fixture');
  RAISE EXCEPTION 'write policy missing';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 IF has_schema_privilege(current_user,'public','CREATE') OR
	 has_schema_privilege(current_user,'app','CREATE') THEN
  RAISE EXCEPTION 'untrusted writable schema';
 END IF;
END $$;
BEGIN;
PREPARE add_doc(integer,text) AS
 INSERT INTO app.documents VALUES($1,current_user,$2);
EXECUTE add_doc(50,'O''Reilly');
SELECT count(*) AS own_rows_in_transaction FROM app.documents;
ROLLBACK;
```

### File: fix.sql
```sql
CREATE POLICY tenant_documents ON app.documents TO app7,app8
 USING(tenant=current_user) WITH CHECK(tenant=current_user);
CREATE POLICY tenant_notes ON app.notes FOR SELECT TO app7,app8
 USING(tenant=current_user);
```

### Baseline, Hints, and Solution

```powershell
docker run --name w3-pg-sec -d -e POSTGRES_PASSWORD=Admin-lab-only-17! -e POSTGRES_DB=lab postgres:17
docker exec w3-pg-sec pg_isready -U postgres -d lab
Get-Content -Raw setup.sql | docker exec -i w3-pg-sec psql -U postgres -d lab -v ON_ERROR_STOP=1
Get-Content -Raw test.sql | docker exec -i -e PGPASSWORD=Tenant7-lab-only! w3-pg-sec psql -h127.0.0.1 -U app7 -d lab -v ON_ERROR_STOP=1
```

Retry readiness manually. Baseline must fail `expected one visible document`: RLS is enabled but no policy allows even intended reads. Objective: restore permitted behavior without opening cross-tenant reads/writes. Hint: ordinary grants alone do not satisfy RLS.

Apply the solution as administrator, then run the identical test as both actual app identities:

```powershell
Get-Content -Raw fix.sql | docker exec -i w3-pg-sec psql -U postgres -d lab -v ON_ERROR_STOP=1
Get-Content -Raw test.sql | docker exec -i -e PGPASSWORD=Tenant7-lab-only! w3-pg-sec psql -h127.0.0.1 -U app7 -d lab -v ON_ERROR_STOP=1
Get-Content -Raw test.sql | docker exec -i -e PGPASSWORD=Tenant8-lab-only! w3-pg-sec psql -h127.0.0.1 -U app8 -d lab -v ON_ERROR_STOP=1
```

Both fixed runs must exit zero; each has one direct/join row and two own rows inside its rolled-back insert transaction. The synthetic unassigned insert is denied and caught. This catches overrestrictive as well as overbroad policies. A superuser run is invalid evidence; it deliberately sees both fixtures.

### Troubleshooting and Cleanup

A connection failure is not a policy pass. Confirm `current_user`, table owner and applied policies when counts differ. The app must have neither membership in the other tenant role nor schema CREATE. Lab joins test both tables independently, not only the parent. Reset by removing only this disposable container:

```powershell
docker rm -f -v w3-pg-sec
```

- [ ] Local PostgreSQL exercise: Build a small transactional table under a nonowner app role. Test rollback, uniqueness, and tenant filtering; inspect a query plan and verify unrelated-schema denial.
- [ ] Boundary check: With two synthetic tenants, query both direct and joined paths under the app role and verify isolation. Confirm that an untrusted schema cannot shadow an object used by privileged code.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W3 Data|W3 Data]]
- [[SQL Injection]]
- [[PostgreSQL]]

## References

- [RLS policies and limitations](https://www.postgresql.org/docs/17/ddl-rowsecurity.html)
- [Safe SECURITY DEFINER functions](https://www.postgresql.org/docs/17/sql-createfunction.html)
- [Schema trust](https://www.postgresql.org/docs/17/ddl-schemas.html)
