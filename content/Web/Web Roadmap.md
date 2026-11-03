---
title: "Web Roadmap"
aliases: []
tags: [web, roadmap]
domain: web
phase: ""
type: moc
status: draft
pair: ""
updated: 2026-11-02
---
# Web Roadmap

[[index|Home]] | [[Web Labs]] | [[Tools Index]]

Work in phase order. Check each note only after meeting its learning and lab goals; complete both sides of every pair. Status progression: stub -> draft -> learning -> practiced -> mastered.

## W0 Foundations

### Phase Goal

Trace a browser request from name resolution through transport, HTTP, and browser policy; operate a reproducible local web lab.

### Notes

- [ ] [[TCP and IP]]
- [ ] [[TCP and IP Security]]
- [ ] [[DNS]]
- [ ] [[DNS Security]]
- [ ] [[TLS and PKI]]
- [ ] [[TLS and PKI Security]]
- [ ] [[HTTP]]
- [ ] [[HTTP Security]]
- [ ] [[HTTP2 and HTTP3]]
- [ ] [[HTTP2 and HTTP3 Security]]
- [ ] [[URLs and Encoding]]
- [ ] [[URLs and Encoding Security]]
- [ ] [[Browser Security Model]]
- [ ] [[Browser Security Model Security]]
- [ ] [[Linux CLI]]
- [ ] [[Linux CLI Security]]
- [ ] [[Git]]
- [ ] [[Git Security]]
- [ ] [[Web Lab Setup]]

### Labs

- [ ] [PortSwigger: HTTP basics](https://portswigger.net/web-security/essential-skills/http-protocol)
- [ ] [HTB Academy](https://academy.hackthebox.com/): web requests and Linux fundamentals
- [ ] [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/): isolated local setup

### Exit Criteria

- [ ] Explain and capture one complete HTTPS request, compare HTTP versions, demonstrate a browser policy boundary, and rebuild the local lab from notes.

## W1 Frontend

### Phase Goal

Build and inspect browser applications, their dependency graph, and client-side trust boundaries.

### Notes

- [ ] [[HTML]]
- [ ] [[HTML Security]]
- [ ] [[CSS]]
- [ ] [[CSS Security]]
- [ ] [[JavaScript]]
- [ ] [[JavaScript Security]]
- [ ] [[TypeScript]]
- [ ] [[TypeScript Security]]
- [ ] [[DOM and Browser APIs]]
- [ ] [[DOM and Browser APIs Security]]
- [ ] [[React]]
- [ ] [[React Security]]
- [ ] [[Angular]]
- [ ] [[Angular Security]]
- [ ] [[Vue]]
- [ ] [[Vue Security]]
- [ ] [[Bundlers]]
- [ ] [[Bundlers Security]]
- [ ] [[npm Ecosystem]]
- [ ] [[npm Ecosystem Security]]
- [ ] [[WebSockets]]
- [ ] [[WebSockets Security]]
- [ ] [[postMessage]]
- [ ] [[postMessage Security]]
- [ ] [[Service Workers]]
- [ ] [[Service Workers Security]]
- [ ] [[WebAssembly]]
- [ ] [[WebAssembly Security]]

### Labs

- [ ] [MDN Learn](https://developer.mozilla.org/en-US/docs/Learn_web_development): frontend exercises
- [ ] [PortSwigger Academy](https://portswigger.net/web-security): DOM-based and WebSocket labs
- [ ] [Juice Shop](https://owasp.org/www-project-juice-shop/): client-side challenges

### Exit Criteria

- [ ] Build a small typed frontend, inspect its production bundle, and demonstrate DOM, messaging, worker, and WebSocket boundaries in a local lab.

## W2 Backend

### Phase Goal

Build, trace, and secure request handling across common runtimes, frameworks, API styles, and web servers.

### Notes

- [ ] [[Nodejs and Express]]
- [ ] [[Nodejs and Express Security]]
- [ ] [[Nextjs]]
- [ ] [[Nextjs Security]]
- [ ] [[Python]]
- [ ] [[Python Security]]
- [ ] [[Flask]]
- [ ] [[Flask Security]]
- [ ] [[Django]]
- [ ] [[Django Security]]
- [ ] [[FastAPI]]
- [ ] [[FastAPI Security]]
- [ ] [[PHP and Laravel]]
- [ ] [[PHP and Laravel Security]]
- [ ] [[Java and Spring]]
- [ ] [[Java and Spring Security]]
- [ ] [[ASP Net Core]]
- [ ] [[ASP Net Core Security]]
- [ ] [[Go]]
- [ ] [[Go Security]]
- [ ] [[Template Engines]]
- [ ] [[Template Engines Security]]
- [ ] [[Serialization]]
- [ ] [[Serialization Security]]
- [ ] [[REST APIs]]
- [ ] [[REST APIs Security]]
- [ ] [[GraphQL]]
- [ ] [[GraphQL Security]]
- [ ] [[gRPC]]
- [ ] [[gRPC Security]]
- [ ] [[Nginx]]
- [ ] [[Nginx Security]]
- [ ] [[Apache]]
- [ ] [[Apache Security]]
- [ ] [[IIS]]
- [ ] [[IIS Security]]

### Labs

- [ ] [OWASP crAPI](https://owasp.org/www-project-crapi/): local API lab
- [ ] [PortSwigger Academy](https://portswigger.net/web-security): API, GraphQL, and server-side labs
- [ ] [DVWA](https://github.com/digininja/DVWA): isolated PHP lab

### Exit Criteria

- [ ] Complete each pair's build and security exercises; trace routing, validation, serialization, authorization, and errors in a representative API behind a web server.

## W3 Data

### Phase Goal

Understand storage and messaging semantics, query boundaries, access controls, and failure modes.

### Notes

- [ ] [[MySQL]]
- [ ] [[MySQL Security]]
- [ ] [[PostgreSQL]]
- [ ] [[PostgreSQL Security]]
- [ ] [[Web SQL Server]]
- [ ] [[Web SQL Server Security]]
- [ ] [[SQLite]]
- [ ] [[SQLite Security]]
- [ ] [[ORMs]]
- [ ] [[ORMs Security]]
- [ ] [[MongoDB]]
- [ ] [[MongoDB Security]]
- [ ] [[Redis]]
- [ ] [[Redis Security]]
- [ ] [[Elasticsearch]]
- [ ] [[Elasticsearch Security]]
- [ ] [[Object Storage]]
- [ ] [[Object Storage Security]]
- [ ] [[Message Queues]]
- [ ] [[Message Queues Security]]

### Labs

- [ ] [PortSwigger Academy](https://portswigger.net/web-security): SQL and NoSQL injection labs
- [ ] [crAPI](https://owasp.org/www-project-crapi/): data/API exercises
- [ ] Local disposable databases, storage emulators, and message brokers

### Exit Criteria

- [ ] Complete each storage pair's exercises, demonstrate parameterized queries and least-privilege access, and explain transaction, consistency, and queue delivery tradeoffs.

## W4 Identity

### Phase Goal

Trace authentication and authorization protocols, credentials, sessions, and token trust decisions.

### Notes

- [ ] [[Sessions and Cookies]]
- [ ] [[Sessions and Cookies Security]]
- [ ] [[Password Storage]]
- [ ] [[Password Storage Security]]
- [ ] [[JWT]]
- [ ] [[JWT Security]]
- [ ] [[OAuth2]]
- [ ] [[OAuth2 Security]]
- [ ] [[OpenID Connect]]
- [ ] [[OpenID Connect Security]]
- [ ] [[SAML]]
- [ ] [[SAML Security]]
- [ ] [[MFA and WebAuthn]]
- [ ] [[MFA and WebAuthn Security]]

### Labs

- [ ] [PortSwigger Academy](https://portswigger.net/web-security): authentication, OAuth, and JWT labs
- [ ] Local test identity provider and relying-party applications

### Exit Criteria

- [ ] Diagram each identity flow, validate issuer/audience/state/nonce where applicable, and complete representative session, JWT, OAuth, and MFA labs.

## W5 Infra and Cloud

### Phase Goal

Deploy isolated applications with explicit infrastructure, identity, network, cache, and supply-chain boundaries.

### Notes

- [ ] [[Docker]]
- [ ] [[Docker Security]]
- [ ] [[Kubernetes]]
- [ ] [[Kubernetes Security]]
- [ ] [[CI and CD]]
- [ ] [[CI and CD Security]]
- [ ] [[Reverse Proxies CDN and WAF]]
- [ ] [[Reverse Proxies CDN and WAF Security]]
- [ ] [[HTTP Caching]]
- [ ] [[HTTP Caching Security]]
- [ ] [[AWS]]
- [ ] [[AWS Security]]
- [ ] [[Azure]]
- [ ] [[Azure Security]]
- [ ] [[Serverless]]
- [ ] [[Serverless Security]]
- [ ] [[Terraform]]
- [ ] [[Terraform Security]]

### Labs

- [ ] [Kubernetes tutorials](https://kubernetes.io/docs/tutorials/): disposable cluster
- [ ] [PortSwigger Academy](https://portswigger.net/web-security): cache labs
- [ ] [AWS Workshops](https://workshops.aws/) and [Microsoft Learn](https://learn.microsoft.com/training/): dedicated sandbox subscriptions with budgets

### Exit Criteria

- [ ] Build a reproducible deployment, verify secrets and least-privilege policy, explain proxy/cache behavior, and complete each infrastructure pair's local or sandbox exercise.

## W6 Attacks

### Phase Goal

Recognize cross-technology vulnerability classes and validate root causes, impact, and fixes in authorized labs.

### Notes

- [ ] [[XSS]]
- [ ] [[CSRF]]
- [ ] [[Clickjacking]]
- [ ] [[CORS Misconfiguration]]
- [ ] [[SQL Injection]]
- [ ] [[NoSQL Injection]]
- [ ] [[Command Injection]]
- [ ] [[Path Traversal]]
- [ ] [[File Upload Attacks]]
- [ ] [[SSRF]]
- [ ] [[XXE]]
- [ ] [[SSTI]]
- [ ] [[Insecure Deserialization]]
- [ ] [[Prototype Pollution]]
- [ ] [[Broken Access Control and IDOR]]
- [ ] [[Business Logic Attacks]]
- [ ] [[Race Conditions]]
- [ ] [[Request Smuggling]]
- [ ] [[Cache Poisoning and Deception]]
- [ ] [[Host Header Attacks]]
- [ ] [[OAuth Attacks]]
- [ ] [[JWT Attacks]]
- [ ] [[GraphQL Attacks]]
- [ ] [[WebSocket Attacks]]
- [ ] [[Supply Chain Attacks]]
- [ ] [[LLM and Prompt Injection]]

### Labs

- [ ] [PortSwigger Web Security Academy](https://portswigger.net/web-security): primary platform
- [ ] [HTB Academy](https://academy.hackthebox.com/) and authorized HTB machines
- [ ] [pwn.college](https://pwn.college/): CSE365 fundamentals where available
- [ ] [Juice Shop](https://owasp.org/www-project-juice-shop/), [DVWA](https://github.com/digininja/DVWA), and [crAPI](https://owasp.org/www-project-crapi/)

### Exit Criteria

- [ ] Complete all available PortSwigger Apprentice labs relevant to this phase, plus at least one suitable local or Academy lab for every remaining technique; explain each root cause and remediation.

## W7 Methodology

### Phase Goal

Run a scoped, repeatable web assessment and communicate evidence, impact, and remediation clearly.

### Notes

- [ ] [[Recon and Subdomain Enumeration]]
- [ ] [[Content Discovery]]
- [ ] [[Burp Workflow]]
- [ ] [[Source Code Review]]
- [ ] [[Bug Bounty Methodology]]
- [ ] [[Reporting]]

### Labs

- [ ] [PortSwigger Academy](https://portswigger.net/web-security): mystery labs when unlocked
- [ ] An authorized HTB web target or local vulnerable application
- [ ] A source review of a small local application

### Exit Criteria

- [ ] Deliver one authorized end-to-end assessment writeup with scope, reproducible findings, evidence, remediation, and retest results.
