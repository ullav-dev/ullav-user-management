# Public API Exposure Plan — ullav-user-management

**Date:** 2026-06-11  
**Scope:** Hardening, rate limiting, TLS, CORS, and observability before exposing the auth service publicly on Civo Kubernetes.

---

## 1. CORS for a Public API — How It Actually Works

### The key distinction: Bearer tokens vs. cookies

This service uses **JWT Bearer tokens**, not browser cookies. That changes the CORS calculus significantly.

`credentials: include` in browser `fetch()` refers to **cookies and TLS client certificates**, not the `Authorization` header. So when a third-party app calls:

```javascript
fetch("https://auth.ullav.com/auth/login", {
  method: "POST",
  headers: {
    "Authorization": "Bearer <token>",
    "Content-Type": "application/json"
  },
  body: JSON.stringify({ username, password })
})
```

The browser sends a CORS preflight (OPTIONS), your server responds with `Access-Control-Allow-Origin: *`, and the request proceeds. **No `credentials: include` needed. No special handling on the 3rd-party side.**

### What `CORS_ORIGINS=*` means for security

With a JWT Bearer API, `*` does **not** mean "anyone can authenticate as your users." It means "any website can prompt their users to authenticate against your API and receive a JWT." The JWT is the credential — it must be explicitly included in every request by the app that holds it. The browser's same-origin policy does not protect it once a user hands a token to a third-party app.

**Practical implication:** Setting `CORS_ORIGINS=*` is correct and safe for a public JWT API. The security model is: *control who can hold tokens via strong auth*, not *control which origins can make requests*.

### What to set

| Deployment | `CORS_ORIGINS` value | Reason |
|---|---|---|
| Public API (intended) | `*` | Any origin can use the API |
| First-party only | `https://ullav.com,https://dam.ullav.com,...` | Restrict to your own apps |
| Mixed (first-party + public 3rd party) | `*` | Still `*` — explicit origins only help with cookies, not Bearer auth |

### What 3rd-party developers need to do

1. **Register** a user account via `POST /users`
2. **Authenticate** via `POST /auth/login` → receive JWT
3. **Include** `Authorization: Bearer <token>` on every protected request
4. **Refresh** via `POST /auth/refresh` before expiry (24h TTL)
5. No CORS configuration required on their end — the browser handles it

### Current code issue

When `CORS_ORIGINS` is empty, your `main.rs` constructs `Cors::default()` with no configuration, which adds no CORS response headers at all. Browsers will block all cross-origin requests. For a public API you **must** set `CORS_ORIGINS=*` in your Helm values.

The existing `allow_any_origin()` path in `main.rs` (triggered by `CORS_ORIGINS=*`) correctly omits `supports_credentials()` — this is right because `*` and `supports_credentials()` are mutually exclusive in the CORS spec.

---

## 2. Rate Limiting

### Strategy

NGINX Ingress Controller (Civo default) handles rate limiting via annotations. The limit applies per source IP per ingress object. Since limits are per-ingress, **use two Ingress objects**:

- **`ingress-auth`** — covers `/auth/*` and `POST /users` (strict: brute-force and spam targets)
- **`ingress-api`** — covers everything else (relaxed: general usage)

### Limits to apply

| Route group | RPS per IP | Burst | Rationale |
|---|---|---|---|
| `/auth/login`, `/auth/password-reset/*`, `/users` (POST) | 3 | 5 | Brute-force and spam prevention |
| `/auth/refresh`, `/auth/confirm-email` | 10 | 20 | Automated but legitimate |
| All other routes | 30 | 60 | Normal API usage |

---

## 3. TLS via cert-manager

### Prerequisites on Civo cluster

```bash
# Install cert-manager (if not already present)
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.5/cert-manager.yaml

# Verify
kubectl get pods -n cert-manager
```

### ClusterIssuer (apply once, cluster-wide)

Create `cluster-issuer.yaml`:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: colin@botharbeag.com
    privateKeySecretRef:
      name: letsencrypt-prod-key
    solvers:
      - http01:
          ingress:
            class: nginx
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    email: colin@botharbeag.com
    privateKeySecretRef:
      name: letsencrypt-staging-key
    solvers:
      - http01:
          ingress:
            class: nginx
```

**Always test with `letsencrypt-staging` first** — Let's Encrypt production has a rate limit of 5 duplicate certificates per week.

---

## 4. Helm Chart Changes

### 4a. `values.yaml` — add rate limiting and CORS defaults

Changes needed:
- `ingress.enabled: true` with split auth/api ingress support
- `CORS_ORIGINS: "*"` for public API
- `REQUIRE_HTTPS: "true"` (already supported by the app)

### 4b. New `ingress-auth.yaml` template (strict limits)

Covers: `POST /users`, `/auth/*`

```yaml
{{- if .Values.ingress.enabled }}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "ullav-user-management.fullname" . }}-auth
  annotations:
    nginx.ingress.kubernetes.io/use-regex: "true"
    nginx.ingress.kubernetes.io/limit-rps: "3"
    nginx.ingress.kubernetes.io/limit-burst-multiplier: "2"
    nginx.ingress.kubernetes.io/limit-connections: "5"
    cert-manager.io/cluster-issuer: {{ .Values.ingress.clusterIssuer | quote }}
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - {{ .Values.ingress.host | quote }}
      secretName: {{ include "ullav-user-management.fullname" . }}-tls
  rules:
    - host: {{ .Values.ingress.host | quote }}
      http:
        paths:
          - path: /auth(/|$)(.*)
            pathType: ImplementationSpecific
            backend:
              service:
                name: {{ include "ullav-user-management.fullname" . }}
                port:
                  name: http
          - path: /users$
            pathType: ImplementationSpecific
            backend:
              service:
                name: {{ include "ullav-user-management.fullname" . }}
                port:
                  name: http
{{- end }}
```

### 4c. Updated `ingress.yaml` (general API, relaxed limits)

Covers everything else:

```yaml
{{- if .Values.ingress.enabled }}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "ullav-user-management.fullname" . }}
  annotations:
    nginx.ingress.kubernetes.io/limit-rps: "30"
    nginx.ingress.kubernetes.io/limit-burst-multiplier: "2"
    nginx.ingress.kubernetes.io/limit-connections: "20"
    cert-manager.io/cluster-issuer: {{ .Values.ingress.clusterIssuer | quote }}
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - {{ .Values.ingress.host | quote }}
      secretName: {{ include "ullav-user-management.fullname" . }}-tls
  rules:
    - host: {{ .Values.ingress.host | quote }}
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: {{ include "ullav-user-management.fullname" . }}
                port:
                  name: http
{{- end }}
```

**Note on path precedence:** NGINX Ingress matches the most specific path first across all Ingress objects with the same host. The regex paths in `ingress-auth` (e.g. `/auth(/|$)(.*)`) will win over the catch-all `/` in the general ingress for auth routes.

### 4d. `values.yaml` additions

```yaml
ingress:
  enabled: true
  className: "nginx"
  clusterIssuer: "letsencrypt-prod"   # or letsencrypt-staging for first test
  host: "auth.ullav.com"              # set in your values override
  tls: []                             # managed by cert-manager, not manually

env:
  CORS_ORIGINS: "*"           # public API — allow any origin
  REQUIRE_HTTPS: "true"       # enforce via X-Forwarded-Proto
```

---

## 5. Admin Route Hardening

`/admin/*` routes are **not part of the public API** and must not be reachable from the public internet. They will be served by a dedicated `ingress-admin.yaml` with an IP allowlist — if your IP is not on the list, you get a 403 before the request reaches the app.

The allowlist is set via:
```yaml
nginx.ingress.kubernetes.io/whitelist-source-range: "YOUR_OFFICE_IP/32,YOUR_VPN_CIDR"
```

This goes in `ingress.adminAllowlist` in `values.yaml`. You must supply your actual office/VPN CIDR(s) in your prod values override file — the chart will not deploy the admin ingress if this value is empty.

---

## 6. Observability Checklist

Before going public, ensure you can detect abuse:

- [ ] **Structured logs** reaching a queryable store (Loki/Grafana on Civo, or ship to Papertrail/Datadog)
- [ ] Alert on: `POST /auth/login` returning 401 > 20/min from a single IP (brute force)
- [ ] Alert on: `POST /users` returning 400 > 10/min (registration spam)
- [ ] Alert on: overall 5xx rate > 1% of requests (service health)
- [ ] NGINX rate limit hits visible: NGINX logs `429` responses — make sure these are collected

---

## 7. End-to-End Implementation Order

### Phase 1 — TLS (prerequisite for everything)
1. Apply `cluster-issuer.yaml` with staging issuer
2. Update Helm values: `ingress.enabled: true`, `ingress.host`, `ingress.clusterIssuer: letsencrypt-staging`
3. `helm upgrade` and verify cert is issued: `kubectl get certificate`
4. Test HTTPS works, then switch to `letsencrypt-prod`

### Phase 2 — Rate Limiting
5. Add `ingress-auth.yaml` template to the Helm chart
6. Update `ingress.yaml` with general rate limit annotations
7. `helm upgrade` and verify: `curl -X POST https://auth.ullav.com/auth/login` rapidly → expect 429 after burst

### Phase 3 — CORS and Env Cleanup
8. Set `CORS_ORIGINS: "*"` in prod values (or your values override file)
9. Set `REQUIRE_HTTPS: "true"` in prod values
10. Confirm `ENABLE_DOCS: "false"` in prod values (already the default)

### Phase 4 — Admin Protection
11. Add `ingress-admin.yaml` with IP allowlist covering your office/VPN IP range
12. Test admin routes unreachable from an external IP

### Phase 5 — Observability
13. Configure log shipping from the cluster
14. Set up 429 / 401 spike alerts

---

## 8. Open Questions Before Shipping

- **What hostname?** e.g. `auth.ullav.com` — needs DNS A record pointing to Civo load balancer IP
- **Admin IP allowlist:** What CIDR(s) should be permitted to reach `/admin`?
- **GeoBlock:** Do you want to enable this? Which countries to block (or whitelist-only)?
- **Docs endpoint:** Leave disabled in prod, or expose it for 3rd-party developer discovery?
