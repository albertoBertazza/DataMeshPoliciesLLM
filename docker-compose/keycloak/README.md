# Trino: pure OAuth2, no LDAP

# if you change storepass
remember also to modify in etc/config.propierties:
```text
http-server.https.keystore.key=dataMeshProject
```

## Setup steps

1. Run `./scripts/gen-trino-keystore.sh` → writes `etc/keystore.jks`.
2. Apply `docker-compose.additions.yml`: delete the three LDAP services,
   add `keycloak`, update `trino-coordinator`.
3. Replace your `etc/config.properties` with the one in this bundle (or
   diff it in — the OAuth2 block at the bottom is the only new part).
4. Keep `keycloak/import/trino-realm.json` at that relative path.
5. **Local DNS**: the issuer (`http://keycloak:8080/realms/trino`) must
   resolve both from inside Docker (already true via Compose DNS) and from
   your browser (since it redirects there for login). Add to your host's
   `/etc/hosts`:
   ```
   127.0.0.1 keycloak
   ```
6. `docker compose up -d`
7. Check `http://keycloak:8081` (admin/admin) → **Users** should show
   `alice` and `trino`, **Groups** should show `hr_managers`/`admin`.
8. Open `https://localhost:8443` — you should be redirected to Keycloak's
   login page. Log in as `alice` / `alice123`.
9. CLI:
   ```
   trino --server https://localhost:8443 --external-authentication --insecure
   
    docker exec -it trino-coordinator trino --server https://localhost:8443 --external-authentication --insecure
   ```
   (`--insecure` only because the keystore is self-signed for dev.)

## Notes for production

- Rotate `trino-client-secret` (in both the realm JSON and
  `config.properties`) and manage it as a secret, not inline config.
- Replace the self-signed `keystore.jks` with a cert from a real CA.
- Local Keycloak users are fine for a handful of accounts; if you later
  need to manage many users, Keycloak can federate to any directory again
  (LDAP, Active Directory, etc.) without touching the Trino side at all —
  Trino only ever talks OAuth2 to Keycloak either way.
- If you want group-based row/column authorization, feed the `groups`
  claim from the token into OPA policies rather than relying solely on
  Trino's built-in authorization.
