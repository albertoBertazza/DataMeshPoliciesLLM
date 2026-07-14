to check if Keycloack is able to send all the user

```bash
docker exec -it keycloak-microservice python -c "
from keycloak import KeycloakAdmin

admin = KeycloakAdmin(
    server_url='http://keycloak:8080',
    username='admin',
    password='admin',
    realm_name='trino',
    user_realm_name='master',
    client_id='admin-cli',
)

for u in admin.get_users({}):
    print(u['username'])
"
```

rebuild the keyclock-microservice:
```bash
docker compose build keycloak-microservice
docker compose up -d --force-recreate keycloak-microservice
```

