# OAuth
```bash
bash scripts/trino_session.sh --user trino --password trino123
```
```bash
bash scripts/trino_session.sh --user alice --password alice123
```

# Public key
```bash
cd docker-compose
keytool -genkeypair -alias trino -keyalg RSA -keysize 2048 -validity 3650 -keystore etc/keystore.jks -storepass dataMeshProject -keypass dataMeshProject  -dname "CN=localhost, OU=Dev, O=Example, L=City, ST=State, C=US"
```
# if you change storepass
remember also to modify in etc/config.propierties:
```text
http-server.https.keystore.key=dataMeshProject
```

# Launch the service and create group 
```bash
bash launcher.sh
```

# Group mapping 
https://trino.io/docs/current/security/group-mapping.html#configuration
it is impossible to pass directly group with oauth, ONLY LDAP can do it.
While i need to create a file group.txt to give info about group to trino.