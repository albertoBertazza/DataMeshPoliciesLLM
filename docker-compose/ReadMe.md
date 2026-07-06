# OAuth
```bash
bash scripts/trino_session.sh --user trino --password trino123
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