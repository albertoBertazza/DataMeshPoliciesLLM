# Public key
```bash
keytool -genkeypair -alias trino -keyalg RSA -keysize 2048 -keystore keystore.jks -storepass dataMeshProject -keypass dataMeshProject -dname "CN=trino"
```
# if you change storepass
remember also to modify in etc/config.propierties:
```text
http-server.https.keystore.key=dataMeshProject
```