# mosquitto test server



## Create dh parameters

```
docker run --rm -it -v .:/local alpine/openssl:latest dhparam -out /local/config/dhparam.pem 4096
```



## Create a new CA

### Create CA key

```powershell
docker run --rm -it -v .:/local alpine/openssl:latest req -new -newkey rsa:4096 -keyout /local/config/ca.key -out /local/config/ca.csr -nodes -subj "/C=CH/L=Buttisholz/O=easy-smart solution GmbH/CN=MQTT TEST CA"
```

### Sign the CA certificate (for 100 years !!!)

```powershell
docker run --rm -it -v .:/local alpine/openssl:latest x509 -req -in /local/config/ca.csr -signkey /local/config/ca.key -out /local/config/ca.crt -days 36500 -sha256
```

### Create a header file for the CA

```powershell
docker run --rm -it -v .:/local -w /local python:latest /bin/sh -c "pip3 install pyopenssl click && python3 pycert.py convert -o ca.crt.h config/ca.crt"
```



## Create a server certificate

### Create server key

```powershell
docker run --rm -it -v .:/local alpine/openssl:latest req -new -newkey rsa:4096 -keyout /local/config/server.key -out /local/config/server.csr -nodes -subj "/C=CH/L=Buttisholz/O=easy-smart solution GmbH/CN=MQTT TEST Broker"
```

### Sign the server certificate (for 100 years !!!)

```powershell
docker run --rm -it -v .:/local alpine/openssl:latest x509 -req -in /local/config/server.csr -CA /local/config/ca.crt -CAkey /local/config/ca.key -CAcreateserial -out /local/config/server.crt -days 36500 -sha256
```



## Create mosquitto password file

```powershell
docker run --rm -it -v .:/local eclipse-mosquitto:openssl mosquitto_passwd -c /local/config/password_file.txt testuser
```



## Build mosquitto image

```powershell
docker build -t mosquitto_test .
```





## Run mosquitto

```powershell
docker run -it --rm --publish 1883:1883 --publish 8883:8883 --publish 9001:9001 --name mosquitto_test mosquitto_test
```



