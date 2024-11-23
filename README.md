
TLC

1. Generate private key for the domain certificate:

```
openssl ecparam -out webapp.key -name secp384r1 -genkey
```

2. Generate a CSR based on this private key

```
openssl req -new -sha384 -key webapp.key -out webapp.csr -config openssl.cnf

openssl req -new -sha384 -key webapp.key -out webapp.csr -config openssl_old.cnf
```

- `group-3.comp3334.xavier2dc.fr` should appear as both **Common Name** and **Subject Alternative Name**
- `wengyu.zhang@connect.polyu.hk`

3. Generate a certificate for this domain by making the CA sign the CSR:

```
openssl x509 -req -in webapp.csr -CA cacert.crt -CAkey cakey.pem -CAcreateserial -out webapp.crt -days 90 -sha384 -extfile openssl.cnf -extensions v3_ca

XXXXX
openssl x509 -req -in webapp.csr -CA cacert.crt -CAkey cakey.key -CAcreateserial -out webapp.crt -days 90 -sha384 -extfile your_config_file.conf -extensions v3_ca

```


---

Docker CMD:

1. docker-compose down 
2. docker-compose build  --no-cache
3. docker-compose up -d 

4. docker-compose restart


MySQL Connection:

```
docker exec -it chat-db-1 bash

mysql -h db -u chatuser -p
[enter: chatpassword]
use chatdb
```

---

Usernames and Passwords:

```
Wayne: WaynePassword3334 kurEyFlykWQoYzTNAgZ

tianyi1: tianyi1Password gC0oD0nhng6SwUScqbo
tianyi2: tianyi2Password kyTHmhDCypOcWlKJDpF

Mike: MikePassword, 68lcrvuFdiDHZvBG7Qz
David: David@password gCgr0efRnby6Dla9LKA

Alice: AlicePassword3334, gosc5v30WwGZ4WIec6R
Bob: BobPassword3334, k9uHijebrqE7Ngs61dY

Jerry, Coe7EpNakH96ETDXdAO
```
