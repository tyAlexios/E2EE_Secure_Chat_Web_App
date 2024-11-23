## Authentication

### Open

1. Deploy the docker container using the following line within the folder that contains the docker-compose.yaml file: $\S$ sudo docker-compose up -d
2. Open a new private window of your browser
3. Open chat app in browser: https://group-3.comp3334.xavier2dc.fr:8443
4. open again for another user
5. Register a new account

### Register
1. Alice, Password: AlicePassword3334, Recovery key, recaptcha, totp
2. Bob, Password: BobPassword3334, Recovery key, recaptcha, totp
3. error register shown
   1. username already exists  i.e. Alice
   2. empty username  i.e. ""
   3. password not match i.e. AlicePassword3334, AlicePassword3335
   4. password too short i.e. passwd
   5. password too weak i.e. 1234567890
   6. SQL injection attacks (;, #) i.e. Al;ic#e
   7. get recovery key before enter username    
   8. Not get recovery key 
   9. recovery key not match 
   10. not check recaptcha
   11. get totp before enter username
   12. Not get totp
   13. totp not match

### Login
1. Alice, Password: AlicePassword3334, Recovery key, recaptcha, totp
2. Bob, Password: BobPassword3334, Recovery key, recaptcha, totp
3. error login shown
   1. username not exists
   2. empty username
   3. empty password
   4. password not match
   5. get recovery key before enter username
   6. Not get recovery key
   7. recovery key not match
   8. not check recaptcha
   9.  get totp before enter username
   10. Not get totp
   11. totp not match
