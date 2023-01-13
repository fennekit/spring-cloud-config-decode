# Spring Cloud Config Cypher

(Spring Cloud Config)[https://docs.spring.io/spring-cloud-config/docs/current/reference/html/] allows for encryption of secrets. 

The encrypt key is generated from a secret using Pbkdf2 (Salt (default value *DEADBEEF*), 1024 iteration, SHA1) to generate a 256 bit key.

The initial 16 byte from the cypher from Spring Cloud config are the IV of the AES encryptrion. The rest of the cipher is the cipher text
