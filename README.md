# Spring Cloud Config Cypher

(Spring Cloud Config)[https://docs.spring.io/spring-cloud-config/docs/current/reference/html/] allows for encryption of secrets. 

The encrypt key is generated from a secret using Pbkdf2 (Salt (default value *DEADBEEF*), 1024 iteration, SHA1) to generate a 256 bit key used in the AES encryption.

The initial 16 byte from the cypher from Spring Cloud config are the IV of the AES encryptrion. The rest of the cipher is the cipher text. 

There appears to be an issue with config server https://github.com/spring-cloud/spring-cloud-config/issues/2208. It appears to always use the default salt, strong, and algorithm settings

Could be useful for https://github.com/SteeltoeOSS/Steeltoe/issues/509
