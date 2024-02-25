# AES encryption
 
The encrypt key is generated from a secret ('the key') using Pbkdf2 (Salt (default value *DEADBEEF*), 1024 iteration, SHA1) 
to generate a 256 bit key used in the AES encryption.

The encrypted key together with a 16 byte random initialization
vector (IV) is used to encrypt the plaintext. The IV is 
concatenated with the ciphertext and returned as a HEX string.

# RSA encryption
 
The plain text is encrypted as in the case of AES encryption 
(be it with some additional config options (salt, strong)). It uses a random 16 byte secret.
The secret used to AES encrypt is then encrypted with a public key using RSA. 
The RSA encrypted secret is then concatenated with the result from AES encryption (IV concatenated with ciphertext) and 
returned as a BASE64 encoded string.
