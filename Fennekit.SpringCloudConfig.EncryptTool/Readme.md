# Introduction

Spring Cloud Config is a configuration server capable of serving encrypted secrets
that are decrypted by a client library. 

[Steeltoe.Config](https://github.com/SteeltoeOSS/Documentation/blob/v4/api/v4/configuration/encryption-resolver.md) (v4.0) is such a client library capable of decrypting these.

This tool fills the gap where the secrets can be created in the .NET ecosystem.

## Installation

To install the tool globally:
```bash
 dotnet tool install --global Fennekit.SpringCloudConfig.EncryptTool
```

To uninstall:
```bash
 dotnet tool uninstall -g  Fennekit.SpringCloudConfig.EncryptTool 
```

## Usage
To use the encryption tool:

```bash
spring-encrypt encrypt aes [key] [plaintext]
```


