password-encryptor-pbkdf2
=========================

PBKDF2 based implementation of the [credential-encryptor-api][1].

#Component
The module contains one Declarative Services component. The component can be 
instantiated multiple times via Configuration Admin. The component registers 
two OSGi services: the **CredentialEncryptor** and the **CredentialMatcher** 
interfaces provided by the [credential-encryptor-api][1].

##Configuration
###Algorithm
The following algorithms are supported by the OSGi component for password 
encryption:
 - PBKDF2WithHmacSHA1 (since Java 1.6)
 - PBKDF2WithHmacSHA224 (since Java 1.8)
 - PBKDF2WithHmacSHA256 (since Java 1.8)
 - PBKDF2WithHmacSHA384 (since Java 1.8)
 - PBKDF2WithHmacSHA512 (since Java 1.8)

###Iteration
This value determines how slow the hash function will be. When computers 
become faster next year we can increase the work factor to balance it out.
Also known as work factor or security.

#Performance

The performance tests were run on Java 8, Windows 8.1 64 bit, Intel Core 
i5-3210M @ 2.5GHz, 12GB RAM

Algorithm|Iteration|Encryption time
---|---:|---:
PBKDF2WithHmacSHA1|1000|1.5 ms
PBKDF2WithHmacSHA1|10000|15 ms
PBKDF2WithHmacSHA1|20000|30 ms
PBKDF2WithHmacSHA256|1000|2.1ms
PBKDF2WithHmacSHA256|10000|21 ms
PBKDF2WithHmacSHA256|20000|42 ms
PBKDF2WithHmacSHA512|1000|3.2ms
PBKDF2WithHmacSHA512|10000|32ms
PBKDF2WithHmacSHA512|20000|64ms

##Default configuration
The default and recommended setting for encryption is PBKDF2WithHmacSHA256 with
100 iterations. This will be secure enough (SHA-250) and fast enough (iteration
100) to store and match passwords. The authentication process can be kept under
1 ms with this configuration.

#Reference
[Secure Password Storage – Don’ts, dos and a Java example][2]

[1]: https://github.com/everit-org/credential-encryptor-api
[2]: http://www.javacodegeeks.com/2012/05/secure-password-storage-donts-dos-and.html
