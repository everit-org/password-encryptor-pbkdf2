password-encryptor-pbkdf2
=========================

PBKDF2 based implementation of the [credential-encryptor-api][1].

#Suported Algoritm
 - PBKDF2WithHmacSHA1 (since Java 1.6)
 - PBKDF2WithHmacSHA224 (since Java 1.8)
 - PBKDF2WithHmacSHA256 (since Java 1.8)
 - PBKDF2WithHmacSHA384 (since Java 1.8)
 - PBKDF2WithHmacSHA512 (since Java 1.8)

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


#Reference
[Secure Password Storage – Don’ts, dos and a Java example][2]

[![Analytics](https://ga-beacon.appspot.com/UA-15041869-4/everit-org/password-encryptor-pbkdf2)](https://github.com/igrigorik/ga-beacon)


[1]: https://github.com/everit-org/credential-encryptor-api
[2]: http://www.javacodegeeks.com/2012/05/secure-password-storage-donts-dos-and.html
