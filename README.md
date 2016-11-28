# java-php-mcrypt
====

## Description

This project is how to do encryption and decryption using /AES/CBC/PCKS#5 algorithm in Java or PHP.
You can encrypt using Java and decrypt using PHP, or encrypt using PHP and decrypt using Java.

## Demo

PHP sample

$secretKey = "secretP@ssw0rd"
$crypt = new Crypt($secretKey);
$data = "abcdefgh12345678";
$encryptedData = $crypt->encrypt($data);
$rawData = $crypt->decrypt($encryptedData);

Java sample

String secreteKey = "secretP@ssw0rd";
String data = "abcdefgh12345678";
Crypt crypt = new Crypt();
String encryptedData = crypt.encrypt(data);
String rawData = crypt.decrypt(encryptedData);


## Requirement
OpenJDK 8 above
php5.4 above 

## Licence
[MIT License](https://github.com/fangjinmin/java-php-mcrypt/blob/master/LICENSE) © fangjinmin

