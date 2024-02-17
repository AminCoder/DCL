# DCL
  DCL  :: One-way encryption with Key and Alpha 

[Try Online DCL](https://amincoder.ir/dcl)

DCL(Data Capping Layer) cryptography is a one-way hash algorithm which is 96 characters long.

The difference between this algorithm and other one-way encryption algorithms like SHA and MD5 is in defining KEY and ALPHA. In this case, you will be protected from usual kinds of attacks like Collision Attack, BruteForce and etc.

The DCL algorithm is designed such that it is necessary to have KEY and ALPHA at the same time for developing online dictionaries and maps. Therefore because of this, mentioned attacks which are very expensive will be unsuccessful in decrypting mentioned cryptographies. Other attraction of DCL is that because you are involved in the process of securing your contacts’ data, even simple passwords and data like “12345” are unpredictable.

Similarities are other features of DCL. For example, a hash in your system or an online dictionary with a KEY and ALPHA is the same as the hash generated in another system. Having said that, the plain texts are not equal. Therefore, hacker thinks that he has the plain text or password but he would be disappointed with seeing a login error.

The purpose of DCL is to disappoint hackers and safeguard your private data.

## How to use 

**PHP**
```php
$key = "mykey12345";
$alpha = 6;
$plaintext = "userdata12345";
$dclInstance = new DCL($key, $alpha);
$result = $dclInstance->generate($plaintext);
echo $result . PHP_EOL;
```
**Python**
```python
key = "mykey12345"
alpha = 6
plaintext = input("> ")
dcl_instance = DCL(key, alpha)
result = dcl_instance.generate(plaintext)
print(result)
```
**Visual Basic .Net**
```c#
Console.Write("> ")
Dim dcl As New dcl("mykey12345", 6)
Console.Write(dcl.generate(Console.ReadLine()))
```
**Javascript**
```c#
const  dclInstance  =  new  DCL("mykey12345", 6);
const  ciphertext  =  dclInstance.generate("mypassword");
console.log(ciphertext);
```


DCL will be released soon. Other languages’ libraries will be developed and it is all open source.
