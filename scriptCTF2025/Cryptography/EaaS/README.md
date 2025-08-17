![image](./eaas.png)

This is the best and thoughest crypto chall from the compition.

They provide us with the source code of the server :

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import random
email=''
flag=open('flag.txt').read()
has_flag=False
sent=False
key = os.urandom(32)
iv = os.urandom(16)
encrypt = AES.new(key, AES.MODE_CBC,iv)
decrypt = AES.new(key, AES.MODE_CBC,iv)

def send_email(recipient):
    global has_flag
    if recipient.count(b',')>0:
        recipients=recipient.split(b',')
    else:
        recipients=recipient
    for i in recipients:
        if i == email.encode():
            has_flag = True

for i in range(10):
    email += random.choice('abcdefghijklmnopqrstuvwxyz')
email+='@notscript.sorcerer'

print(f"Welcome to Email as a Service!\nYour Email is: {email}\n")
password=bytes.fromhex(input("Enter secure password (in hex): "))

assert not len(password) % 16
assert b"@script.sorcerer" not in password
assert email.encode() not in password

encrypted_pass = encrypt.encrypt(password)
print("Please use this key for future login: " + encrypted_pass.hex())

while True:
    choice = int(input("Enter your choice: "))
    print(f"[1] Check for new messages\n[2] Get flag")

    if choice == 1:
        if has_flag:
            print(f"New email!\nFrom: scriptsorcerers@script.sorcerer\nBody: {flag}")
        else:
            print("No new emails!")

    elif choice == 2:
        if sent:
            exit(0)
        sent=True
        user_email_encrypted = bytes.fromhex(input("Enter encrypted email (in hex): ").strip())
        if len(user_email_encrypted) % 16 != 0:
            print("Email length needs to be a multiple of 16!")
            exit(0)
        user_email = decrypt.decrypt(user_email_encrypted)
        if user_email[-16:] != b"@script.sorcerer":
            print("You are not part of ScriptSorcerers!")
            exit(0)

        send_email(user_email)
        print("Email sent!")


```
It seems too large, but don't worry I will try to explain what it does step by step

![image](./one.png)

In this section, a set of variables is defined. We can see that the server will use AES-CBC for encryption with a securely generated random key and IV, but this mode is vulnerable to some attacks like bit flipping. There is also two interesting boolean variables, has_flag and sent, are both initialized to false. These might play a crucial role in discovering the flag. 

![image](./two.png)

The send_email function takes a byte string representing a recipient email (or a comma-separated list of recipients) and iterates through it. If any entry exactly matches the user’s assigned email, it sets the global has_flag variable to True.

![image](./three.png)

This function assign a random email address ending in @notscript.sorcerer to the user.

![image](./four.png)

User must provide a password in hex. Three restrictions:

     - Must be a multiple of 16 bytes (AES block size).

     - Cannot directly contain @script.sorcerer.

     - Cannot contain your assigned email

After that the server gave you two options :

- option 1:
  
![image](./6ix.png)

The server checks the value of has_flag: if it is True, it prints the flag; otherwise, it prints “No new emails.” This means we need to trigger the server to execute the send_email function and satisfy its conditions in order to set has_flag to True. The question then becomes: where in the code is send_email called, and under what circumstances? We'll see.

- option 2:
  
![image](./seven.png)

The server decrypts whatever ciphertext a user provides .It checks if the message length is a multiple of 16 and if its last 16 bytes is "@script.sorcerer" to confirm you are in the right domain. If valid, it calls send_email(). One last thing The variable "sent" just checks if the email is already sent by the server, it stops us from choosing the seconf option more then one. So we need to start from here and meet the requirement to make the server call send_email with all the requirement

To sum up, the server starts by generating a random email address and assign it the user, after that it asks for password in hex that will be encrypted and gived back to the user. Then the server asks to choose an option; the first one verify the has_flag variable and return the flag if it's set to true, the second option the server asks for a hex string that will decrypt and see if it match two requirements(being a multiple of 16 and ends up with "@script.sorcerer"). If so it calls the function send_email which checks if the email generated exist among the recipient and change the value of has_flag variable. 
