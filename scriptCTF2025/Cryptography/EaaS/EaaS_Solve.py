from pwn import *

# Connect to the remote server
r = remote('play.scriptsorcerers.xyz', 10326)

# Receive initial server messages
r.recvline()

# Extract the generated email from the server response
email_line = r.recvline()
email = email_line.decode().split(":")[1].strip()

# Wait for the prompt to enter the secure password
r.recvuntil(b"Enter secure password (in hex): ")

# Craft the plaintext password

P_1 = b"a"*16 # 1st block (16 byte)
P_2and3 = b"a" + b"," + email.encode()[:12] + b"m" + email.encode()[13:] + b"," # 2nd & 3rd blocks (32 bytes)
P_4 = b"a"*16 # 4th block (16 byte)
P_5 = b"@script.sorceref" # 5th block (16 byte)

password_bytes = P_1 + P_2and3 + P_4 + P_5


# Send the password in hex format
r.sendline(password_bytes.hex().encode())

# Receive the encrypted password from the server
enc_pass_line = r.recvline().decode()
enc_pass = bytes.fromhex(enc_pass_line.split(":")[-1].strip())


# Choose option 2
r.recvuntil(b"Enter your choice: ")
r.sendline(b"2")

# Wait for prompt to enter the encrypted email
r.recvuntil(b"Enter encrypted email (in hex): ")

# Convert encrypted password to a mutable bytearray
ciphertext = bytearray(enc_pass)

# Flip 'f' to 'r' in the last block
old_part = b"f"
new_part = b"r"
ciphertext[-17] ^= old_part[0] ^ new_part[0]

# Flip 'm' to 'o' in the second block
old_part1 = b"m"
new_part1 = b"o"
ciphertext[14] ^= old_part1[0] ^ new_part1[0]

# Send the modified ciphertext back to the server
r.sendline(ciphertext.hex().encode())

# Receive server confirmation
confirmation = r.recvline()
log.info(f"Server confirmation: {confirmation.decode()}")

# Go back to option 1 to check result
r.recvuntil(b"Enter your choice: ")
r.sendline(b"1")

# Read unnecessary lines
r.recvuntil(b"Body: ")

# Print the flag
print("Flag : ", r.recvline().decode())

# scriptCTF{CBC_1s_s3cur3_r1ght?_ec65ed2216c9}