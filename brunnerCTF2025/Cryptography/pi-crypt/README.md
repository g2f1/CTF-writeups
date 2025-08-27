![image](./pi-crypt.png)

This was quite an interesting challenge because, although the cipher itself works in a rather simple way, cracking it turned out to be difficult—especially since we were given only the ciphertext, placing us in a ciphertext-only attack model.

I didn’t manage to solve the challenge during the competition, but I came very close. After the event, I went back to study some talks about it, picked up a few useful ideas that I had missed during my initial attempt, and finally managed to solve the challenge.

pi-crypt is a custom cryptographic algorithm that uses the first 1,000 digits of π and a key to shift the characters of a message. The scheme operates over a set of 100 printable characters.


