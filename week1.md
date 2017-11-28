# WEEK 1 

## Simple substitution (permutation of the alphabet)

We can break it by Letter Frequency Analysis. Most frequent letter is 'E', then in the ciphered text we can assume the most frequent letter correspond to 'E'. Also can use the most common digrams and trigrams ("TH", "AND" "HER", etc...)

This is clearly not secure enough.

## Vigenère Cipher

Plaintext and a key. We repeat the key until it has the length of the plaintext and we simply add each letter of the plaintext with the corresponding letter of the expanded Key (a = 0, b = 1, c = 2, etc...).

e.g. Plaintext: "I am a nice person", Key: "abcdef"
expanded key => "abcdefabcdefab"
ciphered text = 'I + a' + 'a + b' .... = "I bo d ...."

## Column-dependent substitution

If key length is known, statistical analysis still works. Can guess length with bigram/trigrams appearances.

Can compute the Probability Pr(xI = xJ | I < J) = Sum c Pr(xI = xJ = c | I < J) for each of k columns and see if it corresponds to the standard probability of english language and if yes, it means k is the correct number of columns (Key length).

## 



