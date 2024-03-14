---
layout: post
title:  "HTB Apocalypse CTF 2024 - arranged"
date:   2024-03-14 18:30:00 -0400
categories: ctf
excerpt: Exploiting a weak elliptic curve
---

## Overview

We are given the following code that encrypts the flag:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes
from hashlib import sha256

from secret import FLAG, p, b, priv_a, priv_b

F = GF(p)
E = EllipticCurve(F, [726, b])
G = E(926644437000604217447316655857202297402572559368538978912888106419470011487878351667380679323664062362524967242819810112524880301882054682462685841995367, 4856802955780604241403155772782614224057462426619061437325274365157616489963087648882578621484232159439344263863246191729458550632500259702851115715803253)

A = G * priv_a
B = G * priv_b

print(A)
print(B)

C = priv_a * B

assert C == priv_b * A

# now use it as shared secret
secret = C[0]

hash = sha256()
hash.update(long_to_bytes(secret))

key = hash.digest()[16:32]
iv = b'u\x8fo\x9aK\xc5\x17\xa7>[\x18\xa3\xc5\x11\x9en'
cipher = AES.new(key, AES.MODE_CBC, iv)

encrypted = cipher.encrypt(pad(FLAG, 16))
print(encrypted)
```

This code generates the elliptic curve given by the equation `y**2 = x**3 + 726x + b` over a finite field of order `p`. A generator point `G` is given, along with two private keys `priv_a` and `priv_b`, which are used to generate a shared secret using elliptic curve Diffie-Hellman. (If you're not familiar with this algorithm, here's my [writeup](/malware/2023/03/17/ecc.html) on the basics of how it works.) The shared secret is then used to derive an AES key that encrypts the flag.

We are given the public keys `A` and `B`, but we do not know either of the private keys `priv_a` or `priv_b`, so we are unable to derive the shared secret. Our goal is to exploit a weakness in the encryption algorithm to calculate `priv_a` or `priv_b`.

## THe Hidden Curve Parameters

The interesting thing about this challenge is that the parameters `p` and `b` are hidden from us. In order for the ECDH algorithm to work, both parties must know the order `p` of the finite field and the equation of the curve. In general, the value of `p`, the parameters of the curve, and the generator `G` are chosen from one of a set of standard curves that are known to be secure. For example, the curve `secp256k1` is specified by the following parameters:
```
y**2 = x**3 + 7
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
G = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 
     0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
```

The generator point `G` that we are given is not equal to the standard generator point of any commonly used curves, so chances are, we're dealing with a nonstandard curve that was designed specifically for this challenge - probably because it's insecure in some way. Since it's not a standard curve, we'll have to determine `p` and `b` solely based on the information given to us in the challenge, so let's look at what we know.

The x- and y-coordinates of `G` are 509 and 511 bits respectively, suggesting that `p` is probably a 512-bit prime. In addition, we're given three different points on the curve: `G`, `A`, and `B`. Each of those points `(x,y)` will need to satisfy `y**2 = x**3 + 726x + b (mod p)`.

Let's call the three sets of points `(x_A, y_A)`, `(x_B, y_B)`, and `(x_G, y_G)`. We can calculate three values `b_A`, `b_B`, and `b_G` using the equation of the curve: `b = y**2 - x**3 - 726x`. This will get us three different values: the curve is defined over `GF(p)` not over the integers, so `b_A`, `b_B`, and `b_G` won't necessarily be equal - but they *will* be congruent mod `p`, whatever `p` is.

This gives us enough information to guess a value of `p`. Since `b_A`, `b_B`, and `b_G` are all congruent mod `p`, their differences `b_A - b_B`, `b_G - b_B`, and `b_A - b_G` are all equal to 0 mod `p`, i.e., they are all divisible by p. Knowing that, we can look at the common divisors of `b_A - b_B`, `b_G - b_B`, and `b_A - b_G`. If one of those common divisors is a 512-bit prime, that's almost certainly the value of `p`.

The following script calculates the greatest common divisor of `b_A - b_B`, `b_G - b_B`, and `b_A - b_G`:

```python
def get_b(xy):
	x = xy[0]
	y = xy[1]
	return y**2 - (x**3 + 726*x)


def guess_p(G_xy, A_xy, B_xy):
	b_G = get_b(G_xy)
	b_A = get_b(A_xy)
	b_B = get_b(B_xy)

	return gcd(b_G - b_A, gcd(b_B - b_A, b_G - b_B))
	
G_xy = (926644437000604217447316655857202297402572559368538978912888106419470011487878351667380679323664062362524967242819810112524880301882054682462685841995367, 4856802955780604241403155772782614224057462426619061437325274365157616489963087648882578621484232159439344263863246191729458550632500259702851115715803253)

A_xy = (6174416269259286934151093673164493189253884617479643341333149124572806980379124586263533252636111274525178176274923169261099721987218035121599399265706997, 2456156841357590320251214761807569562271603953403894230401577941817844043774935363309919542532110972731996540328492565967313383895865130190496346350907696)

B_xy = (4226762176873291628054959228555764767094892520498623417484902164747532571129516149589498324130156426781285021938363575037142149243496535991590582169062734, 425803237362195796450773819823046131597391930883675502922975433050925120921590881749610863732987162129269250945941632435026800264517318677407220354869865)

p = guess_p(G_xy, A_xy, B_xy)
print(p)
```
This prints out the value `6811640204116707417092117962115673978365477767365408659433165386030330695774965849821512765233994033921595018695941912899856987893397852151975650548637533`, which is in fact a 512-bit prime. That means we're on the right track!

## The Vulnerability

Now that we know the full equation of the curve, we can find the order of the generator point `G`: the number of distinct points on the curve that can be obtained by repeatedly adding `G` to itself. Sage has a built-in function `G.order()` to do this. Since every point used in the ECDH algorithm is a multiple of `G`, this gives us a measure of how feasible it would be to bruteforce the value of one of the private keys.

For this curve, it turns out that the order of `G` is only 11, so guessing a private key is easy. To calculate `priv_a`, we just need to calculate `kG` for values of `k` in the range 0 through 10, then compare the result to the public key point `A`. The value of `k` that produces a matching point is `priv_a`. From there, we just need to calculate the shared secret, which is equal to `priv_a * B`, to decrypt the flag.

Final solve script:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes
from hashlib import sha256

def get_b(xy):
	x = xy[0]
	y = xy[1]
	return y**2 - (x**3 + 726*x)


def guess_p(G_xy, A_xy, B_xy):
	b_G = get_b(G_xy)
	b_A = get_b(A_xy)
	b_B = get_b(B_xy)

	return gcd(b_G - b_A, gcd(b_B - b_A, b_G - b_B))
	
G_xy = (926644437000604217447316655857202297402572559368538978912888106419470011487878351667380679323664062362524967242819810112524880301882054682462685841995367, 4856802955780604241403155772782614224057462426619061437325274365157616489963087648882578621484232159439344263863246191729458550632500259702851115715803253)

A_xy = (6174416269259286934151093673164493189253884617479643341333149124572806980379124586263533252636111274525178176274923169261099721987218035121599399265706997, 2456156841357590320251214761807569562271603953403894230401577941817844043774935363309919542532110972731996540328492565967313383895865130190496346350907696)

B_xy = (4226762176873291628054959228555764767094892520498623417484902164747532571129516149589498324130156426781285021938363575037142149243496535991590582169062734, 425803237362195796450773819823046131597391930883675502922975433050925120921590881749610863732987162129269250945941632435026800264517318677407220354869865)

p = guess_p(G_xy, A_xy, B_xy) 
b = get_b(G_xy) % p

F = GF(p)
E = EllipticCurve(F, [726, b % p])

G = E(G_xy[0], G_xy[1])
A = E(A_xy[0], A_xy[1])
B = E(B_xy[0], B_xy[1])


print("Order of G:", G.order())

for i in range(11):
	P = i * G
	if(P == A):
		priv_a = i
		break

print(priv_a)
	
C = priv_a * B
secret = C[0]

hash = sha256()
hash.update(long_to_bytes(int(secret)))

ciphertext = b'V\x1b\xc6&\x04Z\xb0c\xec\x1a\tn\xd9\xa6(\xc1\xe1\xc5I\xf5\x1c\xd3\xa7\xdd\xa0\x84j\x9bob\x9d"\xd8\xf7\x98?^\x9dA{\xde\x08\x8f\x84i\xbf\x1f\xab'
key = hash.digest()[16:32]
iv = b'u\x8fo\x9aK\xc5\x17\xa7>[\x18\xa3\xc5\x11\x9en'
cipher = AES.new(key, AES.MODE_CBC, iv)

flag = cipher.decrypt(ciphertext)
print(flag)
```

This gets us the flag: `HTB{0rD3r_mUsT_b3_prEs3RveD_!!@!}`
