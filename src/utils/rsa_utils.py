import secrets


def miller_rabin(n, k=40):
    """
    Probabilistic Miller–Rabin primality test.
    For robust usage, we increase the default iterations k=40+.
    """
    if n < 2:
        return False
    # Quick check for small primes
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return n == p

    # Factor out powers of 2 from n-1
    d = n - 1
    s = 0
    while d % 2 == 0:
        d >>= 1
        s += 1

    # Main test
    for _ in range(k):
        a = secrets.randbelow(n - 2) + 2  # in [2..n-2]
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits=2048):
    """
    Generate a prime of specified bit length using Miller-Rabin.
    Using the 'secrets' module for cryptographic-quality randomness.
    """
    while True:
        # Get a random number of desired bit length, ensure it's odd
        candidate = secrets.randbits(bits) | 1
        # Make sure top bit is set (to ensure it truly is 'bits' length)
        candidate |= 1 << (bits - 1)

        if miller_rabin(candidate):
            return candidate


def extended_gcd(a, b):
    """
    Return (gcd, x, y) such that a*x + b*y = gcd(a, b).
    """
    if b == 0:
        return (a, 1, 0)
    else:
        g, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return (g, x, y)


def generate_rsa_keys(bits=2048):
    """
    Generate RSA key pair (public, private) with the given bit size.
    public = (e, n), private = (d, n)
    """
    # 1) Generate two large random primes p and q
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    # Ensure p != q
    while q == p:
        q = generate_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    # 2) Choose e
    # Commonly used prime for e is 65537
    e = 65537
    # Verify gcd(e, phi) = 1
    g, _, _ = extended_gcd(e, phi)
    if g != 1:
        # If gcd != 1, pick a random e
        while True:
            e = secrets.randbelow(phi - 2) + 2
            g, _, _ = extended_gcd(e, phi)
            if g == 1:
                break

    # 3) Compute d
    _, d, _ = extended_gcd(e, phi)
    d %= phi  # ensure positive

    return (e, n), (d, n)


def encrypt(message, pub_key):
    """
    RSA Encryption: c = message^e mod n
    'message' here should be an integer < n.
    """
    e, n = pub_key
    return pow(message, e, n)


def decrypt(ciphertext, priv_key):
    """
    RSA Decryption: m = ciphertext^d mod n
    """
    d, n = priv_key
    return pow(ciphertext, d, n)


def str_to_int(s):
    """Convert a string to an integer using UTF-8 encoding."""
    return int.from_bytes(s.encode("utf-8"), "big")


def int_to_str(i):
    """Convert an integer back to a string assuming UTF-8 encoding."""
    # Ensure at least one byte is used.
    byte_length = (i.bit_length() + 7) // 8 or 1
    return i.to_bytes(byte_length, "big").decode("utf-8")
