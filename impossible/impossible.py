from bitarray import bitarray  # https://pypi.org/project/bitarray/
from bitarray.util import ba2int, int2ba


class PRNG:
    """Based on Linear Congruential Generator
    (https://en.wikipedia.org/wiki/Linear_congruential_generator)."""

    def __init__(self, p, a, b, s):
        self.params = p, a, b
        self.seed = s
        self.block_size = p.bit_length()

    def getrandbits(self) -> bitarray:
        """Get `self.block_size` random bits."""
        p, a, b = self.params
        self.seed = (a * self.seed + b) % p
        return int2ba(self.seed, length=self.block_size)


def encrypt(plaintext: bitarray, prng: PRNG) -> bitarray:
    """Encrypt `plaintext` using provided `prng`."""
    # number of blocks needed
    n = (len(plaintext) + prng.block_size - 1) // prng.block_size
    assert n <= 3

    # get random bits from `prng`, treated as a key stream to be XORed
    # with the plaintext
    key_stream = sum([prng.getrandbits() for _ in range(n)], bitarray())

    return plaintext ^ key_stream[:len(plaintext)]


if __name__ == "__main__":
    # `p` is intended to be `getPrime(2020)`. However, freshly generating a new
    # 2020-bit prime for each connection is such a huge waste of resource.
    # Therefore, we decide to fix its value as below:
    p = 65211977220892089569045463186732539303158357084345674525019223922060296962955192052081340976238500998741557164071033324269809415343882851005134334321981343116646432559928036672509078986141816570500249363856922917569581176421339604790053954260199447256675764678917476537199601659744868522143168253773264342459882005081309642416969704634232160589082663834584255588529471102107918634517698293211047541926109452067190602960919204208686203253917293259455554341825327963925122844129780261774584303048218473988438617945144493997764310914009350053694972501833699765812965584451364828122672890270175800017700685562657

    from secret import flag
    plaintext = bitarray()
    plaintext.frombytes(flag.encode())

    from random import randint
    while True:
        prng = PRNG(p, *[randint(0, p - 1) for _ in range(3)])
        prefix = int2ba(int(input()), length=int(input()))
        ciphertext = encrypt(prefix + plaintext, prng)
        print(ba2int(ciphertext))
        print(len(ciphertext))
