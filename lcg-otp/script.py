import base64
import math


def xor(a, b):
    """XOR two byte arrays."""
    return bytes([x ^ y for x, y in zip(a, b)])


class LCG:
    """Linear Congruential Generator."""
    def __init__(self, a, b):
        self.a = a
        self.b = b
        self.mod = 2 ** 16
        self.state = 0

    def next(self):
        """Generate the next LCG state."""
        self.state = (self.a * self.state + self.b) % self.mod
        return self.state


def decode_ciphertext(ciphertext_b64, a, b):
    """Decode the ciphertext given LCG parameters a and b."""
    # Decode Base64 ciphertext
    ciphertext = base64.b64decode(ciphertext_b64)

    # Initialize LCG with parameters
    lcg = LCG(a, b)

    # Generate the key
    states = [lcg.next() for _ in range(math.ceil(len(ciphertext) / 2))]
    key = b"".join([state.to_bytes(2, "little") for state in states])

    # Decrypt by XORing ciphertext with the key
    plaintext = xor(ciphertext, key)

    return plaintext.decode("ASCII", errors="replace")


if __name__ == "__main__":
    # Base64 encoded ciphertext
    ciphertext_b64 = (
        "tHNTAdMJ1niSUNNa3FzGN+FUklnXHdtQwlzAXMY390iSUNdP10iSUNsQ3R3UXNEd1ly"
        "4bsJY207ae95c1UbWafRF12vbX8p0hUz6ceJZgXT5X4YJ4wvdR8tO4XbYW88="
    )

    # LCG parameters (replace with the correct values)
    a = 1337  # Replace with actual value
    b = 2468  # Replace with actual value

    # Decode the ciphertext
    plaintext = decode_ciphertext(ciphertext_b64, a, b)
    print("Decoded plaintext:")
    print(plaintext)
