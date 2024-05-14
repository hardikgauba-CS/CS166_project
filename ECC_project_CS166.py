from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_keypair():
    """Generate an ECC keypair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """Serialize the public key to PEM format."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

def deserialize_public_key(pem):
    """Deserialize the PEM formatted public key."""
    public_key = serialization.load_pem_public_key(pem)
    return public_key

def generate_shared_secret(private_key, public_key):
    """Generate a shared secret using ECDH."""
    shared_secret = private_key.exchange(ec.ECDH(), public_key)
    return shared_secret

# Generate key pairs for Alice and Bob
alice_private, alice_public = generate_keypair()
bob_private, bob_public = generate_keypair()

# Serialize and deserialize public keys (simulate key exchange over network)
alice_public_pem = serialize_public_key(alice_public)
bob_public_pem = serialize_public_key(bob_public)

alice_public_deserialized = deserialize_public_key(alice_public_pem)
bob_public_deserialized = deserialize_public_key(bob_public_pem)

# Generate shared secrets
alice_secret = generate_shared_secret(alice_private, bob_public_deserialized)
bob_secret = generate_shared_secret(bob_private, alice_public_deserialized)

# Demonstrate that the shared secrets are the same
assert alice_secret == bob_secret, "Shared secrets are not equal!"

print("Shared Secret Computed by Alice:", alice_secret.hex())
print("Shared Secret Computed by Bob:", bob_secret.hex())