import ecdsa
import hashlib

'''
    Commit-Reveal Scheme
    In the startGame transaction, the game commits to a random outcome
    without revealing it. In the endGame transaction, the outcome is
    revealed, and anyone can verify that it matches the initial commitment.
'''

def verify(public_key, alpha, beta, proof, initial_hash, salt, revolver_size):
    # Convert the public key from hex to bytes and then to VerifyingKey object
    # Ensure the public key is in uncompressed form
    if public_key.startswith("0x"):
        public_key = public_key[2:]

    # vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key)[1:], curve=ecdsa.SECP256k1)
    vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)

    
    # Verify the proof
    try:
        vk.verify(bytes.fromhex(proof), alpha)
        proof_validity = True
    except ecdsa.keys.BadSignatureError:
        proof_validity = False

    # Calculate expected hash
    chamber_index = int(beta, 16) % revolver_size
    expected_value = hashlib.sha256((str(chamber_index) + salt).encode()).hexdigest()

    return proof_validity and expected_value == initial_hash

public_key = "YOUR_PUBLIC_KEY_FROM_ENDGAME"
proof = "YOUR_PROOF_FROM_ENDGAME"
alpha = b"YOUR_ALPHA_FROM_ENDGAME"
beta = "YOUR_BETA_FROM_ENDGAME"
chamber_index = "YOUR_CHAMBER_INDEX_FROM_ENDGAME"
salt = "YOUR_SALT_FROM_ENDGAME"
initial_hash = "YOUR_INITIAL_HASH_FROM_NEWGAME"
revolver_size = "SIZE_OF REVOLVER_CHAMBERS"

# Verification
result = verify(public_key, alpha, beta, proof, initial_hash, salt, revolver_size)
if result:
    print("The game was fair!")
else:
    print("The game might have been rigged!")
