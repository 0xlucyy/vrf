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

'''
    public_key = "YOUR_PUBLIC_KEY_FROM_ENDGAME"
    proof = "YOUR_PROOF_FROM_ENDGAME"
    alpha = b"YOUR_ALPHA_FROM_ENDGAME"
    beta = "YOUR_BETA_FROM_ENDGAME"
    chamber_index = "YOUR_CHAMBER_INDEX_FROM_ENDGAME"
    salt = "YOUR_SALT_FROM_ENDGAME"
    initial_hash = "YOUR_INITIAL_HASH_FROM_NEWGAME"
    revolver_size = "SIZE_OF REVOLVER_CHAMBERS"
'''
public_key = "04b76603e4ccc3f6b8d1207c123a122c3886ba581f7ed739361acf0514abbbb9493b568685cb949cba9d001cde5c8a74ec0a6b1182d3771c0dd722c297e9e33f2b"
proof = "dfdc62a0c1ea0176ee76c0c56fd76933726a3887eff1605b19ec908a0bd9e5540c245f2293890c4cb3bf3f7851f0598360a37de47a16d35f2fa878bb07e12606"
alpha = b'1694018275300300300300300'
beta = "1cf8771db2454b0a9c41cbd01b7c4480bb131f4c1812a24adfecfaedfcc07064"
salt = "3c628c6503f1750348e9258c26a809a273d40d093804489d69663cb6f0e3ebff"
initial_hash = "1cda36f5fe85073458143d6424a3ccf4e4358e573f254ec86d75e12154e537a5"
revolver_size = 7


# Verification
result = verify(public_key, alpha, beta, proof, initial_hash, salt, revolver_size)
if result:
    print("The game was fair!")
else:
    print("The game might have been rigged!")
