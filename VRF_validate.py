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
    chamber_index = YOUR_CHAMBER_INDEX_FROM_ENDGAME
    salt = "YOUR_SALT_FROM_ENDGAME"
    initial_hash = "YOUR_INITIAL_HASH_FROM_NEWGAME"
'''
public_key = "9f77a31a6d7185352e3479270dcacb2a46a8868305580c950863ae2a64da1db3072ccbee340faaed082dfa0527cf1a9219edd0b62e8a6d999370e55eb7a39d94"
proof = "a5d321f1df9be3fbe220f26cee68242a8faa18c92385a044053ed6d75f6ce299596b77aa27981256163008ed351c9e5f668fea98a298d89d779576a4d1982c1c"
alpha = b'1693941292300300300300300'
beta = "f73c1b10cedb926c6c1ede536a08f5cab19261a53062f113d1339cda14a3849e"
salt = "834b3daae46220210c2a3be8d446f5065683c25eaa56be090baabb6dcf00a8e3"
initial_hash = "01640dad0736379f105311fa756b68b8c247409b93a30d349d83c0b4df962232"
revolver_size = 2

# Verification
result = verify(public_key, alpha, beta, proof, initial_hash, salt, revolver_size)
if result:
    print("The game was fair!")
else:
    print("The game might have been rigged!")
