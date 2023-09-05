import ecdsa
import hashlib
import os
import time


# Generate a random value and its proof using VRF
# Returns beta (random value), proof, and chamber index

def generate_random_value_and_proof(private_key, alpha, revolver_size):
    # Generate VRF proof and beta
    proof = private_key.sign(alpha)
    beta = hashlib.sha256(proof).hexdigest()
    chamber_index = int(beta, 16) % revolver_size

    return beta, proof, chamber_index


def new_game(revolver_size):
    # Generate a cryptographically secure random salt
    salt = os.urandom(32).hex()
    chamber_index = os.urandom(1)[0] % revolver_size  # Random chamber index
    initial_hash = hashlib.sha256((str(chamber_index) + salt).encode()).hexdigest()

    return initial_hash, salt


def end_game(private_key, alpha, revolver_size):
    beta, proof, chamber_index = generate_random_value_and_proof(private_key, alpha, revolver_size)
    public_key = private_key.get_verifying_key()

    return beta, proof, public_key, chamber_index

def verify(public_key, alpha, beta, proof, initial_hash, salt, revolver_size):
    # Verify the proof
    try:
        public_key.verify(proof, alpha)
        proof_validity = True
    except ecdsa.keys.BadSignatureError:
        proof_validity = False

    # Calculate expected hash
    chamber_index = int(beta, 16) % revolver_size
    expected_value = hashlib.sha256((str(chamber_index) + salt).encode()).hexdigest()

    return proof_validity and expected_value == initial_hash


# Main execution
if __name__ == '__main__':
    # Parameters
    revolver_size = 2
    timestamp = str(int(time.time()))
    bets = [300, 300, 300, 300, 300]
    alpha = (timestamp + ''.join(map(str, bets))).encode()

    # Generate VRF private and public keys
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

    # New game
    initial_hash, salt = new_game(revolver_size)
    print(f'Initial Hash (for newGame): {initial_hash}')
    print(f'Salt: {salt}')

    # End game
    beta, proof, pk, chamber_index = end_game(sk, alpha, revolver_size)
    print(f'Alpha (Input Message): {alpha}')
    print(f'Random Value (Beta): {beta}')
    print(f'Proof: {proof.hex()}')
    print(f'Public Key: {pk.to_string().hex()}')

    # Verification
    result = verify(pk, alpha, beta, proof, initial_hash, salt, revolver_size)
    print(f'Verification Result: {result}')