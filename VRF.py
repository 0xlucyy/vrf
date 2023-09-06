import ecdsa
import hashlib
import os
import time

def generate_random_value_and_proof(private_key, alpha, revolver_size, chamber_index, salt):
    proof = private_key.sign(alpha, hashfunc=hashlib.sha256)
    beta = hashlib.sha256(proof + salt.encode() + str(chamber_index).encode()).hexdigest()
    derived_chamber_index = int(beta[:8], 16) % revolver_size
    return beta, proof, derived_chamber_index

def new_game(revolver_size):
    salt = os.urandom(32).hex()
    deterministic_value = hashlib.sha256(salt.encode()).hexdigest()
    chamber_index = int(deterministic_value[:8], 16) % revolver_size
    initial_hash = hashlib.sha256((str(chamber_index) + salt).encode()).hexdigest()
    print(f"Chamber Index (for newGame): {chamber_index}")  # Print chamber index during new game
    return initial_hash, salt, chamber_index

def end_game(private_key, alpha, revolver_size, salt):
    public_key = private_key.get_verifying_key().to_string(encoding="uncompressed")
    beta, proof, _ = generate_random_value_and_proof(private_key, alpha, revolver_size, chamber_index, salt)
    deterministic_value = hashlib.sha256(salt.encode()).hexdigest()
    derived_chamber_index = int(deterministic_value[:8], 16) % revolver_size
    print(f"Chamber Index (for endGame): {derived_chamber_index}")  # Print chamber index during end game
    return beta, proof, public_key, derived_chamber_index


def verify(public_key, alpha, beta, proof, initial_hash, salt, revolver_size):
    try:
        vk = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
        vk.verify(proof, alpha, hashfunc=hashlib.sha256)
        proof_validity = True
    except ecdsa.keys.BadSignatureError:
        proof_validity = False

    deterministic_value = hashlib.sha256(salt.encode()).hexdigest()
    chamber_index = int(deterministic_value[:8], 16) % revolver_size
    print(f"Chamber Index (from Beta): {chamber_index}")

    return proof_validity and initial_hash == hashlib.sha256((str(chamber_index) + salt).encode()).hexdigest()


if __name__ == '__main__':
    revolver_size = 7
    timestamp = str(int(time.time()))
    bets = [30000, 30000, 30000]
    alpha_raw = (timestamp + ''.join(map(str, bets)))
    alpha = alpha_raw.encode()

    print(f'Revolver Size): {revolver_size}')

    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

    initial_hash, salt, chamber_index = new_game(revolver_size)
    print(f'Initial Hash (for newGame): {initial_hash}')
    print(f'Salt: {salt}')

    beta, proof, pk, chamber_index = end_game(sk, alpha, revolver_size, salt)
    print(f'Alpha_Raw (Timestampe + Bets): {alpha_raw}')
    print(f'Alpha (Input Message): {alpha}')
    print(f'Random Value (Beta): {beta}')
    print(f'Proof: {proof.hex()}')
    print(f'Public Key: {pk.hex()}')

    result = verify(pk, alpha, beta, proof, initial_hash, salt, revolver_size)
    print(f'Expected Value: {initial_hash}')
    print(f'Initial Hash: {initial_hash}')
    print(f'Verification Result: {result}')
