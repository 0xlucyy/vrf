import ecdsa.keys
import ecdsa
import hashlib
import secrets
import time
from log import logger
from utils import deterministic_value
from error import SeedError, VerificationError, InputError

HEX_BASE = 16
SUBSTRING_LENGTH = 8

ALPHA_SALT_ERROR_MSG = 'Alpha or Salt must be of type bytes and str, respectively.'
CHAMBER_REVOLVER_ERROR_MSG = 'Chamber index and revolver size must be of type int.'
PRIVATE_KEY_ERROR_MSG = 'Private key must be an instance of ecdsa.keys.SigningKey.'
PROOF_BETA_ERROR_MSG = 'Failed to generate proof or beta.'


# ITERATIONS = 100000
ITERATIONS = 100

def generate_seed(_algorithm: str = 'sha512'):
    """
    Generate a random seed and its hash.

    This function generates a random seed and
    its hash using the PBKDF2 key derivation function.
    It applies a pseudorandom function to the input seed
    along with a randomly generated salt and repeats the
    process multiple times to produce a derived key. This
    makes the generated seed more resistant to brute-force
    attacks and rainbow table attacks.

    Returns:
        tuple: A tuple containing the seed and its hash.
    """
    seed = secrets.token_hex(16)
    salt = secrets.token_bytes(32)
    seed_hash = hashlib.pbkdf2_hmac(_algorithm, seed.encode(), salt, ITERATIONS).hex()
    return seed, seed_hash, salt


def generate_proof(private_key: ecdsa.keys.SigningKey, alpha: bytes):
    """
    Generate a proof using the private key and input message.

    Args:
        private_key: The private key for signing.
        alpha: The input message.

    Returns:
        The generated proof.

    Raises:
        VerificationError: If the proof generation fails.
    """
    try:
        # if alpha == b"" or alpha == "":
        if not alpha:
            raise VerificationError('Alpha cannot be empty.')
        # not hashing data, used in signature generation process.
        return private_key.sign(alpha, hashfunc=hashlib.sha256)
    except Exception as e:
        raise VerificationError('Failed to generate proof.') from e


def generate_beta(proof: bytes, salt: str, chamber_index: int) -> str:
    """
    Generate beta value based on the given proof, salt, and chamber index.

    Args:
        proof: The proof value.
        salt: The salt value.
        chamber_index: The chamber index.

    Returns:
        str: The generated beta value.

    """
    try:
        chamber_index_bytes = str(chamber_index).encode()
        beta = hashlib.pbkdf2_hmac('sha256', b''.join([proof, salt.encode(), chamber_index_bytes]), salt.encode(), ITERATIONS).hex()
        return beta
    except Exception as e:
        raise VerificationError('Failed to generate beta.') from e


def generate_random_value_and_proof(private_key: ecdsa.keys.SigningKey,
                                    alpha: bytes, chamber_index: int,
                                    salt: str, revolver_size: int) -> tuple:
    """
    Generate a random value and its proof.

    Args:
        private_key (ecdsa.keys.SigningKey): The private key for signing.
        alpha (bytes): Input message.
        chamber_index (int): The chamber index.
        salt (str): The salt value.
        revolver_size (int): The size of the revolver.

    Returns:
        tuple: A tuple containing beta, proof, and derived chamber index.

    Raises:
        VerificationError: If the private_key is not an instance of ecdsa.keys.SigningKey.
        VerificationError: If the alpha is not of type bytes or the salt is not of type str.
        VerificationError: If the alpha or salt is empty.
        VerificationError: If the chamber_index or revolver_size is not of type int 
        VerificationError: If the chamber_index is less than or equal to 1
        VerificationError: If the revolver_size is less than or equal to 0
    """
    if not isinstance(private_key, ecdsa.keys.SigningKey):
        raise VerificationError(PRIVATE_KEY_ERROR_MSG)

    if not isinstance(alpha, bytes) or not isinstance(salt, str):
        raise VerificationError(ALPHA_SALT_ERROR_MSG)

    if alpha is None or salt is None:
        raise VerificationError('Alpha or Salt cannot be None.')
    
    if alpha == "" or salt == b"" or salt == "":
        raise VerificationError('Alpha or Salt cannot be empty.')

    if not isinstance(chamber_index, int):
        raise VerificationError('Chamber index must be an integer.')
    if not isinstance(revolver_size, int):
        raise VerificationError('Revolver size must be an integer.')
    if revolver_size <= 1:
        raise VerificationError('Revolver size must be greater than 1.')

    # allow generate_proof & generate_beta to raise their own exceptions.
    proof = generate_proof(private_key, alpha)
    beta = generate_beta(proof, salt, chamber_index)

    derived_value = hashlib.pbkdf2_hmac('sha256', beta.encode(), salt.encode(), ITERATIONS).hex()
    derived_chamber_index = int(derived_value, 16) % revolver_size

    return beta, proof, derived_chamber_index


def new_game(revolver_size: int, bets: list):
    """
    Initialize a new game by generating a random seed and its hash,
    validating the input parameters, and calculating the initial
    hash, salt, and chamber index.

    Args:
        revolver_size (int): The size of the revolver.
        bets (list): bets made by the players.

    Returns:
        tuple: A tuple containing the initial hash, salt, and chamber index.

    Raises:
        InputError: If the input parameters are invalid.

    Example Usage:
        revolver_size = 6
        bets = [100, 200, 300]
        initial_hash, salt, chamber_index = new_game(revolver_size, bets)
        print(f"Initial Hash: {initial_hash}")
        print(f"Salt: {salt}")
        print(f"Chamber Index: {chamber_index}")
    """
    if not isinstance(revolver_size, int):
        raise InputError("Invalid input. revolver size must be an int.")
    if not (2 <= revolver_size <= 50):
        raise InputError("Invalid revolver size. It should be between 2 and 50.")

    if not isinstance(bets, list) or not bets:
        raise InputError("Invalid input. Bets must be a list.")
    for bet in bets:
        if not isinstance(bet, int):
            raise InputError("Invalid input. Bets must be a list of integers.")

    # seed, seed_hash, _ = generate_seed()
    # logger.info(f'Seed Hash (shared with player): {seed_hash}')

    salt = secrets.token_hex(32)
    deterministic_value = hashlib.pbkdf2_hmac('sha256', salt.encode(), salt.encode(), ITERATIONS).hex()

    chamber_index = int(deterministic_value[:8], 16) % revolver_size
    initial_hash = hashlib.pbkdf2_hmac('sha256', (str(chamber_index) + salt).encode(), salt.encode(), ITERATIONS).hex()

    logger.info(f'Chamber Index (for newGame): {chamber_index}')
    return initial_hash, salt, chamber_index


def end_game(private_key: ecdsa.keys.SigningKey, alpha: bytes,
             revolver_size: int, salt: str, chamber_index: int):
    """
    End the game and generate necessary values.
    
    Args:
        private_key (ecdsa.keys.SigningKey): The private key for signing.
        alpha (bytes): The input message.
        revolver_size (int): The size of the revolver.
        salt (str): The salt value.
        chamber_index (int): The chamber index.
        
    Returns:
        tuple: A tuple containing the beta value, proof, public key, and derived chamber index.
    """
    if not alpha:
        raise VerificationError
    if not salt:
        raise VerificationError
    if revolver_size and int(revolver_size) > 50:
        raise VerificationError('Revolver size must be 50 or lower')
    public_key = private_key.verifying_key.to_string(encoding='uncompressed')
    beta, proof, _ = generate_random_value_and_proof(private_key, alpha, chamber_index, salt, revolver_size)
    deterministic_value = hashlib.pbkdf2_hmac('sha256', salt.encode(), salt.encode(), ITERATIONS).hex()

    derived_chamber_index = int(deterministic_value[:8], 16) % revolver_size
    logger.info(f'Chamber Index (for endGame): {derived_chamber_index}')
    # import pdb;pdb.set_trace()
    return beta, proof, public_key, derived_chamber_index


def verify(public_key, alpha, beta, proof, initial_hash, salt, revolver_size):
    """
    Verify the game's outcome.
    
    Args:
        public_key (bytes): The public key for verification.
        alpha (bytes): Input message.
        beta (str): Random value.
        proof (bytes): Proof of the random value.
        initial_hash (str): Initial hash value.
        salt (str): The salt value.
        revolver_size (int): The size of the revolver.
        
    Returns:
        bool: True if verification is successful, False otherwise.
    """
    try:
        # Digital signature verification
        vk = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
        # vk = ecdsa.VerifyingKey.from_pem(public_key)
        vk.verify(proof, alpha, hashfunc=hashlib.sha256)
        proof_validity = True
    except ecdsa.keys.BadSignatureError:
        raise VerificationError('Verification of the proof failed.')

    # deterministic_value = hashlib.sha256(salt.encode()).hexdigest()
    deterministic_value = hashlib.pbkdf2_hmac('sha256', salt.encode(), salt.encode(), ITERATIONS).hex()

    chamber_index = int(deterministic_value[:8], 16) % revolver_size
    logger.info(f'Chamber Index (from Beta): {chamber_index}')

    # return proof_validity and initial_hash == hashlib.sha256((str(chamber_index) + salt).encode()).hexdigest()
    derived_hash = hashlib.pbkdf2_hmac('sha256', f'{chamber_index}{salt}'.encode(), salt.encode(), ITERATIONS).hex()
    return proof_validity and initial_hash == derived_hash



def run():
    revolver_size = 50
    timestamp = str(int(time.time()))
    bets = [30000, 30000, 30000, 30000]

    alpha_raw = (timestamp + ''.join(map(str, bets)))
    alpha = alpha_raw.encode()

    logger.info(f'Revolver Size): {revolver_size}')

    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

    initial_hash, salt, chamber_index = new_game(revolver_size, bets)
    # logger.info(f"Seed (revealed at end): {seed}")
    logger.info(f'Initial Hash (for newGame): {initial_hash}')
    logger.info(f'Salt: {salt}')

    beta, proof, pk, _ = end_game(sk, alpha, revolver_size, salt, chamber_index)
    logger.info(f'Alpha_Raw (Timestampe + Bets): {alpha_raw}')
    logger.info(f'Alpha (Input Message): {alpha}')
    logger.info(f'Random Value (Beta): {beta}')
    logger.info(f'Proof: {proof.hex()}')
    logger.info(f'Public Key: {pk.hex()}')

    result = verify(pk, alpha, beta, proof, initial_hash, salt, revolver_size)
    logger.info(f'Expected Value: {initial_hash}')
    logger.info(f'Initial Hash: {initial_hash}')
    logger.info(f'Verification Result: {result}')

if __name__ == '__main__':
    run()
