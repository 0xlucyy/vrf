import ecdsa.keys
import ecdsa
import hashlib
import secrets
import time
from log import logger
from error import SeedError, VerificationError, InputError

HEX_BASE = 16
SUBSTRING_LENGTH = 8

ALPHA_SALT_ERROR_MSG = 'Alpha or Salt must be of type bytes and str, respectively.'
CHAMBER_REVOLVER_ERROR_MSG = 'Chamber index and revolver size must be of type int.'
PRIVATE_KEY_ERROR_MSG = 'Private key must be an instance of ecdsa.keys.SigningKey.'
PROOF_BETA_ERROR_MSG = 'Failed to generate proof or beta.'


def generate_seed(_iterations=100000, _algorithm='sha512'):
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
    iterations = _iterations
    seed_hash = hashlib.pbkdf2_hmac(_algorithm, seed.encode(), salt, iterations).hex()
    return seed, seed_hash, salt


def generate_proof(private_key, alpha):
    try:
        return private_key.sign(alpha, hashfunc=hashlib.sha256)
    except Exception as e:
        raise VerificationError('Failed to generate proof.') from e


def generate_beta(proof, salt, chamber_index):
    beta = hashlib.sha256(b''.join([proof, salt.encode(), str(chamber_index).encode()])).hexdigest()
    return beta


def generate_random_value_and_proof(private_key: ecdsa.keys.SigningKey, alpha: bytes, chamber_index: int, salt: str, revolver_size: int) -> tuple:
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

    '''
    calculates derived_chamber_index by hashing beta to produce
    an integer & taking the modulus with revolver_size.
    '''
    derived_chamber_index = int(hashlib.sha256(beta.encode()).hexdigest(), 16) % revolver_size

    return beta, proof, derived_chamber_index


def new_game(revolver_size, bets):
    """
    Initialize a new game.
    
    Args:
        revolver_size (int): The size of the revolver.
        
    Returns:
        tuple: A tuple containing initial hash, salt, chamber index, and seed.
    """
    if not (2 <= revolver_size <= 50):
        raise InputError("Invalid revolver size. It should be between 2 and 50.")
    
    if len(bets) > revolver_size:
        raise InputError("Too many players!")

    seed, seed_hash, _ = generate_seed()
    logger.info(f'Seed Hash (shared with player): {seed_hash}')

    salt = secrets.token_hex(32)
    deterministic_value = hashlib.sha256(salt.encode()).hexdigest()
    chamber_index = int(deterministic_value[:8], 16) % revolver_size
    initial_hash = hashlib.sha256((str(chamber_index) + salt).encode()).hexdigest()
    logger.info(f'Chamber Index (for newGame): {chamber_index}')
    return initial_hash, salt, chamber_index


def end_game(private_key, alpha, revolver_size, salt, chamber_index):
    """
    End the game and generate necessary values.
    
    Args:
        private_key (ecdsa.keys.SigningKey): The private key for signing.
        alpha (bytes): Input message.
        revolver_size (int): The size of the revolver.
        salt (str): The salt value.
        
    Returns:
        tuple: A tuple containing beta, proof, public key, and derived chamber index.
    """
    public_key = private_key.get_verifying_key().to_string(encoding='uncompressed')
    beta, proof, _ = generate_random_value_and_proof(private_key, alpha, chamber_index, salt, revolver_size)
    deterministic_value = hashlib.sha256(salt.encode()).hexdigest()
    derived_chamber_index = int(deterministic_value[:8], 16) % revolver_size
    logger.info(f'Chamber Index (for endGame): {derived_chamber_index}')
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
        vk = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
        vk.verify(proof, alpha, hashfunc=hashlib.sha256)
        proof_validity = True
    except ecdsa.keys.BadSignatureError:
        raise VerificationError('Verification of the proof failed.')

    deterministic_value = hashlib.sha256(salt.encode()).hexdigest()
    chamber_index = int(deterministic_value[:8], 16) % revolver_size
    logger.info(f'Chamber Index (from Beta): {chamber_index}')

    return proof_validity and initial_hash == hashlib.sha256((str(chamber_index) + salt).encode()).hexdigest()


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
