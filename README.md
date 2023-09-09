# Verifiable Random Function
VRF.py provides an implementation of a Verifiable Random Function (VRF) to ensure the randomness and fairness of a game. The script contains functions to generate seeds, proofs, and random values, and to verify the outcome of a game.


## Initialization
Initialization of game is achived with a `new_game` function. Belows's a detailed breakdown of the `new_game` function.

### generate_seed_salt_hash Function
The `generate_seed_salt_hash` function is a foundational step in the initialization process. It's responsible for creating a random seed and its corresponding hash. Here's a breakdown of its purpose and functionality:

- Seed Generation: The function generates a random seed using Python's `secrets.token_hex(16)`. This seed acts as a unique identifier for each game, ensuring that every game has a distinct starting point.

- Salt Generation: A random salt (`salt`) is produced using `secrets.token_hex(32)`. This salt is used in conjunction with the seed to derive the seed hash. The inclusion of a salt ensures that even if the same seed is used in multiple game rounds, the resulting seed hash will be different each time.

- Seed Hash Generation: The `seed`, combined with the `salt`, undergoes a hashing process using the PBKDF2 HMAC SHA-512 algorithm. This produces the `seed_hash`, which is a deterministic yet unpredictable value based on the seed and salt.

```python
  seed = secrets.token_hex(16)
  salt = secrets.token_hex(32)
  seed_hash = hashlib.pbkdf2_hmac(_algorithm, seed.encode(), salt.encode(), ITERATIONS).hex()
```

### generate_random_value_and_proof Function
The `generate_random_value_and_proof` function is a pivotal component in the game's cryptographic operations, ensuring randomness, unpredictability, and verifiability of the game's outcome. Here's a detailed breakdown of its purpose and functionality:

- Alpha: The function takes in an `alpha` value, which is a combination of game-specific parameters; timestamps and bets.

- Proof: Using a provided private key and the `alpha` value, a digital signature (`proof`) is generated. This `proof` acts as a cryptographic commitment, ensuring that the server cannot change the game's parameters without detection.

- Beta: The function calculates the `beta` value, which is derived by hashing a combination of the `seed_hash`, `salt`, and `proof`. This value is deterministic, meaning for the same inputs, it will always produce the same output. However, due to the randomness introduced by the `seed_hash` and `salt`, it remains unpredictable for each game round.

- Bullet Index: The `beta` value is then used to determine the `bullet_index`. This index represents the starting position or the "loaded chamber" in the game, ensuring that the game's outcome is both random and verifiable.

```python
  beta, proof, bullet_index = generate_random_value_and_proof(
    private_key, alpha, seed_hash, salt, revolver_chambers
  )
```

### Final Steps of new_game Function
The concluding lines of the `new_game` function solidify the game's cryptographic foundation, ensuring the game's integrity and verifiability. Here's a detailed breakdown of these operations:

- Bullet Index Hash: This step involves hashing a combination of the `bullet_index`, `salt`, and `seed_hash`. The resulting hash, termed `bullet_index_hash`, acts as a commitment to the initial state of the game. It ensures that the starting position of the bullet, along with the game's foundational parameters, remains tamper-proof.

- Public Key: The function extracts the public key from the provided private key. This public key, represented in PEM format as `public_key_pem`, will be used later for verification purposes. It ensures that any cryptographic proof provided by the server can be verified by the player.

```python
  bullet_index_hash = hashlib.pbkdf2_hmac(
    ALGO,
    (str(bullet_index) + salt + seed_hash).encode(),
    salt.encode(),
    ITERATIONS
  ).hex()

  public_key_pem = private_key.verifying_key.to_pem()
```


## Generating Random Values
The generation of random values is a crucial step in the game's lifecycle, ensuring unpredictability and fairness. This process is primarily handled by the `generate_random_value_and_proof` function in the `VRF.py` script. Let's delve into its components and their significance:

#### Proof Generation:
- Function `generate_random_value_and_proof` calls function `generate_proof` to produce a cryptographic proof using the provided private key and the input message (`alpha`).
- This proof acts as a signature, ensuring that the generated random value (`beta`) can be verified against the original input message (`alpha`).

```python
proof = generate_proof(private_key, alpha)
```

#### Beta Value Calculation:
- Function `generate_random_value_and_proof` calls function `generate_beta` to produce a `beta` value using the generated `proof, salt, and seed hash`.
- The `beta` value is deterministic yet unpredictable, derived from the proof, salt, and chamber index. It ensures that each game round, even with the same input message, will have a unique outcome due to the varying proof and seed hash.

```python
beta = generate_beta(proof, salt, bullet_index)
```







### Significance of Generating Random Values:

#### Unpredictability:
The use of cryptographic proofs and the PBKDF2 HMAC SHA-256 hashing algorithm ensures that the generated values (`beta` and the derived chamber index) are unpredictable. This guarantees that players cannot foresee the game's outcome.

#### Verifiability:
The generated proof allows players to verify that the random values were derived from the original input message (`alpha`). This ensures that the server did not tamper with the game's outcome.

#### Integrity:
The entire process of generating random values is deterministic, meaning that for the same input parameters, the function will always produce the same output. However, due to the varying input message (`alpha`) and chamber index, the outcome is unique for each game round.

### Generating Random Values Summary:
The generation of random values in the game is a combination of cryptographic operations that ensure unpredictability, verifiability, and integrity. These values play a pivotal role in determining the game's outcome, and their generation process ensures that the game remains provably fair.









## TLDR
VRF Mechanism Breakdown:
Seed, Salt, and Seed Hash Generation:
  - A random `seed` and `salt` are generated using the secrets module.
  - A `seed hash` is then generated using the PBKDF2 HMAC algorithm with the seed and salt as inputs.
Proof Generation:
  - A `proof` is generated using the private key (sk) and an input message (`alpha`). The input message is created by concatenating the current UNIX timestamp with the array of player bets.
  - The `proof` is signed using the ECDSA algorithm with the SHA-256 hash function.
Beta Generation:
  - `Beta` is generated using the PBKDF2 HMAC algorithm with the seed hash, salt, and proof as inputs.
Bullet Index Determination:
  - The `bullet index` is determined by taking the integer representation of beta and then computing its modulo with the revolver size.
Bullet Index Hash Generation:
  - A `bullet index hash` of the bullet index is generated using the PBKDF2 HMAC algorithm with the bullet index, salt, and seed hash as inputs.
Verification:
  - A `public key` is extracted from a private key.
  - A `proof` is verified using the `public key` and an input message (`alpha`).
  - A deterministic `beta` is generated using the `proof, salt, and seed hash`.
  - The `bullet index` is derived from this beta.
  - A `derived bullet index hash` is generated using the derived bullet index, salt, and seed hash.
  - The derived bullet index hash is then compared with the bullet index hash generated during the game setup to verify the game's fairness.