import unittest
import ecdsa
from VRF import (
    new_game,
    end_game,
    verify,
    generate_random_value_and_proof
)
import time



class TestIntegration(unittest.TestCase):

  def test_vrf_various_scenarios(self):
    """
    Test the VRF system end-to-end for various scenarios to ensure
    consistent and correct behavior across different inputs.

    Steps:
    1. Define multiple scenarios with varying revolver sizes and bets.
    2. For each scenario:
        a. Generate a timestamp and convert the bets to a byte-encoded alpha.
        b. Generate a private key for signing.
        c. Initialize a new game to get the initial hash, salt, and chamber index.
        d. End the game to get the beta, proof, and public key.
        e. Verify the outcome of the game using the provided values.
        f. Assert that the verification result is True.

    Expected Outcome:
    The VRF system should correctly verify the outcome for each scenario,
    returning True for each verification.

    """

    # Step 1: Define multiple scenarios with varying revolver sizes and bets.
    scenarios = [
      {
        "revolver_size": 50,
        "bets": [30000, 30000, 30000, 30000]
      },
      {
        "revolver_size": 6,
        "bets": [100, 200, 300]
      },
      {
        "revolver_size": 10,
        "bets": [500, 1000, 1500, 2000, 2500]
      },
      {
        "revolver_size": 25,
        "bets": [50, 100, 150, 200]
      },
      {
        "revolver_size": 2,
        "bets": [100, 100]
      }
    ]

    for scenario in scenarios:
      # Step 2a: Generate a timestamp and convert the bets to a byte-encoded alpha.
      timestamp = str(int(time.time()))
      alpha_raw = (timestamp + ''.join(map(str, scenario["bets"])))
      alpha = alpha_raw.encode()

      # Step 2b: Generate a private key for signing.
      sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

      # Step 2c: Initialize a new game to get the initial hash, salt, and chamber index.
      initial_hash, salt, chamber_index, seed_hash = new_game(scenario["revolver_size"], scenario["bets"])

      # Step 2d: End the game to get the beta, proof, and public key.
      beta, proof, public_key_pem, _ = end_game(sk, alpha, scenario["revolver_size"], salt, chamber_index, seed_hash)

      # Step 2e: Verify the outcome of the game using the provided values.
      result = verify(public_key_pem, alpha, beta, proof, initial_hash, salt, scenario["revolver_size"], seed_hash)

      # Step 2f: Assert that the verification result is True.
      self.assertTrue(result, f"VRF verification failed for revolver size {scenario['revolver_size']} and bets {scenario['bets']}!")
