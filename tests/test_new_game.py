# import pytest
# from VRF import (
#     new_game
# )
# from error import SeedError, VerificationError, InputError
# from unittest.mock import patch

# class TestNewGame:

#     # Tests that the function initializes a new game with revolver size 2 and bets [1, 1]
#     def test_happy_path_revolver_size_2_bets_1_1(self):
#         """
#         Test the function new_game with a revolver size of 2 and bets [1, 1].
        
#         This test checks if the function can correctly initialize a new game
#         with the given parameters and return valid outputs.
#         """
#         revolver_size = 2
#         bets = [1, 1]
#         initial_hash, salt, chamber_index = new_game(revolver_size, bets)
#         assert isinstance(initial_hash, str)
#         assert isinstance(salt, str)
#         assert isinstance(chamber_index, int)


#     # Tests that the function initializes a new game with revolver size 50 and bets [1, 1, 1, 1]
#     def test_happy_path_revolver_size_50_bets_1_1_1_1(self):
#         """
#         Test the function new_game with a revolver size of 50 and bets [1, 1, 1, 1].
        
#         This test checks if the function can correctly initialize a new game
#         with the given parameters and return valid outputs.
#         """
#         revolver_size = 50
#         bets = [1, 1, 1, 1]
#         initial_hash, salt, chamber_index = new_game(revolver_size, bets)
#         assert isinstance(initial_hash, str)
#         assert isinstance(salt, str)
#         assert isinstance(chamber_index, int)
#         assert 2 <= chamber_index <= revolver_size


#     @patch("secrets.token_hex")
#     def test_happy_path_revolver_size_10_bets_0_0_0_0_0_0_0_0_0_0(self, mock_token_hex):
#         """
#         Test the function new_game with a revolver size of 10 and bets [0, 0, 0, 0, 0, 0, 0, 0, 0, 0].
        
#         This test checks if the function can correctly initialize a new game
#         with the given parameters and return valid outputs. The randomness of the
#         function is mocked to ensure repeatability.
#         """
#         # Mock the secrets.token_hex function to always return a fixed value
#         mock_token_hex.return_value = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

#         revolver_size = 10
#         bets = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
#         initial_hash, salt, chamber_index = new_game(revolver_size, bets)
#         assert isinstance(initial_hash, str)
#         assert isinstance(salt, str)
#         assert isinstance(chamber_index, int)
#         assert 2 <= chamber_index <= revolver_size


#     # Tests that the function raises an InputError when the revolver size is 1 and bets is [1]
#     def test_edge_case_revolver_size_1_bets_1(self):
#         """
#         Test the function new_game with a revolver size of 1 and bets [1].
        
#         This test checks if the function raises an InputError when provided with
#         an invalid revolver size.
#         """
#         revolver_size = 1
#         bets = [1]
#         with pytest.raises(InputError):
#             new_game(revolver_size, bets)


#     # Tests that the function raises an InputError when the revolver size is 51 and bets is [1, 1, 1, 1]
#     def test_edge_case_revolver_size_51_bets_1_1_1_1(self):
#         """
#         Test the function new_game with a revolver size of 51 and bets [1, 1, 1, 1].
        
#         This test checks if the function raises an InputError when provided with
#         an invalid revolver size.
#         """
#         revolver_size = 51
#         bets = [1, 1, 1, 1]
#         with pytest.raises(InputError):
#             new_game(revolver_size, bets)


#     # Tests that the function raises an InputError when the bets list is empty
#     def test_edge_case_revolver_size_10_bets_empty(self):
#         """
#         Test the function new_game with a revolver size of 10 and an empty bets list.
        
#         This test checks if the function raises an InputError when provided with
#         an empty bets list.
#         """
#         revolver_size = 10
#         bets = []
#         with pytest.raises(InputError):
#             new_game(revolver_size, bets)