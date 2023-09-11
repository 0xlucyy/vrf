#!/bin/bash

# Run tests with coverage
coverage run -m pytest tests/

# Generate a coverage report
coverage report -m > coverage.txt

# # Create a temporary file
# temp_file="temp_readme.md"

# # Split README.md at "VRF Code Coverage:" and save the first part to the temporary file
# sed -n '1,/VRF Code Coverage:/p' README.md > $temp_file

# # Append coverage.txt content to the temporary file
# cat coverage.txt >> $temp_file

# # Append the remaining part of README.md after "VRF Code Coverage:" to the temporary file
# sed -n '/VRF Code Coverage:/,$p' README.md >> $temp_file

# # # Replace README.md with the temporary file
# # mv $temp_file README.md

# # Clean up
# # rm coverage.txt
# rm .coverage
# # rm -f .pytest_cache
