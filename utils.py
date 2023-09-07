import hashlib
def deterministic_value(beta, salt, ITERATIONS):
  password = beta.encode()
  salt_value = salt.encode()
  deterministic_value = hashlib.pbkdf2_hmac('sha256', password, salt_value, ITERATIONS).hex()
  return hashlib.pbkdf2_hmac('sha256', password, salt_value, ITERATIONS).hex()