"""
Universidad del Valle de Guatemala
Cifrado de Información
Ejercicio - JWT
Santiago Taracena Puga (20017)
"""

# Librerías necesarias para el ejercicio.
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generación de claves RSA.
private_key = rsa.generate_private_key(
    public_exponent=65_537,
    key_size=2_048,
)

# Exportación de la clave privada.
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

# Exportación de la clave pública correspondiente.
public_key_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# Información (payload) a incluir en el JWT.
payload = {
    "id": "753",
    "username": "santiago01",
    "email": "santiagotaracena01@example.com",
}

# Creación del JWT firmado.
encoded_jwt = jwt.encode(payload, private_key_pem, algorithm="RS256")
print("JWT Firmado:", encoded_jwt)

# Try-catch que verifica el JWT firmado.
try:
    # Verificación del JWT usando la clave pública.
    decoded_payload = jwt.decode(encoded_jwt, public_key_pem, algorithms=["RS256"])
    print("JWT verificado. Payload:", decoded_payload)

# Manejo de errores de expiración de tokens.
except jwt.ExpiredSignatureError:
    print("El token ha expirado.")

# Manejo de errores de tokens inválidos.
except jwt.InvalidTokenError:
    print("El token es inválido.")
