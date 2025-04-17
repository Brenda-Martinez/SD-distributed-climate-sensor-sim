from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

print("Gerando par de chaves RSA (2048 bits)...")

# gera a chave privada
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# serializa a chave privada para formato PEM PKCS8 (sem senha)
pem_priv = private_key.private_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PrivateFormat.PKCS8,
   encryption_algorithm=serialization.NoEncryption()
)

# serializa a chave publica
pem_pub = public_key.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# salva as chaves em arquivos
try:
    with open('server_private.pem', 'wb') as f:
        f.write(pem_priv)
    print("Chave privada gerada...")

    with open('server_public.pem', 'wb') as f:
        f.write(pem_pub)
    print("Chave publica gerada...")

except IOError as e:
    print(f"Erro ao salvar arquivos de chave: {e}")