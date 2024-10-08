import base64
import struct


def decomposer_message_fernet(token):
    # Décodage du message Fernet de la base64
    data = base64.urlsafe_b64decode(token)

    # Extraction de la version (1 byte)
    version = data[0]

    # Extraction de l'horodatage (8 bytes)
    timestamp = struct.unpack(">Q", data[1:9])[0]  # ">Q" pour un entier non signé de 8 octets (Big-endian)

    # Extraction de l'IV (16 bytes)
    iv = data[9:25]

    # Extraction des données chiffrées (de 25 à -32)
    encrypted_data = data[25:-32]

    # Extraction du HMAC (les 32 derniers bytes)
    hmac = data[-32:]

    # Affichage des différentes parties
    print("Version         :", version)
    print("Horodatage      :", timestamp)
    print("IV              :", iv.hex())
    print("Données chiffrées:", encrypted_data.hex())
    print("HMAC            :", hmac.hex())


# Exemple d'utilisation
token = input("Entrez le message Fernet chiffré: ")
decomposer_message_fernet(token)
