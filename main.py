import base64
import os
from tkinter import Tk, Label, Entry, Button, Text, END, messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# Fichiers où la clé et les mots de passe chiffrés sont stockés
KEY_FILE = "secret.key"
PASSWORDS_FILE = "passwords.txt"

# Salt fixe pour garantir que la clé reste la même entre le chiffrement et le déchiffrement
SALT = b'super_secure_salt'


# Fonction pour dériver une clé Fernet à partir du mot de passe utilisateur
def derive_key_from_password(password):
    password = password.encode()  # Convertir le mot de passe en bytes

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Utilise SHA-256
        length=32,  # 32 octets pour Fernet
        salt=SALT,  # Utiliser un salt fixe
        iterations=100000,  # Rend le calcul plus coûteux pour plus de sécurité
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))  # Dériver la clé et l'encoder en Base64
    return key


# Fonction pour générer et sauvegarder une clé dans le fichier secret.key
def generate_and_save_key(password):
    key = derive_key_from_password(password)  # Dérive la clé à partir du mot de passe
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)  # Sauvegarder la clé dans le fichier
    return Fernet(key)


# Fonction pour charger la clé à partir de secret.key
def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
            return Fernet(key)
    else:
        return None


# Fonction pour chiffrer un mot de passe
def encrypt_password(key, password):
    return key.encrypt(password.encode())


# Fonction pour déchiffrer un mot de passe
def decrypt_password(key, encrypted_password):
    try:
        return key.decrypt(encrypted_password.encode()).decode()
    except Exception as e:
        messagebox.showerror("Erreur", "Impossible de déchiffrer les mots de passe.")
        return None


# Fonction pour vérifier si c'est la première exécution
def is_first_run():
    return not os.path.exists(PASSWORDS_FILE)


# Fonction pour sauvegarder un mot de passe dans le fichier
def save_password(service, password, key):
    encrypted_password = encrypt_password(key, password)

    with open(PASSWORDS_FILE, "a") as f:
        f.write(f"{service}:{encrypted_password.decode()}\n")
    messagebox.showinfo("Succès", "Mot de passe sauvegardé avec succès.")


# Fonction pour lire et déchiffrer les mots de passe du fichier
def read_passwords(key):
    if not os.path.exists(PASSWORDS_FILE):
        messagebox.showwarning("Erreur", "Aucun fichier de mots de passe trouvé.")
        return None

    try:
        with open(PASSWORDS_FILE, "r") as f:
            data = f.readlines()
            if not data:
                messagebox.showwarning("Erreur", "Aucun mot de passe stocké.")
                return None
            result = ""
            for line in data:
                service, encrypted_password = line.strip().split(":")
                decrypted_password = decrypt_password(key, encrypted_password)
                result += f"Service: {service} | Mot de passe: {decrypted_password}\n"
            return result
    except FileNotFoundError:
        messagebox.showwarning("Erreur", "Le fichier n'existe pas.")
        return None


# Fonction pour afficher les mots de passe déchiffrés
def show_passwords():
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Erreur", "Veuillez entrer un mot de passe.")
        return

    # Charger la clé à partir du fichier secret.key
    key = load_key()
    if key:
        passwords = read_passwords(key)
        if passwords:
            result_text.delete(1.0, END)
            result_text.insert(END, passwords)
    else:
        messagebox.showwarning("Erreur", "La clé de chiffrement n'a pas été trouvée.")


# Fonction pour ajouter un nouveau mot de passe
def add_password():
    service = service_entry.get()
    password = new_password_entry.get()
    master_password = password_entry.get()

    if not service or not password or not master_password:
        messagebox.showwarning("Erreur", "Veuillez remplir tous les champs.")
        return

    # Charger ou générer une clé dérivée
    key = load_key()
    if not key:  # Si aucune clé n'existe, en générer une
        key = generate_and_save_key(master_password)
        messagebox.showinfo("Clé créée", "Une nouvelle clé de chiffrement a été générée et sauvegardée.")

    # Sauvegarder le mot de passe
    save_password(service, password, key)
    service_entry.delete(0, END)
    new_password_entry.delete(0, END)


# Interface utilisateur Tkinter
root = Tk()
root.title("Gestionnaire de mots de passe sécurisé")

# Vérification de la première exécution
if is_first_run():
    messagebox.showinfo("Première exécution",
                        "Bienvenue ! Entrez un mot de passe maître pour générer une clé de chiffrement.")

# Entrée pour le mot de passe maître
Label(root, text="Entrez votre mot de passe maître :").grid(row=0, column=0, padx=10, pady=10)
password_entry = Entry(root, show="*", width=30)
password_entry.grid(row=0, column=1, padx=10, pady=10)

# Bouton pour afficher les mots de passe
show_button = Button(root, text="Afficher les mots de passe", command=show_passwords)
show_button.grid(row=1, column=1, padx=10, pady=10)

# Zone de texte pour afficher les résultats
result_text = Text(root, height=10, width=50)
result_text.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

# Entrée pour le service/site
Label(root, text="Service/Site :").grid(row=3, column=0, padx=10, pady=10)
service_entry = Entry(root, width=30)
service_entry.grid(row=3, column=1, padx=10, pady=10)

# Entrée pour le mot de passe à ajouter
Label(root, text="Mot de passe :").grid(row=4, column=0, padx=10, pady=10)
new_password_entry = Entry(root, show="*", width=30)
new_password_entry.grid(row=4, column=1, padx=10, pady=10)

# Bouton pour ajouter le mot de passe
add_button = Button(root, text="Ajouter le mot de passe", command=add_password)
add_button.grid(row=5, column=1, padx=10, pady=10)

# Lancement de la fenêtre Tkinter
root.mainloop()
