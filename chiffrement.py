import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet

# Générer une clé de chiffrement (normalement, on la sauvegarde pour une utilisation future)
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Fonction pour chiffrer le mot de passe
def encrypt_password():
    password = password_entry.get()
    if password:  # Vérifier que le champ n'est pas vide
        encrypted_password = cipher_suite.encrypt(password.encode())
        result_label.config(text=f"Mot de passe chiffré : {encrypted_password.decode()}")
        encrypted_entry.delete(0, tk.END)  # Vider le champ de saisie de mot de passe chiffré
        encrypted_entry.insert(0, encrypted_password.decode())  # Insérer le mot de passe chiffré dans le champ
    else:
        messagebox.showwarning("Erreur", "Veuillez entrer un mot de passe.")

# Fonction pour déchiffrer le mot de passe
def decrypt_password():
    encrypted_password = encrypted_entry.get().encode()  # Obtenir le mot de passe chiffré depuis le champ
    try:
        decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
        result_label.config(text=f"Mot de passe déchiffré : {decrypted_password}")
    except Exception as e:
        messagebox.showerror("Erreur", "Impossible de déchiffrer.")

# Créer la fenêtre principale
root = tk.Tk()
root.title("Chiffrement et Déchiffrement")

# Label et champ d'entrée pour le mot de passe
tk.Label(root, text="Entrez un mot de passe :").grid(row=0, column=0, padx=10, pady=10)
password_entry = tk.Entry(root, show="*", width=30)
password_entry.grid(row=0, column=1, padx=10, pady=10)

# Bouton pour chiffrer le mot de passe
encrypt_button = tk.Button(root, text="Chiffrer", command=encrypt_password)
encrypt_button.grid(row=1, column=0, padx=10, pady=10)

# Champ pour entrer le mot de passe chiffré
tk.Label(root, text="Mot de passe chiffré :").grid(row=2, column=0, padx=10, pady=10)
encrypted_entry = tk.Entry(root, width=50)
encrypted_entry.grid(row=2, column=1, padx=10, pady=10)

# Bouton pour déchiffrer le mot de passe
decrypt_button = tk.Button(root, text="Déchiffrer", command=decrypt_password)
decrypt_button.grid(row=3, column=0, padx=10, pady=10)

# Label pour afficher le résultat
result_label = tk.Label(root, text="")
result_label.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

# Lancer la boucle principale Tkinter
root.mainloop()

