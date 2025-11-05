from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

algoritmos = {
    "AES": {
        "modulo": AES,
        "key_size": 32,  # AES-256 
        "iv_size": 16    # Bloque AES es 16 bytes
    },
    "DES": {
        "modulo": DES,
        "key_size": 8,   # Clave DES es 8 bytes
        "iv_size": 8     # Bloque DES es 8 bytes
    },
    "3DES": {
        "modulo": DES3,
        "key_size": 24,  # 3 claves * 8 bytes = 24 bytes
        "iv_size": 8     # Bloque 3DES es 8 bytes
    }
}

def adjust_key(key_bytes, required_size, algo_name):
    
    if algo_name == "3DES" and required_size == 24 and len(key_bytes) == 16:
        print(f"  -> Clave 3DES de 16 bytes detectada. Aplicando K1-K2-K1.")
        return key_bytes + key_bytes[:8]
    
    if len(key_bytes) < required_size:
        padding = get_random_bytes(required_size - len(key_bytes))
        print(f"  -> Clave corta. Rellenando con {len(padding)} bytes aleatorios.")
        return key_bytes + padding
    elif len(key_bytes) > required_size:
        print(f"  -> Clave larga. Truncando a {required_size} bytes.")
        return key_bytes[:required_size]
    else:
        return key_bytes

def do_encrypt(algo_name):
    print(f"\n--- Cifrando con {algo_name} ---")
    config = algoritmos[algo_name]
    Modulo = config["modulo"]
    KEY_SIZE = config["key_size"]
    IV_SIZE = config["iv_size"]

    key_input = input("  Ingrese clave (ASCII): ")
    iv_input = input("  Ingrese IV (ASCII): ")
    string_input = input("  Texto a cifrar (ASCII): ")
    
    key_bytes = key_input.encode()
    iv_bytes = iv_input.encode()
    text_bytes = string_input.encode()

    final_key = adjust_key(key_bytes, KEY_SIZE, algo_name)
    
    while len(iv_bytes) != IV_SIZE:
        print(f"\n[ERROR] El IV debe tener exactamente {IV_SIZE} bytes. (Ingresaste {len(iv_bytes)})")
        iv_input = input(f"  Ingrese IV (ASCII) de {IV_SIZE} bytes: ")
        iv_bytes = iv_input.encode()
    final_iv = iv_bytes
    
    print("\n--- Resumen de Parámetros ---")
    print(f"  Clave final ({KEY_SIZE} bytes): {final_key.hex()}")
    print(f"  IV usado ({IV_SIZE} bytes):    {final_iv.hex()}")

    try:
        cipher = Modulo.new(final_key, Modulo.MODE_CBC, final_iv)
        ciphertext = cipher.encrypt(pad(text_bytes, Modulo.block_size))
        print("\n--- Resultado ---")
        print(f"  Texto cifrado (HEX): {ciphertext.hex()}")
    except Exception as e:
        print(f"\n[ERROR] Ocurrió un error inesperado: {e}")

def do_decrypt(algo_name):
    print(f"\n--- Descifrando con {algo_name} ---")
    config = algoritmos[algo_name]
    Modulo = config["modulo"]
    KEY_SIZE = config["key_size"]
    IV_SIZE = config["iv_size"]

    key_input = input("  Ingrese clave (ASCII): ")
    iv_input = input("  Ingrese IV (ASCII): ")
    hex_input = input("  Texto cifrado (HEX): ").strip()

    key_bytes = key_input.encode()
    iv_bytes = iv_input.encode()
    
    try:
        ciphertext = bytes.fromhex(hex_input)
    except ValueError as e:
        print(f"\n[ERROR] El texto HEX no es válido.")
        return

    final_key = adjust_key(key_bytes, KEY_SIZE, algo_name)
    
    while len(iv_bytes) != IV_SIZE:
        print(f"\n[ERROR] El IV debe tener exactamente {IV_SIZE} bytes. (Ingresaste {len(iv_bytes)})")
        iv_input = input(f"  Ingrese IV (ASCII) de {IV_SIZE} bytes: ")
        iv_bytes = iv_input.encode()
    final_iv = iv_bytes

    print("\n--- Resumen de Parámetros ---")
    print(f"  Clave final ({KEY_SIZE} bytes): {final_key.hex()}")
    print(f"  IV usado ({IV_SIZE} bytes):    {final_iv.hex()}")

    try:
        decipher = Modulo.new(final_key, Modulo.MODE_CBC, final_iv)
        plaintext_bytes = unpad(decipher.decrypt(ciphertext), Modulo.block_size)
        print("\n--- Resultado ---")
        print(f"  Texto descifrado (UTF-8): {plaintext_bytes.decode()}")
    except ValueError as e:
        if "Incorrect padding" in str(e) or "unpad" in str(e):
            print(f"\n[ERROR] Error de descifrado. Clave, IV o texto cifrado incorrectos.")
        else:
            print(f"\n[ERROR] Ocurrió un error de valor: {e}")
    except Exception as e:
        print(f"\n[ERROR] Ocurrió un error inesperado: {e}")

def main_menu():
    while True:
        print("\n======== Menú de Cifrado (Lab 4) ========")
        print("  --- DES ---")
        print("  1. Cifrar con DES")
        print("  2. Descifrar con DES")
        print("  --- AES-256 ---")
        print("  3. Cifrar con AES-256")
        print("  4. Descifrar con AES-256")
        print("  --- 3DES ---")
        print("  5. Cifrar con 3DES")
        print("  6. Descifrar con 3DES")
        print("  -----------------")
        print("  7. Salir")
        
        choice = input("Ingrese su opción (1-7): ")
        
        if choice == '1':
            do_encrypt("DES")
        elif choice == '2':
            do_decrypt("DES")
        elif choice == '3':
            do_encrypt("AES")
        elif choice == '4':
            do_decrypt("AES")
        elif choice == '5':
            do_encrypt("3DES")
        elif choice == '6':
            do_decrypt("3DES")
        elif choice == '7':
            print("Saliendo del programa...")
            break
        else:
            print("[Error] Opción no válida. Por favor, intente de nuevo.")

if __name__ == "__main__":
    main_menu()