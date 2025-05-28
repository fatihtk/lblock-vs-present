import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# --- RSA Anahtar Fonksiyonları ---

def generate_rsa_key_pair(key_size=2048, public_exponent=65537):
    """Alice için RSA özel ve genel anahtar çifti üretir."""
    print(f"Alice RSA {key_size}-bit anahtar çifti üretiyor...")
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    print("Alice'in RSA anahtar çifti başarıyla üretildi.\n")
    return private_key, public_key

def serialize_public_key_to_pem(public_key):
    """RSA genel anahtarını PEM formatında serileştirir (Bob'a göndermek için)."""
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_public_key

def deserialize_pem_to_public_key(pem_data):
    """PEM formatındaki RSA genel anahtarını yükler (Bob'un Alice'in anahtarını alması)."""
    public_key = serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )
    return public_key

# --- Simetrik Anahtar Fonksiyonları ---

def generate_symmetric_key(length_bytes=10): # 80-bit = 10 byte
    """Bob tarafından belirlenen uzunlukta rastgele bir simetrik anahtar üretir."""
    print(f"Bob {length_bytes*8}-bit'lik simetrik anahtar üretiyor...")
    symmetric_key = os.urandom(length_bytes)
    print(f"Bob'un ürettiği simetrik anahtar (hex): {symmetric_key.hex()}\n")
    return symmetric_key

# --- Şifreleme/Deşifreleme Fonksiyonları (RSA ile Simetrik Anahtar için) ---

def encrypt_symmetric_key_with_rsa(symmetric_key, public_key):
    """Bob, simetrik anahtarı Alice'in RSA genel anahtarıyla şifreler."""
    print("Bob, simetrik anahtarı Alice'in RSA genel anahtarı ile şifreliyor...")
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Bob tarafından şifrelenmiş simetrik anahtar (ilk 16 byte hex): {encrypted_symmetric_key[:16].hex()}...\n")
    return encrypted_symmetric_key

def decrypt_symmetric_key_with_rsa(encrypted_symmetric_key, private_key):
    """Alice, Bob'dan gelen şifreli simetrik anahtarı kendi RSA özel anahtarıyla çözer."""
    print("Alice, Bob'dan gelen şifreli simetrik anahtarı çözüyor...")
    decrypted_symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Alice'in çözdüğü simetrik anahtar (hex): {decrypted_symmetric_key.hex()}\n")
    return decrypted_symmetric_key

# --- Anahtar Değişim Simülasyonu ---

def simulate_key_exchange():
    print("=== RSA ile Simetrik Anahtar Değişim Simülasyonu Başlıyor ===\n")

    # 1. Alice RSA anahtar çiftini üretir.
    alice_private_key, alice_public_key = generate_rsa_key_pair()

    # 2. Alice genel anahtarını serileştirir (Bob'a göndermek için).
    #    Gerçek bir uygulamada bu adım güvenli bir kanal üzerinden yapılmalıdır
    #    veya bir sertifika otoritesi (CA) kullanılmalıdır.
    pem_alice_public_key = serialize_public_key_to_pem(alice_public_key)
    print(f"Alice, genel anahtarını PEM formatında hazırladı (Bob'a gönderilecek):\n{pem_alice_public_key.decode()[:150]}...\n")

    # --- Bob'un Tarafı ---
    print("--- Bob'un İşlemleri ---")
    # 3. Bob, Alice'in PEM formatındaki genel anahtarını alır ve yükler.
    bob_receives_alice_public_key = deserialize_pem_to_public_key(pem_alice_public_key)
    print("Bob, Alice'in genel anahtarını başarıyla aldı ve yükledi.\n")

    # 4. Bob, LBlock/PRESENT için kullanılacak 80-bitlik simetrik anahtarı üretir.
    #    Bu anahtar sizin LBlock/PRESENT kodunuzda kullanacağınız anahtardır.
    symmetric_key_by_bob = generate_symmetric_key(length_bytes=10) # 80-bit

    # 5. Bob, ürettiği simetrik anahtarı Alice'in genel RSA anahtarı ile şifreler.
    encrypted_key_for_alice = encrypt_symmetric_key_with_rsa(
        symmetric_key_by_bob,
        bob_receives_alice_public_key
    )

    # --- Alice'in Tarafı ---
    print("--- Alice'in İşlemleri ---")
    # 6. Alice, Bob'dan gelen şifreli simetrik anahtarı alır.
    #    (Simülasyonda doğrudan `encrypted_key_for_alice` kullanılır)
    print("Alice, Bob'dan şifrelenmiş simetrik anahtarı aldı.")

    # 7. Alice, şifreli anahtarı kendi özel RSA anahtarı ile çözer.
    decrypted_symmetric_key_by_alice = decrypt_symmetric_key_with_rsa(
        encrypted_key_for_alice,
        alice_private_key
    )

    # 8. Doğrulama: Bob'un ürettiği anahtar ile Alice'in çözdüğü anahtar aynı mı?
    print("=== Doğrulama ===")
    if symmetric_key_by_bob == decrypted_symmetric_key_by_alice:
        print("Başarılı! 🎉 Alice ve Bob aynı simetrik anahtara sahip.")
        print(f"Paylaşılan Simetrik Anahtar (Hex): {decrypted_symmetric_key_by_alice.hex()}")
        print("Bu anahtar artık LBlock/PRESENT gibi simetrik şifreleme algoritmalarında kullanılabilir.")
    else:
        print("Hata! ❌ Anahtar değişimi başarısız oldu. Anahtarlar eşleşmiyor.")
        print(f"Bob'un anahtarı: {symmetric_key_by_bob.hex()}")
        print(f"Alice'in çözdüğü: {decrypted_symmetric_key_by_alice.hex()}")

    print("\n=== Simülasyon Tamamlandı ===")
    return decrypted_symmetric_key_by_alice.hex() # Kullanılacak anahtarı döndür

if __name__ == "__main__":
    # `cryptography` kütüphanesi yüklü değilse: pip install cryptography
    try:
        shared_key_hex = simulate_key_exchange()
        if shared_key_hex:
            print(f"\nAna programda kullanılabilecek 80-bit anahtar (20 hex karakter): {shared_key_hex}")
            print("Bu anahtarı kopyalayıp LBlock/PRESENT uygulamanızda kullanabilirsiniz.")
    except ImportError:
        print("Hata: 'cryptography' kütüphanesi bulunamadı.")
        print("Lütfen 'pip install cryptography' komutu ile yükleyin.")
    except Exception as e:
        print(f"Simülasyon sırasında bir hata oluştu: {e}")