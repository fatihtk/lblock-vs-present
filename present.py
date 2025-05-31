from utils import bytes_to_int, int_to_bytes


# --- PRESENT Sabitleri ve Fonksiyonları ---
SBOX_PRESENT = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]

P_LAYER_PRESENT = [
     0, 16, 32, 48,  1, 17, 33, 49,  2, 18, 34, 50,  3, 19, 35, 51,
     4, 20, 36, 52,  5, 21, 37, 53,  6, 22, 38, 54,  7, 23, 39, 55,
     8, 24, 40, 56,  9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
]

# PRESENT Parametreleri
BLOCK_SIZE_BITS_PRESENT = 64
BLOCK_SIZE_BYTES_PRESENT = BLOCK_SIZE_BITS_PRESENT // 8
KEY_SIZE_BITS_PRESENT = 80 # Bu örnekte 80-bit kullanılıyor
KEY_SIZE_BYTES_PRESENT = KEY_SIZE_BITS_PRESENT // 8
NUM_ROUNDS_PRESENT = 31

# --- Anahtar Planı (80-bit için - PRESENT) ---
def key_schedule_80_present(master_key_int):
    """80-bit anahtardan 32 adet 64-bit round anahtarı üretir (K1...K32)."""
    if not (0 <= master_key_int < (1 << KEY_SIZE_BITS_PRESENT)):
        raise ValueError("PRESENT master key integer değeri 80-bit aralığında olmalı.")

    round_keys = [0] * (NUM_ROUNDS_PRESENT + 1) # 32 anahtar (Index 0..31 => K1..K32)
    key_reg = master_key_int # 80-bit anahtar register'ı k79 k78 ... k0

    mask_80 = (1 << 80) - 1
    mask_64 = (1 << 64) - 1

    for i in range(1, NUM_ROUNDS_PRESENT + 2): # i = 1..32 (Round counter)
        # 1. Round anahtarını al (Register'ın sol 64 biti: k79..k16)
        round_keys[i-1] = (key_reg >> (80 - 64)) & mask_64

        # 2. Register'ı Güncelle (bir sonraki round anahtarı için)
        # a. 61 bit sola dairesel döndür: [k79..k0] = [k18..k0 k79..k19]
        key_reg = ((key_reg << 61) | (key_reg >> (80 - 61))) & mask_80

        # b. S-Box uygula (Yeni register'ın sol 4 bitine: k79..k76)
        s_input = (key_reg >> (80 - 4)) & 0xF
        s_output = SBOX_PRESENT[s_input]
        # Eski sol 4 biti sil (sıfırla) ve yeni S-Box sonucunu ekle
        key_reg = (key_reg & ((1 << (80 - 4)) - 1)) | (s_output << (80 - 4))

        # c. Round counter (i) ile XOR (k[19..15] pozisyonlarına)
        # Register'daki bit 19, 18, 17, 16, 15 ile round_counter'ın 5 biti XORlanır.
        round_counter_5bit = i & 0x1F # Sadece 5 bit (1'den 31 veya 32 olacağı için sorun yok)
        # bit 15'ten başlayacak şekilde XORla
        key_reg ^= (round_counter_5bit << 15)
        key_reg &= mask_80 # Gerekli değil ama garanti olsun

    return round_keys

# --- Round Fonksiyonları (PRESENT) ---
def add_round_key_present(state, round_key):
    """State ile round anahtarını XOR'lar."""
    return state ^ round_key

def sbox_layer_present(state):
    """64-bit state'in her 4-bitlik nibble'ına S-Box uygular."""
    output = 0
    for i in range(16): # 64 bit / 4 bit = 16 nibble
        # Sağdan i. 4-bitlik bloğu al (i=0 -> bit 3..0, i=15 -> bit 63..60)
        start_bit = i * 4
        nibble = (state >> start_bit) & 0xF
        s_out = SBOX_PRESENT[nibble]
        output |= (s_out << start_bit)
    return output

def p_layer_present(state):
    """64-bit state'e P-Layer permütasyonunu uygular."""
    output = 0
    for i in range(64):
        # Eğer girişin i. biti 1 ise, çıkışın P_LAYER_PRESENT[i]. bitini 1 yap
        if (state >> i) & 1:
            output |= (1 << P_LAYER_PRESENT[i])
    return output

# --- Şifreleme (PRESENT) ---
def encrypt_block_present(plaintext_int, round_keys):
    """Tek bir 64-bit bloğu PRESENT ile şifreler."""
    state = plaintext_int

    # Round 1 to 31
    for i in range(NUM_ROUNDS_PRESENT): # i = 0..30
        state = add_round_key_present(state, round_keys[i]) # K1..K31 kullanılır (index 0..30)
        state = sbox_layer_present(state)
        state = p_layer_present(state)

    # Son AddRoundKey (K32 ile)
    state = add_round_key_present(state, round_keys[NUM_ROUNDS_PRESENT]) # round_keys[31] yani K32

    return state

# --- Ana Şifreleme Fonksiyonu (Byte Girdi/Çıktı - PRESENT) ---
def encrypt_present(plaintext_bytes, key_bytes):
    """Byte dizisi girdiyi PRESENT ile şifreler (ECB modu).
       Girdi uzunluğu blok boyutunun katı değilse, sonuna boşluk (0x20) byte'ları eklenir.
       DİKKAT: ECB modu güvensizdir. Boşluk padding'i standart değildir.
    """
    if len(key_bytes) != KEY_SIZE_BYTES_PRESENT:
        raise ValueError(f"PRESENT Şifreleme Hatası: Anahtar uzunluğu ({len(key_bytes)} bytes) "
                         f"{KEY_SIZE_BYTES_PRESENT} bytes olmalı.")

    master_key_int = bytes_to_int(key_bytes)
    try:
        round_keys = key_schedule_80_present(master_key_int) # 80-bit anahtar planı
    except ValueError as e:
        raise ValueError(f"PRESENT Anahtar Planı Hatası: {e}") from e

    # --- Padding Başlangıcı ---
    original_length = len(plaintext_bytes)
    remainder = original_length % BLOCK_SIZE_BYTES_PRESENT
    padded_plaintext_bytes = plaintext_bytes

    if remainder != 0:
        bytes_to_add = BLOCK_SIZE_BYTES_PRESENT - remainder
        padding = b' ' * bytes_to_add
        padded_plaintext_bytes += padding
        print(f"Bilgi (PRESENT): Girdi {original_length} byte idi. {bytes_to_add} boşluk byte'ı ile dolduruldu. Yeni boyut: {len(padded_plaintext_bytes)}")
    # --- Padding Sonu ---

    if len(padded_plaintext_bytes) == 0:
        print("Uyarı (PRESENT): Şifrelenecek veri boş.")
        return b''

    ciphertext_bytes = b''
    for i in range(0, len(padded_plaintext_bytes), BLOCK_SIZE_BYTES_PRESENT):
        block = padded_plaintext_bytes[i : i + BLOCK_SIZE_BYTES_PRESENT]
        block_int = bytes_to_int(block)
        encrypted_block_int = encrypt_block_present(block_int, round_keys)
        encrypted_block_bytes = int_to_bytes(encrypted_block_int, BLOCK_SIZE_BYTES_PRESENT)
        if encrypted_block_bytes is None:
             raise ValueError("PRESENT Şifreleme Hatası: Şifrelenmiş blok integer'dan byte'a dönüştürülemedi.")
        ciphertext_bytes += encrypted_block_bytes

    return ciphertext_bytes

# --- Deşifreleme (PRESENT) ---
# Deşifreleme için gerekli ters fonksiyonlar
INV_P_LAYER_PRESENT = [0] * 64
for i in range(64):
    INV_P_LAYER_PRESENT[P_LAYER_PRESENT[i]] = i

def inverse_p_layer_present(state):
    """64-bit state'e ters P-Layer permütasyonunu uygular."""
    output = 0
    for i in range(64):
        # Eğer girişin i. biti 1 ise, çıkışın INV_P_LAYER_PRESENT[i]. bitini 1 yap
        if (state >> i) & 1:
            output |= (1 << INV_P_LAYER_PRESENT[i])
    return output

INV_SBOX_PRESENT = [0] * 16
for i in range(16):
    INV_SBOX_PRESENT[SBOX_PRESENT[i]] = i

def inverse_sbox_layer_present(state):
    """64-bit state'in her 4-bitlik nibble'ına ters S-Box uygular."""
    output = 0
    for i in range(16): # 16 nibble
        start_bit = i * 4
        nibble = (state >> start_bit) & 0xF
        s_out = INV_SBOX_PRESENT[nibble]
        output |= (s_out << start_bit)
    return output

def decrypt_block_present(ciphertext_int, round_keys):
    """Tek bir 64-bit bloğu PRESENT ile deşifreler."""
    state = ciphertext_int

    # Son AddRoundKey'i geri al (K32 ile)
    state = add_round_key_present(state, round_keys[NUM_ROUNDS_PRESENT]) # round_keys[31]

    # Round 31'den 1'e kadar ters sırada
    for i in range(NUM_ROUNDS_PRESENT - 1, -1, -1): # i = 30..0
        state = inverse_p_layer_present(state)
        state = inverse_sbox_layer_present(state)
        state = add_round_key_present(state, round_keys[i]) # K31..K1 kullanılır (index 30..0)

    return state

def decrypt_present(ciphertext_bytes, key_bytes):
    """Byte dizisi girdiyi PRESENT ile deşifreler (ECB modu)."""
    if len(ciphertext_bytes) == 0:
        print("Uyarı: Deşifrelenecek veri boş.")
        return b''
    if len(ciphertext_bytes) % BLOCK_SIZE_BYTES_PRESENT != 0:
        raise ValueError(f"PRESENT Deşifreleme Hatası: Şifrelenmiş metin uzunluğu ({len(ciphertext_bytes)} bytes) "
                         f"blok boyutunun ({BLOCK_SIZE_BYTES_PRESENT} bytes) katı olmalı (ECB modu).")
    if len(key_bytes) != KEY_SIZE_BYTES_PRESENT:
        raise ValueError(f"PRESENT Deşifreleme Hatası: Anahtar uzunluğu ({len(key_bytes)} bytes) "
                         f"{KEY_SIZE_BYTES_PRESENT} bytes olmalı.")

    master_key_int = bytes_to_int(key_bytes)
    try:
        round_keys = key_schedule_80_present(master_key_int)
    except ValueError as e:
        raise ValueError(f"PRESENT Anahtar Planı Hatası: {e}") from e

    plaintext_bytes = b''
    for i in range(0, len(ciphertext_bytes), BLOCK_SIZE_BYTES_PRESENT):
        block = ciphertext_bytes[i : i + BLOCK_SIZE_BYTES_PRESENT]
        block_int = bytes_to_int(block)
        decrypted_block_int = decrypt_block_present(block_int, round_keys)
        decrypted_block_bytes = int_to_bytes(decrypted_block_int, BLOCK_SIZE_BYTES_PRESENT)
        if decrypted_block_bytes is None:
             raise ValueError("PRESENT Deşifreleme Hatası: Deşifrelenmiş blok integer'dan byte'a dönüştürülemedi.")
        plaintext_bytes += decrypted_block_bytes

    return plaintext_bytes