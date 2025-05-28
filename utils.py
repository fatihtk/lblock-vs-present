import time
import os
import sys
try:
    import psutil # Bellek ölçümü için gerekli. Yüklü değilse: pip install psutil
except ImportError:
    print("Hata: 'psutil' kütüphanesi bulunamadı.")
    print("Lütfen 'pip install psutil' komutu ile yükleyin.")
    sys.exit(1)


# --- Yardımcı Fonksiyonlar ---

def bytes_to_int(bytes_data):
    """Byte dizisini integer'a dönüştürür (big-endian)."""
    return int.from_bytes(bytes_data, byteorder='big')

def int_to_bytes(int_data, num_bytes):
    """Integer'ı belirtilen boyutta byte dizisine dönüştürür (big-endian)."""
    try:
        return int_data.to_bytes(num_bytes, byteorder='big')
    except OverflowError:
        # Bu hata, şifreleme/deşifreleme mantığında bir sorun varsa veya
        # num_bytes yanlışsa ortaya çıkabilir.
        print(f"Hata: Integer {int_data}, {num_bytes} byte'a sığmıyor.")
        # Hata durumunda None döndürmek yerine istisna fırlatmak daha iyi olabilir
        # ancak mevcut yapıya uyum için None döndürüyoruz.
        # raise ValueError(f"Integer {int_data} cannot fit in {num_bytes} bytes.")
        return None
    except Exception as e:
        # Beklenmeyen diğer hatalar için
        print(f"int_to_bytes hatası: {e}")
        return None
    

def read_file_bytes(filepath):
    """Veriyi ikili formatta dosyadan okur."""
    try:
        with open(filepath, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Hata: '{filepath}' dosyası bulunamadı.")
        return None
    except Exception as e:
        print(f"Dosya okuma hatası ({filepath}): {e}")
        return None

def write_file_bytes(filepath, data_bytes):
    """Veriyi ikili formatta dosyaya yazar."""
    try:
        with open(filepath, 'wb') as f:
            f.write(data_bytes)
        print(f"Veri başarıyla '{filepath}' dosyasına yazıldı.")
        return True
    except Exception as e:
        print(f"Dosya yazma hatası ({filepath}): {e}")
        return False

def hex_to_bytes(hex_string):
    """Hexadecimal string'i byte dizisine dönüştürür."""
    try:
        # Boşlukları temizle (varsa)
        cleaned_hex = ''.join(hex_string.split())
        if len(cleaned_hex) % 2 != 0:
            print("Hata: Hexadecimal string çift sayıda karakter içermelidir.")
            return None
        return bytes.fromhex(cleaned_hex)
    except ValueError:
        print("Hata: Geçersiz hexadecimal karakterler içeriyor.")
        return None
    except Exception as e:
        print(f"Hex dönüştürme hatası: {e}")
        return None


def format_bytes(byte_count):
    """Byte sayısını okunabilir formatta (B, KB, MB, GB) döndürür."""
    if byte_count is None or not isinstance(byte_count, (int, float)) or byte_count < 0:
        return "N/A"
    if byte_count == 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(byte_count) < 1024.0:
            # Eğer çok küçükse (örn. bellek farkı negatifse) veya normalse
            if unit == 'B':
                 return f"{int(byte_count)} {unit}" # Byte için ondalık gösterme
            else:
                 return f"{byte_count:.2f} {unit}"
        byte_count /= 1024.0
    # Çok büyükse TB olarak göster
    return f"{byte_count:.2f} PB" # Petabyte'a kadar gidelim

def measure_performance(operation_name, algorithm_name, data_bytes, key_bytes, crypto_func, block_size_bytes, key_size_bytes):
    """Şifreleme/Deşifreleme performansını ölçer."""
    process = psutil.Process(os.getpid())
    result_bytes = None
    metrics = None

    # İşlem öncesi bellek kullanımı (RSS - Resident Set Size)
    try:
        mem_before = process.memory_info().rss
    except psutil.Error as e:
        print(f"Bellek ölçümü hatası (öncesi): {e}")
        mem_before = 0 # Hata durumunda varsayılan

    start_time = time.time()
    try:
        # Kripto fonksiyonunu çağır
        result_bytes = crypto_func(data_bytes, key_bytes)
        # Hata fırlatıldıysa buraya gelinmez
        end_time = time.time()
        duration = end_time - start_time

        # İşlem sonrası bellek kullanımı
        try:
            mem_after = process.memory_info().rss
        except psutil.Error as e:
            print(f"Bellek ölçümü hatası (sonrası): {e}")
            mem_after = mem_before # Hata durumunda fark sıfır olur

        memory_used = mem_after - mem_before # Bu, operasyon sırasındaki RSS değişimidir.
                                            # Negatif veya sıfır olabilir.

        metrics = {
            "İşlem": operation_name,
            "Algoritma": algorithm_name,
            "Veri Boyutu": format_bytes(len(data_bytes)),
            "Anahtar Boyutu": f"{key_size_bytes * 8} bits ({key_size_bytes} bytes)",
            "Süre (sn)": f"{duration:.6f}", # Daha hassas süre
            "Bellek Farkı": format_bytes(memory_used), # Adını değiştirdik
            # Ham değerleri de saklamak isteyebilirsiniz
            "_Veri Boyutu (bytes)": len(data_bytes),
            "_Süre (sn)": duration,
            "_Bellek Farkı (bytes)": memory_used,
        }

    except ValueError as e:
        # crypto_func içinde oluşan hatalar (blok boyutu, anahtar boyutu vb.)
        print(f"\n{algorithm_name} {operation_name} sırasında HATA: {e}")
        # Metrikler ve sonuç None olarak dönecek
        pass # Hata zaten yazdırıldı, fonksiyon None döndürecek
    except Exception as e:
        # Beklenmedik diğer hatalar
        import traceback
        print(f"\nBeklenmedik HATA ({algorithm_name} {operation_name}): {e}")
        print(traceback.format_exc())
        # Metrikler ve sonuç None olarak dönecek
        pass

    return metrics, result_bytes # metrics None olabilir

def display_performance_table(results):
    """Performans ölçüm sonuçlarını tablo olarak görüntüler."""
    valid_results = [r for r in results if r is not None] # None olmayan sonuçları al
    if not valid_results:
        print("\nGörüntülenecek geçerli performans ölçümü sonucu yok.")
        return

    # Başlıkları al (ilk geçerli sonuçtan)
    # Ham değerleri (_ ile başlayanları) göstermeyelim
    headers = [h for h in valid_results[0].keys() if not h.startswith('_')]

    # Sütun genişliklerini belirle
    col_widths = {header: len(header) for header in headers}
    for row in valid_results:
        for header in headers:
            col_widths[header] = max(col_widths[header], len(str(row[header])))

    # Başlıkları yazdır
    header_line = " | ".join(header.ljust(col_widths[header]) for header in headers)
    separator_line = "-+-".join("-" * col_widths[header] for header in headers) # Düzeltildi: + ayırıcı

    print("\n--- Performans Ölçüm Sonuçları ---")
    print(header_line)
    print(separator_line)

    # Verileri yazdır
    for row in valid_results:
        data_line = " | ".join(str(row[header]).ljust(col_widths[header]) for header in headers)
        print(data_line)

    print(separator_line)
    print("*Bellek Farkı, operasyon sırasındaki tahmini RSS (Resident Set Size) değişimidir.")
    print(" Bu değer, sistemdeki diğer etkenlere ve GC'ye bağlı olarak değişebilir.")
    print("-" * (len(separator_line)))


