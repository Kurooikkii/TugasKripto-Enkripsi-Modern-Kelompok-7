import os
import time
import math
import pandas as pd
import matplotlib.pyplot as plt

# Import fungsi utama dari crypto_core kelompokmu
from crypto_core import encrypt, decrypt

def hitung_entropi(data: bytes) -> float:
    """Menghitung nilai entropi Shannon dari data byte (0-8 bit/byte)."""
    if not data:
        return 0.0
    frekuensi = {}
    for byte in data:
        frekuensi[byte] = frekuensi.get(byte, 0) + 1
    
    entropi = 0.0
    total = len(data)
    for count in frekuensi.values():
        p = count / total
        entropi -= p * math.log2(p)
    return entropi

def hitung_avalanche_effect(payload1: bytes, payload2: bytes) -> float:
    """Menghitung persentase bit cipherteks yang berubah (Avalanche Effect)."""
    min_len = min(len(payload1), len(payload2))
    bit_berbeda = 0
    total_bit = min_len * 8
    
    for i in range(min_len):
        xor_byte = payload1[i] ^ payload2[i]
        bit_berbeda += bin(xor_byte).count('1')
        
    return (bit_berbeda / total_bit) * 100 if total_bit > 0 else 0.0

def buat_histogram(plain_bytes, cipher_bytes, nama_file):
    """Menghasilkan grafik perbandingan histogram byte plainteks vs cipherteks."""
    os.makedirs("hasil_grafik", exist_ok=True)
    plt.figure(figsize=(10, 4))
    
    plt.subplot(1, 2, 1)
    plt.hist(list(plain_bytes), bins=256, range=(0, 255), color='blue', alpha=0.7)
    plt.title("Histogram Plainteks (Asli)")
    plt.xlabel("Nilai Byte (0-255)")
    plt.ylabel("Frekuensi")
    
    plt.subplot(1, 2, 2)
    plt.hist(list(cipher_bytes), bins=256, range=(0, 255), color='red', alpha=0.7)
    plt.title("Histogram Cipherteks (Terenkripsi)")
    plt.xlabel("Nilai Byte (0-255)")
    
    plt.tight_layout()
    plt.savefig(f"hasil_grafik/histogram_{nama_file}.png")
    plt.close()

def jalankan_pengujian():
    folder_data = "data_uji"
    if not os.path.exists(folder_data):
        print(f"Error: Folder '{folder_data}' tidak ditemukan!")
        return

    berkas_list = os.listdir(folder_data)
    if len(berkas_list) < 10:
        print(f"Peringatan: Jumlah berkas baru {len(berkas_list)}. Disarankan minimal 10 berkas!")

    password_utama = "password-rahasia-123"
    # Password dengan perubahan 1 karakter untuk uji Avalanche Effect
    password_uji = "Password-rahasia-123" 

    hasil_pengujian = []

    print("\n=== MEMULAI PENGUJIAN KUANTITATIF KRIPTOGRAFI ===")

    for file_name in berkas_list:
        file_path = os.path.join(folder_data, file_name)
        if os.path.isdir(file_path):
            continue

        with open(file_path, "rb") as f:
            plain_data = f.read()

        ukuran_bytes = len(plain_data)
        ukuran_str = f"{ukuran_bytes / (1024*1024):.2f} MB" if ukuran_bytes >= 1024*1024 else f"{ukuran_bytes / 1024:.2f} KB"
        entropi_plain = hitung_entropi(plain_data)

        for algo in ["AES-256-GCM", "ChaCha20-Poly1305"]:
            # 1. Uji Waktu Enkripsi
            t_start = time.perf_counter()
            cipher_payload = encrypt(plain_data, password_utama, algorithm=algo)
            t_enc = (time.perf_counter() - t_start) * 1000  # ms

            # 2. Uji Waktu Dekripsi
            t_start = time.perf_counter()
            restored_data = decrypt(cipher_payload, password_utama)
            t_dec = (time.perf_counter() - t_start) * 1000  # ms

            # Status Validasi Dekripsi
            status_dekripsi = "BERHASIL" if restored_data == plain_data else "GAGAL"

            # 3. Hitung Entropi Cipherteks
            entropi_cipher = hitung_entropi(cipher_payload)

            # 4. Uji Avalanche Effect (Ubah 1 Karakter Password)
            cipher_payload_alt = encrypt(plain_data, password_uji, algorithm=algo)
            avalanche_effect = hitung_avalanche_effect(cipher_payload, cipher_payload_alt)

            # 5. Buat Grafik Histogram (Untuk sampel file pertama tiap algoritma)
            buat_histogram(plain_data, cipher_payload, f"{file_name}_{algo}")

            hasil_pengujian.append({
                "Nama Berkas": file_name,
                "Ukuran Berkas": ukuran_str,
                "Algoritma": algo,
                "Status Dekripsi": status_dekripsi,
                "Waktu Enkripsi (ms)": round(t_enc, 2),
                "Waktu Dekripsi (ms)": round(t_dec, 2),
                "Entropi Plainteks": round(entropi_plain, 4),
                "Entropi Cipherteks": round(entropi_cipher, 4),
                "Avalanche Effect (%)": round(avalanche_effect, 2)
            })

            print(f"[{algo}] {file_name} ({ukuran_str}) -> Enkripsi: {t_enc:.2f}ms | Avalanche: {avalanche_effect:.2f}% | Status: {status_dekripsi}")

    # Export hasil ke Excel (.xlsx) untuk lampiran tugas
    df = pd.DataFrame(hasil_pengujian)
    file_excel = "pengujian_kriptografi.xlsx"
    df.to_excel(file_excel, index=False)
    
    print("\n==================================================")
    print(f"PENGUJIAN SELESAI!")
    print(f"1. File Rekap Hasil: {file_excel} (Siap dilampirkan)")
    print(f"2. Grafik Histogram : Folder 'hasil_grafik/' (Siap dimasukkan ke laporan)")
    print("==================================================")

if __name__ == "__main__":
    jalankan_pengujian()