import os
import hashlib

folder = "data_uji" # Pastikan nama foldernya sesuai tempat kamu menyimpan 10 file uji
print("=== NILAI HASH SHA-256 UNTUK TABEL 5.1 ===\n")

for nama_file in os.listdir(folder):
    path = os.path.join(folder, nama_file)
    if os.path.isfile(path):
        with open(path, "rb") as f:
            # Membaca file dan menghitung hash-nya
            file_hash = hashlib.sha256(f.read()).hexdigest()
            print(f"{nama_file} :\n{file_hash}\n")