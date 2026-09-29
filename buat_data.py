import os

# Buat folder data_uji jika belum ada
os.makedirs('data_uji', exist_ok=True)

# Definisi ukuran dalam satuan byte
ukuran_file = {
    "1KB.bin": 1024,
    "1MB.bin": 1024 * 1024,
    "10MB.bin": 10 * 1024 * 1024
}

for nama_file, ukuran in ukuran_file.items():
    path = os.path.join('data_uji', nama_file)
    # os.urandom menghasilkan data byte acak
    with open(path, 'wb') as f:
        f.write(os.urandom(ukuran))
    print(f"File {nama_file} ({ukuran} bytes) berhasil dibuat!")