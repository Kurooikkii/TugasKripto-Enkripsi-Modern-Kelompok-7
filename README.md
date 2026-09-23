# TugasKripto-Enkripsi-Modern-Kelompok-7
Aplikasi Enkripsi &amp; Dekripsi Modern (AES-256-GCM &amp; ChaCha20-Poly1305) - Tugas Proyek Keamanan Informasi.

# Aplikasi Enkripsi & Dekripsi Modern (Topik A)
> Tugas Proyek Mata Kuliah Keamanan Informasi - Program Studi Informatika, Universitas Siliwangi

Aplikasi berbasis web untuk mengenkripsi dan mendekripsi teks maupun berkas menggunakan algoritma kriptografi modern (**AES-256-GCM** dan **ChaCha20-Poly1305**) dengan penyesuaian penurunan kunci (*Key Derivation Function*) menggunakan **PBKDF2/scrypt**.

---

## 👥 Anggota Kelompok
1. Chintia Aurizki Putri- 247006111175: `[NPM Ketua]`
2. Adithyaa Nurrahman - 247006111176: `[NPM Anggota 2]`
3. Muhamad Rifqi Nurjaman - 247006111177: `[NPM Anggota 3]`

---

## ✨ Fitur Utama
* **Enkripsi Simetris Modern:** Mendukung AES-256-GCM dan ChaCha20-Poly1305 untuk teks & berkas.
* **Keamanan Kunci:** Penurunan kunci berbasis kata sandi (PBKDF2/scrypt) dengan *salt* dan IV/*nonce* acak aman (*cryptographically secure*).
* **Format Output:** Cipherteks dapat disalin/ditampilkan dalam format Base64 dan Heksadesimal.
* **Integritas Data:** Otomatis menolak dekripsi jika kata sandi salah atau cipherteks/tag telah diubah (*tampered*).
* **Analisis & Pengujian Kuantitatif:**
  * Pengujian waktu enkripsi/dekripsi (berkas 1 KB, 1 MB, 10 MB).
  * Perhitungan *Avalanche Effect*.
  * Visualisasi Entropi & Histogram Byte.
* **Fitur Pengayaan:** Visualisasi enkripsi citra (Perbandingan mode ECB vs mode aman GCM).

---

## 🛠️ Cara Instalasi

1. **Clone Repositori ini:**
   ```bash
   git clone [https://github.com/](https://github.com/)[username-github]/TugasKripto-Enkripsi-Modern.git
   cd TugasKripto-Enkripsi-Modern
