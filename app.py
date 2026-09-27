"""Streamlit interface for the encryption helpers."""

import streamlit as st
import base64

from crypto_core import decrypt, encrypt
from rsa_hybrid import generate_rsa_keypair, hybrid_encrypt, hybrid_decrypt, HybridDecryptionError

st.set_page_config(page_title="Enkripsi Data", page_icon="🔒", layout="centered")

st.markdown("""
<style>
    .stButton > button[kind="primary"] {
        background-color: #1e3a5f;
        border-color: #1e3a5f;
    }
    .stButton > button[kind="primary"]:hover {
        background-color: #16293f;
        border-color: #16293f;
    }
    .algo-badge {
        display: inline-block;
        background-color: #f0f4f8;
        border: 1px solid #d5dde5;
        border-radius: 20px;
        padding: 5px 12px;
        font-size: 0.82em;
        font-weight: 600;
        margin: 3px 4px 4px 0;
        transform: scale(1);
        transform-origin: center;
        transition: transform 0.2s ease-out, box-shadow 0.2s ease-out;
        cursor: default;
    }
    .algo-badge:hover {
        transform: scale(1.1);
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.12);
    }
    .algo-badge.aes { color: #1e3a5f; background-color: #e6f1fb; border-color: #b5d4f4; }
    .algo-badge.chacha { color: #0f6e56; background-color: #e1f5ee; border-color: #9fe1cb; }
    .algo-badge.rsa { color: #712b13; background-color: #faece7; border-color: #f0997b; }
    .team-card {
        border-left: 3px solid #1e3a5f;
        padding: 4px 0 4px 12px;
        margin-bottom: 6px;
        font-size: 0.92em;
        transform: scale(1);
        transform-origin: left center;
        transition: transform 0.2s ease-out;
        cursor: default;
    }
    .team-card:hover {
        transform: scale(1.15);
    }
    @media (prefers-color-scheme: dark) {
        .algo-badge.aes { color: #b5d4f4; background-color: #0c447c; border-color: #378add; }
        .algo-badge.chacha { color: #9fe1cb; background-color: #085041; border-color: #1d9e75; }
        .algo-badge.rsa { color: #f0997b; background-color: #4a1b0c; border-color: #d85a30; }
        .team-card { border-left-color: #85b7eb; }
    }
    section[data-testid="stSidebar"] h2, section[data-testid="stSidebar"] h3 {
        color: #1e3a5f;
    }
    div[data-testid="stTabs"] button[data-baseweb="tab"] {
        font-weight: 600;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 6px;
    }
    div[data-testid="stTabs"] button[aria-selected="true"] {
        border-bottom-color: #1e3a5f !important;
    }
    div[data-testid="stTabs"] button[aria-selected="true"] p {
        color: #1e3a5f !important;
    }
    @media (max-width: 500px) {
        div[data-testid="column"] {
            width: 100% !important;
            flex: 1 1 100% !important;
            min-width: 100% !important;
        }
    }
</style>
""", unsafe_allow_html=True)

st.title("Brankas Enkripsi")
st.caption("AES-256-GCM dan ChaCha20-Poly1305 dengan kunci berbasis password - Tugas Keamanan Informasi (Topik A)")
st.markdown(
    '<span class="algo-badge aes">AES-256-GCM</span>'
    '<span class="algo-badge chacha">ChaCha20-Poly1305</span>'
    '<span class="algo-badge rsa">RSA-OAEP (hibrida)</span>',
    unsafe_allow_html=True,
)
st.info(
    "Cara pakai: pilih tab sesuai kebutuhan (Teks / Berkas / RSA Hibrida) → pilih Enkripsi atau "
    "Dekripsi → isi password → tekan tombol aksi di bagian bawah."
)

with st.sidebar:
    st.header("Tugas Proyek Kriptografi")
    st.caption("Keamanan Informasi — Topik A: Enkripsi Algoritma Modern")

    st.subheader("Disusun oleh")
    st.markdown('<div class="team-card team-card-1">Chintia Aurizki Putri<br><span style="color:gray">247006111175</span></div>', unsafe_allow_html=True)
    st.markdown('<div class="team-card team-card-2">Adithyaa Nurrahman<br><span style="color:gray">247006111176</span></div>', unsafe_allow_html=True)
    st.markdown('<div class="team-card team-card-3">Muhamad Rifqi Nurjaman<br><span style="color:gray">247006111177</span></div>', unsafe_allow_html=True)

    st.divider()
    st.subheader("FAQ")

    with st.expander("Bagaimana cara memakai aplikasi ini?"):
        st.write(
            "1. Pilih tab Teks, Berkas, atau RSA (Hibrida) sesuai kebutuhan.\n"
            "2. Pilih Enkripsi atau Dekripsi.\n"
            "3. Masukkan kata sandi, lalu tekan tombol aksi.\n"
            "4. Hasil enkripsi bisa disalin (teks) atau diunduh (berkas)."
        )

    with st.expander("Algoritma apa yang dipakai, dan kenapa aman?"):
        st.write(
            "Data dienkripsi memakai AES-256-GCM atau ChaCha20-Poly1305, "
            "dua algoritma modern yang sudah terstandarisasi luas dan diuji "
            "bertahun-tahun oleh komunitas kriptografi. Kunci diturunkan dari "
            "kata sandi memakai Argon2id dengan salt acak, dan setiap enkripsi "
            "memakai nonce baru sehingga hasil ciphertext selalu berbeda "
            "walau plaintext dan kata sandinya sama."
        )

    with st.expander("Kenapa dekripsi bisa ditolak?"):
        st.write(
            "Dekripsi otomatis ditolak jika kata sandi salah atau data telah "
            "diubah (misalnya rusak saat dikirim). Sistem memakai mekanisme "
            "autentikasi bawaan AES-GCM/ChaCha20-Poly1305 yang mendeteksi "
            "perubahan sekecil apa pun pada data terenkripsi."
        )

    with st.expander("Apa itu fitur RSA (Hibrida)?"):
        st.write(
            "Fitur pengayaan yang menggabungkan AES (untuk mengenkripsi data) "
            "dan RSA-OAEP (untuk membungkus kunci AES). Private Key RSA yang "
            "dihasilkan juga disimpan terenkripsi dengan kata sandi, sehingga "
            "aman walau berkas kuncinya bocor."
        )

    st.divider()
    with st.expander("Tools yang digunakan"):
        st.write(
            "- Python 3 sebagai bahasa pemrograman utama\n"
            "- Streamlit untuk antarmuka web\n"
            "- Library `cryptography` untuk implementasi AES-256-GCM, "
            "ChaCha20-Poly1305, dan RSA-OAEP\n"
            "- Argon2id untuk derivasi kunci dari password"
        )

    with st.expander("Log aktivitas sesi ini"):
        log = st.session_state.get("activity_log", [])
        if log:
            for entry in log:
                st.caption(f"• {entry}")
        else:
            st.caption("Belum ada aktivitas pada sesi ini.")

def password_hint(password_value):
    if password_value and len(password_value) < 8:
        st.caption(":orange[Password sebaiknya minimal 8 karakter agar lebih aman.]")

def clear_fields(*keys):
    for k in keys:
        st.session_state.pop(k, None)
    st.rerun()

def log_activity(message):
    st.session_state.setdefault("activity_log", [])
    st.session_state["activity_log"].insert(0, message)
    st.session_state["activity_log"] = st.session_state["activity_log"][:20]

tab_teks, tab_berkas, tab_rsa = st.tabs(["Teks", "Berkas", "RSA (Hibrida)"])

with tab_teks:
    with st.container(border=True):
        operation_t = st.radio(
            "Operasi", ["Enkripsi", "Dekripsi"], horizontal=True, key="op_teks",
            format_func=lambda x: "Enkripsi" if x == "Enkripsi" else "Dekripsi",
        )
        algorithm_t = st.selectbox(
            "Algoritma", ["AES-256-GCM", "ChaCha20-Poly1305"], key="algo_teks",
            help="Keduanya sama-sama aman dan modern. AES-256-GCM lebih umum dipakai, "
                 "ChaCha20-Poly1305 biasanya lebih cepat di perangkat tanpa akselerasi hardware AES."
        )
        password_t = st.text_input(
            "Password", type="password", key="pw_teks",
            placeholder="Contoh: rahasia123",
            help="Password ini dipakai untuk menurunkan kunci enkripsi. Simpan baik-baik, "
                 "karena tanpa password yang sama persis, data tidak bisa didekripsi kembali."
        )
        password_hint(password_t)

        if operation_t == "Enkripsi":
            plaintext = st.text_area(
                "Teks yang mau dienkripsi", height=120, key="input_teks",
                placeholder="Tulis atau tempel teks rahasia di sini..."
            )

            if st.button("Enkripsi Teks", type="primary", key="btn_enc_teks"):
                if not password_t:
                    st.error("Password wajib diisi.")
                elif not plaintext:
                    st.error("Teks tidak boleh kosong.")
                else:
                    with st.spinner("Mengenkripsi..."):
                        payload = encrypt(plaintext.encode("utf-8"), password_t, algorithm_t)

                    b64_result = base64.b64encode(payload).decode("ascii")
                    hex_result = payload.hex()

                    st.success("Berhasil dienkripsi!")
                    st.caption("Ciphertext (Base64) — klik ikon salin di pojok kanan atas kotak ini")
                    st.code(b64_result, language=None)
                    with st.expander("Lihat dalam format Heksadesimal"):
                        st.code(hex_result, language=None)
                    log_activity(f"Enkripsi teks berhasil ({algorithm_t})")

            if st.button("Bersihkan formulir", key="clear_enc_teks"):
                clear_fields("pw_teks", "input_teks")

        else:
            ciphertext_input = st.text_area(
                "Tempel ciphertext (Base64) di sini", height=120, key="input_cipher_teks",
                placeholder="Tempel hasil enkripsi (format Base64) di sini..."
            )

            if st.button("Dekripsi Teks", type="primary", key="btn_dec_teks"):
                if not password_t:
                    st.error("Password wajib diisi.")
                elif not ciphertext_input:
                    st.error("Ciphertext tidak boleh kosong.")
                else:
                    try:
                        with st.spinner("Mendekripsi..."):
                            payload = base64.b64decode(ciphertext_input.strip())
                            plaintext_bytes = decrypt(payload, password_t)
                            hasil = plaintext_bytes.decode("utf-8")
                    except Exception:
                        st.error("Dekripsi gagal. Password salah, ciphertext diubah, atau format Base64 tidak valid.")
                    else:
                        st.success("Berhasil didekripsi!")
                        st.caption("Hasil dekripsi — klik ikon salin di pojok kanan atas kotak ini")
                        st.code(hasil, language=None)
                        log_activity("Dekripsi teks berhasil")

            if st.button("Bersihkan formulir", key="clear_dec_teks"):
                clear_fields("pw_teks", "input_cipher_teks")

with tab_berkas:
    with st.container(border=True):
        operation = st.radio(
            "Operasi", ["Enkripsi", "Dekripsi"], horizontal=True, key="op_file",
            format_func=lambda x: "Enkripsi" if x == "Enkripsi" else "Dekripsi",
        )
        algorithm = st.selectbox(
            "Algoritma", ["AES-256-GCM", "ChaCha20-Poly1305"], key="algo_file",
            help="Pilih algoritma yang sama dengan yang dipakai saat enkripsi apabila sedang mendekripsi."
        )
        password = st.text_input(
            "Password", type="password", key="pw_file",
            placeholder="Contoh: rahasia123",
            help="Password yang sama harus dipakai saat enkripsi dan dekripsi berkas ini."
        )
        password_hint(password)

        if operation == "Enkripsi":
            data = st.file_uploader("Pilih file untuk dienkripsi")
            if data is not None and st.button("Enkripsi", type="primary", key="btn_enc_file"):
                if not password:
                    st.error("Password wajib diisi.")
                else:
                    with st.spinner("Mengenkripsi berkas..."):
                        encrypted = encrypt(data.getvalue(), password, algorithm)
                    st.success("Berhasil dienkripsi!")

                    preview_len = 128
                    hex_preview = encrypted[:preview_len].hex()
                    st.caption(
                        f"Cuplikan ciphertext (heksadesimal, {min(preview_len, len(encrypted))} byte pertama "
                        f"dari total {len(encrypted):,} byte):"
                    )
                    st.code(hex_preview + (" ..." if len(encrypted) > preview_len else ""), language=None)

                    st.download_button(
                        "Unduh file terenkripsi",
                        encrypted,
                        file_name=f"{data.name}.enc",
                        mime="application/octet-stream",
                    )
                    log_activity(f"Enkripsi berkas '{data.name}' berhasil ({algorithm})")

            if st.button("Bersihkan formulir", key="clear_enc_file"):
                clear_fields("pw_file")
        else:
            data = st.file_uploader("Pilih file terenkripsi", type="enc")
            if data is not None and st.button("Dekripsi", type="primary", key="btn_dec_file"):
                if not password:
                    st.error("Password wajib diisi.")
                else:
                    try:
                        with st.spinner("Mendekripsi berkas..."):
                            decrypted = decrypt(data.getvalue(), password)
                    except Exception:
                        st.error("Dekripsi gagal. Periksa password atau file terenkripsi.")
                    else:
                        st.success("Berhasil didekripsi!")
                        output_name = data.name.removesuffix(".enc") or "decrypted.bin"
                        st.download_button(
                            "Unduh file hasil dekripsi",
                            decrypted,
                            file_name=output_name,
                            mime="application/octet-stream",
                        )
                        log_activity(f"Dekripsi berkas '{data.name}' berhasil")

            if st.button("Bersihkan formulir", key="clear_dec_file"):
                clear_fields("pw_file")

with tab_rsa:
    st.caption(
        "Enkripsi hibrida: data dienkripsi AES-256-GCM dengan kunci sesi acak, "
        "lalu kunci sesi itu dibungkus RSA-OAEP dengan Public Key penerima."
    )

    sub_generate, sub_enkripsi, sub_dekripsi = st.tabs(
        ["1. Generate Kunci", "2. Enkripsi", "3. Dekripsi"]
    )

    with sub_generate:
        with st.container(border=True):
            st.info("Mulai dari sini jika kamu belum punya pasangan kunci RSA.")
            st.write("Bikin pasangan kunci RSA baru (2048-bit). Lakukan ini SEKALI, simpan kedua filenya.")
            rsa_key_password = st.text_input(
                "Password Private Key", type="password", key="pw_rsa_generate",
                placeholder="Contoh: rahasia123",
                help="Password ini dipakai untuk mengenkripsi private key yang dihasilkan, "
                     "bukan untuk mengenkripsi data. Diperlukan lagi saat proses dekripsi."
            )
            password_hint(rsa_key_password)
            rsa_key_password_confirm = st.text_input(
                "Konfirmasi Password Private Key", type="password", key="pw_rsa_generate_confirm",
                placeholder="Ulangi password di atas",
                help="Diketik ulang supaya tidak salah ketik — kalau typo, private key tidak bisa dibuka lagi nanti."
            )

            if st.button("Generate Pasangan Kunci RSA", type="primary", key="btn_gen_rsa"):
                if not rsa_key_password:
                    st.error("Password private key wajib diisi.")
                elif rsa_key_password != rsa_key_password_confirm:
                    st.error("Password dan konfirmasi password tidak sama.")
                else:
                    with st.spinner("Membuat pasangan kunci RSA 2048-bit..."):
                        private_pem, public_pem = generate_rsa_keypair(rsa_key_password)
                    st.session_state["rsa_private_pem"] = private_pem
                    st.session_state["rsa_public_pem"] = public_pem
                    st.success("Berhasil dibuat!")
                    log_activity("Pasangan kunci RSA 2048-bit berhasil dibuat")

            if "rsa_public_pem" in st.session_state:
                col1, col2 = st.columns(2)
                with col1:
                    st.download_button(
                        "Unduh Public Key",
                        st.session_state["rsa_public_pem"],
                        file_name="public_key.pem",
                        mime="application/x-pem-file",
                        use_container_width=True,
                    )
                with col2:
                    st.download_button(
                        "Unduh Private Key",
                        st.session_state["rsa_private_pem"],
                        file_name="private_key.pem",
                        mime="application/x-pem-file",
                        use_container_width=True,
                    )
                st.warning("Private key JANGAN disebar dan JANGAN di-commit ke GitHub. Simpan hanya di komputer sendiri.")

                with st.expander("Lihat cuplikan Public Key (untuk verifikasi)"):
                    public_pem_text = st.session_state["rsa_public_pem"]
                    if isinstance(public_pem_text, bytes):
                        public_pem_text = public_pem_text.decode("utf-8")
                    preview_lines = "\n".join(public_pem_text.strip().splitlines()[:4]) + "\n..."
                    st.code(preview_lines, language=None)

            if st.button("Bersihkan formulir", key="clear_gen_rsa"):
                clear_fields("pw_rsa_generate", "pw_rsa_generate_confirm")

    with sub_enkripsi:
        with st.container(border=True):
            st.caption("Butuh Public Key penerima. Minta file public_key.pem dari orang yang akan menerima pesan.")
            public_key_file = st.file_uploader("Upload Public Key (.pem)", type="pem", key="upload_pubkey")
            plaintext_rsa = st.text_area(
                "Teks yang mau dienkripsi", height=100, key="input_teks_rsa",
                placeholder="Tulis pesan rahasia untuk penerima di sini..."
            )

            if st.button("Enkripsi (Hibrida)", type="primary", key="btn_enc_rsa"):
                if public_key_file is None:
                    st.error("Upload public key dulu.")
                elif not plaintext_rsa:
                    st.error("Teks tidak boleh kosong.")
                else:
                    try:
                        with st.spinner("Mengenkripsi (AES + RSA-OAEP)..."):
                            payload = hybrid_encrypt(plaintext_rsa.encode("utf-8"), public_key_file.getvalue())
                    except Exception as e:
                        st.error(f"Enkripsi gagal: {e}")
                    else:
                        b64_result = base64.b64encode(payload).decode("ascii")
                        st.success("Berhasil dienkripsi!")
                        st.caption("Ciphertext (Base64) — klik ikon salin di pojok kanan atas kotak ini")
                        st.code(b64_result, language=None)
                        log_activity("Enkripsi hibrida (RSA) berhasil")

            if st.button("Bersihkan formulir", key="clear_enc_rsa"):
                clear_fields("input_teks_rsa")

    with sub_dekripsi:
        with st.container(border=True):
            st.caption("Butuh Private Key milikmu sendiri beserta password yang dipakai saat generate kunci.")
            private_key_file = st.file_uploader("Upload Private Key (.pem)", type="pem", key="upload_privkey")
            rsa_decrypt_password = st.text_input(
                "Password Private Key", type="password", key="pw_rsa_decrypt",
                placeholder="Password yang dipakai saat generate kunci"
            )
            ciphertext_rsa = st.text_area(
                "Tempel ciphertext (Base64) di sini", height=100, key="input_cipher_rsa",
                placeholder="Tempel hasil enkripsi hibrida (format Base64) di sini..."
            )

            if st.button("Dekripsi (Hibrida)", type="primary", key="btn_dec_rsa"):
                if private_key_file is None:
                    st.error("Upload private key dulu.")
                elif not rsa_decrypt_password:
                    st.error("Password private key wajib diisi.")
                elif not ciphertext_rsa:
                    st.error("Ciphertext tidak boleh kosong.")
                else:
                    try:
                        with st.spinner("Mendekripsi (RSA-OAEP + AES)..."):
                            payload = base64.b64decode(ciphertext_rsa.strip())
                            plaintext_bytes = hybrid_decrypt(
                                payload, private_key_file.getvalue(), rsa_decrypt_password
                            )
                            hasil_rsa = plaintext_bytes.decode("utf-8")
                    except HybridDecryptionError as e:
                        st.error(str(e))
                    except Exception:
                        st.error("Dekripsi gagal. Periksa private key atau format ciphertext.")
                    else:
                        st.success("Berhasil didekripsi!")
                        st.caption("Hasil dekripsi — klik ikon salin di pojok kanan atas kotak ini")
                        st.code(hasil_rsa, language=None)
                        log_activity("Dekripsi hibrida (RSA) berhasil")

            if st.button("Bersihkan formulir", key="clear_dec_rsa"):
                clear_fields("pw_rsa_decrypt", "input_cipher_rsa")

st.divider()

with st.container(border=True):
    col_badge, col_text = st.columns([1, 9])
    with col_badge:
        st.markdown(
            '<div style="width:40px;height:40px;border-radius:50%;background-color:#1e3a5f;'
            'color:white;display:flex;align-items:center;justify-content:center;font-weight:bold;">'
            'KI</div>',
            unsafe_allow_html=True,
        )
    with col_text:
        st.markdown(
            "**Brankas Enkripsi** dikembangkan untuk memenuhi Tugas Mata Kuliah Keamanan Informasi "
            "(Topik A). Aplikasi ini ditujukan untuk keperluan pembelajaran, bukan untuk melindungi "
            "data produksi atau data sensitif sungguhan."
        )

st.markdown(
    """
    <div style="text-align:center; color:gray; font-size:0.85em; margin-top:12px;">
        Keamanan Informasi &middot; Topik A: Enkripsi Algoritma Modern &middot; 2026
    </div>
    """,
    unsafe_allow_html=True,
)