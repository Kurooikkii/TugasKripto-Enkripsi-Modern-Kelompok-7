"""Streamlit interface for the encryption helpers."""

import streamlit as st
import base64

from crypto_core import decrypt, encrypt

st.set_page_config(page_title="Enkripsi Data", layout="centered")

st.title("Brankas Enkripsi")
st.caption("AES-256-GCM dan ChaCha20-Poly1305 dengan kunci berbasis password - Tugas Keamanan Informasi (Topik A)")

tab_teks, tab_berkas = st.tabs(["Teks", "Berkas"])

with tab_teks:
    operation_t = st.radio("Operasi", ["Enkripsi", "Dekripsi"], horizontal=True, key="op_teks")
    algorithm_t = st.selectbox("Algoritma", ["AES-256-GCM", "ChaCha20-Poly1305"], key="algo_teks")
    password_t = st.text_input("Password", type="password", key="pw_teks")

    if operation_t == "Enkripsi":
        plaintext = st.text_area("Teks yang mau dienkripsi", height=120, key="input_teks")

        if st.button("Enkripsi Teks", type="primary", key="btn_enc_teks"):
            if not password_t:
                st.error("Password wajib diisi.")
            elif not plaintext:
                st.error("Teks tidak boleh kosong.")
            else:
                payload = encrypt(plaintext.encode("utf-8"), password_t, algorithm_t)

                b64_result = base64.b64encode(payload).decode("ascii")
                hex_result = payload.hex()

                st.success("Berhasil dienkripsi!")
                st.text_area("Ciphertext (Base64) — salin ini", value=b64_result, height=100)
                with st.expander("Lihat dalam format Heksadesimal"):
                    st.code(hex_result, language=None)

    else: 
        ciphertext_input = st.text_area(
            "Tempel ciphertext (Base64) di sini", height=120, key="input_cipher_teks"
        )

        if st.button("Dekripsi Teks", type="primary", key="btn_dec_teks"):
            if not password_t:
                st.error("Password wajib diisi.")
            elif not ciphertext_input:
                st.error("Ciphertext tidak boleh kosong.")
            else:
                try:
                    payload = base64.b64decode(ciphertext_input.strip())
                    plaintext_bytes = decrypt(payload, password_t)
                    hasil = plaintext_bytes.decode("utf-8")
                except Exception:
                    st.error("Dekripsi gagal. Password salah, ciphertext diubah, atau format Base64 tidak valid.")
                else:
                    st.success("Berhasil didekripsi!")
                    st.text_area("Hasil dekripsi", value=hasil, height=120)

with tab_berkas:
    operation = st.radio("Operasi", ["Enkripsi", "Dekripsi"], horizontal=True, key="op_file")
    algorithm = st.selectbox("Algoritma", ["AES-256-GCM", "ChaCha20-Poly1305"], key="algo_file")
    password = st.text_input("Password", type="password", key="pw_file")

    if operation == "Enkripsi":
        data = st.file_uploader("Pilih file untuk dienkripsi")
        if data is not None and st.button("Enkripsi", type="primary", key="btn_enc_file"):
            if not password:
                st.error("Password wajib diisi.")
            else:
                encrypted = encrypt(data.getvalue(), password, algorithm)
                st.download_button(
                    "Unduh file terenkripsi",
                    encrypted,
                    file_name=f"{data.name}.enc",
                    mime="application/octet-stream",
                )
    else:
        data = st.file_uploader("Pilih file terenkripsi", type="enc")
        if data is not None and st.button("Dekripsi", type="primary", key="btn_dec_file"):
            if not password:
                st.error("Password wajib diisi.")
            else:
                try:
                    decrypted = decrypt(data.getvalue(), password)
                except Exception:
                    st.error("Dekripsi gagal. Periksa password atau file terenkripsi.")
                else:
                    output_name = data.name.removesuffix(".enc") or "decrypted.bin"
                    st.download_button(
                        "Unduh file hasil dekripsi",
                        decrypted,
                        file_name=output_name,
                        mime="application/octet-stream",
                    )
