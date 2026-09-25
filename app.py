"""Streamlit interface for the encryption helpers."""

import streamlit as st
import base64

from crypto_core import decrypt, encrypt
from rsa_hybrid import generate_rsa_keypair, hybrid_encrypt, hybrid_decrypt, HybridDecryptionError

st.set_page_config(page_title="Enkripsi Data", layout="centered")

st.title("Brankas Enkripsi")
st.caption("AES-256-GCM dan ChaCha20-Poly1305 dengan kunci berbasis password - Tugas Keamanan Informasi (Topik A)")

tab_teks, tab_berkas, tab_rsa = st.tabs(["Teks", "Berkas", "RSA (Hibrida)"])

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

with tab_rsa:
    st.caption(
        "Enkripsi hibrida: data dienkripsi AES-256-GCM dengan kunci sesi acak, "
        "lalu kunci sesi itu dibungkus RSA-OAEP dengan Public Key penerima."
    )

    sub_generate, sub_enkripsi, sub_dekripsi = st.tabs(
        ["1. Generate Kunci", "2. Enkripsi", "3. Dekripsi"]
    )

    with sub_generate:
        st.write("Bikin pasangan kunci RSA baru (2048-bit). Lakukan ini SEKALI, simpan kedua filenya.")
        rsa_key_password = st.text_input("Password Private Key", type="password", key="pw_rsa_generate")

        if st.button("Generate Pasangan Kunci RSA", type="primary", key="btn_gen_rsa"):
            if not rsa_key_password:
                st.error("Password private key wajib diisi.")
            else:
                private_pem, public_pem = generate_rsa_keypair(rsa_key_password)
                st.session_state["rsa_private_pem"] = private_pem
                st.session_state["rsa_public_pem"] = public_pem
                st.success("Berhasil dibuat!")

        if "rsa_public_pem" in st.session_state:
            col1, col2 = st.columns(2)
            with col1:
                st.download_button(
                    "Unduh Public Key",
                    st.session_state["rsa_public_pem"],
                    file_name="public_key.pem",
                    mime="application/x-pem-file",
                )
            with col2:
                st.download_button(
                    "Unduh Private Key (RAHASIA!)",
                    st.session_state["rsa_private_pem"],
                    file_name="private_key.pem",
                    mime="application/x-pem-file",
                )
            st.warning("Private key JANGAN disebar dan JANGAN di-commit ke GitHub. Simpan hanya di komputer sendiri.")

    with sub_enkripsi:
        public_key_file = st.file_uploader("Upload Public Key (.pem)", type="pem", key="upload_pubkey")
        plaintext_rsa = st.text_area("Teks yang mau dienkripsi", height=100, key="input_teks_rsa")

        if st.button("Enkripsi (Hibrida)", type="primary", key="btn_enc_rsa"):
            if public_key_file is None:
                st.error("Upload public key dulu.")
            elif not plaintext_rsa:
                st.error("Teks tidak boleh kosong.")
            else:
                try:
                    payload = hybrid_encrypt(plaintext_rsa.encode("utf-8"), public_key_file.getvalue())
                except Exception as e:
                    st.error(f"Enkripsi gagal: {e}")
                else:
                    import base64
                    b64_result = base64.b64encode(payload).decode("ascii")
                    st.success("Berhasil dienkripsi!")
                    st.text_area("Ciphertext (Base64) - salin ini", value=b64_result, height=100, key="output_rsa_cipher")

    with sub_dekripsi:
        private_key_file = st.file_uploader("Upload Private Key (.pem)", type="pem", key="upload_privkey")
        rsa_decrypt_password = st.text_input("Password Private Key", type="password", key="pw_rsa_decrypt")
        ciphertext_rsa = st.text_area("Tempel ciphertext (Base64) di sini", height=100, key="input_cipher_rsa")

        if st.button("Dekripsi (Hibrida)", type="primary", key="btn_dec_rsa"):
            if private_key_file is None:
                st.error("Upload private key dulu.")
            elif not rsa_decrypt_password:
                st.error("Password private key wajib diisi.")
            elif not ciphertext_rsa:
                st.error("Ciphertext tidak boleh kosong.")
            else:
                import base64
                try:
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
                    st.text_area("Hasil dekripsi", value=hasil_rsa, height=100, key="output_rsa_plain")
