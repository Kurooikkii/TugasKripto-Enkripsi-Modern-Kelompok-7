"""Streamlit interface for the encryption helpers."""

import streamlit as st

from crypto_core import decrypt, encrypt

st.set_page_config(page_title="Enkripsi File", page_icon="🔐")
st.title("Enkripsi Data")
st.caption("AES-256-GCM dan ChaCha20-Poly1305 dengan kunci berbasis password")

operation = st.radio("Operasi", ["Enkripsi", "Dekripsi"], horizontal=True)
algorithm = st.selectbox("Algoritma", ["AES-256-GCM", "ChaCha20-Poly1305"])
password = st.text_input("Password", type="password")

if operation == "Enkripsi":
    data = st.file_uploader("Pilih file untuk dienkripsi")
    if data is not None and st.button("Enkripsi", type="primary"):
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
    if data is not None and st.button("Dekripsi", type="primary"):
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
