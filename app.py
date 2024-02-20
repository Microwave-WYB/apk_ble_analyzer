"""
Main streamlit APP
"""

import os
import tempfile
import streamlit as st

from apk_ble_analyzer import Analyzer, decompile_apk


def save_temp_file(file) -> str | None:
    """
    Save the given file as a temporary file with a .apk suffix.

    Args:
        file: The file to be saved.

    Returns:
        The name of the saved temporary file, or None if there was an error.

    Raises:
        IOError: If there was an error saving the file.
    """
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp_file:
            tmp_file.write(file.getvalue())
            return tmp_file.name
    except IOError as e:
        st.error(f"Error saving file: {e}")
        return None


if __name__ == "__main__":
    st.set_page_config(page_title="APK BLE Analyzer")
    st.title("APK BLE Analyzer")
    jadx_path = st.text_input("Path to jadx", "/usr/bin/jadx")
    uploaded_file = st.file_uploader("Upload APK file", type=["apk"])

    if uploaded_file is not None:
        apk_path = save_temp_file(uploaded_file)
        if apk_path:
            with st.spinner("Decompiling..."):
                analyzer = Analyzer(apk_path, jadx_path)
                base_path = decompile_apk(jadx_path, apk_path)
            with st.spinner("Analyzing..."):
                uuids = analyzer.match_uuids(base_path)

            st.write("Found UUIDs:")
            st.write([result.to_dict() for result in uuids])

            os.remove(apk_path)
