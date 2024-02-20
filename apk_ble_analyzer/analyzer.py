"""
Module for analyzing APKs to extract BLE UUID information.
"""

import re
from typing import List, Optional
from dataclasses import dataclass, asdict
import subprocess
import os


@dataclass
class UUIDInfo:
    """
    Dataclass to store UUID information.

    Attributes:
        uuid (str): The UUID.
        variable (str): The variable name.
        path (str): The path to the source file relative to the decompiled directory.
    """

    uuid: str
    variable: str
    path: str

    def to_dict(self) -> dict:
        """
        Convert the UUIDInfo object to a dictionary.

        Returns:
            dict: _description_
        """
        return asdict(self)


def match_uuids(file_path: str, relative_path: Optional[str]) -> List[UUIDInfo]:
    """
    Match UUIDs in a file.

    Args:
        file_path (str): Path to the file.

    Returns:
        list[UUIDInfo]: List of UUIDInfo objects.
    """
    uuid_regex = (
        r"(?!00000000-0000-0000-0000-000000000000)"
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    )
    uuid_infos: List[UUIDInfo] = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            match = re.search(uuid_regex, line)
            if match is None:
                continue

            # Split the line by "=" and then get the variable name
            parts = line.split("=")
            if len(parts) <= 1:
                continue

            variable_part = parts[0].strip()
            # Split by spaces and take the last part as variable name
            variable_name = variable_part.split()[-1]
            # Extract the UUID
            uuid = match.group().strip('"')
            uuid_infos.append(
                UUIDInfo(
                    uuid=uuid,
                    variable=variable_name,
                    path=(relative_path or file_path),
                )
            )

    return uuid_infos


def decompile_apk(jadx_path: str, apk_path: str) -> str:
    """
    Decompile an APK using jadx.

    Args:
        jadx_path (str): Path to the jadx executable.
        apk_path (str): Path to the APK file.

    Returns:
        str: Path to the decompiled source code directory.
    """
    apk_dir = os.path.dirname(apk_path)
    apk_base_name = os.path.basename(apk_path)
    if apk_base_name.endswith(".apk"):
        output_dir_name = apk_base_name[:-4]
    else:
        output_dir_name = apk_base_name
    output_dir = os.path.join(apk_dir, output_dir_name)
    subprocess.run([jadx_path, "-d", output_dir, apk_path], check=True)
    return output_dir


class Analyzer:
    """
    Class representing an analyzer for extracting BLE UUID information from APK sources.
    """

    def __init__(self, apk_path: str, jadx_path: str) -> None:
        if not os.path.exists(jadx_path):
            raise FileNotFoundError("jadx_path does not exist")
        if not os.path.exists(apk_path):
            raise FileNotFoundError("apk_path does not exist")
        if not os.path.isfile(jadx_path):
            raise FileNotFoundError("jadx_path is not a file")
        if not os.path.isfile(apk_path):
            raise FileNotFoundError("apk_path is not a file")
        if not os.access(jadx_path, os.X_OK):
            raise PermissionError("jadx_path is not executable")
        self.apk_path: str = apk_path
        self.jadx_path: str = jadx_path

    def _decompile_apk(self) -> str:
        """
        Decompile the APK and return the path to the decompiled source code directory.

        Returns:
            str: Path to the decompiled source code directory.
        """
        base_path = decompile_apk(self.jadx_path, self.apk_path)
        return base_path

    def match_uuids_in_sources(self, base_path: Optional[str] = None) -> List[UUIDInfo]:
        """
        Matches UUIDs in the APK sources and returns a list of UUIDInfo objects.

        Returns:
            A list of UUIDInfo objects representing the matched UUIDs.
        """
        all_uuid_infos = []
        if base_path is None:
            base_path = self._decompile_apk()
        sources_path = os.path.join(base_path, "sources")

        for root, _, files in os.walk(sources_path):
            for file in files:
                if not file.endswith(".java"):
                    continue
                file_path = os.path.join(root, file)
                all_uuid_infos.extend(
                    match_uuids(file_path, os.path.relpath(file_path, sources_path))
                )

        return all_uuid_infos
