# Awaiting the Inevitable Return of Emotet: Ghidra Analysis Scripts

Here you find the Ghidra scripts from our blog post [Awaiting the Inevitable Return of Emotet](https://www.hornetsecurity.com/en/security-information/awaiting-the-inevitable-return-of-emotet):

- [emotet_lib_imports.py](emotet_lib_imports.py)
- [emotet_func_imports.py](emotet_func_imports.py)
- [emotet_string_decode.py](emotet_string_decode.py)
- [emotet_ip_decode.py](emotet_ip_decode.py)
- [emotet_data_decode.py](emotet_data_decode.py)

## Usage

0. Copy the scripts from this repository to your `ghidra_scripts` folder.
1. Unpack your Emotet sample. E.g., using the free open source community developed CAPE sandbox [CAPE].
2. Import into Ghidra [GHIDRA].
3. Run Auto Analysis.
4. Run `emotet_lib_imports.py` with `currentAddress` in 2nd function called in `entry` function (this is what we refer to
 as the `emotet_get_lib` function).
5. Run `emotet_func_imports.py` (selecting `func_names.txt`) with `currentAddress` in  3rd function called in `entry` fun
ction (this is what we refer to as the `emotet_get_func` function).
6. Run `emotet_string_decode.py` with `currentAddress` in `emo_*_LoadLibraryW` function.
7. Run `emotet_string_decode.py` with `currentAddress` in 1st function called in `emo_*_LoadLibraryW` function.

Then you have:

- Comments for library and function resolution.
- Two enum types `emotet_{lib,func}_hash` with enums for the library and function hashes, which you can optionally apply 
to the `emotet_get_{lib,func}` functions.
- Emotet strings decrypted and set as comments, labels as well as searchable bookmarks.

For further details please read our blog post [Awaiting the Inevitable Return of Emotet](https://www.hornetsecurity.com/en/security-information/awaiting-the-inevitable-return-of-emotet).


