# PyPass

**PyPass** is a command-line password manager built with Python, leveraging modern libraries like `polars`, `rich`, and `prompt_toolkit` to provide a secure and user-friendly interface for managing passwords locally.

## ✨ Features

- 🔐 **Secure Storage**: Encrypt and store passwords locally using `cryptography`.
- 🧭 **Interactive CLI**: Navigate your password vault with an intuitive interface.
- 🔍 **Search**: Quickly find entries using fuzzy search.
- 📋 **Clipboard Integration**: Copy credentials securely via `pyclip`.
- 🧪 **Cross-Platform**: Works on Linux and Windows.

## 🚀 Installation

### From Source

```bash
git clone https://github.com/jonnypeace/PyPass.git
cd PyPass
pip install .
```

### From github versions

Download the windows exe, or the python pyz.

To run the pyz...

```bash
python pypass.pyz
```

The windows exe will run as it.

## 🛠 Usage

The CLI will guide you through navigating, searching, copying, and managing your stored credentials.

Some commandline args exist to automate workflows, i.e. passing a config, with stored credentials, but not essential for interactive use.

> The UI is fully interactive, using arrow keys, fuzzy search, and prompt-toolkit widgets.

## 🧩 Configuration

Using `-c` with a filename such as `pypass.conf` containing username and password, will log you in automatically. Remember to include the `-i` option for interactive if you still want to navigate. The database (`py_pass.db`) is encrypted and kept locally.

## 📦 Dependencies

PyPass uses:

- [`polars`](https://pola-rs.github.io/polars/) for fast dataframe handling
- [`rich`](https://github.com/Textualize/rich) for pretty CLI output
- [`cryptography`](https://cryptography.io/) for secure encryption
- [`prompt_toolkit`](https://github.com/prompt-toolkit/python-prompt-toolkit) for CLI widgets
- [`pyclip`](https://github.com/astrand/pyclip) for clipboard support

These are automatically installed via `pip`.

## 🧑‍💻 Development

```bash
git clone https://github.com/jonnypeace/PyPass.git
cd PyPass
pip install -e .
```

To build a standalone binary (Linux/macOS):

```bash
python -m build
shiv -c pypass -o pypass.pyz dist/*.whl
```

To build an `.exe` (Windows):

```bash
pip install pyinstaller
pyinstaller --onefile pypass/pypass.py --name pypass
```

## 📜 License

MIT License — see the [LICENSE](LICENSE) file for full details.

---

Made with ❤️ by [@jonnypeace](https://github.com/jonnypeace)

