# 🔐 Hash Generator (SHA-256 & MD5)

This is a simple command-line hash generator written in **C++**, supporting both **SHA-256** and **MD5** hashing algorithms. You can input any string and get the hash output in a formatted or filter-friendly way.

---

## ✨ Features

* Compute **SHA-256** hashes (custom implementation)
* Compute **MD5** hashes (custom implementation)
* Optional filtered output (`type:text:hash`)
* Colorized terminal output for enhanced readability

---

## 🧠 How It Works

### SHA-256 Process:

1. **Preprocessing**:

   * Message is converted into bytes.
   * A `1` bit is appended, followed by `0`s to align to 448 bits mod 512.
   * Message length is appended as a 64-bit big-endian integer.
   * The message is split into 512-bit (64-byte) blocks.

2. **Hash Computation**:

   * Each block is expanded to 64 32-bit words.
   * The SHA-256 compression function is applied to update hash state.
   * After all blocks are processed, the final hash is returned as a 64-character hexadecimal string.

### MD5 Process:

1. **Initialization**:

   * Four 32-bit words (A, B, C, D) are initialized with fixed values.

2. **Preprocessing**:

   * Similar padding strategy as SHA-256, with little-endian encoding.

3. **Rounds**:

   * The message block goes through 4 rounds of operations using auxiliary functions (`F`, `G`, `H`, `I`) and predefined constants.

4. **Finalization**:

   * The final hash is produced by combining A, B, C, D into a 128-bit (16-byte) digest.

---

## ⚙️ Compilation

Compile using a C++ compiler like `g++`:

```bash
g++ -o hasher main.cpp
```

---

## 🚀 Usage

```bash
./hasher <type> [--filter] <message>
```

### Arguments:

* `<type>`: Either `sha256` or `md5`
* `[--filter]`: Optional flag to enable colon-separated output
* `<message>`: The string to hash

---

## 📌 Examples

### Standard Output (Pretty):

```bash
./hasher sha256 HelloWorld
```

```
==================================
> TYPE: sha256
> TEXT: HelloWorld
> HASH: a591a6d40bf420404a011733cfb7b190...
==================================
```

### Filter Output:

```bash
./hasher md5 --filter admin
```

```
md5:admin:21232f297a57a5a743894a0e4a801fc3
```

This format is useful for scripting, parsing, or logging.

---

## 🖍️ Color Legend

* **TYPE**: Cyan
* **TEXT**: Cyan
* **HASH**: Cyan
* **Borders**: Yellow

ANSI escape codes are used, so the output is colorized on most UNIX terminals.

---

## 🧪 Supported Platforms

* Linux
* macOS
* Windows (via WSL or terminal with ANSI support)

---

## 🧾 License

This project is open source. You are free to modify and use it however you like.
