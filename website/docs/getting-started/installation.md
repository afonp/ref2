---
sidebar_position: 1
---

# installation

## prerequisites

| dependency | version | notes |
|---|---|---|
| rust | ≥ 1.75 | install via [rustup](https://rustup.rs) |
| cmake | ≥ 3.20 | `brew install cmake` / `apt install cmake` |
| libpcap | any recent | see below |
| pkg-config | any | `brew install pkg-config` |

### installing libpcap

**macos (homebrew)**

```bash
brew install libpcap
# libpcap.pc is not automatically symlinked — run this once:
ln -s $(brew --prefix libpcap)/lib/pkgconfig/libpcap.pc \
      $(brew --prefix)/lib/pkgconfig/libpcap.pc
```

**debian / ubuntu**

```bash
sudo apt install libpcap-dev
```

**fedora / rhel**

```bash
sudo dnf install libpcap-devel
```

---

## building from source

```bash
git clone <repo-url> ref2
cd ref2

# macos: tell pkg-config where homebrew libraries live
export PKG_CONFIG_PATH="$(brew --prefix)/lib/pkgconfig:$PKG_CONFIG_PATH"

cargo build --release
```

the binary ends up at `target/release/ref2`. add it to your `$PATH` or copy it somewhere convenient:

```bash
sudo cp target/release/ref2 /usr/local/bin/
```

---

## verifying the installation

```bash
ref2 --version
# ref2 0.1.0

ref2 --help
```

---

## build flags

| flag | effect |
|---|---|
| `--release` | optimised build (lto, codegen-units=1) |
| `RUST_LOG=debug` | verbose pipeline logging at runtime |
| `CMAKE_BUILD_TYPE=Debug` | debug symbols in the C static library |

to build the C library in debug mode independently:

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
```
