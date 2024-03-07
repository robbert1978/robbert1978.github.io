---
title: 'Thêm debug symbol vào stripped libc '
categories:
  - Tool
  - Pwnable
tags:
  - Trick
  - Pwn
published: true
date: 2022-12-11
---
# Thêm debug symbol vào stripped libc 
Vào một ngày khi làm một bài pwn, với đề bài đưa libc trước, mình xài pwninit tool ...
![](https://i.imgur.com/wt45zjz.png)
pwninit bị lỗi nào đó không thể lấy file dbg trong package package `libc6-dbg_....deb` để unstrip libc.

Khi gặp nhiều bài ctf cần debug các hàm trong libc, đặc biệt là liên quan tới heap, việc không có debug symbol sẽ gây khó khăn hơn trong việc debug.
![](https://i.imgur.com/RBb0eBi.png)


Sau đây, mình xin trình bày 2 cách để "chữa cháy" lỗi này.
## Cách 1: Load debug symbol vào gdb
Bạn để ý thì pwninit nó cũng tải package libc6-dbg_....deb rồi giải nén ra, mình cũng thử tải package xem sao.
![File nén](https://i.imgur.com/K4WgOXq.png)

Ta để ý bây giờ file tên là `data.tar.xz` thay vì `data.tar` nên pwninit mới báo lỗi `failed to find file in data.tar`.

Mình thử giải nén file `data.tar.xz` ra.

Giải nén ta được thư mục usr
```
tree usr -all                                                                                                                         ─╯
usr
├── lib
│   └── debug
│       └── .build-id
│           ├── 00
│           │   ├── 329f3d85e153a01672b77b853beda0faf0dee6.debug
│           │   ├── c4ae3a65bc87ea96986b3b2441e892c8a433f0.debug
│           │   └── cd9124f765fe93560701d55d5c61c37be4657a.debug
│           ├── 01
│           │   └── 177dee353e3e44244586eed35b15f161a63908.debug
│           ├── 03
│           │   ├── 505bbb2b0381d376b10ba11b0d82f36a29155d.debug
│           │   ├── c1af6b8e962c17f07c5bea32165949660247d7.debug
│           │   └── f2e8478015abbd5470fef1563891e73f50feb3.debug
...        ...
│           └── ff
│               └── 9e98bb0b0dd91b63ac3bd84f29c82d844bddf5.debug
└── share
    └── doc
        └── libc6-dbg
            ├── changelog.Debian.gz
            └── copyright

174 directories, 300 files
```
Ta thấy giờ người ta đã chia nhỏ thành nhiều file dbg nên ta phải viết script add từng file vào gdb.
```python 
import gdb
import os
path_of_dbg_files='/tmp/test/usr/lib/debug/.build-id/'
global_path=''
def add_all_folder(path):
	global global_path
	global_path+=path+':'
	dir = os.listdir(path)
	for i in dir:
		subfolder = path + i + '/'
		if os.path.isdir(subfolder):
			add_all_folder(subfolder)
add_all_folder(path_of_dbg_files)
gdb.execute('set debug-file-directory ' + global_path[:len(global_path)-1])
```
[Document về lệnh debug-file-directory trong gdb](https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html)

Mình lưu tên file là `add_sym_libc.py`.

Mở gdb rồi chạy lệnh `source add_sym_libc.py` (trước khi `run`).

Enjoy ...
![](https://i.imgur.com/Y2MdJq9.png)
***Lưu ý:***
* Phải add sym trước khi chạy chương trình, khi chương trình đang chạy hay attach một process thì việc add sym không có giá trị (Khi viết script python dùng pwntool các bạn nên xài `gdb.debug` thay vì `gdb.attach`)
* Biến `path_of_dbg_files` luôn có `/` ở sau cùng.
## Cách 2: Build lại pwninit từ source code
Đã có [@dp1](https://github.com/dp1/) viết lại code cho libc >=2.34, dù [pull request này đã được chấp nhận](https://github.com/io12/pwninit/pull/282) nhưng mình không hiểu sao tác giả io12 vẫn giữ code cũ và không release ra phiên bản mới.

Mình clone repo https://github.com/dp1/pwninit rồi sửa lại một chút source code.

Trước khi sửa source code thì mình có đọc qua, tác giả dp1 viết code xử lý các trường hợp khi tên file là `data.tar.xz`, `data.tar.gz`, `data,tar.zst` ,gom các file dbg thành 1 file duy nhất (thật là out trình :)) )
```rust
        match ext {
            b"gz" => {
                let data = GzDecoder::new(entry);
                write_ubuntu_data_tar_file(data, file_name, out_path)
            }
            b"xz" => {
                let data = LzmaReader::new_decompressor(entry).context(DataUnzipLzmaSnafu)?;
                write_ubuntu_data_tar_file(data, file_name, out_path)
            }
            b"zst" => {
                let data = zstd::stream::read::Decoder::new(entry).context(DataUnzipZstdSnafu)?;
                write_ubuntu_data_tar_file(data, file_name, out_path)
            }
            ext => None.context(DataExtSnafu { ext }),
        }?;
```
(Đoạn này ở trong file libc_deb.rs)
### Bước 1: sửa source code
Vào file unstrip_libc.rs ở line 61
```rust 
    let name = if version_compare::compare_to(&ver.string_short, "2.34", Cmp::Lt).unwrap() {
        format!("libc-{}.so", ver.string_short)
    } else {
        let build_id = elf::get_build_id(libc).context(ElfParseSnafu)?;
        build_id.chars().skip(2).collect::<String>() + ".debug"
    };
```
sửa `"2.34"` thành `"2.31"` (theo như mình tìm hiểu thì từ libc 2.31 mới chia thành các file dbg nhỏ khác nhau)
### Bước 2: Cài các compiler và thư viện để build
Chúng ta cần cài `rustc`, `cargo`, `rust-lzma`

Mình xài ubuntu nên mình chạy lệnh
```sh 
sudo apt install rustc cargo rust-lzma-sys
```
Vào thư mục ```pwninit``` rồi chạy lệnh
```sh 
export source="$(pwd)"
cargo build --release
```
Nếu các bạn build thành công thì binary sẽ nằm ở thư mục target/release
![](https://i.imgur.com/iq0aQLl.png)

Enjoy ...
![](https://i.imgur.com/lucv8GB.png)
file libc từ `stripped` đã thành `not stripped` .

Trong trường hợp không build được ( hoặc lười ), mình đã release binary trên [github](https://github.com/robbert1978/pwninit/releases/tag/3.2.0.1).

Good luck pwning.

P/s: Mình đang viết một [tool](https://github.com/robbert1978/alt-pwninit) thay thế pwninit <(")
