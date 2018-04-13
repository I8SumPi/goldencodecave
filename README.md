# GoldenCodeCave
A simple python script to find some code caves in a PE File.
## How to use
```sh
python goldencodecave.py -f <PE File> [-sc shellcode_file] [-s size] [-b byte_to_find]
```
or if you prefer:
```sh
./goldencodecave -f <PE File> [-sc shellcode_file] [-s size] [-b byte_to_find]
```
## Examples
* By default, the minimum code cave size is set to 250. So the script will search for at least 250 null bytes.
```sh
./goldencodecave -f target.exe
```
* If you specify a shellcode file, then the script will determine its size and will search for null bytes.
```sh
./goldencodecave -f target.exe -sc reverse_tcp_x86.bin
```
* If you want to search more or less than 250 bytes, you can specify the size. (if you specify a shellcode file, this arg will be ignored)
```sh
./goldencodecave -f target.exe -s 400
```
* You can also tell to the script to search a specific byte.
```sh
./goldencodecave -f target.exe -b 65
```

## Screenshot
![ScreenShot from LinuxMint with Python3](https://i.imgur.com/Fz5nRkw.jpg)

## Issues
I noticed that when I run this script with Python2 the script finds 0 code cave. It maybe only work with Python3.

## Tasks
- [x] Find code cave in PE Files
- [ ] Find code cave in ELF Files
- [ ] Write the shellcode and modify the code to jump in it and execute it
