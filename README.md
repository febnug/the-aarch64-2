# the-aarch64-2
<p><img src="https://fnlqxz.my.id/asset/frieren-arm.jpg" width="330px" height=425px"/></p>
small ELF aarch64 example
<p>Cara compile:</p>
<p><pre>
aarch64-linux-gnu-as fn_arm64.S -o fn_arm64.o
aarch64-linux-gnu-ld -T link.ld -o linked.elf fn_arm64.o
aarch64-linux-gnu-objcopy -O binary linked.elf fn_arm64
chmod +x fn_arm64

file fn_arm64
readelf -h fn_arm64 | grep Entry
readelf -l fn_arm64
qemu-aarch64 ./fn_arm64</pre></p>
