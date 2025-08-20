### Welcome to kernel-rop-finder
This tool can find ret gadgets with up to 4 preceeding assembly instructions before the ret. <br>
It is currently being developed for Linux x86-64 and only tested on the Ubuntu 24 LTS kernel.<br>
If you encounter an error or bug, please do notify me.

### Usage
```
./kernel-rop-finder vmlinux
```
And you could for example write the results to a file:
```
./kernel-rop-finder vmlinux > gadgets.txt
```

Best regards,
Cl1nical
