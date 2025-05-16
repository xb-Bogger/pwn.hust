# pwn.hust
漏洞利用-内核攻防实践
将四个ELF文件在VS Code界面上传到桌面(因为桌面和QEMU是相通的)，文件和题号对应

如果遇到权限问题导致无法执行，在命令行输入chmod 777 [filename] 即可
## 1 空指针解引用
在命令行中，首先vm connect进入QEMU虚拟机，然后cd Desktop切换到桌面，执行./1，便能获得root shell，然后便能cat /flag，复制得到flag
## 2 空指针引用进阶版
同上，注意程序名对应换一下
## 3 内核释放后使用
同上
## 4 脏管道实践
同上，但是执行./4后需要再次执行/bin/mount才能进入root shell，继续获得flag
