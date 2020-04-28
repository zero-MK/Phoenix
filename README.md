Phoenix is the spiritual successor to the Protostar challenges. It covers the following topics:

- Network programming
- Stack overflows
- Format string vulnerabilities
- Heap overflows

The idea is to introduce the simplest concepts first, from memory corruption, modification, function redirection, and eventually, executing shellcode. These challenges are available for both 32 bit, and 64 bit mode. The 64 bit challenges are new, and were not available on Protostar.

### Download

You may download Phoenix from the [downloads](https://exploit.education/downloads/) page.

### Getting started

For more information on how to get started, see the [getting started](https://exploit.education/phoenix/getting-started/) page.



官方仓库：https://github.com/ExploitEducation/Phoenix

上面是主页的原话

主要就是有一些有漏洞的 ELF

- 网络编程
- 栈溢出
- 格式化字符串
- 堆溢出

我最近要总结一下以前学的 PWN

一直在看 Linux 内核源码，以及发生了一些不是很好的事情，很久没有参加 CTF 赛事了，差不多都忘了，现在也算是想回到赛场吧

抱怨了那么多，开始吧

我的做题环境是用 IDA， Ghidra， cutter，pwntools，gdb ，所以我把 Phoenix 提供的 deb 解包，然后拿出里面的 binary 分析

```bash
wget https://github.com/ExploitEducation/Phoenix/releases/download/v1.0.0-alpha-3/exploit-education-phoenix_1.0.0-_amd64.deb 

dpkg -X exploit-education-phoenix_1.0.0-_amd64.deb
```

解压出来两个文件夹，binary 都在 opt/Phoenix 里面

当然你也可以直接安装

```bash
sudo dpkg -i exploit-education-phoenix_1.0.0-_amd64.deb
```

好了开始