---

title: 通过Fuzz挖掘包含复杂编码过程软件的漏洞

layout: post

img: post-4.jpg

---

## 背景

2018年9月21日上午，第二届[机器人网络安全大赛](http://www.integritytech.com.cn/html/News/News_312_1.html)在武汉进行，我们HALFBIT战队通过4道一血共512分的成绩成功卫冕冠军。  

赛后分析发现，有一类题目包含复杂编码过程，无法通过简单的Fuzz获得crash，而这类题目在符号执行时也会造成求解器消耗大量资源，甚至造成机器人宕机。

## 一个例子

程序主函数如下：


~~~ c

int main(void) {
    createSBox("deadbeef", 8);
    int choose;
    rcPuts("Welcome to my shellcode manager");
    while (1) {
        putMenu();
        choose = readNumber();
        switch (choose) {
            case 1:
                create();
                break;
            case 2:
                delete();
                break;
            case 3:
                run();
                break;
            default:
                return 0;
        }
    }
}
~~~

主函数为简单的菜单类型，通过用户输入选择不同的功能，与普通的CTF菜单类题目基本类似。但`readNumber`函数却与普通的读取函数有很大区别：

~~~ c

int readNumber(void) {
    char buffer[9];
    rcRead(STDIN_FILENO, buffer, 8);
    return atoi(buffer);
}
~~~

`readNumber`函数内部没有直接通过`read`函数从标准输入`stdio`中读取，而是通过调用`rcRead`函数：

~~~ c

ssize_t rcRead(int fd, char *buffer, size_t size) {
    ssize_t getSize;
    getSize = read(fd, buffer, size);
    rc4Enncrypt(buffer, getSize);
    return getSize;
}

~~~

`rcRead`函数通过从标准输入读取`size`字节数据，然后调用`rc4Enncrypt`对已读取的`buffer`进行加密，然后返回。  

也就是说，`readNumber`返回数据是经过加密编码的，因此，如果我们直接在标准输入中输入1，程序则会直接退出。考虑到Fuzz模块仅仅在纯数据域进行变异，很难通过简单变异获得一个加密后等于1的数据，所以简单fuzz很难触发这类程序中潜在的漏洞。

## 一个思路

[TaintScope](faculty.cs.tamu.edu/guofei/paper/TaintScope-Oakland10.pdf)提出可以通过预先识别checkSum并针对性绕过的思路。那么，根据这一思路，我们同样可以实现对包含复杂编码过程软件的漏洞挖掘。  

我们称之为 **基于程序变换的漏洞挖掘方法**


## 基于程序变换的漏洞挖掘方法

具体思路：

1.通过函数CFG相似性识别`rc4Enncrypt`函数

2.通过静态分析获得`rc4Enncrypt`函数的调用点

3.通过静态Patch将`rc4Enncrypt`调用指令变换为以下逻辑

```
read(fd, buffer, size);
omit_offset(start, end);
```

这样，我们可以将程序简化为普通类型程序，`omit_offset`逻辑输出二元组`<start, end>`，其中`start`表征读取时标准输入流的偏移量，`end`表征读取结束时标准输入流的偏移量。

4.通过fuzz变换后的程序获得crash文件

5.通过对二元组序列进行`rc4Decrypt`获得可以触发原始程序漏洞的crash.new文件


## 具体实现

相似性识别、调用点获取、静态patch均可基于[r2](https://radare.org) 完成。
