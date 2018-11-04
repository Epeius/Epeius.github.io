---
title: 做想做的事情----利用S2E强制发掘CTF题目中的漏洞 
layout: post
img: post-2.jpg
---
## 背景
2017年9月21号上午，国内首届[机器人网络安全大赛](http://rhg.ichunqiu.com/)进行，我们HALFBIT战队也参与了当时的比赛，最终以攻+防第一的成绩夺得第一名 （由于当时在瑞士EPFL/[DSLab](http://dslab.epfl.ch/)/[S2E](http://s2e.systems/) 小组联合培养，未能赶赴比赛现场）。   

所有战队的机器人大同小异，[思路基本一致](https://www.leiphone.com/news/201709/zf1EKXWvjo6rgf3H.html)：   

1. 利用fuzz模块，输入错误的东西让程序崩溃；   
2. 利用漏洞挖掘引擎，找到可以挖掘的漏洞；   
3. 根据漏洞点，生成可利用的 EXP；   
4. 验证该漏洞利用程序的破坏性   

决赛题目共有10道，HALFBIT机器人的挖掘引擎总共挖掘出9道题目的漏洞，利用引擎成功对其中的3道**自动生成**7个可利用的exploit POV。

## 难点在哪里
赛后进行复盘时，我们对挖掘引擎为何无法成功挖掘出最后一道题目进行了分析，发现挖掘引擎无法穿透其中的一个函数抵达崩溃点。通过对该题目进行逆向分析，得出结论：**路径约束过于复杂，无法通过模糊变异生成可穿透的测试用例**。

CB主函数如下：

~~~ c
int main()
{
  int result; // eax@2  
  int decoded_string; // eax@3
  int v2; // eax@3
  signed int v3; // [esp+10h] [ebp-10h]@1
  int v4; // [esp+14h] [ebp-Ch]@1
  int v5; // [esp+18h] [ebp-8h]@3
  sub_80482BC();
  puts("So I give you a change to execute shellcode");
  puts("but do you know how to encode it?");
  v4 = malloc(4096);
  v3 = read(v4, 4096);
  if ( v3 > 11 )
  {
    decoded_string = decode(v4, v3);
    v5 = decoded_string;
    strcmp(decoded_string, (int)"ichunqiu"); // 漏洞触发条件
    if ( !v2 )
      ((void (*)(void))(v5 + 9))(); // 崩溃点+可利用点
    result = 0;
  }
  else
  {
    puts("Too short");
    result = 0;
  }
  return result;
~~~

主函数中对`decode`函数进行调用，通过将`decode`的结果与固定字符串`ichunqiu`对比，如果匹配，则触发后续异常。

通过IDA查看`decode`函数反编译的结果：

~~~c
int __cdecl decode(int a1, int a2)
{
  int v2; // ST1C_4@1
  char v3; // ST29_1@22
  char v4; // ST2A_1@22
  char v5; // ST2B_1@22
  int i; // [esp+20h] [ebp-18h]@1
  int j; // [esp+20h] [ebp-18h]@21
  char v9; // [esp+27h] [ebp-11h]@2
  int v10; // [esp+2Ch] [ebp-Ch]@1

  v2 = 3 * (a2 / 4);
  v10 = alloc(v2);
  memset(v10, 0, v2);
  /* 数据预处理 */
  for ( i = 0; i < a2; ++i ) 
  {
    v9 = *(_BYTE *)(a1 + i);
    if ( v9 <= 64 || v9 > 90 )
    {
      if ( v9 <= 96 || v9 > 122 )
      {
        if ( v9 <= 47 || v9 > 57 )
        {
          if ( v9 == 43 )
          {
            *(_BYTE *)(a1 + i) = 62;
          }
          else if ( v9 == 47 )
          {
            *(_BYTE *)(a1 + i) = 63;
          }
          else
          {
            if ( v9 != '=' )
            {
              puts("decode error");
              exit(1);
            }
            *(_BYTE *)(a1 + i) = 0;
          }
        }
        else
        {
          *(_BYTE *)(a1 + i) = v9 + 4;
        }
      }
      else
      {
        *(_BYTE *)(a1 + i) = v9 - 71;
      }
    }
    else
    {
      *(_BYTE *)(a1 + i) = v9 - 65;
    }
  }
  /* 重新计算 */
  for ( j = 0; a2 / 4 > j; ++j )
  {
    v3 = *(_BYTE *)(a1 + 4 * j + 1);
    v4 = *(_BYTE *)(a1 + 2 * (2 * j + 1));
    v5 = *(_BYTE *)(a1 + 4 * j + 3);
    *(_BYTE *)(v10 + 3 * j) = 4 * *(_BYTE *)(a1 + 4 * j) + (v3 >> 4);
    *(_BYTE *)(v10 + 3 * j + 1) = 16 * v3 + (v4 >> 2);
    *(_BYTE *)(v10 + 3 * j + 2) = (v4 << 6) + v5;
  }
  return v10;
}
~~~

`decode`函数第一个参数`a1`为`char`数组指针，该指针指向用户输入数据；第二个参数`a2`为输入数据的总长度。该函数第一个`for`循环对输入数据进行预处理，然后通过第二个`for`循环对连续三字节进行算术运算，将计算结果写入到新分配的堆空间中`v10`。函数最后将`v10`作为返回数据返回。

`decode` (maybe `base64_decode`) 内部逻辑较为复杂，如果通过模糊测试对整个输入空间进行随机搜索，在短时间内无法成功触发漏洞，即无法通过随机搜索产生一个解码后为`ichunqiu`的输入字符串。

## 解决思路
**符号执行 *有能力* 解决复杂约束带来的随机搜索效率低的问题。**
我们尝试通过符号执行去解决该问题，考虑到[CTF goodboy](http://angr.io) 目前对真实二进制软件+真实系统的支持不够，我们决定采用[S2E](https://github.com/s2e) 完成该任务。

S2E的使用过程一般为，首先对输入数据进行符号标记，然后设置需要监控的执行事件，最后启动执行即可 （相当EASY/相当便捷 有木有！！！）。
设置好配置文件和初始输入，启动多核模式(24核)之后，我去吃了一碗油泼面，想着吃完饭回来等着收crash就行。

然而事实告诉我，I'm TOO young, always NAIVE !!!!! 吃完饭回来后发现 毛线 都没有，S2E还在疯跑。好吧，可能是因为我吃饭太快。于是，我将S2E运行时长设置为12小时，回家睡觉了。

然而更严酷的事实告诉我，12个小时过去了，S2E依然没有报告任何Crash !!! 

杀死所有S2E进程后对debug输出进行分析，发现S2E fork产生了非常多的状态(state)，再对应到CB中，我发现，S2E是在`decode`函数中fork了太多的状态。

`decode`函数的第一个`for`循环包含7个分支，考虑到输入至少为12字节，因此，该循环理论上可以产生 `pow(7,12) = 13841287201`个状态！假设每个状态执行需要0.5s，最坏情况下(漏洞触发发生在最后一个状态)，需要**219年**才能完全遍历！

考虑使用[KLEE](https://klee.github.io/) 的状态合并(state merging)机制，然而状态合并仍然需要将状态生成，然后进行合并。因此不是可行的方法。

最后，我决定根据我编写S2E/FunctionModel的经验，手动将状态合并，避免产生过多状态。根据前面的分析，如果能避免在`decode`函数里第一个`for`循环内进行状态分化，那么就可以将13841287201个状态合并为1个大状态，从而提升测试速度。

具体思路：

1. 插桩程序执行，在进入`decode`函数第一个`for`循环前暂停执行
2. 修改循环变量`i`为巨大值，从而强制执行流绕过该`for`循环
3. 对`a1`所指向的内存进行符号数据重写，更新每个字节的符号变量
4. 恢复程序执行

具体代码：

~~~c
void Crasher::slotExecuteInstructionStart(S2EExecutionState *state, uint64_t pc) {
    assert(pc == 0x80484CA);  // 0x80484CA为for循环进入的指令地址
    preMergeStates(state);
}

/*
 *按字节读取原始输入数据，通过构建IF--THEN--ELSE表达式模拟`for`循环程序语义
 *将构建的符号表达式重新写回，并修改循环变量`i`绕过循环
*/
void Crasher::preMergeStates(S2EExecutionState *state)
{
    getWarningsStream() << "Pre-merging states..." << "\n";
    bool writeSucceed = true;
    assert(m_targetAddr);
    uint64_t offset = 0;
    for (; offset < m_targetLen; offset++) {
        // 读取原始输入数据
        klee::ref<klee::Expr> _o_v = state->readMemory8(m_targetAddr + offset);
        if (_o_v.isNull()) {
            writeSucceed = false;
            break;
        }

        std::vector<klee::ref<klee::Expr> > conditions;
        std::vector<klee::ref<klee::Expr> > values;

        klee::ref<klee::Expr> GT64 = klee::SgtExpr::create(_o_v, E_CONST(64, klee::Expr::Int8)); 
        klee::ref<klee::Expr> LE90 = klee::SleExpr::create(_o_v, E_CONST(90, klee::Expr::Int8));

        klee::ref<klee::Expr> _1c = E_AND(GT64, LE90);
        conditions.push_back(_1c); // 64 < x <= 90
        values.push_back(E_SUB(_o_v, E_CONST(65, klee::Expr::Int8))); // y := x-65

        klee::ref<klee::Expr> GT96  = klee::SgtExpr::create(_o_v, E_CONST(96, klee::Expr::Int8)); 
        klee::ref<klee::Expr> LE122 = klee::SleExpr::create(_o_v, E_CONST(122, klee::Expr::Int8));

        klee::ref<klee::Expr> _2c = E_AND(GT96, LE122);
        conditions.push_back(_2c); // 96 < x <= 122
        values.push_back(E_SUB(_o_v, E_CONST(71, klee::Expr::Int8))); // y := x-71

        klee::ref<klee::Expr> GT47 = klee::SgtExpr::create(_o_v, E_CONST(47, klee::Expr::Int8)); 
        klee::ref<klee::Expr> LE57 = klee::SleExpr::create(_o_v, E_CONST(57, klee::Expr::Int8));

        klee::ref<klee::Expr> _3c = E_AND(GT47, LE57);
        conditions.push_back(_3c); // 47 < x <= 57
        values.push_back(klee::AddExpr::create(_o_v, E_CONST(4, klee::Expr::Int8))); // y := x+4

        klee::ref<klee::Expr> _4c = E_EQ(_o_v, E_CONST(43, klee::Expr::Int8));
        conditions.push_back(_4c); // x == 43
        values.push_back(E_CONST(62, klee::Expr::Int8)); // y := 62

        klee::ref<klee::Expr> _5c = E_EQ(_o_v, E_CONST(47, klee::Expr::Int8));
        conditions.push_back(_5c); // x== 47
        values.push_back(E_CONST(63, klee::Expr::Int8)); // y := 63

        klee::ref<klee::Expr> _6c = E_EQ(_o_v, E_CONST(61, klee::Expr::Int8));
        conditions.push_back(_6c); // x == 61
        values.push_back(E_CONST(0, klee::Expr::Int8)); // y := 0

        uint8_t size = conditions.size();
        klee::ref<klee::Expr> _n_v = E_CONST(0, klee::Expr::Int8);

        /* 构建 IF--THEN--ELSE 表达式*/
        while (size) {
            klee::ref<klee::Expr> c = conditions[size-1];
            klee::ref<klee::Expr> tv = values[size-1];

            _n_v = E_ITE(c, tv, _n_v);  

            size -= 1;
        }

        // 写回对应的内存地址
        if (!state->mem()->writeMemory8(m_targetAddr + offset, _n_v)) {
            writeSucceed = false;
            break;
        }

        // Hack: add extra path constraint to avoid `decode error'
        size = conditions.size() - 1;
        getWarningsStream() << conditions[size];
        klee::ref<klee::Expr> DE = E_NOT(conditions[size--]);

        while (size) {
            DE = E_AND(E_NOT(conditions[size]), DE);
            size -= 1;
        }

        DE = E_AND(E_NOT(conditions[0]), DE);
        DE = E_EQ(E_CONST(0, klee::Expr::Bool), DE);
        state->constraints.addConstraint(DE);
    }

    if (writeSucceed) {
        assert(m_targetLen);
        target_ulong index = m_targetLen + 2;
        // EAX为循环变量`i`
        state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &index, sizeof(index));
    }

    return;
}
~~~

## 测试效果

通过预合并状态，S2E可以在不到1分钟的时间内触发crash并求解得到对应的输入用例。下表罗列出在5小时内三种不同方法的详细情况。

	
|      方法     | 内存消耗峰值 | 检出时间 | 是否检出 |
|:-------------:|-------------:|:--------:|:--------:|
|      FUZZ     |        1.28G |    N/A   |    否    |
| Non-Merge S2E |        8.91G |    N/A   |    否    |
| Pre-Merge S2E |        4.37G |  < 1 min |    是    |


## 总结
通过预先分析程序语义，可以在状态分化前**预先**合并可能的状态，避免资源消耗过大。然而这种方法存在两个问题：
1. 需要人工干预

使用该方法的前提是人工分析出程序或函数的语义，然后根据语义构建符号表达式。未来一种可行的自动化方法是对可能产生状态爆炸的代码（比如，循环）进行抽象解释分析，提取松弛过后的变量表达式，辅助符号执行跳过该段代码。

2. 约束求解器负担提升

状态预合并或合并所带来的缺点是生成的`IF--THEN--ELSE`符号表达式较传统符号执行复杂（可参见S2E/FunctionModel中`strcat`函数模型的注释），从而增加了约束求解器的负担。

PS：类似思路，也可以在CTF goodboy上实现。
