# PEparser
Simple PEparser

## PEparser
write by C++
compiled by VS2019

## PE tools
one useful petools collected from internet

## CheckSum_PE
两种方法 提取和计算 PE校验和
IMAGE_OPTIONAL_HEADER.CheckSum 为一个DWORD(64位下也是DWORD)型的校验值,用于检查PE文件的完整性,在一些内核模式驱动及DLL中,该值必须是存在且正确的
* 利用 win32API 函数 MapFileAndCheckSum()
<br>`#include <ImageHlp.h>`<br>
`#pragma comment(lib,"ImageHlp.lib")`<br>
`MapFileAndCheckSumA(fileName, &HeaderSum, &CheckSum);`<br>
* 根据原理手工计算，部分代码汇编实现
