#include <iostream>
#include <Windows.h>
#include <iomanip>
#include <ImageHlp.h>
#pragma comment(lib,"ImageHlp.lib")
using namespace std;


// check pe sum
// 将 IMAGE_OPTIONAL_HEADER.CheckSum 清0 (因为这部分在文件中也是有值的, 计算时得去掉)
// 以 WORD 为单位对数据块进行带进位的累加, 记住要用 adc 指令而不是 add
// 将累加和加上文件的长度(还是用adc)
int main(int argc, char* argv[])
{
    // using win32 API 
    CHAR fileName[260] = "C:\\Windows\\SysWOW64\\notepad.exe";
    DWORD HeaderSum{};
    DWORD CheckSum{};
    MapFileAndCheckSumA(fileName, &HeaderSum, &CheckSum);
    cout << setw(12) << left << "HeaderSum:" << hex << HeaderSum << endl;
    cout << setw(12) << left << "CheckSum:" << hex << CheckSum << endl;

    // myCheckSum
    HANDLE hFile;
    DWORD fileSize{};
    PVOID fileBuffer;
    hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return -1;
    }
    fileSize = GetFileSize(hFile, NULL);
    fileBuffer = new char[fileSize];
    ZeroMemory(fileBuffer, fileSize);
    if (!ReadFile(hFile, fileBuffer, fileSize, NULL, NULL))
    {
        CloseHandle(hFile);
        return -1;
    }
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_OPTIONAL_HEADER pOptionHeader;
    pDosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 24);
    DWORD myHeaderCheckSum = pOptionHeader->CheckSum;
    pOptionHeader->CheckSum = 0;
    DWORD myCheckSum{};
    __asm
    {
        pushad
        xor eax, eax
        xor ebx, ebx
        mov esi, fileBuffer
        mov ecx, fileSize
        inc ecx
        shr ecx, 1;         // filesize / 2
        clc                 // clear cf
        loop_entry:
            lodsw;          // 是把SI指向的存储单元读入累加器, LODSW 就读入AX中, 
                            // 然后SI自动增加或减小2，lodsb 同理
            adc bx, ax;
            loop loop_entry
        mov eax, fileSize
        adc eax, ebx;
        mov myCheckSum, eax
        popad
    }
    cout << setw(12) << left << "myCheckSum:" << hex << myCheckSum << endl;
    CloseHandle(hFile);
    delete[]fileBuffer;
    return 0;
}
