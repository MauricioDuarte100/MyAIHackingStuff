# X AND OR
We were given the challenge text:
```
Author : M_Alpha    
```

Along with the file [x-and-or](x-and-or).

After opening the main function in Ghidra we see that it takes input (the flag), and then casts it to the variable `code`. 
```c
int iVar1;
size_t sVar2;
long in_FS_OFFSET;
char local_118 [264];
long local_10;

local_10 = *(long *)(in_FS_OFFSET + 0x28);
printf("Enter the flag: ");
fgets(local_118,0x100,stdin);
sVar2 = strcspn(local_118,"\r\n");
local_118[sVar2] = '\0';
sVar2 = strnlen(local_118,0x100);
iVar1 = (*code)(local_118,sVar2 & 0xffffffff,sVar2 & 0xffffffff,code);
```
If `iVar1` equals 0, then we have the correct flag.

I explore a bit more, and look in the `init` function. Here we see that `code` is a memory area, which is later looped over and set to the contents of the memory area `check_password` XORed with `0x42`.
```c
long lVar1;

code = (undefined *)mmap((void *)0x0,0x1000,7,0x22,0,0); // https://www.man7.org/linux/man-pages/man2/mmap.2.html
*code = 0x17;
lVar1 = 1;
do { // XORs the data in check_passord and writes it to the newly mapped memory area
    code[lVar1] = (&check_password)[lVar1] ^ 0x42;
    lVar1 = lVar1 + 1;
} while (lVar1 != 500);
```

If we go to `check_password` there's of course just garbage. I used Ghidra's `XORMemoryScript.java` plugin to XOR the entire area with `0x42`, and got the appropriate function. After a bit of cleaning, this is the function.
```c
uint check_password(char *password,int flag_length)
{
  uint ret_value;
  int i;
  char to_xor [38];
  char local_12;
  long local_10;
  
  to_xor._0_8_ = 0x3136483b7c696d66;
  to_xor._8_8_ = 0x786c31631977283e;
  to_xor._16_8_ = 0x4e267d3d63334e24;
  to_xor._24_8_ = 0x31311c232b303937;
  to_xor._32_4_ = 0x1b74296a;
  to_xor._36_2_ = 0x7c62;
  if (flag_length == 0x26) {
    i = 0;
    while (i < 0x26) {
      if (((int)to_xor[i] ^ (i % 6) * (i % 6) * (i % 6)) != (int)password[i]) {
        return 0xffffffff;
      }
      i = i + 1;
    }
    ret_value = 0;
  }
  else {
    ret_value = 0xffffffff;
  }
  return ret_value;
}
```

However, due to my limited (no) reversing knowledge and not a lot of C knowledge, I was unable to get the flag by static analysis. I later realized my error; the hex values were little-endian, which of course lead me to not getting any good output. I ended up solving it dynamically in GDB by looking at the registers when it compared the correct char with my input char. This took some time as I had to build the flag char by char, but in the end I finally got it: `flag{560637dc0dcd33b5ff37880ca10b24fb}`.