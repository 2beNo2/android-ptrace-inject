
#include <stdio.h>

__attribute__((constructor)) void my_inject()
{
    printf("inject ok!\n");
    fflush(stdout);
}
