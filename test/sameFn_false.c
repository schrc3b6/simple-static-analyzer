#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv, char** envp)
{

    int z=8;
    int* p = malloc(sizeof(int));
    if(!p)
        exit(EXIT_FAILURE);
    scanf("%d",&z);
    if(z<8) {
        printf("%d",z);
    } else {
        *p=4; // expected-no-diagnostics
        printf("%d, %d",*p,z);
    }
    memcpy(p,&z,sizeof(int)); // expected-no-diagnostics
    free(p);
}
