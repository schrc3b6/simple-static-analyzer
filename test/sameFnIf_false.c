#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv, char** envp)
{

    int z=8;
    int* p = malloc(sizeof(int));
    scanf("%d",&z);
    if(z<8) {
        if(!p)
            exit(EXIT_FAILURE);
        printf("%d",z);
    } else {
        if(!p)
            exit(EXIT_FAILURE);
        *p=4; // expected-no-diagnostics
        printf("%d, %d",*p,z);
    }
    memcpy(p,&z,sizeof(int)); // expected-no-diagnostics
    free(p);
}
