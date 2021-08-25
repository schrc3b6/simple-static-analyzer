#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void allocatingSomething(void** p)
{
    *p = malloc(sizeof(int));
}

int main(int argc, char** argv, char** envp)
{

    int z=8;
    int* p;
    allocatingSomething((void**)&p);
    if(p==NULL)
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

