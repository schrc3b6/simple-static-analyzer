#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv, char** envp)
{

    int z=8;
    int* p = malloc(sizeof(int));
    scanf("%d",&z);
    if(z<8) {
        printf("%d",z);
    } else {
        *p=4; //expected-warning {{Using Variable before checking it for Errors}}
        printf("%d, %d",*p,z);
    }
    memcpy(p,&z,sizeof(int)); //expected-warning {{Using Variable before checking it for Errors}}
    free(p);
}
