#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    int a = 1000,b = 2000,c = 3000;
    while(1){
    	    a = a^b^c;	
    	}
	
    return 0;
}

