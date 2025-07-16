#include "server.h"
#include <stdio.h>

int main() {
    printf("[SERVER DEBUG] Server started\n");
    Server s(PORT);
    s.start();
    return 0;
}
