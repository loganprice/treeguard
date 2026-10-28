#include <stdio.h>

// ruleid: c-cognitive-complexity
void complex_c_function(int a, int b) {
    if (a > 0) {
        for (int i = 0; i < 10; i++) {
            if (b > 5) {
                while (b < 100) {
                    if (a == b) {
                        b++;
                    } else {
                        b += 2;
                    }
                }
            }
        }
    }
}

// ok: c-cognitive-complexity
void simple_c_function(int x) {
    if (x > 0) {
        printf("positive\n");
    }
}
