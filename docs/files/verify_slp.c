/* Independent C99 verifier for the published 29-AND AES S-box SLP. */
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_WIRES 1024
#define MAX_OPS 512
#define NAME_LEN 64
#define LINE_LEN 1024

typedef enum { OP_XOR, OP_AND, OP_NOT } Kind;
typedef struct { Kind kind; int out, a, b; } Op;

static char names[MAX_WIRES][NAME_LEN];
static int wire_count = 0;
static Op operations[MAX_OPS];
static int operation_count = 0;

static int find_wire(const char *name) {
    int i;
    for (i = 0; i < wire_count; ++i) {
        if (strcmp(names[i], name) == 0) return i;
    }
    return -1;
}

static int add_wire(const char *name) {
    size_t length = strlen(name);
    if (length == 0 || length >= NAME_LEN || wire_count >= MAX_WIRES) return -1;
    if (find_wire(name) >= 0) return -1;
    memcpy(names[wire_count], name, length + 1);
    return wire_count++;
}

static uint8_t gf256_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    int i;
    for (i = 0; i < 8; ++i) {
        uint8_t high;
        if (b & 1U) result ^= a;
        high = (uint8_t)(a & 0x80U);
        a = (uint8_t)(a << 1);
        if (high) a ^= 0x1bU;
        b = (uint8_t)(b >> 1);
    }
    return result;
}

static uint8_t aes_sbox(uint8_t x) {
    uint8_t inverse = 0;
    uint8_t output = 0;
    int i;
    if (x != 0) {
        uint8_t base = x;
        int exponent = 254;
        inverse = 1;
        while (exponent != 0) {
            if (exponent & 1) inverse = gf256_mul(inverse, base);
            base = gf256_mul(base, base);
            exponent >>= 1;
        }
    }
    for (i = 0; i < 8; ++i) {
        int bit = (
            ((inverse >> i) & 1U)
            ^ ((inverse >> ((i + 4) & 7)) & 1U)
            ^ ((inverse >> ((i + 5) & 7)) & 1U)
            ^ ((inverse >> ((i + 6) & 7)) & 1U)
            ^ ((inverse >> ((i + 7) & 7)) & 1U)
            ^ ((0x63U >> i) & 1U)
        );
        output = (uint8_t)(output | (uint8_t)(bit << i));
    }
    return output;
}

static void trim(char *text) {
    char *hash = strchr(text, '#');
    char *first;
    size_t length;
    if (hash != NULL) *hash = '\0';
    length = strlen(text);
    while (length > 0 && isspace((unsigned char)text[length - 1])) text[--length] = '\0';
    first = text;
    while (*first != '\0' && isspace((unsigned char)*first)) ++first;
    if (first != text) memmove(text, first, strlen(first) + 1);
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "circuits/aes-sbox-fwd-g228-a29-d35-ad6.slp";
    FILE *file;
    char line[LINE_LEN];
    int line_number = 0;
    int inside = 0;
    int began = 0;
    int ended = 0;
    int and_count = 0;
    int output_indices[8];
    uint8_t values[MAX_WIRES];
    int i;

    if (argc > 2) {
        fprintf(stderr, "usage: %s [circuit.slp]\n", argv[0]);
        return 2;
    }
    file = fopen(path, "r");
    if (file == NULL) {
        perror(path);
        return 2;
    }
    for (i = 0; i < 8; ++i) {
        char name[16];
        (void)snprintf(name, sizeof name, "U%d", i);
        if (add_wire(name) < 0) {
            fprintf(stderr, "input setup failed\n");
            fclose(file);
            return 2;
        }
    }

    while (fgets(line, sizeof line, file) != NULL) {
        char opcode[16], output[NAME_LEN], a[NAME_LEN], b[NAME_LEN], extra[2];
        int fields;
        Kind kind;
        int ai, bi = -1, oi;
        ++line_number;
        if (strchr(line, '\n') == NULL && !feof(file)) {
            fprintf(stderr, "line %d exceeds %d bytes\n", line_number, LINE_LEN - 1);
            fclose(file);
            return 2;
        }
        trim(line);
        if (line[0] == '\0') continue;
        if (strcmp(line, "begin SLP") == 0) {
            if (inside || began || ended) {
                fprintf(stderr, "line %d: duplicate begin SLP\n", line_number);
                fclose(file);
                return 2;
            }
            inside = began = 1;
            continue;
        }
        if (strcmp(line, "end SLP") == 0) {
            if (!inside || ended) {
                fprintf(stderr, "line %d: unmatched end SLP\n", line_number);
                fclose(file);
                return 2;
            }
            inside = 0;
            ended = 1;
            continue;
        }
        if (!inside) continue;

        fields = sscanf(line, "%15s %63s %63s %63s %1s", opcode, output, a, b, extra);
        if ((strcmp(opcode, "XOR") == 0 || strcmp(opcode, "AND") == 0) && fields == 4) {
            kind = strcmp(opcode, "XOR") == 0 ? OP_XOR : OP_AND;
            bi = find_wire(b);
            if (bi < 0) {
                fprintf(stderr, "line %d: undefined operand %s\n", line_number, b);
                fclose(file);
                return 2;
            }
        } else if (strcmp(opcode, "NOT") == 0 && fields == 3) {
            kind = OP_NOT;
        } else {
            fprintf(stderr, "line %d: illegal instruction\n", line_number);
            fclose(file);
            return 2;
        }

        ai = find_wire(a);
        if (ai < 0) {
            fprintf(stderr, "line %d: undefined operand %s\n", line_number, a);
            fclose(file);
            return 2;
        }
        oi = add_wire(output);
        if (oi < 0) {
            fprintf(stderr, "line %d: duplicate or invalid output %s\n", line_number, output);
            fclose(file);
            return 2;
        }
        if (operation_count >= MAX_OPS) {
            fprintf(stderr, "too many operations\n");
            fclose(file);
            return 2;
        }
        operations[operation_count++] = (Op){kind, oi, ai, bi};
        if (kind == OP_AND) ++and_count;
    }
    fclose(file);

    if (!began || !ended || inside) {
        fprintf(stderr, "missing or unbalanced SLP delimiters\n");
        return 2;
    }
    if (and_count != 29) {
        fprintf(stderr, "expected exactly 29 AND gates, found %d\n", and_count);
        return 1;
    }
    for (i = 0; i < 8; ++i) {
        char name[16];
        (void)snprintf(name, sizeof name, "S%d", i);
        output_indices[i] = find_wire(name);
        if (output_indices[i] < 0) {
            fprintf(stderr, "missing output %s\n", name);
            return 2;
        }
    }

    for (i = 0; i < 256; ++i) {
        int operation_index;
        int output = 0;
        int bit;
        int expected;
        memset(values, 0, sizeof values);
        for (bit = 0; bit < 8; ++bit) values[bit] = (uint8_t)((i >> (7 - bit)) & 1);
        for (operation_index = 0; operation_index < operation_count; ++operation_index) {
            Op operation = operations[operation_index];
            if (operation.kind == OP_XOR) {
                values[operation.out] = (uint8_t)(values[operation.a] ^ values[operation.b]);
            } else if (operation.kind == OP_AND) {
                values[operation.out] = (uint8_t)(values[operation.a] & values[operation.b]);
            } else {
                values[operation.out] = (uint8_t)(values[operation.a] ^ 1U);
            }
        }
        for (bit = 0; bit < 8; ++bit) output |= values[output_indices[bit]] << (7 - bit);
        expected = aes_sbox((uint8_t)i);
        if (output != expected) {
            fprintf(stderr, "mismatch at %02x: obtained %02x, expected %02x\n", i, output, expected);
            return 1;
        }
    }

    printf("PASS: C99 verifier; %d instructions; 29 AND; all 256 inputs\n", operation_count);
    return 0;
}
