#include "catch.hpp"

#include "../compiler/tinytokenizer.h"

inline tiny::token_t* T_2(tiny::token_type t1, tiny::token_type t2) {
    tiny::token_t* v1 = new tiny::token_t(t1, nullptr);
    tiny::token_t* v2 = new tiny::token_t(t2, v1);
    return v1;
}

inline size_t token_count(tiny::token_t* head) {
    size_t z = 0;
    for (tiny::token_t* curr = head; curr; curr = curr->next) z++;
    return z;
}

TEST_CASE("Simple Tokenize", "[tokenize-simple]") {
    SECTION("1 token") {
        #define T(t) tiny::token_t(t, nullptr)
        #define TV(t, v) tiny::token_t(t, v, nullptr)
        const char* inputs[] = {
            "0",
            "1",
            "arr",
            "\"hello world\"",
            ";",
            "=",
            "==",
            "!=",
            "my_var",
            "*",
            "0x",
            "0b",
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            "aabbccddeeff00112233445566778899gaabbccddeeff0011223344556677889",
            nullptr,
        };
        tiny::token_t expected[] = {
            T(tiny::tok_number),
            T(tiny::tok_number),
            T(tiny::tok_symbol),
            TV(tiny::tok_string, "\"hello world\""),
            T(tiny::tok_semicolon),
            T(tiny::tok_set),
            T(tiny::tok_eq),
            T(tiny::tok_ne),
            T(tiny::tok_symbol),
            T(tiny::tok_mul),
            T(tiny::tok_hex),
            T(tiny::tok_bin),
            T(tiny::tok_symbol),
            T(tiny::tok_symbol),
        };
        for (size_t i = 0; inputs[i]; ++i) {
            GIVEN(inputs[i]) {
                tiny::token_t* t = tiny::tokenize(inputs[i]);
                REQUIRE(token_count(t) == 1);
                REQUIRE(t->token == expected[i].token);
                if (expected[i].value) REQUIRE(std::string(t->value) == expected[i].value);
                delete t;
            }
        }
        #undef T
        #undef TV
    }

    SECTION("2 tokens") {
        #define T T_2
        const char* inputs[] = {
            "0x123",
            "-a",
            "var1 var2",
            "!!",
            "-1",
            nullptr,
        };
        tiny::token_t* expected[] = {
            T(tiny::tok_hex, tiny::tok_number),
            T(tiny::tok_minus, tiny::tok_symbol),
            T(tiny::tok_symbol, tiny::tok_symbol),
            T(tiny::tok_not, tiny::tok_not),
            T(tiny::tok_minus, tiny::tok_number),
        };
        for (size_t i = 0; inputs[i]; ++i) {
            GIVEN(inputs[i]) {
                tiny::token_t* t = tiny::tokenize(inputs[i]);
                REQUIRE(token_count(t) == 2);
                REQUIRE(t->token == expected[i]->token);
                REQUIRE(t->next->token == expected[i]->next->token);
                delete t;
                delete expected[i];
            }
        }
        #undef T
    }
}
