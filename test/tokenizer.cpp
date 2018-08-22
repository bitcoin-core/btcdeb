#include "catch.hpp"

#include "../tinyparser.h"

inline tiny::token_t* T_2(tiny::token_type t1, tiny::token_type t2) {
    tiny::token_t* v1 = new tiny::token_t(t1, nullptr);
    tiny::token_t* v2 = new tiny::token_t(t2, v1);
    return v1;
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
            T(tiny::tok_equal),
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
                REQUIRE(t->next == nullptr);
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
            "==",
            "!=",
            "!!",
            "-1",
            nullptr,
        };
        tiny::token_t* expected[] = {
            T(tiny::tok_hex, tiny::tok_number),
            T(tiny::tok_minus, tiny::tok_symbol),
            T(tiny::tok_symbol, tiny::tok_symbol),
            T(tiny::tok_equal, tiny::tok_equal),
            T(tiny::tok_exclaim, tiny::tok_equal),
            T(tiny::tok_exclaim, tiny::tok_exclaim),
            T(tiny::tok_minus, tiny::tok_number),
        };
        for (size_t i = 0; inputs[i]; ++i) {
            GIVEN(inputs[i]) {
                tiny::token_t* t = tiny::tokenize(inputs[i]);
                REQUIRE(t->next != nullptr);
                REQUIRE(t->token == expected[i]->token);
                REQUIRE(t->next->next == nullptr);
                REQUIRE(t->next->token == expected[i]->next->token);
                delete t;
                delete expected[i];
            }
        }
        #undef T
    }
}

// TEST_CASE("Segwit Multisig Signing", "[signing-segwit-multisig]") {
//     btc_logf = btc_logf_dummy;
// 
//     SECTION("Valid inputs") {
//         Instance instance;
//         instance.parse_transaction(TXAMT ":" TXHEX, true);
// 
//         instance.parse_script(SCRIPT);
//         // script should have 6 entries
//         {
//             size_t count = 0;
//             CScriptIter it = instance.script.begin();
//             opcodetype opcode;
//             std::vector<uint8_t> pushval;
//             while (instance.script.GetOp(it, opcode, pushval)) {
//                 count++;
//             }
//             REQUIRE(count == 6);
//         }
// 
//         const char* argv[] = {STACK1, STACK2, STACK3};
//         instance.parse_stack_args(3, (char* const*)argv, 0);
//         instance.setup_environment();
// 
//         // Script should have 6 operations and 3 initial items on the stack
//         // The items should be (top-bottom) 0x, 303435..., 304402...
//         REQUIRE(instance.env->stack.size() == 3);
//         REQUIRE(HexStr(instance.stack[0]) == STACK1);
//         REQUIRE(HexStr(instance.stack[1]) == STACK2);
//         REQUIRE(HexStr(instance.stack[2]) == STACK3);
// 
//         // Stepping 5 times should place 5 additional items on the stack
//         instance.step(5);
//         REQUIRE(instance.env->stack.size() == 8);
// 
//         // Stepping again should put a 01 on the stack
//         REQUIRE(instance.step());
//         REQUIRE(HexStr(instance.env->stack[0]) == "01");
//     }
// 
//     SECTION("Invalid signature 1 (stack item 2)") {
//         #define STACK2X "304502207f874ef00f11dcc9a621acad9354f3fca1bf90c43878f607b7e2d358088487e7022052a01b47b8eef5e1c96a6affdc3dac46fdc11b60612464dc8c5921a852090d2701"
//         Instance instance;
//         instance.parse_transaction(TXAMT ":" TXHEX, true);
//         instance.parse_script(SCRIPT);
//         const char* argv[] = {STACK1, STACK2X, STACK3};
//         instance.parse_stack_args(3, (char* const*)argv, 0);
//         instance.setup_environment();
// 
//         // Script should have 6 operations and 3 initial items on the stack
//         // The items should be (bottom-top) 0x, 303435..., 304402...
//         REQUIRE(instance.env->stack.size() == 3);
//         REQUIRE(HexStr(instance.stack[0]) == STACK1);
//         REQUIRE(HexStr(instance.stack[1]) == STACK2X);
//         REQUIRE(HexStr(instance.stack[2]) == STACK3);
// 
//         // Stepping 5 times should place 5 additional items on the stack
//         instance.step(5);
//         REQUIRE(instance.env->stack.size() == 8);
// 
//         // Stepping again should cause a failure
//         REQUIRE(!instance.step());
//     }
// 
//     SECTION("Invalid signature 2 (stack item 3)") {
//         #define STACK3X "3045022100c56ab2abb17fdf565417228763bc9f2940a6465042fd62fbd9f4c7406345d7f702201cb1a56b45181f8347713627b325ec5df48fc1aee6bdaf937cbb804d7409b10c00"
//         Instance instance;
//         instance.parse_transaction(TXAMT ":" TXHEX, true);
//         instance.parse_script(SCRIPT);
//         const char* argv[] = {STACK1, STACK2, STACK3X};
//         instance.parse_stack_args(3, (char* const*)argv, 0);
//         instance.setup_environment();
// 
//         // Script should have 6 operations and 3 initial items on the stack
//         // The items should be (bottom-top) 0x, 303435..., 304402...
//         REQUIRE(instance.env->stack.size() == 3);
//         REQUIRE(HexStr(instance.stack[0]) == STACK1);
//         REQUIRE(HexStr(instance.stack[1]) == STACK2);
//         REQUIRE(HexStr(instance.stack[2]) == STACK3X);
// 
//         // Stepping 5 times should place 5 additional items on the stack
//         instance.step(5);
//         REQUIRE(instance.env->stack.size() == 8);
// 
//         // Stepping again should cause a failure
//         REQUIRE(!instance.step());
//     }
// 
//     SECTION("Invalid amount") {
//         #define TXAMTX "8.947025"
//         Instance instance;
//         instance.parse_transaction(TXAMTX ":" TXHEX, true);
//         instance.parse_script(SCRIPT);
//         const char* argv[] = {STACK1, STACK2, STACK3};
//         instance.parse_stack_args(3, (char* const*)argv, 0);
//         instance.setup_environment();
// 
//         // Script should have 6 operations and 3 initial items on the stack
//         // The items should be (bottom-top) 0x, 303435..., 304402...
//         REQUIRE(instance.env->stack.size() == 3);
//         REQUIRE(HexStr(instance.stack[0]) == STACK1);
//         REQUIRE(HexStr(instance.stack[1]) == STACK2);
//         REQUIRE(HexStr(instance.stack[2]) == STACK3);
// 
//         // Stepping 5 times should place 5 additional items on the stack
//         instance.step(5);
//         REQUIRE(instance.env->stack.size() == 8);
// 
//         // Stepping again should cause a failure
//         REQUIRE(!instance.step());
//     }
// }
