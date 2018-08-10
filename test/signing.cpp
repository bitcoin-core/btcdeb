#include "catch.hpp"

#include "../instance.h"

/*
Application version:
./btcdeb \
tx=8.947024:010000000001019086ce64fce1bb086395faf6fac37c73f32ba4ea89330432bf8ee8035e9315aa0100000000ffffffff021353b9030000000017a914c3f413d0918853a8e23766678d2e3c2e5c8138bb8725e4973100000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d040047304402207f874ef00f11dcc9a621acad9354f3fca1bf90c43878f607b7e2d358088487e7022052a01b47b8eef5e1c96a6affdc3dac46fdc11b60612464dc8c5921a852090d2701483045022100c56ab2abb17fdf565417228763bc9f2940a6465042fd62fbd9f4c7406345d7f702201cb1a56b45181f8347713627b325ec5df48fc1aee6bdaf937cbb804d7409b10c016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000 \
52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae \
0x \
304402207f874ef00f11dcc9a621acad9354f3fca1bf90c43878f607b7e2d358088487e7022052a01b47b8eef5e1c96a6affdc3dac46fdc11b60612464dc8c5921a852090d2701 \
3045022100c56ab2abb17fdf565417228763bc9f2940a6465042fd62fbd9f4c7406345d7f702201cb1a56b45181f8347713627b325ec5df48fc1aee6bdaf937cbb804d7409b10c01
*/
#define SCRIPT "52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae"
#define STACK1 ""
#define STACK2 "304402207f874ef00f11dcc9a621acad9354f3fca1bf90c43878f607b7e2d358088487e7022052a01b47b8eef5e1c96a6affdc3dac46fdc11b60612464dc8c5921a852090d2701"
#define STACK3 "3045022100c56ab2abb17fdf565417228763bc9f2940a6465042fd62fbd9f4c7406345d7f702201cb1a56b45181f8347713627b325ec5df48fc1aee6bdaf937cbb804d7409b10c01"
#define TXHEX  "010000000001019086ce64fce1bb086395faf6fac37c73f32ba4ea89330432bf8ee8035e9315aa0100000000ffffffff021353b9030000000017a914c3f413d0918853a8e23766678d2e3c2e5c8138bb8725e4973100000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d040047304402207f874ef00f11dcc9a621acad9354f3fca1bf90c43878f607b7e2d358088487e7022052a01b47b8eef5e1c96a6affdc3dac46fdc11b60612464dc8c5921a852090d2701483045022100c56ab2abb17fdf565417228763bc9f2940a6465042fd62fbd9f4c7406345d7f702201cb1a56b45181f8347713627b325ec5df48fc1aee6bdaf937cbb804d7409b10c016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000"
#define TXAMT  "8.947024"

TEST_CASE("Segwit Multisig Signing", "[signing-segwit-multisig]") {
    btc_logf = btc_logf_dummy;

    SECTION("Valid inputs") {
        Instance instance;
        instance.parse_transaction(TXAMT ":" TXHEX, true);

        instance.parse_script(SCRIPT);
        // script should have 6 entries
        {
            size_t count = 0;
            CScriptIter it = instance.script.begin();
            opcodetype opcode;
            std::vector<uint8_t> pushval;
            while (instance.script.GetOp(it, opcode, pushval)) {
                count++;
            }
            REQUIRE(count == 6);
        }

        const char* argv[] = {STACK1, STACK2, STACK3};
        instance.parse_stack_args(3, (char* const*)argv, 0);
        instance.setup_environment();

        // Script should have 6 operations and 3 initial items on the stack
        // The items should be (top-bottom) 0x, 303435..., 304402...
        REQUIRE(instance.env->stack.size() == 3);
        REQUIRE(HexStr(instance.stack[0]) == STACK1);
        REQUIRE(HexStr(instance.stack[1]) == STACK2);
        REQUIRE(HexStr(instance.stack[2]) == STACK3);

        // Stepping 5 times should place 5 additional items on the stack
        instance.step(5);
        REQUIRE(instance.env->stack.size() == 8);

        // Stepping again should put a 01 on the stack
        REQUIRE(instance.step());
        REQUIRE(HexStr(instance.env->stack[0]) == "01");
    }

    SECTION("Invalid signature 1 (stack item 2)") {
        #define STACK2X "304502207f874ef00f11dcc9a621acad9354f3fca1bf90c43878f607b7e2d358088487e7022052a01b47b8eef5e1c96a6affdc3dac46fdc11b60612464dc8c5921a852090d2701"
        Instance instance;
        instance.parse_transaction(TXAMT ":" TXHEX, true);
        instance.parse_script(SCRIPT);
        const char* argv[] = {STACK1, STACK2X, STACK3};
        instance.parse_stack_args(3, (char* const*)argv, 0);
        instance.setup_environment();

        // Script should have 6 operations and 3 initial items on the stack
        // The items should be (bottom-top) 0x, 303435..., 304402...
        REQUIRE(instance.env->stack.size() == 3);
        REQUIRE(HexStr(instance.stack[0]) == STACK1);
        REQUIRE(HexStr(instance.stack[1]) == STACK2X);
        REQUIRE(HexStr(instance.stack[2]) == STACK3);

        // Stepping 5 times should place 5 additional items on the stack
        instance.step(5);
        REQUIRE(instance.env->stack.size() == 8);

        // Stepping again should cause a failure
        REQUIRE(!instance.step());
    }

    SECTION("Invalid signature 2 (stack item 3)") {
        #define STACK3X "3045022100c56ab2abb17fdf565417228763bc9f2940a6465042fd62fbd9f4c7406345d7f702201cb1a56b45181f8347713627b325ec5df48fc1aee6bdaf937cbb804d7409b10c00"
        Instance instance;
        instance.parse_transaction(TXAMT ":" TXHEX, true);
        instance.parse_script(SCRIPT);
        const char* argv[] = {STACK1, STACK2, STACK3X};
        instance.parse_stack_args(3, (char* const*)argv, 0);
        instance.setup_environment();

        // Script should have 6 operations and 3 initial items on the stack
        // The items should be (bottom-top) 0x, 303435..., 304402...
        REQUIRE(instance.env->stack.size() == 3);
        REQUIRE(HexStr(instance.stack[0]) == STACK1);
        REQUIRE(HexStr(instance.stack[1]) == STACK2);
        REQUIRE(HexStr(instance.stack[2]) == STACK3X);

        // Stepping 5 times should place 5 additional items on the stack
        instance.step(5);
        REQUIRE(instance.env->stack.size() == 8);

        // Stepping again should cause a failure
        REQUIRE(!instance.step());
    }

    SECTION("Invalid amount") {
        #define TXAMTX "8.947025"
        Instance instance;
        instance.parse_transaction(TXAMTX ":" TXHEX, true);
        instance.parse_script(SCRIPT);
        const char* argv[] = {STACK1, STACK2, STACK3};
        instance.parse_stack_args(3, (char* const*)argv, 0);
        instance.setup_environment();

        // Script should have 6 operations and 3 initial items on the stack
        // The items should be (bottom-top) 0x, 303435..., 304402...
        REQUIRE(instance.env->stack.size() == 3);
        REQUIRE(HexStr(instance.stack[0]) == STACK1);
        REQUIRE(HexStr(instance.stack[1]) == STACK2);
        REQUIRE(HexStr(instance.stack[2]) == STACK3);

        // Stepping 5 times should place 5 additional items on the stack
        instance.step(5);
        REQUIRE(instance.env->stack.size() == 8);

        // Stepping again should cause a failure
        REQUIRE(!instance.step());
    }
}
