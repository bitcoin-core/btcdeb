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
            CScript::const_iterator it = instance.script.begin();
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

    SECTION("Invalid input index") {
#define TXIII "01000000000102d200f8939dd0b1078c39426d19a91112beecafdd33d0b2c8407acc81a7bccc6d0000000000feffffff230666759103969e1df0906f7dd421d83caf2d13f0fb49f11f15435e82caa7bd0100000000feffffff0292681e0000000000160014ef664686809ac47fdb5a1909bde542f248cf200b0000000000000000166a14a2760fae2b10c85d48951b0077aa9cd32954cb880248304502210083b8a3569df9cdd8ead0cb2217c82b73d8427eba1359583856d66ed0485f97eb0220587561cffc22ef06bcde5457e22535bf764787e53a910ae832cad973604376db0121038b8f1123a130e976f95b160b5ab54c308482b8b57a33b113b56c5e28c0641f2102483045022100da7237baba714c9b0680369f6aa45e23b1175c61061ae50c225e889882434e7a0220274746f72290e7e34063ccce333c4c6ee4eae4f53283d59d29c62b092455bf960121038b8f1123a130e976f95b160b5ab54c308482b8b57a33b113b56c5e28c0641f2100000000"
#define TXIIIIN "01000000000101d1e0f4cebc2322072ba36d338580279900c53c50ef329f8e3d9f6947c1d41d7b0000000000feffffff02a8ba06000000000016001442a870dbf5fdb9e72a87d170cd352823c0208bba80841e0000000000160014ef664686809ac47fdb5a1909bde542f248cf200b02483045022100a7b09b01fa54dfa46030de6c8ba13a3dc0db63a4d157e314a76629816a5776b002201e49477972520879ecf640027f3a322667b4f5ec561ebbd3811a495fc1994fad012103dce50589d2b42e65f6c81fc55c7bd700b52337e4a9aedec61d8f1162332ff30721790800"
        Instance instance;
        REQUIRE(instance.parse_transaction(TXIII, true));
        REQUIRE(instance.parse_input_transaction(TXIIIIN));
        REQUIRE(instance.tx_internal_vin_index_of_txin == 1);
        REQUIRE(instance.txin_vout_index_spent_by_tx == 1);
        REQUIRE(instance.configure_tx_txin());
        REQUIRE(instance.setup_environment());
        REQUIRE(ContinueScript(*instance.env));
    }
}
