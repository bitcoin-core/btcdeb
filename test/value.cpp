#include <test/catch.hpp>

#include <value.h>
#include <script/script.h>

TEST_CASE("Conversions", "[conversions]") {
    SECTION("Int to hex") {
        REQUIRE(Value("144").hex_str() == "9000");
        REQUIRE(Value("123").hex_str() == "7b");
        REQUIRE(Value("43981").hex_str() == "cdab00");
        REQUIRE(Value("2635706").hex_str() == "ba3728");
    }

    SECTION("Hex to int") {
        REQUIRE(Value("0x9000").int_value() == 144);
        REQUIRE(Value("7b").int_value() == 123);
        REQUIRE(Value("cdab00").int_value() == 43981);
        REQUIRE(Value("ba3728").int_value() == 2635706);
    }

    SECTION("Back and forth") {
        for (int64_t i = 0; i < 0x10000000; i += 123 + (i / 3)) {
            std::vector<uint8_t> data;
            CScript s;
            s << i;
            CScript::const_iterator pc = s.begin();
            opcodetype opcode;
            REQUIRE(s.GetOp(pc, opcode, data));
            // printf("%9lld: %-8s | %s\n", i, Value(i).hex_str().c_str(), HexStr(data).c_str());
            REQUIRE(Value(i).hex_str() == HexStr(data));
            REQUIRE(Value((std::string("0x") + HexStr(data)).c_str()).int_value() == i);
        }
    }
}

TEST_CASE("Single entry values are interpreted correctly", "[single-entry-values]") {
    VALUE_WARN = false;

    SECTION("Integer value is an integer value") {
        Value intv("123");
        REQUIRE(intv.type == Value::T_INT);
        REQUIRE(intv.int64 == 123);
    }

    SECTION("String value is a string") {
        Value strv("hello");
        REQUIRE(strv.type == Value::T_STRING);
        REQUIRE(strv.str == "hello");
    }

    SECTION("Hex value is data") {
        Value hexv("0123456789abcdef");
        REQUIRE(hexv.type == Value::T_DATA);
        REQUIRE(hexv.hex_str() == "0123456789abcdef");
    }

    SECTION("Opcode value is opcode") {
        Value opcv("OP_CHECKSEQUENCEVERIFY");
        REQUIRE(opcv.type == Value::T_OPCODE);
        REQUIRE(opcv.opcode == OP_CHECKSEQUENCEVERIFY);
        REQUIRE(opcv.hex_str() == strprintf("%02x", OP_CHECKSEQUENCEVERIFY));
    }

    SECTION("0x translates to minimal 0-length data") {
        Value minimal0("0x");
        REQUIRE(minimal0.type == Value::T_DATA);
        REQUIRE(minimal0.data.size() == 0);
        REQUIRE(minimal0.hex_str() == "");
    }

    SECTION("nonambiguous integers are treated as numbers") {
        Value nonambiguousnum("144");
        REQUIRE(nonambiguousnum.type == Value::T_INT);
        REQUIRE(nonambiguousnum.int64 == 144);
        REQUIRE(nonambiguousnum.hex_str() == "9000");
    }

    SECTION("ambiguous integers are also treated as numbers") {
        Value ambiguousnum("1234");
        REQUIRE(ambiguousnum.type == Value::T_INT);
        REQUIRE(ambiguousnum.int64 == 1234);
    }

    SECTION("OP_1 translates to the opcode, not to 0x01") {
        Value opcodev("OP_1");
        REQUIRE(opcodev.type == Value::T_OPCODE);
        REQUIRE(opcodev.int_value() == OP_1);
    }

    SECTION("1 translates to the integer value, not to OP_1") {
        Value opcodeish("1");
        REQUIRE(opcodeish.type == Value::T_INT);
        REQUIRE(opcodeish.int64 == 1);
    }

    SECTION("123a translates to the hexadecimal value 0x123a") {
        Value hexv("123a");
        REQUIRE(hexv.type == Value::T_DATA);
        REQUIRE(hexv.data.size() == 2);
        REQUIRE(hexv.data[0] == 0x12);
        REQUIRE(hexv.data[1] == 0x3a);
    }
}

TEST_CASE("Compact size encoder", "[compact-size]") {
    SECTION("Fitting in 1 byte") {
        std::string s = "0x";
        for (uint8_t i = 1; i < 253; ++i) {
            s += strprintf("%02x", i);
            Value v(s.c_str());
            v.do_prefix_compact_size();
            REQUIRE(v.data[0] == i);
        }
        s += "fd"; // -> 253 bytes -> 0xfd (16 bit) + LE(253) == 0xfdfd00
        {
            Value v(s.c_str());
            v.do_prefix_compact_size();
            REQUIRE((uint32_t)v.data[0] == 0xfd); // 2 byte size
            REQUIRE((uint32_t)v.data[1] == 0xfd); // 253 (lower byte)
            REQUIRE((uint32_t)v.data[2] == 0x00); // 00 (higher byte)
        }
        s += "feff000102"; // -> 258 bytes -> 0xfd + LE(258) == 0xfd0201
        {
            Value v(s.c_str());
            v.do_prefix_compact_size();
            REQUIRE((uint32_t)v.data[0] == 0xfd); // 2 byte size
            REQUIRE((uint32_t)v.data[1] == 0x02); // 02 (lower byte)
            REQUIRE((uint32_t)v.data[2] == 0x01); // 01 (higher byte)
        }
        {
            Value v("0x00");
            v.data.resize(65537);
            v.do_prefix_compact_size();
            // 65537 = 0x010001 = 0xfe (32 bit) + LE(65537) = 0xfc01000100
            REQUIRE((uint32_t)v.data[0] == 0xfe); // 4 byte size
            REQUIRE((uint32_t)v.data[1] == 0x01); // 01 (lowest byte)
            REQUIRE((uint32_t)v.data[2] == 0x00); // 00 (lower byte)
            REQUIRE((uint32_t)v.data[3] == 0x01); // 01 (higher byte)
            REQUIRE((uint32_t)v.data[4] == 0x00); // 01 (highest byte)
        }
        {
            Value v("0x00");
            v.data.resize(65538);
            v.do_prefix_compact_size();
            // 65538 = 0x010002 = 0xfe (32 bit) + LE(65538) = 0xfc02000100
            REQUIRE((uint32_t)v.data[0] == 0xfe); // 4 byte size
            REQUIRE((uint32_t)v.data[1] == 0x02); // 02 (lowest byte)
            REQUIRE((uint32_t)v.data[2] == 0x00); // 00 (lower byte)
            REQUIRE((uint32_t)v.data[3] == 0x01); // 01 (higher byte)
            REQUIRE((uint32_t)v.data[4] == 0x00); // 01 (highest byte)
        }
    }
}

TEST_CASE("Script or not to script", "[script-notscript]") {
    SECTION("515293 becomes the number, not the script") {
        Value notascript("515293");
        REQUIRE(notascript.type == Value::T_INT);
        REQUIRE(notascript.int64 == 515293);
    }

    SECTION("515293 becomes the script OP_1 OP_2 OP_ADD if non_numeric is true") {
        Value ascript("515293", 0, true);
        REQUIRE(ascript.type == Value::T_DATA);
        REQUIRE(ascript.data.size() == 3);
        REQUIRE(ascript.data[0] == OP_1);
        REQUIRE(ascript.data[1] == OP_2);
        REQUIRE(ascript.data[2] == OP_ADD);
    }
}

TEST_CASE("Bracketed values", "[bracketed-values]") {
    SECTION("push of integer 1234 = 0xd204 (with endianness)") {
        Value bracketed1("[1234]");
        REQUIRE(bracketed1.type == Value::T_DATA);
        REQUIRE(bracketed1.data.size() == 1 + 2);
        REQUIRE(bracketed1.data[0] == 2);
        REQUIRE(bracketed1.data[1] == 0xd2);
        REQUIRE(bracketed1.data[2] == 0x04);
    }

    SECTION("push of hex value 0x1234") {
        Value bracketed2("[0x1234]");
        REQUIRE(bracketed2.type == Value::T_DATA);
        REQUIRE(bracketed2.data.size() == 1 + 2);
        REQUIRE(bracketed2.data[0] == 2);
        REQUIRE(bracketed2.data[1] == 0x12);
        REQUIRE(bracketed2.data[2] == 0x34);
    }
}

TEST_CASE("Single argument args parsing", "[single-arg-parsing]") {
    SECTION("Fall through of args '1234' becomes the integer value 1234") {
        Value fallthrough = Value(Value::parse_args("1234"), true);
        REQUIRE(fallthrough.type == Value::T_INT);
        REQUIRE(fallthrough.int64 == 1234);
    }
}

TEST_CASE("Input format discrepancies (Issue #4)", "[input-format-discrepancies]") {
    SECTION("OP_ADD 99 OP_EQUAL") {
        auto withbraces = Value::parse_args("[OP_ADD 99 OP_EQUAL]");
        auto withoutbcs = Value::parse_args("OP_ADD 99 OP_EQUAL");

        // should have 1 entry, should be data
        REQUIRE(withbraces.size() == 1);
        REQUIRE(withbraces[0].type == Value::T_DATA);
        // should be a push of the given data
        REQUIRE(withbraces[0].data_value().size() == 4);
        REQUIRE(withbraces[0].data[0] == OP_ADD);
        REQUIRE(withbraces[0].data[1] == 1);
        REQUIRE(withbraces[0].data[2] == 99);
        REQUIRE(withbraces[0].data[3] == OP_EQUAL);

        // should have 3 entries
        REQUIRE(withoutbcs.size() == 3);
        // each entry should be of type data
        REQUIRE(withoutbcs[0].type == Value::T_OPCODE);
        REQUIRE(withoutbcs[1].type == Value::T_INT);
        REQUIRE(withoutbcs[2].type == Value::T_OPCODE);
        // should be the given data
        REQUIRE(withoutbcs[0].opcode == OP_ADD);
        REQUIRE(withoutbcs[1].int64 == 99);
        REQUIRE(withoutbcs[2].opcode == OP_EQUAL);

        std::string withser = Value::serialize(withbraces);
        std::string without = Value::serialize(withoutbcs);
        // with braces should be pushing the content, so it should be prepended with the size of without
        REQUIRE(withser == Value(int64_t(without.length()>>1)).hex_str() + without);
    }
}

TEST_CASE("Data push not larger than necessary", "[data-push-minimal]") {
    VALUE_WARN = false;
    char buf[30];
    for (int i = 0; i < 256; i++) {
        sprintf(buf, "[%d OP_EQUAL]", i);
        Value x(buf);
        REQUIRE(x.type == Value::T_DATA);
        CScript s;
        s << i;
        s << OP_EQUAL;
        REQUIRE(x.hex_str() == HexStr(s));
    }
    for (int64_t i = 257; i < 0x10000000; i = i * 2 - (i >> 5)) {
        sprintf(buf, "[0x%s OP_EQUAL]", Value(i).hex_str().c_str());
        Value x(buf);
        REQUIRE(x.type == Value::T_DATA);
        CScript s;
        s << i;
        s << OP_EQUAL;
        // printf("%s -> %s / %s\n", buf, x.hex_str().c_str(), HexStr(s).c_str());
        REQUIRE(x.hex_str() == HexStr(s));
    }
}

TEST_CASE("Brace insanity", "[brace-insanity]") {
    VALUE_WARN = false;
    SECTION("Double-brace") {
        const char* script = "93016387";
        Value xnfallthru(Value::parse_args("[[OP_ADD 99 OP_EQUAL]]"));
        Value xyfallthru(Value::parse_args("[[OP_ADD 99 OP_EQUAL]]"), true);
        // xnfallthru is a push of the script [OP_ADD 99 OP_EQUAL], i.e. 0493016387
        REQUIRE(xnfallthru.hex_str() == std::string("0504") + script);
    }
}

TEST_CASE("MAST article examples", "[mast-article]") {
    SECTION("[01 OP_EQUAL]") {
        Value x("[01 OP_EQUAL]");
        REQUIRE(x.hex_str() == "5187");
    }

    SECTION("OP_FROMALTSTACK OP_1 OP_EQUAL") {
        Value x("[OP_FROMALTSTACK OP_1 OP_EQUAL]");
        REQUIRE(x.hex_str() == "6c5187");
    }

    // SECTION("TOALTSTACK 9e2") {
    //     Value x("[TOALTSTACK 9e2232a0e2a41073464bdd218fa4ae9221b20ce93af704dceb0db1a0aa253fed OP_2 MERKLEBRANCHVERIFY 2DROP DROP]");
    //     REQUIRE(x.hex_str() == "6b209e2232a0e2a41073464bdd218fa4ae9221b20ce93af704dceb0db1a0aa253fed52b36d75");
    // }

    SECTION("1-2 Lightning Network Example") {
        Value x("[OP_IF 144 OP_CHECKSEQUENCEVERIFY OP_DROP 01 OP_ELSE 02 OP_ENDIF OP_EQUAL]");
        REQUIRE(x.hex_str() == "63029000b2755167526887");
    }
}

TEST_CASE("Addresses and scriptpubkeys (legacy)", "[addr-spk]") {
    static const char* address = "1PqhyaTFgaHeYVmi5qBV9AjjeiyiTV1hpx";
    static const std::vector<uint8_t> scriptPubKey = {0x76, 0xa9, 0x14, 0xfa, 0x88, 0xf0, 0x20, 0xe2, 0x22, 0x26, 0x4e, 0x2c, 0xd4, 0x00, 0x83, 0x90, 0x2b, 0xff, 0xb4, 0x02, 0x05, 0x83, 0x4a, 0x88, 0xac};
    SECTION("Decoding address") {
        Value x(address);
        x.do_addr_to_spk();
        REQUIRE(x.data == scriptPubKey);
    }
    SECTION("Encoding scriptPubKey") {
        Value x(scriptPubKey);
        x.do_spk_to_addr();
        REQUIRE(x.str == address);
    }
}

#ifdef ENABLE_DANGEROUS
TEST_CASE("Signing", "[signing]") {
    Value privkey("hello"), message("message");
    privkey.do_sha256(); message.do_sha256();
    REQUIRE(privkey.hex_str() == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    REQUIRE(message.hex_str() == "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d");

    Value pubkey = privkey;
    pubkey.do_get_pubkey();
    REQUIRE(pubkey.hex_str() == "0387d82042d93447008dfe2af762068a1e53ff394a5bf8f68a045fa642b99ea5d1");

    Value sig = Value::parse_args("ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    sig.do_sign();
    REQUIRE(sig.hex_str() == "3045022100d9a181eec58ed38289fa3bd10c65daa80a90ad9b607041848cc12ce35dcc8cfd02206e0b7f8b77bfa8e49d3c23e6b3de39bde684e5eba391782738768b01902f84aa");

    Value ver = Value::parse_args("ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d 0387d82042d93447008dfe2af762068a1e53ff394a5bf8f68a045fa642b99ea5d1 3045022100d9a181eec58ed38289fa3bd10c65daa80a90ad9b607041848cc12ce35dcc8cfd02206e0b7f8b77bfa8e49d3c23e6b3de39bde684e5eba391782738768b01902f84aa");
    ver.do_verify_sig();
    REQUIRE(ver.int_value() == 1);
}
#endif
