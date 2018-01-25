#include "catch.hpp"

#include "../value.h"
#include "../script.h"

TEST_CASE("Single entry values are interpreted correctly", "[single-entry-values]") {
    VALUE_WARN = false;

    SECTION("0x translates to minimal 0-length data") {
        Value minimal0("0x");
        REQUIRE(minimal0.type == Value::T_DATA);
        REQUIRE(minimal0.data.size() == 0);
        REQUIRE(minimal0.hex_str() == "");
    }

    SECTION("nonambiguous integers are treated as numbers") {
        Value nonambiguousnum("144");
        REQUIRE(nonambiguousnum.type == Value::T_INT);
        REQUIRE(nonambiguousnum.i == 144);
        REQUIRE(nonambiguousnum.hex_str() == "90");
    }

    SECTION("ambiguous integers are also treated as numbers") {
        Value ambiguousnum("1234");
        REQUIRE(ambiguousnum.type == Value::T_INT);
        REQUIRE(ambiguousnum.i == 1234);
    }

    SECTION("OP_1 translates to the opcode, not to 0x01") {
        Value opcodev("OP_1");
        REQUIRE(opcodev.type == Value::T_DATA);
        REQUIRE(opcodev.data.size() == 1);
        REQUIRE(opcodev.int_value() == OP_1);
    }

    SECTION("1 translates to the integer value, not to OP_1") {
        Value opcodeish("1");
        REQUIRE(opcodeish.type == Value::T_INT);
        REQUIRE(opcodeish.i == 1);
    }

    SECTION("123a translates to the hexadecimal value 0x123a") {
        Value hexv("123a");
        REQUIRE(hexv.type == Value::T_DATA);
        REQUIRE(hexv.data.size() == 2);
        REQUIRE(hexv.data[0] == 0x12);
        REQUIRE(hexv.data[1] == 0x3a);
    }
}

TEST_CASE("Script or not to script", "[script-notscript]") {
    SECTION("515293 becomes the number, not the script") {
        Value notascript("515293");
        REQUIRE(notascript.type == Value::T_INT);
        REQUIRE(notascript.i == 515293);
    }

    SECTION("515293 becomes the script OP_1 OP_2 OP_ADD if non_numeric is true") {
        Value ascript("515293", 0, false, false, true);
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
        Value fallthrough = Value(Value::parse_args("1234", 4), true);
        REQUIRE(fallthrough.type == Value::T_INT);
        REQUIRE(fallthrough.i == 1234);
    }
}
