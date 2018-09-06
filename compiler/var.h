// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef included_compiler_var_h_
#define included_compiler_var_h_

#include <value.h>

struct var;

extern var* G;
extern var* Gx;
extern var* Gy;

extern std::shared_ptr<var> env_true;
extern std::shared_ptr<var> env_false;
#define env_bool(b) ((b) ? env_true : env_false)

struct var {
    Value data;
    tiny::ref pref = 0;
    bool on_curve = false;
    bool internal_function = false;
    var(const std::string& internal_function_name) : var(0) {
        data.type = Value::T_STRING;
        data.str = internal_function_name;
        internal_function = true;
    }
    var(Value data_in, bool on_curve_in = false) : data(data_in), on_curve(on_curve_in) {}
    var(tiny::ref pref_in) : data((int64_t)0), pref(pref_in) {}
    var() : data((int64_t)0) {}
    std::shared_ptr<var> shared_cp() const { return std::make_shared<var>(data, on_curve); }
    std::shared_ptr<var> encoded() const {
        if (data.type == Value::T_DATA) return shared_cp();
        if (on_curve) throw std::runtime_error("invalid var (on curve non-data)");
        Value v(data);
        v.data_value(); v.type = Value::T_DATA;
        if (data.type == Value::T_INT) {
            v.data.resize(32);
            std::reverse(v.data.begin(), v.data.end());
        }
        return std::make_shared<var>(v);
    }
    Value curve_check_and_prep(const var& other, const std::string& op) const {
        // only works if both are on the same curve
        if (on_curve != other.on_curve) {
            throw std::runtime_error(strprintf("invalid binary operation: variables must be of same type for %s operator", op));
        }
        return Value::prepare_extraction(data, other.data);
    }
    std::shared_ptr<var> invert() const {
        if (on_curve) throw std::runtime_error("cannot invert a curve point (not implemented)");
        auto v = encoded();
        v->data.do_invert_privkey();
        return v;
    }
    std::shared_ptr<var> negate(bool negneg = false) const {
        if (!on_curve && data.type == Value::T_INT) {
            if (data.int64 == 0) return shared_cp();
            if (!negneg) {
                Value v((int64_t)-data.int64);
                return std::make_shared<var>(std::move(v));
            }
        }
        if (negneg && on_curve) throw std::runtime_error("-- (negate negate) operator not viable for curve points");
        if (negneg && data.type != Value::T_INT) throw std::runtime_error("-- (negate negate) operator not viable for non-int types");
        Value v(negneg ? Value(-(int64_t)data.int64) : data);
        v.data_value();
        v.type = Value::T_DATA;
        if (on_curve) v.do_negate_pubkey(); else v.do_negate_privkey();
        return std::make_shared<var>(std::move(v), on_curve);
    }
    std::shared_ptr<var> add(const var& other, const std::string& op = "addition") const {
        if (data.type == Value::T_INT && other.data.type == Value::T_INT) {
            Value v2(data.int64 + other.data.int64);
            return std::make_shared<var>(v2, false);
        }
        if (data.type == Value::T_INT && data.int64 < 0) return negate(true)->add(other, op);
        if (other.data.type == Value::T_INT && other.data.int64 < 0) {
            auto v = other.negate();
            return add(*v, op);
        }
        if (data.is_null_or_int(0)) return other.shared_cp();
        if (other.data.is_null_or_int(0)) return shared_cp();
        if (data.type == Value::T_STRING && other.data.type == Value::T_STRING) {
            Value v2((int64_t)0);
            v2.type = Value::T_STRING;
            v2.str = data.str + other.data.str;
            return std::make_shared<var>(v2);
        }
        if (data.type == Value::T_INT) {
            return encoded()->add(other, op);
        }
        if (other.data.type == Value::T_INT) {
            auto v = other.encoded();
            return add(*v, op);
        }
        if (data.data == other.negate()->data.data) return std::make_shared<var>((int64_t)0);
        Value prep = curve_check_and_prep(other, op);
        if (on_curve) prep.do_combine_pubkeys();
        else          prep.do_combine_privkeys();
        return std::make_shared<var>(prep, on_curve);
    }
    std::shared_ptr<var> sub(const var& other) const {
        if (data.type == Value::T_DATA && other.data.type == Value::T_DATA && data.data == other.data.data) return std::make_shared<var>(Value((int64_t)0));
        if (other.data.is_null_or_int(0)) return shared_cp();
        if (data.type == Value::T_INT && other.data.type == Value::T_INT) {
            Value v2(data.int64 - other.data.int64);
            return std::make_shared<var>(v2, false);
        }
        if (other.data.type == Value::T_INT && other.data.int64 < 0) {
            auto v = other.negate();
            return add(*v, "subtraction");
        }
        Value x(other.data);
        if (other.on_curve) x.do_negate_pubkey(); else x.do_negate_privkey();
        return add(var(x, other.on_curve), "subtraction");
    }
    std::shared_ptr<var> mul(const var& other) const {
        if (data.is_null_or_int(0)) return shared_cp();
        if (data.type == Value::T_INT && data.int64 == 1) return other.shared_cp();
        if (other.data.is_null_or_int(1)) return shared_cp();
        if (other.data.type == Value::T_INT && other.data.int64 == 0) return other.shared_cp();
        if (data.type == Value::T_INT && other.data.type == Value::T_INT) {
            Value v2(data.int64 * other.data.int64);
            return std::make_shared<var>(v2, false);
        }
        if (data.type == Value::T_INT && data.int64 < 0) {
            return negate(true)->mul(other);
        }
        if (other.data.type == Value::T_INT && other.data.int64 < 0) {
            // a*-x == -(a*x)
            auto v = other.negate();
            return mul(*v)->negate();
        }
        //              on curve        off curve
        // on curve     INVALID         tweak-pubkey
        // off curve    tweak-pubkey    multiply-privkeys
        if (on_curve && other.on_curve) {
            throw std::runtime_error("invalid binary operation: variables cannot both be curve points for multiplication operator");
        }
        if (&other == G) {
            Value prep(data);
            prep.do_get_pubkey();
            return std::make_shared<var>(prep, true);
        }
        if (on_curve) return other.mul(*this);
        // we need both to be data types at this point
        if (data.type != Value::T_DATA) return encoded()->mul(other);
        if (other.data.type != Value::T_DATA) {
            auto v = other.encoded();
            return mul(*v);
        }
        Value prep = Value::prepare_extraction(data, other.data);
        if (!other.on_curve) prep.do_multiply_privkeys();
        else prep.do_tweak_pubkey();
        return std::make_shared<var>(prep, other.on_curve);
    }
    std::shared_ptr<var> pow(const var& other) const {
        if (data.is_null_or_int(0)) return shared_cp();
        if (other.data.is_null_or_int(0)) return std::make_shared<var>(Value((int64_t)1));
        if (other.data.type == Value::T_INT && other.data.int64 == 1) return shared_cp();
        if (data.type == Value::T_INT && data.int64 < 0) {
            return negate(true)->pow(other);
        }
        if (other.data.type == Value::T_INT && other.data.int64 < 0) {
            // a^(-x) = (a^(-1))^x
            return invert()->pow(Value(-other.data.int64));
        }
        //              on curve        off curve
        // on curve     INVALID         INVALID
        // off curve    INVALID         pow_privkey
        if (on_curve || other.on_curve) {
            throw std::runtime_error("invalid binary operation: variables cannot be curve points for pow operator");
        }
        // we need both to be data types at this point
        if (data.type != Value::T_DATA) return encoded()->pow(other);
        if (other.data.type != Value::T_DATA) {
            auto v = other.encoded();
            return pow(*v);
        }
        Value prep = Value::prepare_extraction(data, other.data);
        prep.do_pow_privkey();
        return std::make_shared<var>(prep, false);
    }
    std::shared_ptr<var> div(const var& other) const {
        if (on_curve || other.on_curve) throw std::runtime_error("cannot divide curve points");
        if (data.type == Value::T_INT && other.data.type == Value::T_INT) {
            Value v2(data.int64 / other.data.int64);
            return std::make_shared<var>(v2, false);
        }
        if (data.is_null_or_int(0)) return shared_cp();
        if (other.data.is_null_or_int(1)) return shared_cp();
        if (other.data.type == Value::T_INT && other.data.int64 == 0) throw std::runtime_error("division by zero");
        if (data.type == Value::T_INT && data.int64 < 0) {
            return negate(true)->div(other);
        }
        if (other.data.type == Value::T_INT && other.data.int64 < 0) {
            auto neg = other.negate(true);
            return div(*neg);
        }
        // we need both to be data types at this point
        if (data.type != Value::T_DATA) return encoded()->div(other);
        if (other.data.type != Value::T_DATA) {
            auto v = other.encoded();
            return div(*v);
        }
        // a/x = a / (x/1) = a*(1/x) = a*(x^-1)
        auto v = other.invert();
        return mul(*v);
    }
    std::shared_ptr<var> concat(const var& other) const {
        if (data.type == Value::T_DATA && data.data.size() == 0) return other.shared_cp();
        if (other.data.type == Value::T_DATA && other.data.data.size() == 0) return shared_cp();
        if (data.type == Value::T_STRING && other.data.type == Value::T_STRING) return add(other);
        Value v(data), v2(other.data);
        v.data_value();
        v.type = Value::T_DATA;
        v2.data_value();
        v2.type = Value::T_DATA;
        v.data.insert(v.data.end(), v2.data.begin(), v2.data.end());
        return std::make_shared<var>(v, false);
    }
    std::shared_ptr<var> land(const var& other) const {
        Value v(data), v2(other.data);
        v.do_boolify();
        if (!v.int64) return env_false;
        v2.do_boolify();
        return env_bool(v2.int64);
    }
    std::shared_ptr<var> lor(const var& other) const {
        Value v(data), v2(other.data);
        v.do_boolify();
        if (v.int64) return env_true;
        v2.do_boolify();
        return env_bool(v2.int64);
    }
    std::shared_ptr<var> lxor(const var& other) const {
        Value v(data), v2(other.data);
        v.do_boolify();
        v2.do_boolify();
        return env_bool(v.int64 != v2.int64);
    }
};

#endif // included_compiler_var_h_
