// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <vector>
#include <unordered_map>
#include <script/script.h>
#include <script/miniscript.h>
#include <span.h>
#include <util/strencodings.h>

#include <miniscript/compiler.h>

#include <assert.h>

const CompilerContext COMPILER_CTX;

namespace {

using Node = miniscript::NodeRef<CompilerContext::Key>;
using NodeType = miniscript::NodeType;
using miniscript::operator"" _mst;

template<typename... Args>
Node MakeNode(Args&&... args) { return miniscript::MakeNodeRef<CompilerContext::Key>(std::forward<Args>(args)...); }

struct Policy {
    enum class Type {
        NONE,

        PK,
        OLDER,
        AFTER,
        HASH160,
        HASH256,
        RIPEMD160,
        SHA256,
        AND,
        OR,
        THRESH
    };

    Type node_type = Type::NONE;
    std::vector<Policy> sub;
    std::vector<unsigned char> data;
    std::vector<CompilerContext::Key> keys;
    std::vector<uint32_t> prob;
    uint32_t k = 0;

    ~Policy() = default;
    Policy(const Policy& x) = delete;
    Policy& operator=(const Policy& x) = delete;
    Policy& operator=(Policy&& x) = default;
    Policy(Policy&& x) = default;

    explicit Policy(Type nt) : node_type(nt) {}
    explicit Policy(Type nt, uint32_t kv) : node_type(nt), k(kv) {}
    explicit Policy(Type nt, std::vector<unsigned char>&& dat) : node_type(nt), data(std::move(dat)) {}
    explicit Policy(Type nt, std::vector<unsigned char>&& dat, uint32_t kv) : node_type(nt), data(std::move(dat)), k(kv) {}
    explicit Policy(Type nt, std::vector<Policy>&& subs) : node_type(nt), sub(std::move(subs)) {}
    explicit Policy(Type nt, std::vector<CompilerContext::Key>&& key) : node_type(nt), keys(std::move(key)) {}
    explicit Policy(Type nt, std::vector<Policy>&& subs, std::vector<uint32_t>&& probs) : node_type(nt), sub(std::move(subs)), prob(std::move(probs)) {}
    explicit Policy(Type nt, std::vector<Policy>&& subs, uint32_t kv) : node_type(nt), sub(std::move(subs)), k(kv) {}
    explicit Policy(Type nt, std::vector<CompilerContext::Key>&& key, uint32_t kv) : node_type(nt), keys(std::move(key)), k(kv) {}

    bool operator()() const { return node_type != Type::NONE; }
};

std::vector<unsigned char> Hash(const Span<const char>& in, size_t len)
{
    auto unhex = ParseHex(std::string(in.begin(), in.end()));
    if (unhex.size() == len) return unhex;
    return {};
}

Policy Parse(Span<const char>& in);

Policy ParseProb(Span<const char>& in, uint32_t& prob) {
    prob = 0;
    while (in.size() && in[0] >= ('0' + (prob == 0)) && in[0] <= '9') {
        prob = std::min<uint32_t>(prob * 10 + (in[0] - '0'), std::numeric_limits<uint16_t>::max());
        in = in.subspan(1);
    }
    if (prob) {
        if (in.size() == 0 || in[0] != '@') return Policy(Policy::Type::NONE);
        in = in.subspan(1);
    } else {
        prob = 1;
    }
    return Parse(in);
}

Policy Parse(Span<const char>& in) {
    using namespace spanparsing;
    auto expr = Expr(in);
    if (Func("pk", expr)) {
        CompilerContext::Key key;
        if (COMPILER_CTX.FromString(expr.begin(), expr.end(), key)) {
            return Policy(Policy::Type::PK, Vector(std::move(key)));
        }
        return Policy(Policy::Type::NONE);
    } else if (Func("after", expr)) {
        uint64_t num;
        if (!ParseUInt64(std::string(expr.begin(), expr.end()), &num)) {
            return Policy(Policy::Type::NONE);
        }
        if (num >= 1 && num < 0x80000000UL) {
            return Policy(Policy::Type::AFTER, num);
        }
        return Policy(Policy::Type::NONE);
    } else if (Func("older", expr)) {
        uint64_t num;
        if (!ParseUInt64(std::string(expr.begin(), expr.end()), &num)) {
            return Policy(Policy::Type::NONE);
        }
        if (num >= 1 && num < 0x80000000UL) {
            return Policy(Policy::Type::OLDER, num);
        }
        return Policy(Policy::Type::NONE);
    } else if (Func("sha256", expr)) {
        auto hash = Hash(expr, 32);
        if (hash.size()) return Policy(Policy::Type::SHA256, std::move(hash));
        return Policy(Policy::Type::NONE);
    } else if (Func("ripemd160", expr)) {
        auto hash = Hash(expr, 20);
        if (hash.size()) return Policy(Policy::Type::RIPEMD160, std::move(hash));
        return Policy(Policy::Type::NONE);
    } else if (Func("hash256", expr)) {
        auto hash = Hash(expr, 32);
        if (hash.size()) return Policy(Policy::Type::HASH256, std::move(hash));
        return Policy(Policy::Type::NONE);
    } else if (Func("hash160", expr)) {
        auto hash = Hash(expr, 20);
        if (!hash.size()) {
            // symbol
            size_t len = 0;
            while (expr[len] && expr[len] != ')') ++len;
            hash = std::vector<uint8_t>((uint8_t*)&expr[0], (uint8_t*)&expr[len]);
        }
        return Policy(Policy::Type::HASH160, std::move(hash));
    } else if (Func("or", expr)) {
        std::vector<Policy> sub;
        std::vector<uint32_t> prob;
        uint32_t p;
        sub.emplace_back(ParseProb(expr, p));
        if (!sub.back()()) return Policy(Policy::Type::NONE);
        prob.push_back(p);
        while (expr.size()) {
            if (!Const(",", expr)) return Policy(Policy::Type::NONE);
            sub.emplace_back(ParseProb(expr, p));
            if (!sub.back()()) return Policy(Policy::Type::NONE);
            prob.push_back(p);
        }
        return Policy(Policy::Type::OR, std::move(sub), std::move(prob));
    } else if (Func("and", expr)) {
        std::vector<Policy> sub;
        sub.emplace_back(Parse(expr));
        if (!sub.back()()) return Policy(Policy::Type::NONE);
        while (expr.size()) {
            if (!Const(",", expr)) return Policy(Policy::Type::NONE);
            sub.emplace_back(Parse(expr));
            if (!sub.back()()) return Policy(Policy::Type::NONE);
        }
        return Policy(Policy::Type::AND, std::move(sub));
    } else if (Func("thresh", expr)) {
        auto arg = Expr(expr);
        uint32_t count;
        if (!ParseUInt32(std::string(arg.begin(), arg.end()), &count)) {
            return Policy(Policy::Type::NONE);
        }
        if (count < 1) return Policy(Policy::Type::NONE);
        std::vector<Policy> sub;
        while (expr.size()) {
            if (!Const(",", expr)) return Policy(Policy::Type::NONE);
            sub.emplace_back(Parse(expr));
            if (!sub.back()()) return Policy(Policy::Type::NONE);
        }
        if (sub.size() > 100 || count > sub.size()) return Policy(Policy::Type::NONE);
        return Policy(Policy::Type::THRESH, std::move(sub), count);
    }

    return Policy(Policy::Type::NONE);
}

Policy Parse(const std::string& in) {
    try {
        Span<const char> sp(in.data(), in.size());
        Policy ret = Parse(sp);
        if (sp.size()) return Policy(Policy::Type::NONE);
        return ret;
    } catch (const std::logic_error&) {
        return Policy(Policy::Type::NONE);
    }
}

struct Strat {
    enum class Type {
        JUST_0, JUST_1,
        PK, THRESH_M,
        OLDER, AFTER,
        HASH160, HASH256, SHA256, RIPEMD160,
        AND, OR, ANDOR, THRESH,
        WRAP_AS, WRAP_C, WRAP_D, WRAP_V, WRAP_J, WRAP_N, // Several kinds of wrappers that don't change semantics
        MULTI, // Every subgraph is a separate compilation strategy; try each once
        CACHE, // sub[0] is the dependency; sub[1] and higher are (possibly self-referential) improvements to try repeatedly until all of them stop improving
    };

    Type node_type;
    std::vector<const Strat*> sub;
    std::vector<CompilerContext::Key> keys;
    std::vector<unsigned char> data;
    int64_t k = 0;
    double prob;

    explicit Strat(Type nt) : node_type(nt) {}
    explicit Strat(Type nt, int64_t kv) : node_type(nt), k(kv) {}
    explicit Strat(Type nt, std::vector<unsigned char> dat) : node_type(nt), data(std::move(dat)) {}
    explicit Strat(Type nt, std::vector<unsigned char> dat, int64_t kv) : node_type(nt), data(std::move(dat)), k(kv) {}
    explicit Strat(Type nt, std::vector<const Strat*> subs) : node_type(nt), sub(std::move(subs)) {}
    explicit Strat(Type nt, std::vector<CompilerContext::Key> key) : node_type(nt), keys(std::move(key)) {}
    explicit Strat(Type nt, std::vector<const Strat*> subs, double probs) : node_type(nt), sub(std::move(subs)), prob(probs) {}
    explicit Strat(Type nt, std::vector<const Strat*> subs, int64_t kv, double probs) : node_type(nt), sub(std::move(subs)), k(kv), prob(probs) {}
    explicit Strat(Type nt, std::vector<const Strat*> subs, int64_t kv) : node_type(nt), sub(std::move(subs)), k(kv) {}
    explicit Strat(Type nt, std::vector<CompilerContext::Key> key, int64_t kv) : node_type(nt), keys(std::move(key)), k(kv) {}
};

typedef std::vector<std::unique_ptr<Strat>> StratStore;

template <typename... X>
const Strat* MakeStrat(StratStore& store, X&&... args) { 
    Strat* ret = new Strat(std::forward<X>(args)...);
    store.emplace_back(ret);
    return ret;
}

template <typename... X>
Strat* MakeMutStrat(StratStore& store, X&&... args) { 
    Strat* ret = new Strat(std::forward<X>(args)...);
    store.emplace_back(ret);
    return ret;
}

const Strat* ComputeStrategy(const Policy& node, std::unordered_map<const Policy*, const Strat*>& cache, StratStore& store);

const Strat* GetStrategy(const Policy& node, std::unordered_map<const Policy*, const Strat*>& cache, StratStore& store) {
    auto it = cache.find(&node);
    if (it != cache.end()) return it->second;
    auto ret = ComputeStrategy(node, cache, store);
    if (ret) cache.emplace(&node, ret);
    return ret;
}

static StratStore STRAT_GLOBAL;
static const Strat* STRAT_FALSE = MakeStrat(STRAT_GLOBAL, Strat::Type::CACHE, Vector(MakeStrat(STRAT_GLOBAL, Strat::Type::JUST_0)));
static const Strat* STRAT_TRUE = MakeStrat(STRAT_GLOBAL, Strat::Type::CACHE, Vector(MakeStrat(STRAT_GLOBAL, Strat::Type::JUST_1)));

const Strat* ComputeStrategy(const Policy& node, std::unordered_map<const Policy*, const Strat*>& cache, StratStore& store) {
    std::vector<const Strat*> strats;
    switch (node.node_type) {
        case Policy::Type::NONE:
            return {};
        case Policy::Type::PK:
            strats.push_back(MakeStrat(store, Strat::Type::PK, node.keys));
            break;
        case Policy::Type::OLDER:
            strats.push_back(MakeStrat(store, Strat::Type::OLDER, node.k));
            break;
        case Policy::Type::AFTER:
            strats.push_back(MakeStrat(store, Strat::Type::AFTER, node.k));
            break;
        case Policy::Type::HASH256:
            strats.push_back(MakeStrat(store, Strat::Type::HASH256, node.data));
            break;
        case Policy::Type::HASH160:
            strats.push_back(MakeStrat(store, Strat::Type::HASH160, node.data));
            break;
        case Policy::Type::SHA256:
            strats.push_back(MakeStrat(store, Strat::Type::SHA256, node.data));
            break;
        case Policy::Type::RIPEMD160:
            strats.push_back(MakeStrat(store, Strat::Type::RIPEMD160, node.data));
            break;
        case Policy::Type::AND: {
            if (node.sub.size() != 2) return {};
            const auto left = GetStrategy(node.sub[0], cache, store);
            const auto right = GetStrategy(node.sub[1], cache, store);
            if (!left || !right) return {};
            strats.push_back(MakeStrat(store, Strat::Type::AND, Vector(left, right))); // and(X,Y)
            strats.push_back(MakeStrat(store, Strat::Type::ANDOR, Vector(std::move(left), std::move(right), STRAT_FALSE), 1.0)); // or(and(X,Y),0)
            break;
        }
        case Policy::Type::OR: {
            if (node.sub.size() != 2) return {};
            if (node.prob[0] + node.prob[1] < node.prob[0]) return {};
            double prob = ((double)node.prob[0]) / (node.prob[0] + node.prob[1]);
            const auto left = GetStrategy(node.sub[0], cache, store);
            const auto right = GetStrategy(node.sub[1], cache, store);
            if (!left || !right) return {};
            if (node.sub[0].node_type == Policy::Type::AND && node.sub[0].sub.size() == 2) {
                const auto leftleft = GetStrategy(node.sub[0].sub[0], cache, store);
                const auto leftright = GetStrategy(node.sub[0].sub[1], cache, store);
                if (!leftleft || !leftright) return {};
                strats.push_back(MakeStrat(store, Strat::Type::ANDOR, Vector(std::move(leftleft), std::move(leftright), right), prob));
            }
            if (node.sub[1].node_type == Policy::Type::AND && node.sub[1].sub.size() == 2) {
                const auto rightleft = GetStrategy(node.sub[1].sub[0], cache, store);
                const auto rightright = GetStrategy(node.sub[1].sub[1], cache, store);
                if (!rightleft || !rightright) return {};
                strats.push_back(MakeStrat(store, Strat::Type::ANDOR, Vector(std::move(rightleft), std::move(rightright), left), 1.0 - prob));
            }
            strats.push_back(MakeStrat(store, Strat::Type::ANDOR, Vector(left, STRAT_TRUE, right), prob));
            strats.push_back(MakeStrat(store, Strat::Type::OR, Vector(std::move(left), std::move(right)), prob));
            break;
        }
        case Policy::Type::THRESH: {
            std::vector<const Strat*> subs;
            std::transform(node.sub.begin(), node.sub.end(), std::back_inserter(subs), [&](const Policy& x){ return GetStrategy(x, cache, store); });
            for (const auto& s : subs) {
                if (!s) return {};
            }
            if (node.sub.size() <= 20 && std::all_of(node.sub.begin(), node.sub.end(), [&](const Policy& x){ return x.node_type == Policy::Type::PK; })) {
                std::vector<CompilerContext::Key> keys;
                for (const Policy& x : node.sub) {
                    keys.push_back(x.keys[0]);
                }
                strats.push_back(MakeStrat(store, Strat::Type::THRESH_M, std::move(keys), node.k));
            }
            if (node.k > 1 && node.k < node.sub.size()) {
                strats.push_back(MakeStrat(store, Strat::Type::THRESH, subs, node.k, (double)node.k / subs.size()));
            }
            if (node.k == 1 || node.k == node.sub.size()) {
                while (subs.size() > 1) {
                    auto rep = MakeStrat(store, node.k == 1 ? Strat::Type::OR : Strat::Type::AND, Vector(*(subs.rbegin() + 1), subs.back()), 1.0 / subs.size());
                    subs.pop_back();
                    subs.pop_back();
                    subs.push_back(MakeStrat(store, Strat::Type::CACHE, Vector(rep)));
                }
                strats.push_back(subs[0]);
            }
            break;
        }
    }

    if (strats.size() != 1) {
        auto sub = std::move(strats);
        strats.push_back(MakeStrat(store, Strat::Type::MULTI, std::move(sub)));
    }

    auto ret = MakeMutStrat(store, Strat::Type::CACHE, std::move(strats));
    ret->sub.push_back(MakeStrat(store, Strat::Type::WRAP_C, std::vector<const Strat*>{ret}));
    ret->sub.push_back(MakeStrat(store, Strat::Type::WRAP_V, std::vector<const Strat*>{ret}));
    ret->sub.push_back(MakeStrat(store, Strat::Type::AND, std::vector<const Strat*>{ret, STRAT_TRUE}));
    ret->sub.push_back(MakeStrat(store, Strat::Type::WRAP_N, std::vector<const Strat*>{ret}));
    ret->sub.push_back(MakeStrat(store, Strat::Type::WRAP_D, std::vector<const Strat*>{ret}));
    ret->sub.push_back(MakeStrat(store, Strat::Type::WRAP_J, std::vector<const Strat*>{ret}));
    ret->sub.push_back(MakeStrat(store, Strat::Type::OR, std::vector<const Strat*>{ret, STRAT_FALSE}, 1.0));
    ret->sub.push_back(MakeStrat(store, Strat::Type::WRAP_AS, std::vector<const Strat*>{ret}));

    return ret;
}

struct CostPair {
    double sat;
    double nsat;

    constexpr CostPair(double s, double n) : sat(s), nsat(n) {}
};

struct Result {
    Node node;
    CostPair pair;
    double cost;

    int Compare(double other_cost, const Node& other_node) const {
        if (cost < other_cost) return -1;
        if (cost > other_cost) return 1;
        if (node->ScriptSize() > other_node->ScriptSize()) return -1;
        if (node->ScriptSize() < other_node->ScriptSize()) return 1;
        return 0;
    }

    Result(Node&& in_node, const CostPair& in_pair, double in_cost) : node(std::move(in_node)), pair(in_pair), cost(in_cost) {}
};

double inline Mul(double coef, double val) {
    if (coef == 0) return 0;
    return coef * val;
}

typedef std::pair<miniscript::Type, miniscript::Type> TypeFilter; // First element is required type properties; second one is which one we care about

constexpr TypeFilter ParseFilter(const char *c, size_t len, size_t split) {
    return c[split] == '/' ? TypeFilter{operator"" _mst(c, split), operator"" _mst(c + split + 1, len - split - 1)} :
           split == len ? TypeFilter{operator"" _mst(c, len), ""_mst} : ParseFilter(c, len, split + 1);
}

constexpr TypeFilter operator"" _mstf(const char* c, size_t len) { return ParseFilter(c, len, 0); }

struct Compilation {
    std::vector<Result> results;
    double p, q;
    int seq = 0;

    Compilation(double p_, double q_) : p(p_), q(q_) {}
    Compilation(const Compilation&) = default;
    Compilation(Compilation&&) = default;
    Compilation& operator=(const Compilation&) = default;
    Compilation& operator=(Compilation&&) = default;
    ~Compilation() = default;

    double Cost(const CostPair& pair, const Node& node) {
        return node->ScriptSize() + Mul(p, pair.sat) + Mul(q, pair.nsat);
    }

    void Add(const CostPair& pair, Node node) {
        auto new_typ = node->GetType();
        double cost = Cost(pair, node);
        if (!node->CheckOpsLimit()) return;
        if (node->GetStackSize() > MAX_STANDARD_P2WSH_STACK_ITEMS) return;
        if (!(new_typ << "m"_mst)) return;
        if (cost > 10000) return;
        for (const Result& x : results) {
            auto old_typ = x.node->GetType();
            if (old_typ << new_typ && (x.Compare(cost, node) <= 0)) return; // There is an existing element that's a subtype and better. New item is not useful.
        }
        // We're at least better in some conditions.
        results.erase(std::remove_if(results.begin(), results.end(), [&](const Result& x){
            auto old_typ = x.node->GetType();
            return (new_typ << old_typ && (x.Compare(cost, node) >= 0)); // Delete existing types which are supertypes of the new type and worse.
        }), results.end());
        // Add the new item.
        results.emplace_back(std::move(node), pair, cost);
        ++seq;
    }

    void Add(const Result& x) { Add(x.pair, x.node); }

    template<typename... X>
    void Add(const CostPair& pair, X&&... args) { Add(pair, MakeNode(std::forward<X>(args)...)); }

    std::vector<Result> Query(const TypeFilter typ) const {
        std::map<miniscript::Type, Result> rm;
        for (const Result& x : results) {
            if (x.node->GetType() << typ.first) {
                auto masked = x.node->GetType() & typ.second;
                auto r = rm.emplace(masked, x);
                if (!r.second && x.Compare(r.first->second.cost, r.first->second.node) < 0) r.first->second = x;
            }
        }
        std::vector<Result> ret;
        for (const auto& elem : rm) ret.push_back(std::move(elem.second));
        return ret;
    }
};


struct CompilationKey {
    const Strat* strat;
    double p, q;

    bool operator<(const CompilationKey& other) const {
        if (strat < other.strat) return true;
        if (strat > other.strat) return false;
        if (p < other.p) return true;
        if (p > other.p) return false;
        return q < other.q;
    }

    bool operator==(const CompilationKey& other) const {
        if (strat != other.strat) return false;
        if (p != other.p) return false;
        return q == other.q;
    }
};

const Compilation& GetCompilation(const Strat* strat, double p, double q, std::map<CompilationKey, Compilation>& cache);
void Compile(const Strat* strat, Compilation& compilation, std::map<CompilationKey, Compilation>& cache);

constexpr double INF = std::numeric_limits<double>::infinity();

CostPair CalcCostPair(NodeType nt, const std::vector<const Result*>& s, double l) {
    double r = 1.0 - l;
    if (nt != NodeType::OR_B && nt != NodeType::OR_D && nt != NodeType::OR_C && nt != NodeType::OR_I && nt != NodeType::THRESH && nt != NodeType::ANDOR && nt != NodeType::THRESH_M) {
        assert(l == 0);
    }
    switch (nt) {
        case NodeType::PK: return {73, 1};
        case NodeType::PK_H: return {107, 35};
        case NodeType::SIG: return {75, 75};
        case NodeType::OLDER:
        case NodeType::AFTER:
            return {0, INF};
        case NodeType::HASH256:
        case NodeType::HASH160:
        case NodeType::SHA256:
        case NodeType::RIPEMD160:
            return {33, 33};
        case NodeType::WRAP_A:
        case NodeType::WRAP_S:
        case NodeType::WRAP_C:
        case NodeType::WRAP_N:
            return s[0]->pair;
        case NodeType::WRAP_D: return {2 + s[0]->pair.sat, 1};
        case NodeType::WRAP_V: return {s[0]->pair.sat, INF};
        case NodeType::WRAP_J: return {s[0]->pair.sat, 1};
        case NodeType::JUST_1: return {0, INF};
        case NodeType::JUST_0: return {INF, 0};
        case NodeType::AND_V: return {s[0]->pair.sat + s[1]->pair.sat, INF};
        case NodeType::AND_B: return {s[0]->pair.sat + s[1]->pair.sat, s[0]->pair.nsat + s[1]->pair.nsat};
        case NodeType::OR_B:
            return {Mul(l, s[0]->pair.sat + s[1]->pair.nsat) + Mul(r, s[0]->pair.nsat + s[1]->pair.sat), s[0]->pair.nsat + s[1]->pair.nsat};
        case NodeType::OR_D:
        case NodeType::OR_C:
            return {Mul(l, s[0]->pair.sat) + Mul(r, s[0]->pair.nsat + s[1]->pair.sat), s[0]->pair.nsat + s[1]->pair.nsat};
        case NodeType::OR_I:
            return {Mul(l, s[0]->pair.sat + 2) + Mul(r, s[1]->pair.sat + 1), std::min(2 + s[0]->pair.nsat, 1 + s[1]->pair.nsat)};
        case NodeType::ANDOR:
            return {Mul(l, s[0]->pair.sat + s[1]->pair.sat) + Mul(r, s[0]->pair.nsat + s[2]->pair.sat), s[0]->pair.nsat + s[2]->pair.nsat};
        case NodeType::THRESH_M: return CostPair{1.0 + l * 73.0, 1.0 + l};
        case NodeType::THRESH: {
            double sat = 0.0, nsat = 0.0;
            for (const auto& sub : s) {
                sat += sub->pair.sat;
                nsat += sub->pair.nsat;
            }
            return CostPair{Mul(l, sat) + Mul(r, nsat), nsat};
        }
    }
    throw std::runtime_error("Computing CostPair of unknown nodetype");
}

std::pair<std::vector<double>, std::vector<double>> GetPQs(NodeType nt, double p, double q, double l, int m) {
    static const std::pair<std::vector<double>, std::vector<double>> NONE;
    double r = 1.0 - l;
    switch (nt) {
        case NodeType::JUST_1:
        case NodeType::JUST_0:
        case NodeType::PK:
        case NodeType::PK_H:
        case NodeType::THRESH_M:
        case NodeType::OLDER:
        case NodeType::AFTER:
        case NodeType::HASH256:
        case NodeType::HASH160:
        case NodeType::SHA256:
        case NodeType::RIPEMD160:
        case NodeType::SIG:
            return NONE;
        case NodeType::WRAP_A:
        case NodeType::WRAP_S:
        case NodeType::WRAP_C:
        case NodeType::WRAP_N:
            return {{p}, {q}};
        case NodeType::WRAP_D:
        case NodeType::WRAP_V:
        case NodeType::WRAP_J:
            return {{p}, {0}};
        case NodeType::AND_V:
        case NodeType::AND_B:
            return {{p, p}, {q, q}};
        case NodeType::OR_B: return {{l*p, r*p}, {r*p + q, l*p + q}};
        case NodeType::OR_D: return {{l*p, r*p}, {r*p + q, q}};
        case NodeType::OR_C: return {{l*p, r*p}, {r*p, 0}};
        case NodeType::OR_I: return {{l*p, r*p}, {m == 0 ? q : 0, m == 1 ? q : 0}};
        case NodeType::ANDOR: return {{l*p, l*p, r*p}, {q + r*p, 0, q}};
        case NodeType::THRESH: return {std::vector<double>(m, p * l), std::vector<double>(m, q + p * r)};
    }
    assert(false);
    return NONE;
}

typedef std::vector<std::vector<TypeFilter>> TypeFilters;

const TypeFilters& GetTypeFilter(NodeType nt) {
    static const TypeFilters FILTER_NO{{}};
    static const TypeFilters FILTER_WRAP_A{{"B/udfems"_mstf}};
    static const TypeFilters FILTER_WRAP_S{{"Bo/udfemsx"_mstf}};
    static const TypeFilters FILTER_WRAP_C{{"K/onde"_mstf}};
    static const TypeFilters FILTER_WRAP_D{{"V/zfms"_mstf}};
    static const TypeFilters FILTER_WRAP_V{{"B/zonmsx"_mstf}};
    static const TypeFilters FILTER_WRAP_J{{"Bn/oufms"_mstf}};
    static const TypeFilters FILTER_WRAP_N{{"B/zondfems"_mstf}};
    static const TypeFilters FILTER_AND_V{
        {"V/nzoms"_mstf, "B/unzofmsx"_mstf},
        {"V/nsoms"_mstf, "K/unzofmsx"_mstf},
        {"V/nzoms"_mstf, "V/unzofmsx"_mstf}
    };
    static const TypeFilters FILTER_AND_B{{"B/zondfems"_mstf, "W/zondfems"_mstf}};
    static const TypeFilters FILTER_OR_B{{"Bde/zoms"_mstf, "Wde/zoms"_mstf}};
    static const TypeFilters FILTER_OR_D{{"Bdue/zoms"_mstf, "B/zoudfems"_mstf}};
    static const TypeFilters FILTER_OR_C{{"Bdue/zoms"_mstf, "V/zoms"_mstf}};
    static const TypeFilters FILTER_OR_I{
        {"V/zudfems"_mstf, "V/zudfems"_mstf},
        {"B/zudfems"_mstf, "B/zudfems"_mstf},
        {"K/zudfems"_mstf, "K/zudfems"_mstf}
    };
    static const TypeFilters FILTER_ANDOR{
        {"Bdue/zoms"_mstf, "B/zoufms"_mstf, "B/zoudfems"_mstf},
        {"Bdue/zoms"_mstf, "K/zoufms"_mstf, "K/zoudfems"_mstf},
        {"Bdue/zoms"_mstf, "V/zoufms"_mstf, "V/zoudfems"_mstf}
    };

    switch (nt) {
        case NodeType::JUST_1:
        case NodeType::JUST_0:
        case NodeType::PK:
        case NodeType::PK_H:
        case NodeType::THRESH_M:
        case NodeType::OLDER:
        case NodeType::AFTER:
        case NodeType::HASH256:
        case NodeType::HASH160:
        case NodeType::SHA256:
        case NodeType::RIPEMD160:
        case NodeType::SIG:
            return FILTER_NO;
        case NodeType::WRAP_A: return FILTER_WRAP_A;
        case NodeType::WRAP_S: return FILTER_WRAP_S;
        case NodeType::WRAP_C: return FILTER_WRAP_C;
        case NodeType::WRAP_D: return FILTER_WRAP_D;
        case NodeType::WRAP_V: return FILTER_WRAP_V;
        case NodeType::WRAP_J: return FILTER_WRAP_J;
        case NodeType::WRAP_N: return FILTER_WRAP_N;
        case NodeType::AND_V: return FILTER_AND_V;
        case NodeType::AND_B: return FILTER_AND_B;
        case NodeType::OR_B: return FILTER_OR_B;
        case NodeType::OR_C: return FILTER_OR_C;
        case NodeType::OR_D: return FILTER_OR_D;
        case NodeType::OR_I: return FILTER_OR_I;
        case NodeType::ANDOR: return FILTER_ANDOR;
        case NodeType::THRESH: break;
    }
    assert(false);
    return FILTER_NO;
}

template<typename... Args>
void AddInner(Compilation& compilation, std::map<CompilationKey, Compilation>& cache, NodeType nt, const std::vector<const Result*>& resp, double prob, Args&&... args) {
    std::vector<Node> subs;
    for (const Result* res : resp) subs.push_back(res->node);
    compilation.Add(CalcCostPair(nt, resp, prob), nt, std::move(subs), std::forward<Args>(args)...);
}

template<typename... Args>
void Add(Compilation& compilation, std::map<CompilationKey, Compilation>& cache, NodeType nt, const std::vector<const Strat*>& s, double prob, int m, Args&&... args) {
    auto pqs = GetPQs(nt, compilation.p, compilation.q, prob, m);
    auto filter = GetTypeFilter(nt);
    std::vector<const Result*> resp;
    resp.resize(s.size());
    for (size_t j = 0; j < filter.size(); ++j) {
        std::vector<std::vector<Result>> res;
        uint32_t num_comb = 1;
        assert(s.size() == filter[j].size());
        for (size_t i = 0; i < s.size(); ++i) {
            const Compilation& subcomp = GetCompilation(s[i], pqs.first[i], pqs.second[i], cache);
            res.push_back(subcomp.Query(filter[j][i]));
            num_comb *= res.back().size();
        }
        for (uint32_t comb = 0; comb < num_comb; ++comb) {
            uint32_t c = comb;
            for (size_t i = 0; i < s.size(); ++i) {
                resp[i] = &res[i][c % res[i].size()];
                c /= res[i].size();
            }
            if (comb + 1 == num_comb) {
                AddInner(compilation, cache, nt, resp, prob, std::forward<Args>(args)...);
            } else {
                AddInner(compilation, cache, nt, resp, prob, args...);
            }
        }
    }
}

const Compilation& GetCompilation(const Strat* strat, double p, double q, std::map<CompilationKey, Compilation>& cache) {
    assert(strat->node_type == Strat::Type::CACHE);
    CompilationKey key{strat, p, q};
    auto it = cache.find(key);
    if (it != cache.end()) {
        assert(it->second.p == p);
        assert(it->second.q == q);
        return it->second;
    }
    Compilation new_entry(p, q);
    assert(strat->sub.size() > 0);
    Compile(strat->sub[0], new_entry, cache);
    auto it2 = cache.emplace(key, std::move(new_entry));
    assert(it2.second);
    Compilation &result = it2.first->second;
    if (strat->sub.size() > 1) {
        size_t last = 1, pos = 1;
        do {
            int prevseq = result.seq;
            Compile(strat->sub[pos], result, cache);
            if (result.seq != prevseq) last = pos;
            ++pos;
            if (pos == strat->sub.size()) pos = 1;
        } while (pos != last);
    }

    return result;
}

void Compile(const Strat* strat, Compilation& compilation, std::map<CompilationKey, Compilation>& cache) {
    double p = compilation.p, q = compilation.q;
    switch (strat->node_type) {
        case Strat::Type::MULTI:
            for (const auto& x : strat->sub) {
                Compile(x, compilation, cache);
            }
            return;
        case Strat::Type::CACHE: {
            const Compilation& sub = GetCompilation(strat, p, q, cache);
            for (const Result& x : sub.results) {
                compilation.Add(x);
            }
            return;
        }
        case Strat::Type::JUST_0:
            Add(compilation, cache, NodeType::JUST_0, strat->sub, 0, 0);
            return;
        case Strat::Type::JUST_1:
            Add(compilation, cache, NodeType::JUST_1, strat->sub, 0, 0);
            return;
        case Strat::Type::AFTER:
        case Strat::Type::OLDER: {
            Add(compilation, cache, strat->node_type == Strat::Type::OLDER ? NodeType::OLDER : NodeType::AFTER, strat->sub, 0, 0, strat->k);
            return;
        }
        case Strat::Type::HASH160: {
            Add(compilation, cache, NodeType::HASH160, strat->sub, 0, 0, strat->data);
            return;
        }
        case Strat::Type::HASH256: {
            Add(compilation, cache, NodeType::HASH256, strat->sub, 0, 0, strat->data);
            return;
        }
        case Strat::Type::RIPEMD160: {
            Add(compilation, cache, NodeType::RIPEMD160, strat->sub, 0, 0, strat->data);
            return;
        }
        case Strat::Type::SHA256: {
            Add(compilation, cache, NodeType::SHA256, strat->sub, 0, 0, strat->data);
            return;
        }
        case Strat::Type::PK: {
            Add(compilation, cache, NodeType::PK, strat->sub, 0, 0, strat->keys);
            Add(compilation, cache, NodeType::PK_H, strat->sub, 0, 0, strat->keys);
            return;
        }
        case Strat::Type::THRESH_M:
            Add(compilation, cache, NodeType::THRESH_M, strat->sub, strat->k, 0, strat->keys, strat->k);
            return;
        case Strat::Type::WRAP_AS:
            Add(compilation, cache, NodeType::WRAP_A, strat->sub, 0, 0);
            Add(compilation, cache, NodeType::WRAP_S, strat->sub, 0, 0);
            return;
        case Strat::Type::WRAP_C:
            Add(compilation, cache, NodeType::WRAP_C, strat->sub, 0, 0);
            return;
        case Strat::Type::WRAP_D:
            Add(compilation, cache, NodeType::WRAP_D, strat->sub, 0, 0);
            return;
        case Strat::Type::WRAP_N:
            Add(compilation, cache, NodeType::WRAP_N, strat->sub, 0, 0);
            return;
        case Strat::Type::WRAP_J:
            Add(compilation, cache, NodeType::WRAP_J, strat->sub, 0, 0);
            return;
        case Strat::Type::WRAP_V:
            Add(compilation, cache, NodeType::WRAP_V, strat->sub, 0, 0);
            return;
        case Strat::Type::AND: {
            const auto& sub = strat->sub;
            const std::vector<const Strat*> rev{sub[1], sub[0]};
            if (q == 0) {
                Add(compilation, cache, NodeType::AND_V, sub, 0, 0);
                Add(compilation, cache, NodeType::AND_V, rev, 0, 0);
            }
            Add(compilation, cache, NodeType::AND_B, sub, 0, 0);
            Add(compilation, cache, NodeType::AND_B, rev, 0, 0);
            return;
        }
        case Strat::Type::OR: {
            const auto& sub = strat->sub;
            const std::vector<const Strat*> rev{sub[1], sub[0]};
            double l = strat->prob, r = 1.0 - l;
            if (q == 0) {
                Add(compilation, cache, NodeType::OR_C, sub, l, 0);
                Add(compilation, cache, NodeType::OR_C, rev, r, 0);
            }
            Add(compilation, cache, NodeType::OR_B, sub, l, 0);
            Add(compilation, cache, NodeType::OR_B, rev, r, 0);
            Add(compilation, cache, NodeType::OR_D, sub, l, 0);
            Add(compilation, cache, NodeType::OR_D, rev, r, 0);
            Add(compilation, cache, NodeType::OR_I, sub, l, 0);
            Add(compilation, cache, NodeType::OR_I, rev, r, 0);
            Add(compilation, cache, NodeType::OR_I, sub, l, 1);
            Add(compilation, cache, NodeType::OR_I, rev, r, 1);
            return;
        }
        case Strat::Type::ANDOR: {
            const auto& sub = strat->sub;
            const std::vector<const Strat*> rev{sub[1], sub[0], sub[2]};
            double l = strat->prob;
            Add(compilation, cache, NodeType::ANDOR, sub, l, 0);
            Add(compilation, cache, NodeType::ANDOR, rev, l, 0);
            return;
        }
        case Strat::Type::THRESH: {
            auto pqs = GetPQs(NodeType::THRESH, p, q, strat->prob, (int)strat->sub.size());
            std::vector<Result> Bs, Ws;
            int B_pos = -1;
            double cost_diff = -1.0;
            for (size_t i = 0; i < strat->sub.size(); ++i) {
                const Compilation& comp = GetCompilation(strat->sub[i], pqs.first[i], pqs.second[i], cache);
                auto res_B = comp.Query("Bemdu"_mstf);
                if (res_B.size() == 0) {fprintf(stderr, "Cannot compile arg=%i as B\n", (int)i); return; }
                assert(res_B.size() == 1);
                Bs.push_back(std::move(res_B[0]));
                auto res_W = comp.Query("Wemdu"_mstf);
                if (res_W.size() == 0) {fprintf(stderr, "Cannot compile arg=%i as W\n", (int)i); return; }
                assert(res_W.size() == 1);
                Ws.push_back(std::move(res_W[0]));
                if (Ws.back().cost - Bs.back().cost > cost_diff) {
                    cost_diff = Ws.back().cost - Bs.back().cost;
                    B_pos = i;
                }
            }
            std::vector<const Result*> resp;
            resp.push_back(&Bs[B_pos]);
            for (size_t i = 0; i < strat->sub.size(); ++i) {
                if ((int)i != B_pos) resp.push_back(&Ws[i]);
            }
            AddInner(compilation, cache, NodeType::THRESH, resp, strat->prob, strat->k);
            return;
        }
    }
}

std::string Disassembler(CScript::const_iterator& it, CScript::const_iterator end, int indent = 0) {
    std::string ret;
    bool newline = true;
    size_t last_newline = 0;
    size_t last_space = 0;
    while (it != end) {
        opcodetype opcode;
        std::vector<unsigned char> data;
        auto it2 = it;
        if (!GetScriptOp(it2, end, opcode, &data)) return ret + " [error]";
        if (opcode == OP_ELSE || opcode == OP_ENDIF) break;
        it = it2;
        if (newline) {
            for (int i = 0; i < indent; ++i) ret += "  ";
        } else {
            ret += ' ';
            last_space = ret.size() - 1;
        }
        if (data.size() == 20) {
            if (data == std::vector<unsigned char>(20, 0x99)) {
                ret += "<h>";
            } else if (data[0] == 'P' && data[1] == 'K' && data[2] == 'h') {
                while (data.size() && data.back() == 0) data.pop_back();
                ret += "<HASH160(" + std::string((const char*)data.data() + 3, data.size() - 3) + ")>";
            }
        } else if (data.size() == 32 && data == std::vector<unsigned char>(32, 0x88)) {
            ret += "<H>";
        } else if (data.size() == 33 && data[0] == 2 && data[1] == 'P' && data[2] == 'K' && data[3] == 'b') {
            while (data.size() && data.back() == 0) data.pop_back();
            ret += "<" + std::string((const char*)data.data() + 4, data.size() - 4) + ">";
        } else if (data.size() > 0) {
            ret += "<" + HexStr(data.begin(), data.end()) + ">";
        } else {
            ret += std::string(GetOpName(opcode));
            if (opcode == OP_IF || opcode == OP_NOTIF) {
                ret += '\n';
                ret += Disassembler(it, end, indent + 1);
                if (it != end && *it == OP_ELSE) {
                    for (int i = 0; i < indent; ++i) ret += "  ";
                    ret += std::string(GetOpName(opcodetype(*(it++)))) + '\n';
                    ret += Disassembler(it, end, indent + 1);
                }
                if (it != end && *it == OP_ENDIF) {
                    for (int i = 0; i < indent; ++i) ret += "  ";
                    ret += std::string(GetOpName(opcodetype(*(it++)))) + '\n';
                }
                last_newline = ret.size();
                newline = true;
            }
        }
        if (!newline && ret.size() - last_newline > 80) {
          ret[last_space] = '\n';
          for (int i = 0; i < indent; ++i) ret.insert(last_space + 1, "  ");
          last_newline = last_space + 1;
        }
        newline = (ret.size() == last_newline);
    }
    if (!newline) ret += '\n';
    return ret;
}

/*
std::string DebugNode(const Node& node) {
    switch (node->nodetype) {
        case NodeType::PK: return "pk";
        case NodeType::PK_H: return "pk_h";
        case NodeType::THRESH_M: return "thresh_m(" + std::to_string(node->k) + " of " + std::to_string(node->keys.size()) + ")";
        case NodeType::AFTER: return "after";
        case NodeType::OLDER: return "older";
        case NodeType::SHA256: return "sha256";
        case NodeType::HASH256: return "hash256";
        case NodeType::RIPEMD160: return "ripemd160";
        case NodeType::HASH160: return "hash160";
        case NodeType::JUST_1: return "1";
        case NodeType::JUST_0: return "0";
        case NodeType::WRAP_C: return "c:";
        case NodeType::WRAP_A: return "a:";
        case NodeType::WRAP_S: return "s:";
        case NodeType::WRAP_V: return "v:";
        case NodeType::WRAP_D: return "d:";
        case NodeType::WRAP_J: return "j:";
        case NodeType::WRAP_N: return "n:";
        case NodeType::AND_V: return "and_v";
        case NodeType::AND_B: return "and_b";
        case NodeType::OR_B: return "or_b";
        case NodeType::OR_C: return "or_c";
        case NodeType::OR_D: return "or_d";
        case NodeType::OR_I: return "or_i";
        case NodeType::ANDOR: return "andor";
        case NodeType::THRESH: return "thresh(" + std::to_string(node->k) + " of " + std::to_string(node->subs.size()) + ")";
    }
    assert(false);
    return "";
}

void PrintCompilationResult(int level, const Result& res) {
    for (int i = 0; i < level; ++i) fprintf(stderr, "  ");
    fprintf(stderr, "* %s p=%f q=%f scriptlen=%i sat=%f nsat=%f cost=%f\n", DebugNode(res.node).c_str(), res.p, res.q, (int)res.node->ScriptSize(), res.pair.sat, res.pair.nsat, res.cost);
    assert(res.subs.size() == res.node->subs.size());
    for (size_t j = 0; j < res.subs.size(); ++j) {
        PrintCompilationResult(level + 1, *(res.subs[j]));
    }
}
*/

} // namespace

bool Compile(const std::string& policy, miniscript::NodeRef<CompilerContext::Key>& ret, double& avgcost) {
    Policy pol = Parse(policy);
    if (!pol()) return false;

    const Strat* strat;
    StratStore store;
    {
        std::unordered_map<const Policy*, const Strat*> cache;
        strat = ComputeStrategy(pol, cache, store);
    }
    if (!strat) return false;

    std::map<CompilationKey, Compilation> cache;
    const Compilation& compilation = GetCompilation(strat, 1.0, 0.0, cache);

    auto res = compilation.Query("Bms"_mstf);
    bool ok = false;
    if (res.size() == 1) {
        ret = std::move(res[0].node);
        avgcost = res[0].pair.sat;
        ok = true;
    }

    return ok;
}

std::string Expand(std::string str) {
    while (true) {
        auto pos = str.find("sha256(H)");
        if (pos == std::string::npos) break;
        str.replace(pos, 9, "sha256(8888888888888888888888888888888888888888888888888888888888888888)");
    }
    while (true) {
        auto pos = str.find("hash256(H)");
        if (pos == std::string::npos) break;
        str.replace(pos, 10, "hash256(8888888888888888888888888888888888888888888888888888888888888888)");
    }
    while (true) {
        auto pos = str.find("ripemd160(H)");
        if (pos == std::string::npos) break;
        str.replace(pos, 12, "ripemd160(9999999999999999999999999999999999999999)");
    }
    while (true) {
        auto pos = str.find("hash160(H)");
        if (pos == std::string::npos) break;
        str.replace(pos, 10, "hash160(9999999999999999999999999999999999999999)");
    }
    while (true) {
        auto pos = str.find(" ");
        if (pos == std::string::npos) break;
        str.replace(pos, 1, "");
    }
    return str;
}

std::string Abbreviate(std::string str) {
    while (true) {
        auto pos = str.find("sha256(8888888888888888888888888888888888888888888888888888888888888888)");
        if (pos == std::string::npos) break;
        str.replace(pos, 72, "sha256(H)");
    }
    while (true) {
        auto pos = str.find("hash256(8888888888888888888888888888888888888888888888888888888888888888)");
        if (pos == std::string::npos) break;
        str.replace(pos, 73, "hash256(H)");
    }
    while (true) {
        auto pos = str.find("ripemd160(9999999999999999999999999999999999999999)");
        if (pos == std::string::npos) break;
        str.replace(pos, 51, "ripemd160(H)");
    }
    while (true) {
        auto pos = str.find("hash160(9999999999999999999999999999999999999999)");
        if (pos == std::string::npos) break;
        str.replace(pos, 49, "hash160(H)");
    }
    return str;
}

std::string Disassemble(const CScript& script) {
    auto it = script.begin();
    return Disassembler(it, script.end());
}
