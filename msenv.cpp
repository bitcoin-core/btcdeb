// Copyright (c) 2020 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <msenv.h>
#include <ansi-colors.h>

void Situation::emit(const std::string& description, Node activates) {
    std::set<Node> active_nodes(m_activated.begin(), m_activated.end());
    if (activates) active_nodes.insert(activates);
    m_solutions.emplace_back(description, active_nodes);
}

bool Situation::iterate(Node parent, Branch&& branch, const std::string& prefix, const std::string& suffix, bool wrapped) {
        m_activated.push_back(parent);
        bool res = branch.iterate(*this, prefix, suffix, wrapped);
        assert(m_activated.back() == parent);
        m_activated.pop_back();
        return res;
}

std::shared_ptr<Situation> Situation::spawn() {
    auto sit = std::make_shared<Situation>();
    m_subsits.push_back(sit);
    return sit;
}

inline std::vector<std::string> Merge(const std::vector<std::string>& src1, const std::vector<std::string>& src2, const std::string& sep = ",") {
    size_t len1 = src1.size();
    size_t len2 = src2.size();
    std::vector<std::string> res;
    for (size_t i = 0; i < len1; ++i) {
        for (size_t j = 0; j < len2; ++j) {
            res.emplace_back(src1[i] + sep + src2[j]);
        }
    }
    return res;
}

Solution Solution::merge(const Solution& other) const {
    std::set<Node> u = m_active_nodes;
    std::set<Node> v = other.m_active_nodes;
    u.insert(v.begin(), v.end());
    return Solution(m_description + "," + other.m_description, u);
}

std::vector<Solution> Solution::merge(const std::vector<Solution>& src1, const std::vector<Solution>& src2) {
    size_t len1 = src1.size();
    size_t len2 = src2.size();
    std::vector<Solution> res;
    for (size_t i = 0; i < len1; ++i) {
        for (size_t j = 0; j < len2; ++j) {
            res.push_back(src1[i].merge(src2[j]));
        }
    }
    return res;
}

void Situation::discard(std::shared_ptr<Situation> sit, bool merge_solutions) {
    m_elements.insert(sit->m_elements.begin(), sit->m_elements.end());
    if (merge_solutions) m_solutions = Solution::merge(m_solutions, sit->m_solutions);
    auto it = std::find(m_subsits.begin(), m_subsits.end(), sit);
    if (it != m_subsits.end()) m_subsits.erase(it); else fprintf(stderr, "note: sub-situation not in vector\n");
}

void Situation::analyze(int confirmations, Node tree) {
    m_confirmations = confirmations;
    std::set<std::string> inv, missing;
    for (const auto& ss : m_inventory) {
        if (ss.second == Availability::NO) {
            missing.insert(ss.first);
        } else if (ss.second == Availability::YES) {
            inv.insert(ss.first);
        }
    }
    tree->CalcAvail(COMPILER_CTX, inv, missing, confirmations);
}

Branch::Branch(const Node& node) : m_node(node) {
    using Type = miniscript::NodeType;
    switch (node->nodetype) {
    // single path with no alternatives
    case Type::JUST_0:
    case Type::JUST_1:
    case Type::PK:
    case Type::PK_H:
    case Type::OLDER:
    case Type::AFTER:
    case Type::SHA256:
    case Type::HASH256:
    case Type::RIPEMD160:
    case Type::HASH160:
    case Type::WRAP_A:
    case Type::WRAP_S:
    case Type::WRAP_C:
    case Type::WRAP_D:
    case Type::WRAP_V:
    case Type::WRAP_J:
    case Type::WRAP_N:
        break;
    // two alternatives, [0], [1]
    case Type::AND_V:
    case Type::AND_B:
    case Type::OR_B:
    case Type::OR_C:
    case Type::OR_D:
    case Type::OR_I:
        assert(node->subs.size() == 2);
        for (const Node& n : node->subs) {
            m_children.emplace_back(n);
        }
        break;
    case Type::ANDOR:
        // [0] NOTIF [2] ELSE [1] ENDIF
        assert(node->subs.size() == 3);
        m_selector = new Branch(node->subs[0]);
        m_children.emplace_back(node->subs[1]);
        m_children.emplace_back(node->subs[2]);
        break;
    case Type::THRESH_M:
        // TODO: determine what to do here; technically we have >1 path
        break;
    case Type::THRESH:
        // TODO: determine what to do here; technically we have >1 path
        break;
    default:
        assert(!"unknown node type");
    }
}

bool Branch::iterate(Situation& situation, const std::string& prefix, const std::string& suffix, bool wrapped) {
    // std::string ret = wrapped ? ":" : "";
    // std::string zzz; m_node->ToString(COMPILER_CTX, zzz, wrapped); fprintf(stderr, "<> iter %s <...> %s (%s) :: %s\n", prefix.c_str(), suffix.c_str(), wrapped ? "wrapped" : "not wrapped", zzz.c_str());
    #define OUTCOME(expr) situation.emit(prefix + expr + suffix, m_node)
    using miniscript::NodeType;
    auto& ctx = COMPILER_CTX;

    bool force_add = false;
    Node which = m_node->subs.size() ? m_node->subs[0] : nullptr;
    std::string add = "";
    switch (m_node->nodetype) {
    case NodeType::WRAP_A: add = "a"; break;
    case NodeType::WRAP_S: force_add = true; break;
    case NodeType::WRAP_C: add = "c"; break;
    case NodeType::WRAP_D: add = "d"; break;
    case NodeType::WRAP_V: add = "v"; break;
    case NodeType::WRAP_J: add = "j"; break;
    case NodeType::WRAP_N: add = "n"; break;
    case NodeType::AND_V:
        // t:X is syntactic sugar for and_v(X,1).
        if (m_node->subs[1]->nodetype == NodeType::JUST_1) { add = "t"; break; }
        break;
    case NodeType::OR_I:
        if (m_node->subs[0]->nodetype == NodeType::JUST_0) { add = "l"; which = m_node->subs[1]; break; }
        if (m_node->subs[1]->nodetype == NodeType::JUST_0) { add = "u"; break; }
        break;
    default:
        break;
    }

    if (force_add || add != "") {
        std::string sub_prefix;
        if (add != "" && prefix.size() > 0 && prefix[prefix.size() - 1] == ':') {
            sub_prefix = prefix.substr(0, prefix.size() - 1);
        }
        return situation.iterate(m_node, Branch(which), (sub_prefix.size() ? sub_prefix : prefix) + add + (add == "" ? "" : ":"), suffix, true);
    }

    std::shared_ptr<Situation> sub_outcomes;
    std::shared_ptr<Situation> subsub_outcomes;
    std::string sub_type;

    switch (m_node->nodetype) {
    case NodeType::PK: {
        std::string key_str;
        if (!ctx.ToString(m_node->keys[0], key_str)) return false;
        situation.m_elements.insert(key_str);
        OUTCOME("pk(" + std::move(key_str) + ")");
        return true;
    }
    case NodeType::PK_H: {
        std::string key_str;
        if (!ctx.ToString(m_node->keys[0], key_str)) return false;
        situation.m_elements.insert(key_str);
        OUTCOME("pk_h(" + std::move(key_str) + ")");
        return true;
    }
    case NodeType::AFTER: OUTCOME("after(" + std::to_string(m_node->k) + ")"); return true;
    case NodeType::OLDER: OUTCOME("older(" + std::to_string(m_node->k) + ")"); return true;
    #define preimage(hashfun, len) \
        OUTCOME(#hashfun "(" + miniscript::HashValue(m_node->data, len) + ")"); \
        situation.m_elements.insert(std::string(#hashfun "^-1(" + miniscript::HashValue(m_node->data, len) + ")")); \
        return true
    case NodeType::HASH256:   preimage(hash256, 32);
    case NodeType::HASH160:   preimage(hash160, 20);
    case NodeType::SHA256:    preimage(sha256, 32);
    case NodeType::RIPEMD160: preimage(ripemd160, 20);
    #undef preimage
    case NodeType::JUST_1: OUTCOME("1"); return true;
    case NodeType::JUST_0: OUTCOME("0"); return true;
    case NodeType::AND_V:
    case NodeType::AND_B:
        sub_type = m_node->nodetype == NodeType::AND_V ? "v" : "b";
        sub_outcomes = situation.spawn();
        if (!m_children[0].iterate(*sub_outcomes)) return false;
        for (const auto& s : sub_outcomes->m_solutions) {
            if (!m_children[1].iterate(situation, prefix + "and_" + sub_type + "(" + s.m_description + ",", ")" + suffix)) return false;
        }
        situation.discard(sub_outcomes);
        return true;
    case NodeType::OR_B:
    case NodeType::OR_D:
    case NodeType::OR_C:
    case NodeType::OR_I:
        sub_type = "b";
        if (m_node->nodetype == NodeType::OR_D) sub_type = "d";
        if (m_node->nodetype == NodeType::OR_C) sub_type = "c";
        if (m_node->nodetype == NodeType::OR_I) sub_type = "i";
        for (auto& c : m_children) {
            if (!c.iterate(situation, prefix, suffix)) return false;
        }
        return true;
    case NodeType::ANDOR:
        // and_n(X,Y) is syntactic sugar for andor(X,Y,0).
        if (m_node->subs[2]->nodetype == NodeType::JUST_0) {
            sub_outcomes = situation.spawn();
            if (!m_children[0].iterate(*sub_outcomes)) return false;
            for (const auto& s : sub_outcomes->m_solutions) {
                if (!m_children[1].iterate(situation, prefix + "and_n(" + s.m_description + ",", ")" + suffix)) return false;
            }
            situation.discard(sub_outcomes);
            return true;
        }
        assert(m_selector);
        sub_outcomes = situation.spawn();
        subsub_outcomes = sub_outcomes->spawn();
        if (!m_selector->iterate(*sub_outcomes)) return false;
        if (!m_children[0].iterate(*subsub_outcomes)) return false;
        sub_outcomes->discard(subsub_outcomes, true);
        for (const auto& s : sub_outcomes->m_solutions) {
            if (!m_children[1].iterate(situation, prefix + "andor(" + s.m_description + ",", ")" + suffix)) return false;
        }
        situation.discard(sub_outcomes);
        return true;
    case NodeType::THRESH_M: {
        auto str = "thresh_m(" + std::to_string(m_node->k);
        for (const auto& key : m_node->keys) {
            std::string key_str;
            if (!ctx.ToString(key, key_str)) return false;
            str += "," + std::move(key_str);
        }
        OUTCOME(str + ")");
    }
    case NodeType::THRESH: {
        auto str = "thresh(" + std::to_string(m_node->k);
        for (const auto& sub : m_node->subs) {
            std::string s;
            if (!sub->ToString(ctx, s)) return false;
            str += "," + s;
        }
        OUTCOME(str + ")");
        return true;
    }
    default: assert(false); // Wrappers should have been handled above
    }
}

MSEnv::MSEnv(const std::string& input) {
    if (input.size() == 0) return; // empty

    m_input = input;
    Node ret;
    if (Compile(input, ret, m_avgcost)) {
        m_root = Branch(ret);
        PrintTree();
        return;
    }
    if ((ret = miniscript::FromString(input, COMPILER_CTX))) {
        m_root = Branch(ret);
        PrintTree();
        return;
    }
    throw std::runtime_error("MSEnv failed to compile input");
}

void MSEnv::PrintTree() const {
    // redo analysis
    const_cast<Situation*>(&m_situation)->analyze(m_confirmations, m_root.m_node);
    std::string str;
    std::shared_ptr<miniscript::StringEmitter> emitter = std::make_shared<TreeStringEmitter>();
    m_root.m_node->ToString(COMPILER_CTX, str, false, emitter);
    str += ansi::reset;
    printf("X %17.10f %5i %s\n%s\n", m_root.m_node->ScriptSize() + m_avgcost, (int)m_root.m_node->ScriptSize(), m_input.c_str(), Abbreviate(std::move(str)).c_str());
}

inline std::string spaces(int count) {
    static std::string s = "         ";
    while (s.size() < count) s = s + s;
    return s.substr(0, count);
}

void TreeStringEmitter::set_avail(miniscript::Availability avail) {
    if (avail == m_avail) return;
    m_avail = avail;
    switch (avail) {
    case Availability::NO:
        m_str += ansi::fg_red + ansi::bold;
        break;
    case Availability::YES:
        m_str += ansi::fg_green + ansi::bold;
        break;
    case Availability::MAYBE:
        m_str += ansi::reset;
        break;
    }
}

void TreeStringEmitter::emit(const std::string& value, bool own_line, bool ends_line, int indents, bool strip_end, EmitType type) {
    bool pushed_color = false;
    if (type != EmitType::Default && m_avail == Availability::MAYBE) {
        pushed_color = true;
        switch (type) {
        case EmitType::Func: m_str += ansi::fg_magenta + ansi::bold; break;
        case EmitType::Key: m_str += ansi::fg_cyan + ansi::bold; break;
        case EmitType::Modifier: m_str += ansi::fg_yellow + ansi::bold; break;
        default: m_str += ansi::fg_white + ansi::bold; break; // Value
        }
    }
    // does this want us to strip the end?
    if (strip_end) {
        size_t i = m_str.size() - 1;
        while (i > 0 && (m_str[i] == ' ' || m_str[i] == '\n' || m_str[i] == '\t')) --i;
        if (i + 1 < m_str.size()) {
            m_str = m_str.substr(0, i + 1);
            m_empty_line = false;
        }
    }
    // does this want its own line, and are we on a non-empty line?
    if (!m_empty_line && own_line) {
        // yeah, newline
        nl();
    }
    if (m_empty_line && value.size() > 0) {
        // indent before insertion
        m_str += m_ind;
        m_empty_line = false;
    }
    m_str += value;

    // does this alter indentation?
    if (indents < 0) {
        if ((int)m_ind.size() < -indents) throw std::runtime_error("cannot deindent " + std::to_string(-indents) + " characters");
        m_ind = m_ind.substr(0, m_ind.size() + indents);
    } else if (indents > 0) {
        m_ind += spaces(indents);
    }

    // does this end its line?
    if (ends_line) {
        nl();
    }

    if (pushed_color) {
        m_avail = Availability((int)m_avail + 1);
        set_avail(Availability((int)m_avail - 1));
    }
}

void TreeStringEmitter::nl() {
    m_empty_line = true;
    m_str += "\n";
}
