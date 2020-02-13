// Copyright (c) 2020 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef included_btcdeb_msenv_h_
#define included_btcdeb_msenv_h_

#include <miniscript/compiler.h>
#include <script/miniscript.h>

// #include <util/strencodings.h>
// #include <policy/policy.h>
// #include <streams.h>
// #include <pubkey.h>
// #include <value.h>
#include <vector>
// #include <map>

typedef miniscript::NodeRef<CompilerContext::Key> Node;

using miniscript::Availability;
using miniscript::EmitType;

struct TreeStringEmitter : public miniscript::StringEmitter {
    using miniscript::StringEmitter::m_str;
    bool m_empty_line{true};
    Availability m_avail{Availability::MAYBE};
    int m_indentation{0};
    std::string m_ind;
    void emit(const std::string& value, bool own_line = false, bool ends_line = false, int indents = 0, bool strip_end = false, EmitType type = EmitType::Default) override;
    void set_avail(Availability avail) override;
    void nl();
};

struct Solution {
    Availability m_avail;
    std::set<Node> m_active_nodes;
    std::string m_description;
    Solution(const std::string& description, std::set<Node> active_nodes) : m_avail(Availability::MAYBE), m_active_nodes(active_nodes), m_description(description) {}
    Solution merge(const Solution& other) const;
    static std::vector<Solution> merge(const std::vector<Solution>& sol1, const std::vector<Solution>& sol2);
};

struct Branch;

struct Situation {
    int m_confirmations{-1};
    std::map<std::string, Availability> m_inventory;
    std::vector<Solution> m_solutions;
    std::set<std::string> m_elements;
    std::vector<Node> m_activated;
    std::vector<std::shared_ptr<Situation>> m_subsits;
    void emit(const std::string& description, Node activates = nullptr);
    bool iterate(Node parent, Branch&& branch, const std::string& prefix, const std::string& suffix, bool wrapped);
    std::shared_ptr<Situation> spawn();
    void discard(std::shared_ptr<Situation> sit, bool merge_solutions = false);
    void analyze(int confirmations, Node tree);
};

struct Branch {
    Availability m_avail{Availability::MAYBE};
    Node m_node;
    Branch* m_selector{nullptr}; // [Z] expression, for ANDOR
    std::vector<Branch> m_children;

    Branch() {}
    Branch(const Node& node);

    bool iterate(Situation& situation, const std::string& prefix = "", const std::string& suffix = "", bool wrapped = false);
};

struct MSEnv {
    std::string m_input{""};
    double m_avgcost{0.0};
    int m_confirmations{-1};
    // std::map<Node,Availability> m_availmap;
    Situation m_situation;
    Branch m_root;
    explicit MSEnv(const std::string& input);
    void PrintTree() const;
};

#endif // included_btcdeb_msenv_h_
