#include <interpreter.h>
#include <utilstrencodings.h>
#include <policy/policy.h>
#include <streams.h>
#include <pubkey.h>
#include <value.h>
#include <vector>

typedef std::vector<unsigned char> valtype;

class Instance {
public:
    InterpreterEnv* env;
    int count;
    ECCVerifyHandle evh;
    CTransactionRef tx;
    std::vector<CAmount> amounts;
    SigVersion sigver;
    CScript script;
    std::vector<valtype> stack;
    BaseSignatureChecker* checker;
    ScriptError error;

    Instance()
    : env(nullptr)
    , count(0)
    , sigver(SIGVERSION_BASE)
    , checker(nullptr)
    {}

    ~Instance() {
        delete checker;
        delete env;
    }

    bool parse_transaction(const char* txdata, bool parse_amounts = false);

    bool parse_script(const char* script_str);

    void parse_stack_args(size_t argc, const char** argv, size_t starting_index);

    bool setup_environment();

    bool at_end();
    bool at_start();
    const char* error_string();

    bool step();

    bool rewind();

    bool eval(const size_t argc, const char** argv);
};
