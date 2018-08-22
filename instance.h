#include <debugger/interpreter.h>
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
    CTransactionRef txin;
    int64_t txin_index;             ///< index of the input txid in tx's inputs
    int64_t txin_vout_index;        ///< index inside txin of the output to tx
    std::vector<CAmount> amounts;
    SigVersion sigver;
    CScript script;
    CScript successor_script;
    std::vector<valtype> stack;
    BaseSignatureChecker* checker;
    ScriptError error;
    std::string exception_string = "";

    Instance()
    : env(nullptr)
    , count(0)
    , txin_index(-1)
    , txin_vout_index(-1)
    , sigver(SigVersion::BASE)
    , checker(nullptr)
    {}

    ~Instance() {
        delete env;
        delete checker;
    }

    bool parse_transaction(const char* txdata, bool parse_amounts = false);
    bool parse_input_transaction(const char* txdata, int select_index = -1);

    bool parse_script(const char* script_str);
    bool parse_script(const std::vector<uint8_t>& script_data);

    void parse_stack_args(size_t argc, char* const* argv, size_t starting_index);
    void parse_stack_args(const std::vector<const char*> args);

    bool configure_tx_txin();

    bool setup_environment(unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS);

    bool at_end();
    bool at_start();
    const char* error_string();

    bool step(size_t steps = 1);

    bool rewind();

    bool eval(const size_t argc, char* const* argv);
};
