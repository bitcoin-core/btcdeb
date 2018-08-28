// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compiler/env.h>

std::shared_ptr<var> env_true = std::make_shared<var>(Value((int64_t)1));
std::shared_ptr<var> env_false = std::make_shared<var>(Value((int64_t)0));

var* G;
var* Gx;
var* Gy;

env_t env;
