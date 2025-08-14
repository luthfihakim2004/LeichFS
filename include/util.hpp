#pragma once
#include <string>

namespace fsutil {

std::string expand_args(const std::string& path);

std::string rstrip_slash(std::string p);

}
