#include "public_suffix.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

PublicSuffixList::PublicSuffixList() : loaded(false) {
}

std::string PublicSuffixList::default_path() {
  const char* cache = getenv("XDG_CACHE_HOME");
  std::string base;
  if (cache != NULL && cache[0] == '/') {
    base = cache;
  } else {
    const char* home = getenv("HOME");
    base = std::string(home != NULL ? home : ".") + "/.cache";
  }
  return base + "/pingem/public_suffix_list.dat";
}

static std::string lower(const std::string& text) {
  std::string result = text;
  for (size_t i = 0; i < result.size(); i++) {
    result[i] = (char)tolower((unsigned char)result[i]);
  }
  return result;
}

// The file format: one rule per line; "//" starts a comment line; a rule
// ends at the first whitespace. "*.foo" is a wildcard, "!bar.foo" an
// exception to one.
bool PublicSuffixList::load(const std::string& path) {
  FILE* file = fopen(path.c_str(), "r");
  if (file == NULL) {
    return false;
  }
  char line[1024];
  while (fgets(line, sizeof(line), file) != NULL) {
    if (strstr(line, "===BEGIN PRIVATE DOMAINS===") != NULL) {
      break;   // see the header: ICANN section only
    }
    if (line[0] == '/' && line[1] == '/') {
      continue;
    }
    size_t length = strcspn(line, " \t\r\n");
    if (length == 0) {
      continue;
    }
    std::string rule = lower(std::string(line, length));
    if (rule[0] == '!') {
      exceptions.insert(rule.substr(1));
    } else if (rule.size() > 2 && rule[0] == '*' && rule[1] == '.') {
      wildcards.insert(rule.substr(2));
    } else {
      rules.insert(rule);
    }
  }
  fclose(file);
  loaded = !rules.empty();
  return loaded;
}

bool PublicSuffixList::is_loaded() const {
  return loaded;
}

static std::string join_from(const std::vector<std::string>& labels, size_t first) {
  std::string result;
  for (size_t i = first; i < labels.size(); i++) {
    if (!result.empty()) {
      result += '.';
    }
    result += labels[i];
  }
  return result;
}

std::string PublicSuffixList::owner_domain(const std::string& hostname) const {
  std::string name = lower(hostname);
  if (!name.empty() && name[name.size() - 1] == '.') {
    name.erase(name.size() - 1);   // a fully qualified "foo.com."
  }
  std::vector<std::string> labels;
  size_t start = 0;
  while (true) {
    size_t dot = name.find('.', start);
    labels.push_back(name.substr(start, dot == std::string::npos ? std::string::npos
                                                                   : dot - start));
    if (dot == std::string::npos) {
      break;
    }
    start = dot + 1;
  }
  size_t count = labels.size();
  if (count < 2) {
    return name;
  }

  // Where the public suffix starts (an index into labels).
  size_t suffix_start = count - 1;   // the default rule, "*": just the TLD
  if (loaded) {
    // The longest matching rule wins, so try the longest candidates first.
    for (size_t i = 0; i < count; i++) {
      std::string candidate = join_from(labels, i);
      if (exceptions.count(candidate) != 0) {
        suffix_start = i + 1;
        break;
      }
      if (rules.count(candidate) != 0 ||
          (i + 1 < count && wildcards.count(join_from(labels, i + 1)) != 0)) {
        suffix_start = i;
        break;
      }
    }
  } else {
    // The fallback guess.
    static const char* const SECOND_LEVEL[] = {"co", "com", "net", "org", "gov", "edu",
                                               "ac", "ne", "or", "go", NULL};
    if (count >= 3 && labels[count - 1].size() == 2) {
      for (int i = 0; SECOND_LEVEL[i] != NULL; i++) {
        if (labels[count - 2] == SECOND_LEVEL[i]) {
          suffix_start = count - 2;
          break;
        }
      }
    }
  }

  if (suffix_start == 0 || suffix_start > count - 1) {
    return name;   // the whole name is a public suffix
  }
  return join_from(labels, suffix_start - 1);
}
