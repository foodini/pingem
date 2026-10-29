// public_suffix.h - "who owns this router?", from its reverse DNS name.
//
// A router's name is usually long and specific -
// be-33-crs01.sunnyvale.ca.ibone.comcast.net - but the route graph only has
// room for the part that says whose network it is: comcast.net. That part is
// the "registrable domain": one label more than the public suffix. Finding
// the public suffix needs Mozilla's Public Suffix List
// (https://publicsuffix.org), because there's no rule that works everywhere:
// it's "net" for comcast.net, but "co.uk" for bt.co.uk and "com.au" for
// telstra.com.au.
//
// The list is NOT fetched at run time. `make` downloads it once into
// ~/.cache/pingem/ (if it isn't there yet), and `make update-psl` refreshes
// it. Without it, a simple guess is used instead: the last two labels, or
// the last three when the second-to-last is one of the usual "co"/"com"/...
// under a country code. That guess is right for most router names.
//
// Only the list's ICANN section is used. Its "private" section lists domains
// like amazonaws.com where customers get subdomains - right for browser
// cookies, wrong for "who runs this router".

#ifndef PINGEM_PUBLIC_SUFFIX_H
#define PINGEM_PUBLIC_SUFFIX_H

#include <set>
#include <string>

class PublicSuffixList {
public:
  PublicSuffixList();

  // Where `make` puts the list: $XDG_CACHE_HOME/pingem/public_suffix_list.dat,
  // or ~/.cache/pingem/public_suffix_list.dat.
  static std::string default_path();

  // Returns false if the file can't be read; the fallback guess is used.
  bool load(const std::string& path);
  bool is_loaded() const;

  // The registrable domain of `hostname` ("comcast.net"), lower case. If
  // the name is itself a public suffix, or has no dots, returns it as is.
  std::string owner_domain(const std::string& hostname) const;

private:
  std::set<std::string> rules;        // "com", "co.uk"
  std::set<std::string> wildcards;    // "*.ck" stored as "ck"
  std::set<std::string> exceptions;   // "!www.ck" stored as "www.ck"
  bool loaded;
};

#endif
