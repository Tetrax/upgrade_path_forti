"use strict";

(function exposeAdvisoryMatching(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.FortiosAdvisoryMatching = api;
})(typeof globalThis === "object" ? globalThis : this, () => {
  function hopPairs(path) {
    if (!path || !Array.isArray(path.hops)) return [];
    return path.hops.slice(0, -1).map((from, index) => ({
      from,
      to: path.hops[index + 1]
    }));
  }

  function preciseHopMatches(advisory, path) {
    if (!advisory || !advisory.from || !advisory.to) return false;
    return hopPairs(path).some(pair => (
      pair.from === advisory.from && pair.to === advisory.to
    ));
  }

  function preciseHopMatchesVersion(advisory, version, path) {
    return Boolean(advisory && version === advisory.to && preciseHopMatches(advisory, path));
  }

  return {
    hopPairs,
    preciseHopMatches,
    preciseHopMatchesVersion
  };
});
