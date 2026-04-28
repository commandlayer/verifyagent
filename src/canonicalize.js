/**
 * Deterministically canonicalize JSON by sorting object keys recursively.
 * Canonicalization id: json.sorted_keys.v1
 */
export function canonicalize(value) {
  return JSON.stringify(sortKeysDeep(value));
}

function sortKeysDeep(value) {
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }

  if (value && typeof value === 'object') {
    const sorted = {};
    for (const key of Object.keys(value).sort()) {
      sorted[key] = sortKeysDeep(value[key]);
    }
    return sorted;
  }

  return value;
}
