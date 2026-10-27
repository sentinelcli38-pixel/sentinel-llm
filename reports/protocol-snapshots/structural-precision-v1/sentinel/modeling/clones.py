"""Conservative lexical clone grouping, not a semantic-equivalence proof."""

import hashlib
import re
from collections import Counter, defaultdict

from sentinel.modeling.data import strip_comments

TOKEN = re.compile(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[A-Za-z_$][\w$]*|0x[\da-fA-F]+|\d+(?:\.\d+)?|==|!=|<=|>=|&&|\|\||=>|\+\+|--|\*\*|\S''')
KEYWORDS = set("""pragma solidity contract library interface function modifier event error
constructor fallback receive public private internal external pure view payable constant
immutable virtual override returns return mapping memory storage calldata address bool
string bytes uint int if else for while do break continue new delete emit revert require
assert unchecked assembly this super msg sender value tx origin block timestamp number
call delegatecall staticcall send transfer selfdestruct balance true false is using struct
enum import from as try catch throw var gas now length push pop abi encode encodePacked
decode keccak256 sha256 ecrecover type wei ether seconds minutes hours days weeks years""".split())  # noqa: SIM905


def normalized_tokens(source: str) -> tuple[str, ...]:
    tokens = TOKEN.findall(strip_comments(source))
    normalized = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "pragma":
            while index < len(tokens) and tokens[index] != ";":
                index += 1
        elif token[0] in "\"'":
            normalized.append("STR")
        elif token[0].isdigit():
            normalized.append("NUM")
        elif re.fullmatch(r"(?:u?int|bytes)\d*", token) or token in KEYWORDS:
            normalized.append(token)
        elif re.fullmatch(r"[A-Za-z_$][\w$]*", token):
            normalized.append("ID")
        else:
            normalized.append(token)
        index += 1
    return tuple(normalized)


def lexical_fingerprint(source: str) -> str:
    return hashlib.sha256(" ".join(normalized_tokens(source)).encode()).hexdigest()


def clone_components(sources: dict[str, str], identities: dict[str, list[str]], threshold: float = 0.85) -> tuple[dict[str, str], dict]:
    if not 0 < threshold <= 1:
        raise ValueError("Clone threshold must be in (0, 1]")
    parent = {key: key for key in sources}

    def root(key):
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    def join(left, right):
        left, right = root(left), root(right)
        parent[max(left, right)] = min(left, right)

    identity_owner = {}
    postings = defaultdict(list)
    shingles = {}
    near_links = 0
    for key in sorted(sources):
        tokens = normalized_tokens(sources[key])
        fingerprint = hashlib.sha256(" ".join(tokens).encode()).hexdigest()
        for identity in [f"lexical:{fingerprint}", *identities.get(key, [])]:
            if identity in identity_owner:
                join(key, identity_owner[identity])
            else:
                identity_owner[identity] = key
        grams = {tokens[index:index + 5] for index in range(max(1, len(tokens) - 4))}
        candidates = Counter(candidate for gram in grams for candidate in postings[gram])
        for candidate, overlap in candidates.items():
            union = len(grams) + len(shingles[candidate]) - overlap
            if union and overlap / union >= threshold:
                join(key, candidate)
                near_links += 1
        shingles[key] = grams
        for gram in grams:
            postings[gram].append(key)
    components = {key: root(key) for key in sources}
    return components, {"method": "Identifier/literal-normalized 5-token shingle Jaccard connected components",
                        "threshold": threshold, "sources": len(sources),
                        "components": len(set(components.values())), "near_clone_links": near_links,
                        "limitation": "Lexical screening is not a semantic clone or pretraining-contamination proof."}
