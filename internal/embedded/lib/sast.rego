package sast

import future.keywords.in

# is_js_family checks whether the language is JavaScript, TypeScript, or TSX.
is_js_family(lang) = true {
    lang in ["javascript", "typescript", "tsx"]
}

# nodes_by_type returns all AST nodes matching the given type string.
nodes_by_type(node_type) = [n |
    n := input.nodes[_]
    n.type == node_type
]

# get_node retrieves a node by its ID.
get_node(id) = input.nodes[id]

# child retrieves the first child node associated with the specified field name.
child(node, field_name) = input.nodes[node.fields[field_name].id] {
    node.fields[field_name]
}

# field_text returns the text of the child node with the specified field name.
field_text(node, field_name) = node.fields[field_name].text {
    node.fields[field_name]
}

# children returns all direct child nodes of the given node.
children(node) = [input.nodes[cid] |
    cid := node.children[_]
]

# parent returns the direct parent node, or null if the node is root.
parent(node) = input.nodes[node.parent_id] {
    node.parent_id >= 0
}

# ancestors returns all ancestor nodes of the given node.
ancestors(node) = [input.nodes[a_id] |
    a_id := node.ancestors[_]
]

# has_ancestor checks whether any ancestor of the node has the specified type.
has_ancestor(node, ancestor_type) {
    a_id := node.ancestors[_]
    input.nodes[a_id].type == ancestor_type
}

# has_ancestor_or_self checks if the node or any ancestor has the specified type.
has_ancestor_or_self(node, target_type) {
    node.type == target_type
}
has_ancestor_or_self(node, target_type) {
    has_ancestor(node, target_type)
}

# is_descendant checks if node is a descendant of potential_ancestor.
is_descendant(node, potential_ancestor) {
    potential_ancestor.id in node.ancestors
}

# find_calls finds all call expressions across supported languages.
find_calls = [n |
    n := input.nodes[_]
    n.type in [
        "call",
        "call_expression",
        "method_invocation",
        "function_call_expression",
        "scoped_call_expression",
        "member_call_expression",
        "method_call"
    ]
]

# call_name returns the callee name across different language ASTs.
call_name(call_node) = call_node.fields.function.text {
    call_node.fields.function
}
call_name(call_node) = call_node.fields.name.text {
    call_node.fields.name
}
call_name(call_node) = call_node.fields.method.text {
    call_node.fields.method
}

# find_calls_by_name finds calls where the callee function name or attribute equals name.
find_calls_by_name(name) = [c |
    c := find_calls[_]
    call_name(c) == name
]

# find_calls_ending_with finds calls where the callee ends with name (e.g. ".execute").
find_calls_ending_with(name) = [c |
    c := find_calls[_]
    endswith(call_name(c), name)
]

# arguments returns all argument nodes passed to a call expression.
arguments(call_node) = [input.nodes[arg_id] |
    args_container := child(call_node, "arguments")
    arg_id := args_container.children[_]
    input.nodes[arg_id].is_named == true
]

# arg returns the N-th argument node of a call expression (0-indexed).
arg(call_node, index) = unwrap_arg(arguments(call_node)[index])

unwrap_arg(node) = input.nodes[cid] {
    node.type == "argument"
    cid := node.children[_]
    input.nodes[cid].is_named == true
} else = node

# is_string_literal checks if a node is a string literal across languages.
is_string_literal(node) {
    node.type in [
        "string",
        "string_literal",
        "interpreted_string_literal",
        "raw_string_literal",
        "template_string",
        "character_literal",
        "concatenated_string",
        "encapsed_string"
    ]
}

# strip_quotes removes enclosing quotes from string literal text.
strip_quotes(text) = trim(trim(text, `"`), `'`)

# new_finding is a helper to construct a normalized finding object.
new_finding(rule_meta, node, custom_message) = finding {
    msg := object.get(rule_meta, "message", custom_message)
    finding := {
        "rule_id": rule_meta.id,
        "title": object.get(rule_meta, "title", rule_meta.id),
        "message": msg,
        "severity": object.get(rule_meta, "severity", "WARNING"),
        "cwe": object.get(rule_meta, "cwe", ""),
        "owasp": object.get(rule_meta, "owasp", ""),
        "file": input.file.path,
        "range": node.range,
        "code": node.text,
        "metadata": object.get(rule_meta, "metadata", {})
    }
}
