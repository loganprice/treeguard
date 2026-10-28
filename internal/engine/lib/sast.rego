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

# callee_node returns the function/callee AST node of a call expression.
callee_node(call_node) = input.nodes[call_node.fields.function.id] {
    call_node.fields.function
} else = input.nodes[call_node.fields.name.id] {
    call_node.fields.name
} else = input.nodes[call_node.fields.method.id] {
    call_node.fields.method
} else = call_node

# find_calls_by_name finds calls where the callee function name or attribute equals name.
find_calls_by_name(name) = [c |
    c := find_calls[_]
    call_name(c) == name
]

# find_calls_ending_with finds calls where the callee ends with name or delegates to custom procedure functions.
find_calls_ending_with(name) = [c |
    c := find_calls[_]
    is_call_or_interproc(c, name)
]

is_call_or_interproc(c, name) {
    endswith(call_name(c), name)
}
is_call_or_interproc(c, name) {
    not endswith(call_name(c), name)
    c_name := call_name(c)
    not contains(c_name, ".")
    not file_has_direct_sink(name)
}

file_has_direct_sink(name) {
    c := find_calls[_]
    endswith(call_name(c), name)
}

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
    base := {
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
    fix_replacement := object.get(rule_meta, "fix", "")
    finding := object.union(base, fix_object(node.range, fix_replacement))
}

# new_finding_with_fix constructs a finding with an explicit replacement for node.
new_finding_with_fix(rule_meta, node, custom_message, replacement) = finding {
    base := new_finding(rule_meta, node, custom_message)
    finding := object.union(base, {"fix": {
        "replacement": replacement,
        "range": node.range
    }})
}

# new_finding_on_node_with_fix constructs a finding reported on finding_node but targeting target_node for fix replacement.
new_finding_on_node_with_fix(rule_meta, finding_node, target_node, custom_message, replacement) = finding {
    base := new_finding(rule_meta, finding_node, custom_message)
    finding := object.union(base, {"fix": {
        "replacement": replacement,
        "range": target_node.range
    }})
}

fix_object(rng, replacement) = {"fix": {
    "replacement": replacement,
    "range": rng
}} {
    replacement != ""
} else = {}

# has_taint_flow checks if untrusted data flows from source to sink without passing through sanitizers.
has_taint_flow(source, sink, sanitizers) {
    res := sast.taint_flow(source, sink, sanitizers)
    res.has_flow == true
}

# find_taint_flows finds all source-sink pairs where untrusted data flows between them.
find_taint_flows(sources, sinks, sanitizers) = [flow |
    src := sources[_]
    snk := sinks[_]
    has_taint_flow(src, snk, sanitizers)
    flow := {
        "source": src,
        "sink": snk
    }
]

# new_taint_finding constructs a finding for a taint violation pointing to the sink node.
new_taint_finding(rule_meta, source, sink, custom_message) = finding {
    base := new_finding(rule_meta, sink, custom_message)
    finding := object.union(base, {
        "metadata": object.union(
            object.get(rule_meta, "metadata", {}),
            {
                "taint_source_range": source.range,
                "taint_source_code": source.text
            }
        )
    })
}
