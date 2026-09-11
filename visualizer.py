# visualizer.py
# Pipeline visualizer for the NetRule compiler.
# Prints each compilation stage in a readable, structured format.

from ast_nodes import (
    ProgramNode, PolicyNode, RuleNode,
    ComparisonNode, BinaryLogicNode, UnaryLogicNode,
)
from ir_nodes import PolicyIR, CheckIR, AndIR, OrIR, NotIR
from lexer import Token

W = 58   # box width


def _bar(char='─'):
    return char * W

def section(title: str):
    print(f"\n┌{_bar()}┐")
    print(f"│  {title:<{W-2}}│")
    print(f"└{_bar()}┘")

def subsection(title: str):
    print(f"\n  ── {title} {'─' * max(0, W - len(title) - 6)}")


# ── Stage 1: Tokens ───────────────────────────────────────────────────────────

def show_tokens(tokens: list[Token], errors: list):
    section("STAGE 1 · LEXICAL ANALYSIS")
    if errors:
        print(f"\n  ❌ Lexical errors ({len(errors)}):")
        for e in errors:
            print(f"    {e}")
    non_eof = [t for t in tokens if t.ttype != 'EOF']
    print(f"\n  {len(non_eof)} tokens produced:\n")
    for tok in non_eof:
        print(f"    [{tok.ttype:<20}]  {tok.value!r:<25}  {tok.line}:{tok.col}")
    if not errors:
        print(f"\n  ✅ No lexical errors.")


# ── Stage 2: AST ──────────────────────────────────────────────────────────────

def show_ast(program: ProgramNode | None, errors: list):
    section("STAGE 2 · SYNTAX ANALYSIS  (AST)")
    if errors:
        print(f"\n  ❌ Parse errors ({len(errors)}):")
        for e in errors:
            print(f"    {e}")
    if program is None:
        return
    print(f"\n  ProgramNode  ({len(program.policies)} policies)")
    for policy in program.policies:
        print(f"  └── PolicyNode: {policy.name!r}  ({len(policy.rules)} rules)")
        for i, rule in enumerate(policy.rules):
            connector = '└──' if i == len(policy.rules) - 1 else '├──'
            print(f"       {connector} RuleNode: {rule.name!r}  → {rule.action}")
            _print_condition_tree(rule.condition, prefix="            ", last=True)
    if not errors:
        print(f"\n  ✅ AST constructed — no parse errors.")


def _print_condition_tree(node, prefix='', last=True):
    connector = '└── ' if last else '├── '
    child_prefix = prefix + ('    ' if last else '│   ')
    if isinstance(node, ComparisonNode):
        print(f"{prefix}{connector}{node.field_token.value} "
              f"{node.op} {node.value_token.value}")
    elif isinstance(node, BinaryLogicNode):
        print(f"{prefix}{connector}{node.op}")
        _print_condition_tree(node.left,  child_prefix, last=False)
        _print_condition_tree(node.right, child_prefix, last=True)
    elif isinstance(node, UnaryLogicNode):
        print(f"{prefix}{connector}NOT")
        _print_condition_tree(node.operand, child_prefix, last=True)


# ── Stage 3: Semantic analysis ────────────────────────────────────────────────

def show_semantic(errors: list, warnings: list):
    section("STAGE 3 · SEMANTIC ANALYSIS")
    if errors:
        print(f"\n  ❌ Errors ({len(errors)}):")
        for e in errors:
            print(f"    {e}")
    if warnings:
        print(f"\n  ⚠  Warnings ({len(warnings)}):")
        for w in warnings:
            print(f"    {w}")
    if not errors and not warnings:
        print("\n  ✅ All type checks passed. No errors, no warnings.")
    elif not errors:
        print(f"\n  ✅ Passed with {len(warnings)} warning(s).")


# ── Stage 4: Symbol table ─────────────────────────────────────────────────────

def show_symbol_table(st):
    section("STAGE 4 · SYMBOL TABLE")
    st.display()


# ── Stage 5: IR ───────────────────────────────────────────────────────────────

def show_ir(policy_ir: PolicyIR, label="STAGE 5 · IR GENERATION"):
    section(label)
    print(f"\n  PolicyIR: {policy_ir.name!r}")
    for rule in policy_ir.rules:
        print(f"\n  RuleIR: {rule.name!r}  →  {rule.action}")
        _print_ir_tree(rule.condition, prefix="    ", last=True)


def _print_ir_tree(node, prefix='', last=True):
    connector    = '└── ' if last else '├── '
    child_prefix = prefix + ('    ' if last else '│   ')
    if isinstance(node, CheckIR):
        print(f"{prefix}{connector}CHECK  {node.field} {node.op} {node.value!r}")
    elif isinstance(node, AndIR):
        print(f"{prefix}{connector}AND")
        _print_ir_tree(node.left,  child_prefix, last=False)
        _print_ir_tree(node.right, child_prefix, last=True)
    elif isinstance(node, OrIR):
        print(f"{prefix}{connector}OR")
        _print_ir_tree(node.left,  child_prefix, last=False)
        _print_ir_tree(node.right, child_prefix, last=True)
    elif isinstance(node, NotIR):
        print(f"{prefix}{connector}NOT")
        _print_ir_tree(node.operand, child_prefix, last=True)


# ── Stage 6: Optimization ─────────────────────────────────────────────────────

def show_optimization(before: PolicyIR, after: PolicyIR, log: list[str]):
    section("STAGE 6 · OPTIMIZATION  (Boolean Simplification)")
    if not log:
        print("\n  No transformations applied — IR already in simplified form.")
    else:
        print(f"\n  Transformations applied ({len(log)}):")
        for l in log:
            print(f"  {l}")
    print("\n  IR after optimization:")
    for rule in after.rules:
        print(f"\n  RuleIR: {rule.name!r}  →  {rule.action}")
        _print_ir_tree(rule.condition, prefix="    ", last=True)


# ── Stage 7: Execution ────────────────────────────────────────────────────────

def show_execution(packet, result):
    section("STAGE 7 · PACKET SIMULATION")
    print("\n  Packet:")
    packet.display()
    result.display()

    # Final verdict box
    verdict_char = '✅' if result.decision in ('ALLOW', 'LOG') else '❌'
    print(f"\n  ┌{'─'*30}┐")
    print(f"  │  {verdict_char}  VERDICT: {result.decision:<18}│")
    print(f"  └{'─'*30}┘")
