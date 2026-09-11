#!/usr/bin/env python3
# main.py
# NetRule Compiler — entry point.
# NetRule Language Specification v1.0
#
# Usage:
#   python main.py <policy_file.nr> --policy <name> --packet <packet.json>
#   python main.py <policy_file.nr> --policy <name> --interactive
#   python main.py --demo

import sys
import os
import json
import argparse

from lexer import Lexer
from parser import Parser
from symbol_table import SymbolTable
from semantic_analyzer import SemanticAnalyzer
from ir_generator import IRGenerator
from optimizer import Optimizer
from executor import Executor
from packet import Packet, PacketError
from visualizer import (
    show_tokens, show_ast, show_semantic,
    show_symbol_table, show_ir, show_optimization, show_execution,
    section, W,
)

BANNER = r"""
╔══════════════════════════════════════════════════════════╗
║            N E T R U L E   C O M P I L E R             ║
║   Lexer → Parser → Semantic → IR → Optimize → Execute   ║
║   VIT Vellore · Compiler Design Lab · Phase 1           ║
╚══════════════════════════════════════════════════════════╝
"""


# ── Full pipeline ──────────────────────────────────────────────────────────────

def run_pipeline(source: str, policy_name: str, packet: Packet,
                 verbose: bool = True) -> str | None:
    """
    Run the full compilation + simulation pipeline.
    Returns the decision string or None on compile error.
    """
    print(f"\n{'═' * (W + 2)}")
    print(f"  POLICY: {policy_name}")
    print(f"{'═' * (W + 2)}")

    # ── Stage 1: Lex ──────────────────────────────────────────────────────────
    lexer  = Lexer(source)
    tokens, lex_errors = lexer.tokenize()
    if verbose:
        show_tokens(tokens, lex_errors)
    if lex_errors:
        print("\n  ⛔ Compilation stopped: lexical errors.")
        return None

    # ── Stage 2: Parse ────────────────────────────────────────────────────────
    parser  = Parser(tokens)
    program = parser.parse()
    if verbose:
        show_ast(program, parser.errors)
    if parser.errors:
        print("\n  ⛔ Compilation stopped: parse errors.")
        return None

    # ── Stage 3: Semantic analysis ────────────────────────────────────────────
    st       = SymbolTable()
    analyzer = SemanticAnalyzer(st)
    valid    = analyzer.analyze(program)
    if verbose:
        show_semantic(analyzer.errors, analyzer.warnings)
        show_symbol_table(st)
    if not valid:
        print("\n  ⛔ Compilation stopped: semantic errors.")
        return None

    # ── Stage 4: IR generation ────────────────────────────────────────────────
    ir_gen   = IRGenerator()
    ir_map   = ir_gen.generate_program(program)

    if policy_name not in ir_map:
        known = list(ir_map.keys())
        print(f"\n  ❌ Policy {policy_name!r} not found. "
              f"Available: {known}")
        return None

    policy_ir = ir_map[policy_name]
    if verbose:
        show_ir(policy_ir)

    # ── Stage 5: Optimization ─────────────────────────────────────────────────
    optimizer = Optimizer()
    opt_ir, opt_log = optimizer.optimize_policy(policy_ir)
    if verbose:
        show_optimization(policy_ir, opt_ir, opt_log)

    # ── Stage 6: Execution ────────────────────────────────────────────────────
    executor = Executor()
    result   = executor.execute(opt_ir, packet)
    if verbose:
        show_execution(packet, result)

    return result.decision


# ── Demo ───────────────────────────────────────────────────────────────────────

DEMO_POLICY = """\
# NetRule demo — campus security policy
# NetRule Language Specification v1.0

POLICY campus_security {

    RULE allow_https {
        IF protocol == TCP
        AND destination_port == 443
        THEN ALLOW;
    }

    RULE allow_http {
        IF protocol == TCP
        AND destination_port == 80
        THEN ALLOW;
    }

    RULE block_telnet {
        IF protocol == TCP
        AND destination_port == 23
        THEN DENY;
    }

    RULE log_udp {
        IF protocol == UDP
        THEN LOG;
    }

    RULE block_all_tcp {
        IF protocol == TCP
        THEN DENY;
    }

}

POLICY server_policy {

    RULE allow_ssh_from_trusted {
        IF source_ip == 192.168.1.10
        AND protocol == TCP
        AND destination_port == 22
        THEN ALLOW;
    }

    RULE deny_ssh {
        IF destination_port == 22
        AND protocol == TCP
        THEN DENY;
    }

    RULE allow_all {
        IF protocol == TCP
        THEN ALLOW;
    }

}
"""

DEMO_PACKETS = [
    {'source_ip': '10.0.0.5',     'destination_ip': '10.0.0.20',
     'protocol': 'TCP',  'source_port': 52000, 'destination_port': 443},
    {'source_ip': '10.0.0.5',     'destination_ip': '10.0.0.20',
     'protocol': 'TCP',  'source_port': 52001, 'destination_port': 23},
    {'source_ip': '10.0.0.5',     'destination_ip': '10.0.0.20',
     'protocol': 'UDP',  'source_port': 53,    'destination_port': 53},
    {'source_ip': '10.0.0.5',     'destination_ip': '10.0.0.20',
     'protocol': 'TCP',  'source_port': 52002, 'destination_port': 8080},
]

ERROR_DEMOS = [
    ("Type mismatch — port vs protocol value",
     "POLICY err1 { RULE r { IF destination_port == TCP THEN DENY; } }"),
    ("Invalid operator on IP field",
     "POLICY err2 { RULE r { IF source_ip > 10 THEN DENY; } }"),
    ("Undefined field",
     "POLICY err3 { RULE r { IF dest == 443 THEN DENY; } }"),
    ("Duplicate rule name",
     "POLICY err4 { RULE r { IF protocol == TCP THEN ALLOW; } "
     "RULE r { IF protocol == UDP THEN DENY; } }"),
    ("Unreachable rule warning",
     "POLICY err5 { "
     "RULE block_tcp { IF protocol == TCP THEN DENY; } "
     "RULE allow_https { IF protocol == TCP AND destination_port == 443 THEN ALLOW; } }"),
    ("Syntax error — missing THEN",
     "POLICY err6 { RULE r { IF protocol == TCP DENY; } }"),
    ("Lexical error — unknown character",
     "POLICY err7 { RULE r { IF destination_port @ 443 THEN DENY; } }"),
]


def run_demo():
    print(BANNER)
    print("  Running demo: campus_security policy\n")

    for pkt_data in DEMO_PACKETS:
        try:
            pkt = Packet.from_dict(pkt_data)
        except PacketError as e:
            print(f"  Packet error: {e}")
            continue
        run_pipeline(DEMO_POLICY, 'campus_security', pkt, verbose=False)

    print("\n\n" + "═" * 60)
    print("  ERROR DEMONSTRATIONS")
    print("═" * 60)

    dummy_pkt = Packet.from_dict(DEMO_PACKETS[0])
    for label, src in ERROR_DEMOS:
        print(f"\n  ── {label}")
        lexer   = Lexer(src)
        tokens, lex_errs = lexer.tokenize()
        show_tokens(tokens, lex_errs)
        if lex_errs:
            continue
        parser  = Parser(tokens)
        program = parser.parse()
        show_ast(program, parser.errors)
        if parser.errors:
            continue
        st       = SymbolTable()
        analyzer = SemanticAnalyzer(st)
        analyzer.analyze(program)
        show_semantic(analyzer.errors, analyzer.warnings)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)

    ap = argparse.ArgumentParser(
        description='NetRule Compiler and Policy Simulator'
    )
    ap.add_argument('source', nargs='?', help='.nr policy file')
    ap.add_argument('--policy', help='Name of the policy to simulate')
    ap.add_argument('--packet', help='Path to packet JSON file')
    ap.add_argument('--interactive', action='store_true',
                    help='Enter packet fields interactively')
    ap.add_argument('--demo', action='store_true',
                    help='Run built-in demo')
    ap.add_argument('--quiet', action='store_true',
                    help='Suppress per-stage output (results only)')

    args = ap.parse_args()

    if args.demo or not args.source:
        run_demo()
        return

    # Load source
    if not os.path.exists(args.source):
        print(f"  ❌ File not found: {args.source}")
        sys.exit(1)
    with open(args.source) as f:
        source = f.read()

    # Policy name
    policy_name = args.policy
    if not policy_name:
        # Quick lex+parse to discover policy names
        toks, _ = Lexer(source).tokenize()
        prog = Parser(toks).parse()
        names = [p.name for p in prog.policies] if prog else []
        if len(names) == 1:
            policy_name = names[0]
        else:
            print(f"  Available policies: {names}")
            policy_name = input("  Select policy: ").strip()

    # Packet
    try:
        if args.packet:
            packet = Packet.from_json_file(args.packet)
        elif args.interactive:
            packet = Packet.from_interactive()
        else:
            print("  No packet provided. Use --packet <file.json> "
                  "or --interactive.")
            sys.exit(1)
    except PacketError as e:
        print(f"  ❌ Packet error: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"  ❌ {e}")
        sys.exit(1)

    run_pipeline(source, policy_name, packet, verbose=not args.quiet)


if __name__ == '__main__':
    main()
