use std::collections::{HashMap, HashSet};
use std::fmt::Write;

use crate::analysis::FunctionAnalysis;
use crate::ir::{BasicBlock, BinOp, Expr, IrFunction, Stmt, UnOp, VReg, Width};

pub struct CGenerator {
    output: String,
    indent: usize,
    /// VReg → C variable name
    var_names: HashMap<VReg, String>,
    /// VReg → declared type
    var_types: HashMap<VReg, Width>,
    /// Set of VRegs already declared
    declared: HashSet<VReg>,
    /// Name context (for external function names)
    func_names: HashMap<u64, String>,
}

impl CGenerator {
    pub fn new(func_names: HashMap<u64, String>) -> Self {
        Self {
            output: String::new(),
            indent: 0,
            var_names: HashMap::new(),
            var_types: HashMap::new(),
            declared: HashSet::new(),
            func_names,
        }
    }

    fn indent_str(&self) -> String {
        "    ".repeat(self.indent)
    }

    fn writeln(&mut self, line: &str) {
        let ind = self.indent_str();
        writeln!(self.output, "{}{}", ind, line).unwrap();
    }

    fn var_name(&mut self, vr: VReg) -> String {
        if let Some(n) = self.var_names.get(&vr) {
            return n.clone();
        }
        let name = format!("v{}", vr.0);
        self.var_names.insert(vr, name.clone());
        name
    }

    fn ensure_declared(&mut self, vr: VReg, width: Width) -> String {
        let name = self.var_name(vr);
        if !self.declared.contains(&vr) {
            self.declared.insert(vr);
            self.var_types.insert(vr, width);
            let ind = self.indent_str();
            writeln!(self.output, "{}{} {};", ind, width.c_type(), name).unwrap();
        }
        name
    }

    fn expr_to_c(&mut self, expr: &Expr) -> String {
        match expr {
            Expr::Const(v, w) => {
                match w {
                    Width::W64 => format!("{}ULL", v),
                    Width::W32 => format!("{}U", v),
                    _ => format!("{}", v),
                }
            }
            Expr::Reg(vr, w) => {
                let name = self.var_name(*vr);
                // Ensure it's declared (with appropriate type)
                if !self.declared.contains(vr) {
                    self.declared.insert(*vr);
                    self.var_types.insert(*vr, *w);
                    let ind = self.indent_str();
                    writeln!(self.output, "{}{} {};", ind, w.c_type(), name).unwrap();
                }
                name
            }
            Expr::BinOp(op, l, r) => {
                let ls = self.expr_to_c(l);
                let rs = self.expr_to_c(r);
                match op {
                    BinOp::SDiv | BinOp::SMod => {
                        let cast = l.width().c_type_signed();
                        format!("(({cast}){ls} {op} ({cast}){rs})")
                    }
                    BinOp::AShr => {
                        let cast = l.width().c_type_signed();
                        format!("(({cast}){ls} >> {rs})")
                    }
                    BinOp::Slt | BinOp::Sle => {
                        let cast = l.width().c_type_signed();
                        format!("(({cast}){ls} {op} ({cast}){rs})")
                    }
                    _ => format!("({ls} {op} {rs})"),
                }
            }
            Expr::UnOp(op, inner) => {
                let is = self.expr_to_c(inner);
                match op {
                    UnOp::Neg => format!("(-{})", is),
                    UnOp::Not => format!("(~{})", is),
                    UnOp::ZExt(w) => format!("(({}){})", w.c_type(), is),
                    UnOp::SExt(w) => format!("(({}){})", w.c_type_signed(), is),
                    UnOp::Trunc(w) => format!("(({}){})", w.c_type(), is),
                }
            }
            Expr::Load(addr, w) => {
                let as_ = self.expr_to_c(addr);
                format!("(*({} *){})", w.c_type(), as_)
            }
            Expr::StackSlot(off, _w) => {
                if *off < 0 {
                    format!("local_{}", (-off))
                } else {
                    format!("arg_{}", off)
                }
            }
            Expr::Addr(a) => {
                if let Some(name) = self.func_names.get(a) {
                    name.clone()
                } else {
                    format!("0x{:x}ULL", a)
                }
            }
        }
    }

    fn emit_stmt(&mut self, stmt: &Stmt, _func: &IrFunction, _analysis: &FunctionAnalysis) {
        match stmt {
            Stmt::Nop => {}
            Stmt::Assign(dst, expr) => {
                let w = expr.width();
                let name = self.ensure_declared(*dst, w);
                let val = self.expr_to_c(expr);
                self.writeln(&format!("{} = {};", name, val));
            }
            Stmt::Store { addr, val, width } => {
                let as_ = self.expr_to_c(addr);
                let vs = self.expr_to_c(val);
                self.writeln(&format!("*({} *){} = {};", width.c_type(), as_, vs));
            }
            Stmt::Call { dst, func: func_expr, args } => {
                let func_s = self.expr_to_c(func_expr);
                let arg_strs: Vec<String> = args.iter().map(|a| self.expr_to_c(a)).collect();
                let call = format!("{}({})", func_s, arg_strs.join(", "));
                if let Some(d) = dst {
                    let name = self.ensure_declared(*d, Width::W64);
                    self.writeln(&format!("{} = {};", name, call));
                } else {
                    self.writeln(&format!("{};", call));
                }
            }
            Stmt::Return(val) => {
                if let Some(v) = val {
                    let vs = self.expr_to_c(v);
                    self.writeln(&format!("return {};", vs));
                } else {
                    self.writeln("return;");
                }
            }
            Stmt::Jump(_) | Stmt::Branch { .. } => {
                // handled by control flow structure
            }
            Stmt::IndirectJump(expr) => {
                let es = self.expr_to_c(expr);
                self.writeln(&format!("goto *((void *){});", es));
            }
            Stmt::Unhandled(s) => {
                self.writeln(&format!("/* unhandled: {} */", s));
            }
        }
    }

    /// Emit all non-terminator statements of a block
    fn emit_block_body(&mut self, block: &BasicBlock, func: &IrFunction, analysis: &FunctionAnalysis) {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Jump(_) | Stmt::Branch { .. } | Stmt::Return(_) | Stmt::IndirectJump(_) => {
                    // emit return here since it's a terminal
                    if matches!(stmt, Stmt::Return(_) | Stmt::IndirectJump(_)) {
                        self.emit_stmt(stmt, func, analysis);
                    }
                }
                _ => self.emit_stmt(stmt, func, analysis),
            }
        }
    }

    /// Structured code emission using dominance tree traversal
    pub fn emit_function(&mut self, func: &IrFunction, analysis: &FunctionAnalysis) {
        let entry = func.blocks.first().map(|b| b.id).unwrap_or(0);
        let mut emitted: HashSet<u32> = HashSet::new();
        self.emit_region(func, analysis, entry, None, &mut emitted);
    }

    fn get_block<'a>(&self, func: &'a IrFunction, id: u32) -> Option<&'a BasicBlock> {
        func.blocks.iter().find(|b| b.id == id)
    }

    /// Recursively emit structured code for a region of blocks.
    /// `follow` is the "continuation" block id that follows this region.
    fn emit_region(
        &mut self,
        func: &IrFunction,
        analysis: &FunctionAnalysis,
        start: u32,
        follow: Option<u32>,
        emitted: &mut HashSet<u32>,
    ) {
        let mut cur = start;
        loop {
            if emitted.contains(&cur) {
                // Reference via goto if needed
                if Some(cur) != follow {
                    self.writeln(&format!("goto block_{};", cur));
                }
                return;
            }
            // Check if this block is the follow node
            if Some(cur) == follow {
                return;
            }

            let block = match self.get_block(func, cur) {
                Some(b) => b.clone(),
                None => return,
            };

            emitted.insert(cur);

            // Label this block (so gotos can find it)
            let needs_label = analysis.cfg.predecessors(cur).len() > 1 || cur == func.blocks.first().map(|b| b.id).unwrap_or(0);
            if needs_label && cur != start {
                // Outdent for label
                if self.indent > 0 { self.indent -= 1; }
                self.writeln(&format!("block_{}:", cur));
                self.indent += 1;
            }

            // Emit non-terminator statements
            self.emit_block_body(&block, func, analysis);

            // Handle terminator
            match block.terminator() {
                None | Some(Stmt::Return(_)) | Some(Stmt::IndirectJump(_)) => {
                    // Already emitted by emit_block_body
                    return;
                }
                Some(Stmt::Jump(next_id)) => {
                    let next = *next_id;
                    if Some(next) == follow {
                        return;
                    }
                    if analysis.loops.is_back_edge(cur, next) {
                        self.writeln("/* back edge */");
                        return;
                    }
                    cur = next;
                    continue;
                }
                Some(Stmt::Branch { cond, true_id, false_id }) => {
                    let (t, f) = (*true_id, *false_id);
                    // Detect if this is a loop back edge
                    let t_back = analysis.loops.is_back_edge(cur, t);
                    let f_back = analysis.loops.is_back_edge(cur, f);

                    if analysis.loops.is_loop_header(t) && analysis.loops.is_back_edge(cur, t) {
                        // cond is loop-continue; f is break/follow
                        let cond_s = self.expr_to_c(cond);
                        self.writeln(&format!("if ({}) {{ continue; }}", cond_s));
                        if Some(f) != follow {
                            cur = f;
                            continue;
                        }
                        return;
                    }

                    if analysis.loops.is_loop_header(f) && analysis.loops.is_back_edge(cur, f) {
                        let cond_s = self.expr_to_c(cond);
                        self.writeln(&format!("if (!{}) {{ continue; }}", cond_s));
                        if Some(t) != follow {
                            cur = t;
                            continue;
                        }
                        return;
                    }

                    // Determine post-dominator (join point)
                    let join = self.find_join(func, analysis, t, f);

                    let cond_s = self.expr_to_c(cond);

                    // Check if it's a loop: one branch is a back edge
                    if t_back {
                        // while loop: condition = cond, body = nothing (cond is loop-end check)
                        // In this position: if cond, break; else fall through
                        self.writeln(&format!("if ({}) {{ goto block_{}; }}", cond_s, t));
                        if let Some(j) = join {
                            if Some(j) != follow {
                                cur = j;
                                continue;
                            }
                        }
                        return;
                    }
                    if f_back {
                        self.writeln(&format!("if (!{}) {{ goto block_{}; }}", cond_s, f));
                        if let Some(j) = join {
                            if Some(j) != follow {
                                cur = j;
                                continue;
                            }
                        }
                        return;
                    }

                    // Normal if/else
                    self.writeln(&format!("if ({}) {{", cond_s));
                    self.indent += 1;

                    // True branch
                    if !emitted.contains(&t) {
                        self.emit_region(func, analysis, t, join, emitted);
                    } else if Some(t) != join {
                        self.writeln(&format!("goto block_{};", t));
                    }
                    self.indent -= 1;

                    // Check if there's a meaningful false branch
                    let false_is_follow = join == Some(f) || Some(f) == follow;
                    if !false_is_follow && !emitted.contains(&f) {
                        self.writeln("} else {");
                        self.indent += 1;
                        self.emit_region(func, analysis, f, join, emitted);
                        self.indent -= 1;
                    }
                    self.writeln("}");

                    // Continue with join point
                    if let Some(j) = join {
                        if Some(j) != follow && !emitted.contains(&j) {
                            cur = j;
                            continue;
                        }
                    }
                    return;
                }
                _ => return,
            }
        }
    }

    /// Find the join (post-dominator) of two branches using BFS
    fn find_join(&self, _func: &IrFunction, analysis: &FunctionAnalysis, a: u32, b: u32) -> Option<u32> {
        // BFS reachable from a and b; first common node in RPO order is join
        let reachable = |start: u32| -> HashSet<u32> {
            let mut visited = HashSet::new();
            let mut queue = std::collections::VecDeque::new();
            queue.push_back(start);
            while let Some(n) = queue.pop_front() {
                if visited.insert(n) {
                    for &s in analysis.cfg.successors(n) {
                        queue.push_back(s);
                    }
                }
            }
            visited
        };

        let ra = reachable(a);
        let rb = reachable(b);
        let common: HashSet<u32> = ra.intersection(&rb).copied().collect();

        // Pick the one that appears earliest in RPO
        analysis.dom.rpo.iter()
            .find(|&&id| common.contains(&id))
            .copied()
    }

    /// Emit a while-loop structure
    fn emit_loop(
        &mut self,
        func: &IrFunction,
        analysis: &FunctionAnalysis,
        header: u32,
        follow: Option<u32>,
        emitted: &mut HashSet<u32>,
    ) {
        let loop_members = match analysis.loops.loops.get(&header) {
            Some(m) => m.clone(),
            None => return,
        };

        self.writeln("while (1) {");
        self.indent += 1;
        emitted.insert(header);

        let header_block = match self.get_block(func, header) {
            Some(b) => b.clone(),
            None => {
                self.indent -= 1;
                self.writeln("}");
                return;
            }
        };

        self.emit_block_body(&header_block, func, analysis);

        match header_block.terminator() {
            Some(Stmt::Branch { cond, true_id, false_id }) => {
                let (t, f) = (*true_id, *false_id);
                let cond_s = self.expr_to_c(cond);
                let (body_start, exit) = if loop_members.contains(&t) {
                    (t, f)
                } else {
                    // invert condition
                    (f, t)
                };

                // emit "if (!cond) break;"
                if loop_members.contains(&t) {
                    self.writeln(&format!("if (!{}) {{ break; }}", cond_s));
                } else {
                    self.writeln(&format!("if ({}) {{ break; }}", cond_s));
                }

                // Emit loop body
                let mut loop_emitted = emitted.clone();
                self.emit_region(func, analysis, body_start, Some(header), &mut loop_emitted);
                // merge back
                for id in &loop_emitted {
                    emitted.insert(*id);
                }

                self.indent -= 1;
                self.writeln("}");

                // Continue with exit
                if !emitted.contains(&exit) {
                    if Some(exit) != follow {
                        let mut sub = emitted.clone();
                        self.emit_region(func, analysis, exit, follow, &mut sub);
                        for id in sub { emitted.insert(id); }
                    }
                }
            }
            _ => {
                self.indent -= 1;
                self.writeln("}");
            }
        }
    }

    pub fn generate_function(&mut self, func: &IrFunction, analysis: &FunctionAnalysis) -> String {
        self.output.clear();
        self.var_names.clear();
        self.var_types.clear();
        self.declared.clear();

        // Assign parameter names
        let param_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];

        // Build parameter list (heuristic: use first N vregs from entry block)
        let mut params: Vec<(String, Width)> = Vec::new();
        if let Some(entry) = func.entry_block() {
            // Look for vregs read before written (= parameters)
            let mut written: HashSet<VReg> = HashSet::new();
            let mut param_vregs: Vec<VReg> = Vec::new();
            for stmt in &entry.stmts {
                collect_reads(stmt, &mut param_vregs, &written);
                collect_writes(stmt, &mut written);
            }
            param_vregs.dedup();
            for (i, vr) in param_vregs.iter().take(6).enumerate() {
                let name = format!("param_{}", param_regs[i]);
                self.var_names.insert(*vr, name.clone());
                self.declared.insert(*vr);
                let w = Width::W64;
                self.var_types.insert(*vr, w);
                params.push((name, w));
            }
        }

        let param_str = params
            .iter()
            .map(|(n, w)| format!("{} {}", w.c_type(), n))
            .collect::<Vec<_>>()
            .join(", ");

        let ret_type = "uint64_t";
        writeln!(
            self.output,
            "{} {}({}) {{",
            ret_type,
            sanitize_name(&func.name),
            param_str
        )
        .unwrap();
        self.indent = 1;

        let analysis_ref = analysis;
        let mut emitted = HashSet::new();

        // Check if entry is a loop header → emit whole function as while(1)
        let entry_id = func.blocks.first().map(|b| b.id).unwrap_or(0);
        if analysis.loops.is_loop_header(entry_id) {
            self.emit_loop(func, analysis_ref, entry_id, None, &mut emitted);
        } else {
            self.emit_function(func, analysis_ref);
        }

        self.indent = 0;
        self.writeln("}");
        self.output.clone()
    }
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

fn collect_reads(stmt: &Stmt, reads: &mut Vec<VReg>, written: &HashSet<VReg>) {
    match stmt {
        Stmt::Assign(_, expr) => collect_expr_reads(expr, reads, written),
        Stmt::Store { addr, val, .. } => {
            collect_expr_reads(addr, reads, written);
            collect_expr_reads(val, reads, written);
        }
        Stmt::Call { func, args, .. } => {
            collect_expr_reads(func, reads, written);
            for a in args {
                collect_expr_reads(a, reads, written);
            }
        }
        Stmt::Return(Some(e)) => collect_expr_reads(e, reads, written),
        Stmt::Branch { cond, .. } => collect_expr_reads(cond, reads, written),
        _ => {}
    }
}

fn collect_expr_reads(expr: &Expr, reads: &mut Vec<VReg>, written: &HashSet<VReg>) {
    match expr {
        Expr::Reg(vr, _) => {
            if !written.contains(vr) && !reads.contains(vr) {
                reads.push(*vr);
            }
        }
        Expr::BinOp(_, l, r) => {
            collect_expr_reads(l, reads, written);
            collect_expr_reads(r, reads, written);
        }
        Expr::UnOp(_, inner) => collect_expr_reads(inner, reads, written),
        Expr::Load(addr, _) => collect_expr_reads(addr, reads, written),
        _ => {}
    }
}

fn collect_writes(stmt: &Stmt, written: &mut HashSet<VReg>) {
    match stmt {
        Stmt::Assign(dst, _) => { written.insert(*dst); }
        Stmt::Call { dst: Some(dst), .. } => { written.insert(*dst); }
        _ => {}
    }
}

/// Generate C code for all functions
pub fn generate(
    functions: &[IrFunction],
    analyses: &[FunctionAnalysis],
    symbol_names: &HashMap<u64, String>,
) -> String {
    let mut out = String::new();

    // Header
    out.push_str("/* Generated by simple-decompiler */\n");
    out.push_str("#include <stdint.h>\n");
    out.push_str("#include <stddef.h>\n\n");

    // Forward declarations
    for func in functions {
        out.push_str(&format!("uint64_t {}();\n", sanitize_name(&func.name)));
    }
    out.push('\n');

    let func_names: HashMap<u64, String> = symbol_names.clone();

    for (func, analysis) in functions.iter().zip(analyses.iter()) {
        let mut gen = CGenerator::new(func_names.clone());
        let code = gen.generate_function(func, analysis);
        out.push_str(&code);
        out.push('\n');
    }

    out
}
