//! Frontend language layer.
//!
//! This module owns the analysis of the languages that usually live in a
//! frontend codebase: TypeScript / JavaScript (incl. JSX/TSX, so React and
//! Angular both fit) and stylesheets (CSS / SCSS / Sass / Less).
//!
//! The scanner walks the filesystem and decides *which* files to hand here;
//! this module decides *how* to read them. Rust analysis stays in the scanner,
//! so each language layer is kept separate and small instead of behind one
//! generic plugin framework.
//!
//! Script analysis is AST based (via SWC). For every function-like node we
//! record its location, length, parameter count and, crucially, how each
//! parameter is used inside the body so unused parameters can be surfaced.
//! Parameter usage is a name-based reference count: it is approximate (it does
//! not resolve shadowing) but biased towards "used", so it under-reports rather
//! than falsely accusing a parameter of being unused.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use swc_common::{FileName, SourceMap, Span, sync::Lrc};
use swc_ecma_ast::*;
use swc_ecma_parser::{EsSyntax, Parser, StringInput, Syntax, TsSyntax, lexer::Lexer};
use swc_ecma_visit::{Visit, VisitWith};

use super::model::{FileSnapshot, FunctionSnapshot, ParamUsage, StylesheetSnapshot};

// --------------------------------------------------------------------------
// Public entry points
// --------------------------------------------------------------------------

/// Analyze a single TS/TSX/JS/JSX file and return one snapshot per function.
///
/// Returns an empty vector for non-script files or when the file cannot be
/// parsed (we never fail the whole review because one file is malformed).
pub fn scan_functions(file: &FileSnapshot, content: &str) -> Vec<FunctionSnapshot> {
    let Some(language) = script_language(&file.name) else {
        return Vec::new();
    };

    let cm: Lrc<SourceMap> = Default::default();
    let fm = cm.new_source_file(
        FileName::Custom(file.path.clone()).into(),
        content.to_string(),
    );
    let lexer = Lexer::new(
        syntax_for(&file.name),
        Default::default(),
        StringInput::from(&*fm),
        None,
    );
    let mut parser = Parser::new_from(lexer);
    let Ok(module) = parser.parse_module() else {
        return Vec::new();
    };

    let mut collector = Collector {
        file,
        cm: &cm,
        language,
        functions: Vec::new(),
        counter: 0,
    };
    collector.collect_module(&module);
    collector.functions
}

/// Collect lightweight observability snapshots for every stylesheet file.
pub fn scan_stylesheets(files: &[FileSnapshot]) -> Vec<StylesheetSnapshot> {
    let mut stylesheets = Vec::new();
    for file in files {
        if let Some(content) = &file.content
            && is_stylesheet_like(&file.name)
            && !file.category.is_noise()
        {
            stylesheets.push(scan_stylesheet(file, content));
        }
    }
    stylesheets
}

// --------------------------------------------------------------------------
// Language detection
// --------------------------------------------------------------------------

/// Returns the language tag for a script file, or `None` if it is not one.
fn script_language(name: &str) -> Option<&'static str> {
    match ext_of(name)? {
        "ts" | "tsx" | "d.ts" => Some("typescript"),
        "js" | "jsx" | "mjs" | "cjs" => Some("javascript"),
        _ => None,
    }
}

fn syntax_for(name: &str) -> Syntax {
    let ext = ext_of(name);
    if matches!(ext, Some("ts" | "tsx" | "d.ts")) {
        Syntax::Typescript(TsSyntax {
            tsx: matches!(ext, Some("tsx")),
            decorators: true,
            dts: name.ends_with(".d.ts"),
            no_early_errors: true,
            disallow_ambiguous_jsx_like: false,
        })
    } else {
        Syntax::Es(EsSyntax {
            jsx: matches!(ext, Some("jsx")),
            fn_bind: true,
            decorators: true,
            decorators_before_export: true,
            export_default_from: true,
            import_attributes: true,
            allow_super_outside_method: true,
            allow_return_outside_function: true,
            auto_accessors: true,
            explicit_resource_management: true,
        })
    }
}

fn ext_of(name: &str) -> Option<&str> {
    if name.ends_with(".d.ts") {
        return Some("d.ts");
    }
    Path::new(name).extension().and_then(|ext| ext.to_str())
}

fn is_stylesheet_like(name: &str) -> bool {
    matches!(ext_of(name), Some("css" | "scss" | "sass" | "less"))
}

// --------------------------------------------------------------------------
// Function discovery
// --------------------------------------------------------------------------

/// Walks the AST and records every function-like node it finds.
///
/// Holding the shared context (`file`, source map, language) here keeps the
/// traversal methods readable instead of threading four arguments through
/// every recursive call.
struct Collector<'a> {
    file: &'a FileSnapshot,
    cm: &'a Lrc<SourceMap>,
    language: &'static str,
    functions: Vec<FunctionSnapshot>,
    counter: usize,
}

/// The body a function-like node carries, used for parameter usage counting
/// and complexity. Holds only references, so it is cheap to copy.
#[derive(Clone, Copy)]
enum BodyRef<'a> {
    Block(&'a BlockStmt),
    Expr(&'a Expr),
}

impl<'a> Collector<'a> {
    fn collect_module(&mut self, module: &Module) {
        for item in &module.body {
            match item {
                ModuleItem::Stmt(stmt) => self.collect_stmt(stmt),
                ModuleItem::ModuleDecl(decl) => self.collect_module_decl(decl),
            }
        }
    }

    fn collect_module_decl(&mut self, decl: &ModuleDecl) {
        match decl {
            ModuleDecl::ExportDecl(export) => self.collect_decl(&export.decl),
            ModuleDecl::ExportDefaultDecl(export) => self.collect_default_decl(&export.decl),
            ModuleDecl::ExportDefaultExpr(export) => self.collect_expr(&export.expr, None),
            _ => {}
        }
    }

    fn collect_default_decl(&mut self, decl: &DefaultDecl) {
        match decl {
            DefaultDecl::Fn(fn_expr) => {
                let name = fn_expr
                    .ident
                    .as_ref()
                    .map(ident_name)
                    .unwrap_or_else(|| "default_function".to_string());
                self.record_function(name, &fn_expr.function);
            }
            DefaultDecl::Class(class_expr) => {
                let name = class_expr
                    .ident
                    .as_ref()
                    .map(ident_name)
                    .unwrap_or_else(|| "default_class".to_string());
                self.collect_class(&class_expr.class, &name);
            }
            DefaultDecl::TsInterfaceDecl(_) => {}
        }
    }

    fn collect_stmts(&mut self, stmts: &[Stmt]) {
        for stmt in stmts {
            self.collect_stmt(stmt);
        }
    }

    fn collect_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Decl(decl) => self.collect_decl(decl),
            Stmt::Expr(expr_stmt) => self.collect_expr(&expr_stmt.expr, None),
            Stmt::Block(block) => self.collect_stmts(&block.stmts),
            Stmt::If(if_stmt) => {
                self.collect_stmt(&if_stmt.cons);
                if let Some(alt) = &if_stmt.alt {
                    self.collect_stmt(alt);
                }
            }
            Stmt::For(for_stmt) => {
                if let Some(VarDeclOrExpr::VarDecl(var_decl)) = &for_stmt.init {
                    self.collect_var_decl(var_decl);
                }
                self.collect_stmt(&for_stmt.body);
            }
            Stmt::ForIn(for_in) => {
                if let ForHead::VarDecl(var_decl) = &for_in.left {
                    self.collect_var_decl(var_decl);
                }
                self.collect_stmt(&for_in.body);
            }
            Stmt::ForOf(for_of) => {
                if let ForHead::VarDecl(var_decl) = &for_of.left {
                    self.collect_var_decl(var_decl);
                }
                self.collect_stmt(&for_of.body);
            }
            Stmt::While(while_stmt) => self.collect_stmt(&while_stmt.body),
            Stmt::DoWhile(do_stmt) => self.collect_stmt(&do_stmt.body),
            Stmt::Labeled(labeled) => self.collect_stmt(&labeled.body),
            Stmt::Return(ret) => {
                if let Some(arg) = &ret.arg {
                    self.collect_expr(arg, None);
                }
            }
            Stmt::Throw(throw) => self.collect_expr(&throw.arg, None),
            Stmt::Switch(switch) => {
                for case in &switch.cases {
                    self.collect_stmts(&case.cons);
                }
            }
            Stmt::Try(try_stmt) => {
                self.collect_stmts(&try_stmt.block.stmts);
                if let Some(handler) = &try_stmt.handler {
                    self.collect_stmts(&handler.body.stmts);
                }
                if let Some(finalizer) = &try_stmt.finalizer {
                    self.collect_stmts(&finalizer.stmts);
                }
            }
            _ => {}
        }
    }

    fn collect_decl(&mut self, decl: &Decl) {
        match decl {
            Decl::Fn(fn_decl) => {
                self.record_function(ident_name(&fn_decl.ident), &fn_decl.function)
            }
            Decl::Class(class_decl) => {
                self.collect_class(&class_decl.class, &ident_name(&class_decl.ident))
            }
            Decl::Var(var_decl) => self.collect_var_decl(var_decl),
            _ => {}
        }
    }

    fn collect_var_decl(&mut self, var_decl: &VarDecl) {
        for declarator in &var_decl.decls {
            if let Some(init) = &declarator.init {
                let name = pattern_name(&declarator.name);
                self.collect_expr(init, name);
            }
        }
    }

    fn collect_class(&mut self, class: &Class, class_name: &str) {
        for member in &class.body {
            match member {
                ClassMember::Constructor(ctor) => {
                    self.record_constructor(format!("{class_name}::constructor"), ctor)
                }
                ClassMember::Method(method) => {
                    let name = method_name(&method.key).unwrap_or_else(|| "method".to_string());
                    self.record_function(format!("{class_name}::{name}"), &method.function);
                }
                ClassMember::PrivateMethod(method) => {
                    self.record_function(format!("{class_name}::private_method"), &method.function)
                }
                ClassMember::ClassProp(prop) => {
                    if let Some(value) = &prop.value {
                        let name = method_name(&prop.key).unwrap_or_else(|| "property".to_string());
                        self.collect_expr(value, Some(format!("{class_name}::{name}")));
                    }
                }
                ClassMember::PrivateProp(prop) => {
                    if let Some(value) = &prop.value {
                        self.collect_expr(value, Some(format!("{class_name}::private_property")));
                    }
                }
                _ => {}
            }
        }
    }

    fn collect_expr(&mut self, expr: &Expr, inferred_name: Option<String>) {
        match expr {
            Expr::Fn(fn_expr) => {
                let name = fn_expr
                    .ident
                    .as_ref()
                    .map(ident_name)
                    .or(inferred_name)
                    .unwrap_or_else(|| "function".to_string());
                self.record_function(name, &fn_expr.function);
            }
            Expr::Arrow(arrow) => {
                let name = inferred_name.unwrap_or_else(|| "arrow_function".to_string());
                self.record_arrow(name, arrow);
            }
            Expr::Class(class_expr) => {
                let name = class_expr
                    .ident
                    .as_ref()
                    .map(ident_name)
                    .or(inferred_name)
                    .unwrap_or_else(|| "class".to_string());
                self.collect_class(&class_expr.class, &name);
            }
            Expr::JSXElement(element) => self.collect_jsx_element(element),
            Expr::JSXFragment(fragment) => self.collect_jsx_fragment(fragment),
            Expr::Call(call) => {
                if let Callee::Expr(callee) = &call.callee {
                    self.collect_expr(callee, None);
                }
                // Label callback arguments after the call, so e.g. a `describe`
                // / `it` / `useEffect` callback is identifiable instead of just
                // "arrow_function".
                let label = call_label(call);
                for arg in &call.args {
                    self.collect_expr(&arg.expr, label.clone());
                }
            }
            Expr::New(new_expr) => {
                self.collect_expr(&new_expr.callee, None);
                if let Some(args) = &new_expr.args {
                    for arg in args {
                        self.collect_expr(&arg.expr, None);
                    }
                }
            }
            Expr::Object(object) => self.collect_object(object, inferred_name),
            Expr::Array(array) => {
                for item in array.elems.iter().flatten() {
                    self.collect_expr(&item.expr, None);
                }
            }
            Expr::Cond(cond) => {
                self.collect_expr(&cond.test, None);
                self.collect_expr(&cond.cons, None);
                self.collect_expr(&cond.alt, None);
            }
            Expr::Paren(paren) => self.collect_expr(&paren.expr, inferred_name),
            Expr::Assign(assign) => self.collect_expr(&assign.right, inferred_name),
            Expr::Seq(seq) => {
                for expr in &seq.exprs {
                    self.collect_expr(expr, None);
                }
            }
            Expr::Unary(unary) => self.collect_expr(&unary.arg, None),
            Expr::Bin(bin) => {
                self.collect_expr(&bin.left, None);
                self.collect_expr(&bin.right, None);
            }
            Expr::Member(member) => {
                self.collect_expr(&member.obj, None);
                if let MemberProp::Computed(computed) = &member.prop {
                    self.collect_expr(&computed.expr, None);
                }
            }
            Expr::Await(await_expr) => self.collect_expr(&await_expr.arg, None),
            Expr::Yield(yield_expr) => {
                if let Some(arg) = &yield_expr.arg {
                    self.collect_expr(arg, None);
                }
            }
            Expr::Tpl(tpl) => {
                for expr in &tpl.exprs {
                    self.collect_expr(expr, None);
                }
            }
            Expr::TsAs(ts_as) => self.collect_expr(&ts_as.expr, inferred_name),
            Expr::TsTypeAssertion(assertion) => self.collect_expr(&assertion.expr, inferred_name),
            Expr::TsNonNull(non_null) => self.collect_expr(&non_null.expr, inferred_name),
            Expr::TsInstantiation(inst) => self.collect_expr(&inst.expr, inferred_name),
            _ => {}
        }
    }

    fn collect_object(&mut self, object: &ObjectLit, inferred_name: Option<String>) {
        for prop in &object.props {
            match prop {
                PropOrSpread::Prop(prop) => match &**prop {
                    Prop::Method(method) => {
                        let name = method_name(&method.key)
                            .or_else(|| inferred_name.clone())
                            .unwrap_or_else(|| "method".to_string());
                        self.record_function(name, &method.function);
                    }
                    Prop::KeyValue(kv) => {
                        let name = method_name(&kv.key).or_else(|| inferred_name.clone());
                        self.collect_expr(&kv.value, name);
                    }
                    _ => {}
                },
                PropOrSpread::Spread(spread) => self.collect_expr(&spread.expr, None),
            }
        }
    }

    // ---- JSX: only traverse for nested functions (handlers); a JSX element
    // is not itself a function, so it is never recorded as one. ----

    fn collect_jsx_element(&mut self, element: &JSXElement) {
        for attr in &element.opening.attrs {
            match attr {
                JSXAttrOrSpread::JSXAttr(attr) => match &attr.value {
                    Some(JSXAttrValue::JSXExprContainer(container)) => {
                        if let JSXExpr::Expr(expr) = &container.expr {
                            self.collect_expr(expr, None);
                        }
                    }
                    Some(JSXAttrValue::JSXElement(child)) => self.collect_jsx_element(child),
                    Some(JSXAttrValue::JSXFragment(fragment)) => {
                        self.collect_jsx_fragment(fragment)
                    }
                    _ => {}
                },
                JSXAttrOrSpread::SpreadElement(spread) => self.collect_expr(&spread.expr, None),
            }
        }
        for child in &element.children {
            self.collect_jsx_child(child);
        }
    }

    fn collect_jsx_fragment(&mut self, fragment: &JSXFragment) {
        for child in &fragment.children {
            self.collect_jsx_child(child);
        }
    }

    fn collect_jsx_child(&mut self, child: &JSXElementChild) {
        match child {
            JSXElementChild::JSXExprContainer(container) => {
                if let JSXExpr::Expr(expr) = &container.expr {
                    self.collect_expr(expr, None);
                }
            }
            JSXElementChild::JSXSpreadChild(spread) => self.collect_expr(&spread.expr, None),
            JSXElementChild::JSXElement(element) => self.collect_jsx_element(element),
            JSXElementChild::JSXFragment(fragment) => self.collect_jsx_fragment(fragment),
            JSXElementChild::JSXText(_) => {}
        }
    }

    // ---- Recording function-like nodes ----

    fn record_function(&mut self, name: String, function: &Function) {
        let pats: Vec<&Pat> = function.params.iter().map(|param| &param.pat).collect();
        let body = function.body.as_ref().map(BodyRef::Block);
        let (params, unused) = analyze_params(&pats, body);
        let (cyclomatic, max_nesting) = complexity_of(body);
        self.push(
            name,
            function.span,
            function.params.len(),
            params,
            unused,
            cyclomatic,
            max_nesting,
        );
        if let Some(body) = &function.body {
            self.collect_stmts(&body.stmts);
        }
    }

    fn record_arrow(&mut self, name: String, arrow: &ArrowExpr) {
        let pats: Vec<&Pat> = arrow.params.iter().collect();
        let body = match &*arrow.body {
            BlockStmtOrExpr::BlockStmt(block) => BodyRef::Block(block),
            BlockStmtOrExpr::Expr(expr) => BodyRef::Expr(expr),
        };
        let (params, unused) = analyze_params(&pats, Some(body));
        let (cyclomatic, max_nesting) = complexity_of(Some(body));
        self.push(
            name,
            arrow.span,
            arrow.params.len(),
            params,
            unused,
            cyclomatic,
            max_nesting,
        );
        match &*arrow.body {
            BlockStmtOrExpr::BlockStmt(block) => self.collect_stmts(&block.stmts),
            BlockStmtOrExpr::Expr(expr) => self.collect_expr(expr, None),
        }
    }

    fn record_constructor(&mut self, name: String, ctor: &Constructor) {
        // TS parameter properties (`constructor(private x: T)`) are class fields
        // accessed via `this.x`, so they are counted but excluded from usage
        // analysis to avoid false "unused" reports.
        let pats: Vec<&Pat> = ctor
            .params
            .iter()
            .filter_map(|param| match param {
                ParamOrTsParamProp::Param(param) => Some(&param.pat),
                ParamOrTsParamProp::TsParamProp(_) => None,
            })
            .collect();
        let body = ctor.body.as_ref().map(BodyRef::Block);
        let (params, unused) = analyze_params(&pats, body);
        let (cyclomatic, max_nesting) = complexity_of(body);
        self.push(
            name,
            ctor.span,
            ctor.params.len(),
            params,
            unused,
            cyclomatic,
            max_nesting,
        );
        if let Some(body) = &ctor.body {
            self.collect_stmts(&body.stmts);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        name: String,
        span: Span,
        param_count: usize,
        params: Vec<ParamUsage>,
        unused_params: Vec<String>,
        cyclomatic: usize,
        max_nesting: usize,
    ) {
        let lo = self.cm.lookup_char_pos(span.lo());
        let hi = self.cm.lookup_char_pos(span.hi());
        let start_line = lo.line;
        let end_line = hi.line.max(start_line);
        let lines = end_line.saturating_sub(start_line).max(1);
        self.counter += 1;
        let name = if name.is_empty() {
            format!("function_{}", self.counter)
        } else {
            name
        };
        self.functions.push(FunctionSnapshot {
            file: self.file.path.clone(),
            name,
            language: self.language,
            start_line,
            end_line,
            lines,
            param_count,
            params,
            unused_params,
            cyclomatic,
            max_nesting,
            references: 0,
            referenced_by: Vec::new(),
        });
    }
}

// --------------------------------------------------------------------------
// Parameter usage analysis
// --------------------------------------------------------------------------

/// Builds per-binding usage for a function's parameters.
///
/// `pats` are the analyzable parameter patterns (destructured params expand to
/// several bindings). The reference count covers the body plus any default
/// value expressions, so a parameter used only inside another parameter's
/// default still counts as used.
fn analyze_params(pats: &[&Pat], body: Option<BodyRef>) -> (Vec<ParamUsage>, Vec<String>) {
    let mut names = Vec::new();
    let mut defaults: Vec<&Expr> = Vec::new();
    for pat in pats {
        collect_bindings(pat, &mut names, &mut defaults);
    }
    if names.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let targets: HashSet<String> = names.iter().cloned().collect();
    let mut counter = RefCounter {
        targets: &targets,
        counts: HashMap::new(),
    };
    for expr in &defaults {
        expr.visit_with(&mut counter);
    }
    match body {
        Some(BodyRef::Block(block)) => block.visit_with(&mut counter),
        Some(BodyRef::Expr(expr)) => expr.visit_with(&mut counter),
        None => {}
    }

    let mut seen = HashSet::new();
    let mut params = Vec::new();
    for name in names {
        if !seen.insert(name.clone()) {
            continue;
        }
        let references = counter.counts.get(&name).copied().unwrap_or(0);
        params.push(ParamUsage {
            references,
            used: references > 0,
            name,
        });
    }
    // A leading underscore is the universal "intentionally unused" marker, so
    // such parameters are never reported as unused.
    let unused = params
        .iter()
        .filter(|param| !param.used && !param.name.starts_with('_'))
        .map(|param| param.name.clone())
        .collect();
    (params, unused)
}

/// Flattens a parameter pattern into its binding names, collecting any default
/// value expressions encountered along the way.
fn collect_bindings<'a>(pat: &'a Pat, names: &mut Vec<String>, defaults: &mut Vec<&'a Expr>) {
    match pat {
        Pat::Ident(binding) => names.push(binding.id.sym.to_string()),
        Pat::Assign(assign) => {
            defaults.push(assign.right.as_ref());
            collect_bindings(&assign.left, names, defaults);
        }
        Pat::Rest(rest) => collect_bindings(&rest.arg, names, defaults),
        Pat::Array(array) => {
            for elem in array.elems.iter().flatten() {
                collect_bindings(elem, names, defaults);
            }
        }
        Pat::Object(object) => {
            for prop in &object.props {
                match prop {
                    ObjectPatProp::KeyValue(kv) => collect_bindings(&kv.value, names, defaults),
                    ObjectPatProp::Assign(assign) => {
                        names.push(assign.key.id.sym.to_string());
                        if let Some(value) = &assign.value {
                            defaults.push(value.as_ref());
                        }
                    }
                    ObjectPatProp::Rest(rest) => collect_bindings(&rest.arg, names, defaults),
                }
            }
        }
        _ => {}
    }
}

/// Counts identifier reads whose symbol matches one of the target parameter
/// names. Member property names (`obj.x`) use `IdentName`, not `Ident`, so they
/// are never miscounted as parameter references.
struct RefCounter<'a> {
    targets: &'a HashSet<String>,
    counts: HashMap<String, usize>,
}

impl Visit for RefCounter<'_> {
    fn visit_ident(&mut self, ident: &Ident) {
        let symbol = ident.sym.as_str();
        if self.targets.contains(symbol) {
            *self.counts.entry(symbol.to_string()).or_insert(0) += 1;
        }
    }
}

// --------------------------------------------------------------------------
// Complexity (cyclomatic + max nesting)
// --------------------------------------------------------------------------

/// Cyclomatic complexity (`1 + decision points`) and max control-flow nesting
/// for one function body. Decision points: if / else-if / loops / switch cases
/// / catch / ternary (boolean operators are intentionally not counted). Nested
/// function bodies are excluded — each function is measured on its own.
fn complexity_of(body: Option<BodyRef>) -> (usize, usize) {
    let mut visitor = ComplexityVisitor::default();
    match body {
        Some(BodyRef::Block(block)) => block.visit_with(&mut visitor),
        Some(BodyRef::Expr(expr)) => expr.visit_with(&mut visitor),
        None => {}
    }
    (visitor.decisions + 1, visitor.max_depth)
}

#[derive(Default)]
struct ComplexityVisitor {
    decisions: usize,
    depth: usize,
    max_depth: usize,
}

impl ComplexityVisitor {
    fn nested<F: FnOnce(&mut Self)>(&mut self, body: F) {
        self.depth += 1;
        self.max_depth = self.max_depth.max(self.depth);
        body(self);
        self.depth -= 1;
    }
}

impl Visit for ComplexityVisitor {
    fn visit_if_stmt(&mut self, node: &IfStmt) {
        self.decisions += 1;
        node.test.visit_with(self);
        self.nested(|v| node.cons.visit_with(v));
        if let Some(alt) = &node.alt {
            match &**alt {
                // `else if` is a flat chain, not deeper nesting.
                Stmt::If(else_if) => self.visit_if_stmt(else_if),
                other => self.nested(|v| other.visit_with(v)),
            }
        }
    }

    fn visit_for_stmt(&mut self, node: &ForStmt) {
        self.decisions += 1;
        self.nested(|v| node.visit_children_with(v));
    }

    fn visit_for_in_stmt(&mut self, node: &ForInStmt) {
        self.decisions += 1;
        self.nested(|v| node.visit_children_with(v));
    }

    fn visit_for_of_stmt(&mut self, node: &ForOfStmt) {
        self.decisions += 1;
        self.nested(|v| node.visit_children_with(v));
    }

    fn visit_while_stmt(&mut self, node: &WhileStmt) {
        self.decisions += 1;
        self.nested(|v| node.visit_children_with(v));
    }

    fn visit_do_while_stmt(&mut self, node: &DoWhileStmt) {
        self.decisions += 1;
        self.nested(|v| node.visit_children_with(v));
    }

    fn visit_switch_stmt(&mut self, node: &SwitchStmt) {
        self.nested(|v| node.visit_children_with(v));
    }

    fn visit_switch_case(&mut self, node: &SwitchCase) {
        if node.test.is_some() {
            self.decisions += 1;
        }
        node.visit_children_with(self);
    }

    fn visit_try_stmt(&mut self, node: &TryStmt) {
        self.nested(|v| node.visit_children_with(v));
    }

    fn visit_catch_clause(&mut self, node: &CatchClause) {
        self.decisions += 1;
        node.visit_children_with(self);
    }

    fn visit_cond_expr(&mut self, node: &CondExpr) {
        self.decisions += 1;
        node.visit_children_with(self);
    }

    // Each function is measured on its own — do not descend into nested ones.
    fn visit_function(&mut self, _: &Function) {}
    fn visit_arrow_expr(&mut self, _: &ArrowExpr) {}
}

// --------------------------------------------------------------------------
// Shared AST helpers
// --------------------------------------------------------------------------

fn ident_name(ident: &Ident) -> String {
    ident.sym.to_string()
}

/// Best-effort name for a value bound to a pattern (used to label arrow/fn
/// expressions assigned to variables, e.g. `const App = () => ...`).
fn pattern_name(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(binding) => Some(binding.id.sym.to_string()),
        Pat::Assign(assign) => pattern_name(&assign.left),
        Pat::Rest(rest) => pattern_name(&rest.arg),
        Pat::Array(_) => Some("array_binding".to_string()),
        Pat::Object(_) => Some("object_binding".to_string()),
        _ => None,
    }
}

fn method_name(key: &PropName) -> Option<String> {
    match key {
        PropName::Ident(ident) => Some(ident.sym.to_string()),
        PropName::Str(string) => Some(string.value.to_string_lossy().to_string()),
        PropName::Num(num) => Some(num.value.to_string()),
        PropName::BigInt(big) => Some(big.value.to_string()),
        PropName::Computed(_) => None,
    }
}

/// A display label for a function passed as a call argument, derived from the
/// callee and (if present) its first string argument — e.g. `describe("auth")`,
/// `it("returns 200")`, `useEffect`, `map`.
fn call_label(call: &CallExpr) -> Option<String> {
    let callee = match &call.callee {
        Callee::Expr(expr) => callee_name(expr)?,
        _ => return None,
    };
    // Always include parentheses so the label reads as an anonymous callback
    // (`map(…)`, `describe("x")`) and `referenceable_fn_name` excludes it from
    // reference counting / dead-code detection — it is not a named definition.
    match first_string_arg(call) {
        Some(text) => Some(format!("{callee}(\"{text}\")")),
        None => Some(format!("{callee}(…)")),
    }
}

fn callee_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Ident(ident) => Some(ident.sym.to_string()),
        Expr::Member(member) => match &member.prop {
            MemberProp::Ident(ident) => Some(ident.sym.to_string()),
            _ => None,
        },
        _ => None,
    }
}

fn first_string_arg(call: &CallExpr) -> Option<String> {
    call.args.iter().find_map(|arg| match &*arg.expr {
        Expr::Lit(Lit::Str(string)) => Some(truncate(&string.value.to_string_lossy(), 40)),
        _ => None,
    })
}

fn truncate(text: &str, max: usize) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= max {
        return trimmed.to_string();
    }
    let cut: String = trimmed.chars().take(max).collect();
    format!("{cut}…")
}

// --------------------------------------------------------------------------
// Stylesheet observability (lightweight, line based)
// --------------------------------------------------------------------------

/// Reads a stylesheet with a single line scan. This is deliberately not a full
/// CSS parser: it tracks brace depth to approximate rules, nesting, the largest
/// rule block and repeated selectors — enough to be useful without the cost of
/// a real CSS AST.
fn scan_stylesheet(file: &FileSnapshot, content: &str) -> StylesheetSnapshot {
    let mut rule_count = 0usize;
    let mut selector_count = 0usize;
    let mut declaration_count = 0usize;
    let mut variable_count = 0usize;
    let mut import_count = 0usize;
    let mut max_nesting_depth = 0usize;
    let mut largest_rule_lines = 0usize;
    let mut brace_depth = 0usize;
    let mut block_starts: Vec<usize> = Vec::new();
    let mut selector_occurrences: HashMap<String, usize> = HashMap::new();

    for (idx, raw_line) in content.lines().enumerate() {
        let line = strip_line_comment(raw_line).trim();
        if line.is_empty() || line.starts_with("/*") || line.starts_with('*') {
            continue;
        }

        let is_at_rule = line.starts_with('@');
        if is_at_rule
            && (line.starts_with("@import")
                || line.starts_with("@use")
                || line.starts_with("@forward"))
        {
            import_count += 1;
        }
        if !is_at_rule && (line.starts_with('$') || line.starts_with("--")) && line.contains(':') {
            variable_count += 1;
        }

        let opens = line.matches('{').count();
        let closes = line.matches('}').count();

        // Count property declarations by their terminating `;`. This also
        // captures declarations written inline with their selector, e.g.
        // `.a { color: red; }`. Variables and at-rules are excluded.
        if !is_at_rule && !line.starts_with('$') && !line.starts_with("--") {
            declaration_count += line.matches(';').count();
        }

        if opens > 0 {
            if !is_at_rule && let Some(selector) = line.split('{').next() {
                let selector = selector.trim();
                if !selector.is_empty() {
                    selector_count += 1;
                    *selector_occurrences
                        .entry(normalize_selector(selector))
                        .or_insert(0) += 1;
                }
            }
            rule_count += opens;
            for _ in 0..opens {
                block_starts.push(idx);
                brace_depth += 1;
                max_nesting_depth = max_nesting_depth.max(brace_depth.saturating_sub(1));
            }
        }

        for _ in 0..closes {
            if let Some(start) = block_starts.pop() {
                largest_rule_lines = largest_rule_lines.max(idx.saturating_sub(start) + 1);
            }
            brace_depth = brace_depth.saturating_sub(1);
        }
    }

    let duplicate_selector_count = selector_occurrences
        .values()
        .filter(|&&count| count > 1)
        .count();

    StylesheetSnapshot {
        file: file.path.clone(),
        name: file.name.clone(),
        lines: file.lines,
        bytes: file.bytes,
        rule_count,
        selector_count,
        declaration_count,
        variable_count,
        import_count,
        max_nesting_depth,
        largest_rule_lines,
        duplicate_selector_count,
    }
}

fn strip_line_comment(line: &str) -> &str {
    match line.find("//") {
        Some(pos) => &line[..pos],
        None => line,
    }
}

fn normalize_selector(selector: &str) -> String {
    selector.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::classify::FileCategory;

    fn file(name: &str, content: &str) -> FileSnapshot {
        FileSnapshot {
            path: name.to_string(),
            name: name.to_string(),
            lines: content.lines().count().max(1),
            bytes: content.len() as u64,
            depth: 1,
            category: FileCategory::Source,
            content: Some(content.to_string()),
        }
    }

    fn function<'a>(functions: &'a [FunctionSnapshot], name: &str) -> &'a FunctionSnapshot {
        functions
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| {
                let found: Vec<&String> = functions.iter().map(|f| &f.name).collect();
                panic!("function `{name}` not found; collected: {found:?}");
            })
    }

    #[test]
    fn flags_unused_parameter() {
        let src =
            "export function greet(name: string, salutation: number) { return `hi ${name}`; }";
        let functions = scan_functions(&file("greet.ts", src), src);
        let greet = function(&functions, "greet");
        assert_eq!(greet.language, "typescript");
        assert_eq!(greet.param_count, 2);
        assert_eq!(greet.unused_params, vec!["salutation".to_string()]);
        let name = greet.params.iter().find(|p| p.name == "name").unwrap();
        assert!(name.used && name.references >= 1);
    }

    #[test]
    fn counts_parameter_references() {
        let src = "function f(x: number) { return x + x + x; }";
        let functions = scan_functions(&file("f.ts", src), src);
        let x = function(&functions, "f")
            .params
            .iter()
            .find(|p| p.name == "x")
            .unwrap();
        assert_eq!(x.references, 3);
    }

    #[test]
    fn arrow_parameters_all_used() {
        let src = "const add = (a: number, b: number) => a + b;";
        let functions = scan_functions(&file("add.ts", src), src);
        let add = function(&functions, "add");
        assert_eq!(add.param_count, 2);
        assert!(add.unused_params.is_empty());
    }

    #[test]
    fn tracks_destructured_bindings() {
        let src = "function Card({ title, subtitle }: Props) { return title; }";
        let functions = scan_functions(&file("Card.tsx", src), src);
        let card = function(&functions, "Card");
        assert!(card.unused_params.contains(&"subtitle".to_string()));
        assert!(!card.unused_params.contains(&"title".to_string()));
    }

    #[test]
    fn finds_nested_and_jsx_handler_functions() {
        let src = r#"
            export function Panel(props: Props) {
                const onClick = (event: MouseEvent) => props.onSelect(event);
                return <button onClick={onClick} />;
            }
        "#;
        let functions = scan_functions(&file("Panel.tsx", src), src);
        function(&functions, "Panel");
        function(&functions, "onClick");
    }

    #[test]
    fn ignores_non_script_files() {
        let src = "fn main() {}";
        assert!(scan_functions(&file("main.rs", src), src).is_empty());
    }

    #[test]
    fn stylesheet_metrics_are_collected() {
        let css = ".a { color: red; }\n.a { color: blue; }\n.b {\n  margin: 0;\n  padding: 0;\n}\n";
        let sheets = scan_stylesheets(std::slice::from_ref(&file("styles.css", css)));
        assert_eq!(sheets.len(), 1);
        let sheet = &sheets[0];
        assert_eq!(sheet.rule_count, 3);
        assert!(sheet.declaration_count >= 3);
        assert_eq!(sheet.duplicate_selector_count, 1);
        assert!(sheet.largest_rule_lines >= 3);
    }

    #[test]
    fn underscore_params_are_not_flagged_unused() {
        let src = "const f = (_evt: Event, value: number) => value;";
        let functions = scan_functions(&file("f.ts", src), src);
        let f = function(&functions, "f");
        assert!(f.unused_params.is_empty());
    }

    #[test]
    fn callback_args_are_labeled_by_call_context() {
        let src = r#"describe("auth flow", () => { it("returns ok", () => { check(); }); });"#;
        let functions = scan_functions(&file("auth.test.ts", src), src);
        assert!(
            functions
                .iter()
                .any(|f| f.name == "describe(\"auth flow\")")
        );
        assert!(functions.iter().any(|f| f.name == "it(\"returns ok\")"));
    }

    #[test]
    fn computes_cyclomatic_and_nesting() {
        // if (+1) + for (+1) + ternary (+1) → cyclomatic 4; if>for nests to 2.
        let src = "function f(x: number) { if (x > 0) { for (let i = 0; i < x; i++) {} } return x > 1 ? 1 : 2; }";
        let functions = scan_functions(&file("f.ts", src), src);
        let f = function(&functions, "f");
        assert_eq!(f.cyclomatic, 4);
        assert!(f.max_nesting >= 2);
    }

    #[test]
    fn complexity_excludes_nested_functions() {
        // The inner arrow's `if` must not count toward `outer`.
        let src = "function outer() { const cb = (n: number) => { if (n > 0) { return 1; } return 0; }; return cb; }";
        let functions = scan_functions(&file("o.ts", src), src);
        let outer = function(&functions, "outer");
        assert_eq!(outer.cyclomatic, 1);
    }
}
