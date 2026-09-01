use crate::parser::{
    parse_all_functions, parse_state_vars, ParsedExpr, ParsedFunction, ParsedStatement,
};
use crate::StaticAnalysisError;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalCall {
    pub target: String,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossTxDfg {
    #[serde(default)]
    pub address: String,
    pub call_edges: Vec<(String, String)>,
    pub storage_writes: HashMap<String, Vec<String>>,
    pub storage_reads: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub external_calls: HashMap<String, Vec<ExternalCall>>,
    #[serde(default)]
    pub internal_calls: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub entry_points: Vec<String>,
}

fn push_unique(map: &mut HashMap<String, Vec<String>>, key: &str, val: String) {
    let entry = map.entry(key.to_string()).or_default();
    if !entry.contains(&val) {
        entry.push(val);
    }
}

fn push_unique_vec(vec: &mut Vec<String>, val: String) {
    if !vec.contains(&val) {
        vec.push(val);
    }
}

const ACCOUNT_FIELDS: &[&str] = &[
    "lastAccruedWeights",
    "balances",
    "debt",
    "depositedTokens",
    "withdrawAllowances",
    "mintAllowances",
];
const YIELD_TOKEN_FIELDS: &[&str] = &[
    "accruedWeight",
    "totalShares",
    "activeBalance",
    "harvestableBalance",
    "distributedCredit",
    "enabled",
];

fn canonical_field_slot(member: &str) -> Option<String> {
    if ACCOUNT_FIELDS.contains(&member) {
        return Some(format!("_accounts.{}", member));
    }
    if YIELD_TOKEN_FIELDS.contains(&member) {
        return Some(format!("_yieldTokens.{}", member));
    }
    None
}

fn storage_slot_from_expr(expr: &ParsedExpr, state_vars: &HashSet<String>) -> Option<String> {
    match expr {
        ParsedExpr::Variable { name } if state_vars.contains(name) => Some(name.clone()),
        ParsedExpr::MemberAccess { base, member } => {
            if let Some(slot) = canonical_field_slot(member) {
                return Some(slot);
            }
            let base_slot = storage_slot_from_expr(base, state_vars)?;
            Some(format!("{}.{}", base_slot, member))
        }
        ParsedExpr::IndexAccess { base, .. } => storage_slot_from_expr(base, state_vars),
        _ => None,
    }
}

fn collect_storage_reads_expr(
    expr: &ParsedExpr,
    state_vars: &HashSet<String>,
    out: &mut Vec<String>,
) {
    match expr {
        ParsedExpr::Variable { name } if state_vars.contains(name) => {
            push_unique_vec(out, name.clone());
        }
        ParsedExpr::MemberAccess { base, member } => {
            if let Some(slot) = canonical_field_slot(member) {
                push_unique_vec(out, slot);
            }
            collect_storage_reads_expr(base, state_vars, out);
            if let Some(base_name) = root_state_var(base, state_vars) {
                push_unique_vec(out, format!("{}.{}", base_name, member));
            }
        }
        ParsedExpr::IndexAccess { base, index } => {
            collect_storage_reads_expr(base, state_vars, out);
            collect_storage_reads_expr(index, state_vars, out);
        }
        ParsedExpr::FunctionCall { callee, args } => {
            collect_storage_reads_expr(callee, state_vars, out);
            for arg in args {
                collect_storage_reads_expr(arg, state_vars, out);
            }
        }
        ParsedExpr::BinaryOp { left, right, .. } => {
            collect_storage_reads_expr(left, state_vars, out);
            collect_storage_reads_expr(right, state_vars, out);
        }
        ParsedExpr::UnaryOp { operand, .. } => collect_storage_reads_expr(operand, state_vars, out),
        _ => {}
    }
}

fn root_state_var(expr: &ParsedExpr, state_vars: &HashSet<String>) -> Option<String> {
    match expr {
        ParsedExpr::Variable { name } if state_vars.contains(name) => Some(name.clone()),
        ParsedExpr::IndexAccess { base, .. } | ParsedExpr::MemberAccess { base, .. } => {
            root_state_var(base, state_vars)
        }
        _ => None,
    }
}

fn expr_to_name(expr: &ParsedExpr) -> Option<String> {
    match expr {
        ParsedExpr::Variable { name } => Some(name.clone()),
        ParsedExpr::MemberAccess { base, member } => {
            expr_to_name(base).map(|b| format!("{}.{}", b, member))
        }
        _ => None,
    }
}

fn external_call_from_expr(expr: &ParsedExpr) -> Option<ExternalCall> {
    let ParsedExpr::FunctionCall { callee, .. } = expr else {
        return None;
    };
    match callee.as_ref() {
        ParsedExpr::MemberAccess { base, member } => {
            let target = expr_to_name(base).unwrap_or_else(|| "external".into());
            Some(ExternalCall {
                target,
                method: member.clone(),
            })
        }
        ParsedExpr::Variable { name } if matches!(name.as_str(), "call" | "delegatecall" | "staticcall") => {
            Some(ExternalCall {
                target: "address".into(),
                method: name.clone(),
            })
        }
        _ => Some(ExternalCall {
            target: "external".into(),
            method: format!("{:?}", callee),
        }),
    }
}

fn callee_name(expr: &ParsedExpr) -> Option<String> {
    match expr {
        ParsedExpr::FunctionCall { callee, .. } => match callee.as_ref() {
            ParsedExpr::Variable { name } => Some(name.clone()),
            ParsedExpr::MemberAccess { member, .. } => Some(member.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn record_external_call(dfg: &mut CrossTxDfg, func: &str, call: ExternalCall) {
    let entry = dfg.external_calls.entry(func.to_string()).or_default();
    if !entry
        .iter()
        .any(|e| e.target == call.target && e.method == call.method)
    {
        entry.push(call.clone());
        dfg.call_edges
            .push((func.to_string(), format!("{}::{}", call.target, call.method)));
    }
}

fn record_internal_call(dfg: &mut CrossTxDfg, func: &str, callee: &str) {
    if matches!(callee, "call" | "delegatecall" | "staticcall") {
        return;
    }
    push_unique(&mut dfg.internal_calls, func, callee.to_string());
    dfg.call_edges
        .push((func.to_string(), format!("internal::{}", callee)));
}

fn record_call_expr(dfg: &mut CrossTxDfg, func: &str, expr: &ParsedExpr) {
    let Some(name) = callee_name(expr) else {
        return;
    };
    let ParsedExpr::FunctionCall { callee, .. } = expr else {
        return;
    };
    match callee.as_ref() {
        ParsedExpr::Variable { .. } => record_internal_call(dfg, func, &name),
        ParsedExpr::MemberAccess { .. } => {
            if let Some(call) = external_call_from_expr(expr) {
                record_external_call(dfg, func, call);
            }
        }
        _ => {
            if let Some(call) = external_call_from_expr(expr) {
                record_external_call(dfg, func, call);
            }
        }
    }
}

fn walk_statements(
    func: &str,
    stmts: &[ParsedStatement],
    state_vars: &HashSet<String>,
    dfg: &mut CrossTxDfg,
) {
    for stmt in stmts {
        match stmt {
            ParsedStatement::Assignment { lhs, rhs } => {
                if let Some(slot) = storage_slot_from_expr(lhs, state_vars) {
                    push_unique(&mut dfg.storage_writes, func, slot);
                }
                let mut reads = Vec::new();
                collect_storage_reads_expr(rhs, state_vars, &mut reads);
                for r in reads {
                    push_unique(&mut dfg.storage_reads, func, r);
                }
            }
            ParsedStatement::If {
                condition,
                then_body,
                else_body,
            } => {
                let mut reads = Vec::new();
                collect_storage_reads_expr(condition, state_vars, &mut reads);
                for r in reads {
                    push_unique(&mut dfg.storage_reads, func, r);
                }
                walk_statements(func, then_body, state_vars, dfg);
                walk_statements(func, else_body, state_vars, dfg);
            }
            ParsedStatement::Call { callee, args } => {
                let fc = ParsedExpr::FunctionCall {
                    callee: callee.clone(),
                    args: args.clone(),
                };
                record_call_expr(dfg, func, &fc);
                let mut reads = Vec::new();
                collect_storage_reads_expr(&fc, state_vars, &mut reads);
                for r in reads {
                    push_unique(&mut dfg.storage_reads, func, r);
                }
            }
            ParsedStatement::Expression { expr } => walk_expression(func, expr, state_vars, dfg),
            ParsedStatement::Block { statements } | ParsedStatement::Loop { body: statements } => {
                walk_statements(func, statements, state_vars, dfg);
            }
            ParsedStatement::Return { value } => {
                if let Some(v) = value {
                    let mut reads = Vec::new();
                    collect_storage_reads_expr(v, state_vars, &mut reads);
                    for r in reads {
                        push_unique(&mut dfg.storage_reads, func, r);
                    }
                }
            }
            ParsedStatement::VariableDecl { initializer, .. } => {
                if let Some(init) = initializer {
                    walk_expression(func, init, state_vars, dfg);
                }
            }
            ParsedStatement::Other => {}
        }
    }
}

fn walk_expression(func: &str, expr: &ParsedExpr, state_vars: &HashSet<String>, dfg: &mut CrossTxDfg) {
    if let ParsedExpr::FunctionCall { .. } = expr {
        if matches!(
            callee_name(expr).as_deref(),
            Some("require") | Some("revert") | Some("assert")
        ) {
            let mut reads = Vec::new();
            collect_storage_reads_expr(expr, state_vars, &mut reads);
            for r in reads {
                push_unique(&mut dfg.storage_reads, func, r);
            }
        }
        record_call_expr(dfg, func, expr);
    }
    let mut reads = Vec::new();
    collect_storage_reads_expr(expr, state_vars, &mut reads);
    for r in reads {
        push_unique(&mut dfg.storage_reads, func, r);
    }
}

pub fn build_cross_tx_dfg_from_source(source: &str) -> Result<CrossTxDfg, StaticAnalysisError> {
    let state_vars: HashSet<String> = parse_state_vars(source)?.into_iter().collect();
    let functions = parse_all_functions(source)?;
    Ok(build_cross_tx_dfg_with_state(&functions, &state_vars, ""))
}

pub fn build_cross_tx_dfg_with_state(
    functions: &[ParsedFunction],
    state_vars: &HashSet<String>,
    address: &str,
) -> CrossTxDfg {
    let mut dfg = CrossTxDfg {
        address: address.to_string(),
        call_edges: Vec::new(),
        storage_writes: HashMap::new(),
        storage_reads: HashMap::new(),
        external_calls: HashMap::new(),
        internal_calls: HashMap::new(),
        entry_points: functions
            .iter()
            .filter(|f| f.is_entry_point)
            .map(|f| f.name.clone())
            .collect(),
    };
    for func in functions {
        walk_statements(&func.name, &func.body, state_vars, &mut dfg);
    }
    rollup_effects(&mut dfg);
    dfg
}

fn callee_name_from_external(call: &ExternalCall) -> Option<String> {
    if let Some(start) = call.method.find("name: \"") {
        let rest = &call.method[start + 7..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    if call.target != "external" {
        return Some(call.method.clone());
    }
    None
}

fn merge_effects(dfg: &mut CrossTxDfg, caller: &str, callee: &str) {
    if let Some(writes) = dfg.storage_writes.get(callee).cloned() {
        for slot in writes {
            push_unique(&mut dfg.storage_writes, caller, slot);
        }
    }
    if let Some(reads) = dfg.storage_reads.get(callee).cloned() {
        for slot in reads {
            push_unique(&mut dfg.storage_reads, caller, slot);
        }
    }
}

fn rollup_effects(dfg: &mut CrossTxDfg) {
    // Fixed-point: merge direct callee effects into callers until stable (max 8 passes).
    for _ in 0..8 {
        let callers: Vec<String> = dfg
            .internal_calls
            .keys()
            .chain(dfg.external_calls.keys())
            .cloned()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        for caller in &callers {
            if let Some(internal) = dfg.internal_calls.get(caller).cloned() {
                for callee in &internal {
                    merge_effects(dfg, caller, callee);
                }
            }
            if let Some(external) = dfg.external_calls.get(caller).cloned() {
                for call in external {
                    if let Some(callee) = callee_name_from_external(&call) {
                        merge_effects(dfg, caller, &callee);
                    }
                }
            }
        }
    }
}

pub fn build_cross_tx_dfg(functions: &[ParsedFunction]) -> CrossTxDfg {
    build_cross_tx_dfg_with_state(functions, &HashSet::new(), "")
}

pub type CrossTxPath = Vec<(String, usize)>;

pub fn cross_tx_backward_slice(dfg: &CrossTxDfg, sink: (usize, String)) -> Vec<CrossTxPath> {
    let (_idx, name) = sink;
    vec![vec![(name, 0)]]
}
