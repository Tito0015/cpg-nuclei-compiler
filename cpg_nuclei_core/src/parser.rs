//! Solidity parser wrapper using solang-parser.
//!
//! Extracts function definitions and computes selectors.

use crate::types::TaintSource;
use crate::StaticAnalysisError;
use solang_parser::pt::{
    ContractPart, Expression, FunctionAttribute, FunctionDefinition, FunctionTy,
    SourceUnitPart, Statement, Visibility,
};
use tiny_keccak::{Hasher, Keccak};

/// Extracted function information for DFG construction.
#[derive(Debug, Clone)]
pub struct ParsedFunction {
    /// Function name
    pub name: String,

    /// Parameter names and types
    pub params: Vec<(String, String)>,

    /// Function body statements
    pub body: Vec<ParsedStatement>,

    /// Whether the function is public/external
    pub is_entry_point: bool,

    /// Source location for diagnostics
    pub loc: (usize, usize),
}

/// Simplified statement representation for DFG.
#[derive(Debug, Clone, Default)]
pub enum ParsedStatement {
    /// Variable declaration with optional initializer
    VariableDecl {
        name: String,
        type_name: String,
        initializer: Option<Box<ParsedExpr>>,
    },

    /// Assignment: lhs = rhs
    Assignment {
        lhs: Box<ParsedExpr>,
        rhs: Box<ParsedExpr>,
    },

    /// Function/method call
    Call {
        callee: Box<ParsedExpr>,
        args: Vec<ParsedExpr>,
    },

    /// Return statement
    Return { value: Option<Box<ParsedExpr>> },

    /// If statement with optional else
    If {
        condition: Box<ParsedExpr>,
        then_body: Vec<ParsedStatement>,
        else_body: Vec<ParsedStatement>,
    },

    /// For/while loop
    Loop { body: Vec<ParsedStatement> },

    /// Block of statements
    Block { statements: Vec<ParsedStatement> },

    /// Expression statement
    Expression { expr: Box<ParsedExpr> },

    /// Other/unsupported
    #[default]
    Other,
}

/// Simplified expression representation for taint tracking.
#[derive(Debug, Clone)]
pub enum ParsedExpr {
    /// Variable reference
    Variable { name: String },

    /// Member access: base.member
    MemberAccess {
        base: Box<ParsedExpr>,
        member: String,
    },

    /// Function call
    FunctionCall {
        callee: Box<ParsedExpr>,
        args: Vec<ParsedExpr>,
    },

    /// Binary operation
    BinaryOp {
        op: BinaryOperator,
        left: Box<ParsedExpr>,
        right: Box<ParsedExpr>,
    },

    /// Unary operation
    UnaryOp { op: String, operand: Box<ParsedExpr> },

    /// Literal value
    Literal { value: String },

    /// Index access: base[index]
    IndexAccess {
        base: Box<ParsedExpr>,
        index: Box<ParsedExpr>,
    },

    /// Taint source (msg.sender, msg.value, etc.)
    TaintSource { source: TaintSource },

    /// Other/unknown
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOperator {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    BitOr,
    Shl,
    Shr,
    Eq,
    NotEq,
    Lt,
    Gt,
    LtEq,
    GtEq,
    Other,
}

/// Parse contract-level state variable names.
pub fn parse_state_vars(source: &str) -> Result<Vec<String>, StaticAnalysisError> {
    let (unit, _comments) = solang_parser::parse(source, 0)
        .map_err(|diags| StaticAnalysisError::ParseError(format!("{:?}", diags)))?;

    let mut vars = Vec::new();
    for part in &unit.0 {
        if let SourceUnitPart::ContractDefinition(contract) = part {
            for contract_part in &contract.parts {
                if let ContractPart::VariableDefinition(var) = contract_part {
                    if let Some(name) = var.name.as_ref() {
                        vars.push(name.name.clone());
                    }
                }
            }
        }
    }
    Ok(vars)
}

/// Parse all functions (public, external, internal) across contracts.
pub fn parse_all_functions(source: &str) -> Result<Vec<ParsedFunction>, StaticAnalysisError> {
    let contracts = parse_contract_functions(source)?;
    Ok(contracts.into_iter().flat_map(|(_, fns)| fns).collect())
}

/// Parse Solidity source and extract public/external functions.
pub fn parse_solidity(source: &str) -> Result<Vec<ParsedFunction>, StaticAnalysisError> {
    let (unit, _comments) = solang_parser::parse(source, 0)
        .map_err(|diags| StaticAnalysisError::ParseError(format!("{:?}", diags)))?;

    let mut functions = Vec::new();

    for part in &unit.0 {
        if let SourceUnitPart::ContractDefinition(contract) = part {
            for contract_part in &contract.parts {
                if let ContractPart::FunctionDefinition(func) = contract_part {
                    if let Some(parsed) = parse_function(func) {
                        functions.push(parsed);
                    }
                }
            }
        }
    }

    Ok(functions)
}

/// Parse all non-constructor functions grouped by contract name.
pub fn parse_contract_functions(
    source: &str,
) -> Result<Vec<(String, Vec<ParsedFunction>)>, StaticAnalysisError> {
    let (unit, _comments) = solang_parser::parse(source, 0)
        .map_err(|diags| StaticAnalysisError::ParseError(format!("{:?}", diags)))?;

    let mut out = Vec::new();
    for part in &unit.0 {
        if let SourceUnitPart::ContractDefinition(contract) = part {
            let contract_name = contract
                .name
                .as_ref()
                .map(|id| id.name.clone())
                .unwrap_or_default();
            let mut functions = Vec::new();
            for contract_part in &contract.parts {
                if let ContractPart::FunctionDefinition(func) = contract_part {
                    if let Some(parsed) = parse_function_all(func) {
                        functions.push(parsed);
                    }
                }
            }
            if !functions.is_empty() {
                out.push((contract_name, functions));
            }
        }
    }
    Ok(out)
}

/// Extract contract name from source.
pub fn extract_contract_name(source: &str) -> Option<String> {
    let (unit, _) = solang_parser::parse(source, 0).ok()?;

    for part in &unit.0 {
        if let SourceUnitPart::ContractDefinition(contract) = part {
            return contract.name.as_ref().map(|id| id.name.clone());
        }
    }
    None
}

/// Compute 4-byte function selector from name and parameter types.
pub fn compute_selector(name: &str, params: &[(String, String)]) -> [u8; 4] {
    let param_types: Vec<&str> = params.iter().map(|(_, t)| t.as_str()).collect();
    let signature = format!("{}({})", name, param_types.join(","));

    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(signature.as_bytes());
    hasher.finalize(&mut output);

    let mut selector = [0u8; 4];
    selector.copy_from_slice(&output[..4]);
    selector
}

fn parse_function(func: &FunctionDefinition) -> Option<ParsedFunction> {
    let parsed = parse_function_all(func)?;
    if !parsed.is_entry_point {
        return None;
    }
    Some(parsed)
}

fn parse_function_all(func: &FunctionDefinition) -> Option<ParsedFunction> {
    let name = func.name.as_ref()?.name.clone();

    // Only process regular functions (not constructors, fallback, receive)
    if func.ty != FunctionTy::Function {
        return None;
    }

    // Check visibility - only public/external are entry points
    let is_entry_point = func.attributes.iter().any(|attr| {
        matches!(
            attr,
            FunctionAttribute::Visibility(Visibility::Public(_))
                | FunctionAttribute::Visibility(Visibility::External(_))
        )
    });

    let is_internal = func.attributes.iter().any(|attr| {
        matches!(
            attr,
            FunctionAttribute::Visibility(Visibility::Internal(_))
        )
    });

    if !is_entry_point && !is_internal {
        return None;
    }

    let params: Vec<(String, String)> = func
        .params
        .iter()
        .filter_map(|(_, param)| {
            param.as_ref().map(|p| {
                let name = p.name.as_ref().map(|n| n.name.clone()).unwrap_or_default();
                let type_name = format_type(&p.ty);
                (name, type_name)
            })
        })
        .collect();

    let body = func
        .body
        .as_ref()
        .map(|b| parse_statement(b))
        .unwrap_or_default();

    let loc = func.loc.start()..func.loc.end();

    Some(ParsedFunction {
        name,
        params,
        body: if let ParsedStatement::Block { statements } = body {
            statements
        } else {
            vec![body]
        },
        is_entry_point,
        loc: (loc.start, loc.end),
    })
}

fn parse_statement(stmt: &Statement) -> ParsedStatement {
    match stmt {
        Statement::Block { statements, .. } => ParsedStatement::Block {
            statements: statements.iter().map(parse_statement).collect(),
        },

        Statement::VariableDefinition(_, decl, init) => ParsedStatement::VariableDecl {
            name: decl.name.as_ref().map(|n| n.name.clone()).unwrap_or_default(),
            type_name: format_type(&decl.ty),
            initializer: init.as_ref().map(|e| Box::new(parse_expression(e))),
        },

        Statement::Expression(_, expr) => {
            // Check if this is an assignment
            if let Expression::Assign(_, lhs, rhs) = expr {
                ParsedStatement::Assignment {
                    lhs: Box::new(parse_expression(lhs)),
                    rhs: Box::new(parse_expression(rhs)),
                }
            } else {
                ParsedStatement::Expression {
                    expr: Box::new(parse_expression(expr)),
                }
            }
        }

        Statement::Return(_, value) => ParsedStatement::Return {
            value: value.as_ref().map(|e| Box::new(parse_expression(e))),
        },

        Statement::If(_, cond, then_stmt, else_stmt) => ParsedStatement::If {
            condition: Box::new(parse_expression(cond)),
            then_body: vec![parse_statement(then_stmt)],
            else_body: else_stmt
                .as_ref()
                .map(|s| vec![parse_statement(s)])
                .unwrap_or_default(),
        },

        Statement::For(_, _, _, _, body) => ParsedStatement::Loop {
            body: body
                .as_ref()
                .map(|b| vec![parse_statement(b)])
                .unwrap_or_default(),
        },

        Statement::While(_, _, body) => ParsedStatement::Loop {
            body: vec![parse_statement(body)],
        },

        Statement::DoWhile(_, body, _) => ParsedStatement::Loop {
            body: vec![parse_statement(body)],
        },

        _ => ParsedStatement::Other,
    }
}

fn parse_expression(expr: &Expression) -> ParsedExpr {
    match expr {
        Expression::Variable(id) => {
            let name = &id.name;
            // Check for built-in taint sources
            if name == "msg" {
                ParsedExpr::Variable {
                    name: name.clone(),
                }
            } else {
                ParsedExpr::Variable {
                    name: name.clone(),
                }
            }
        }

        Expression::MemberAccess(_, base, member) => {
            let base_expr = parse_expression(base);
            let member_name = member.name.clone();

            // Detect taint sources like msg.sender, msg.value
            if let ParsedExpr::Variable { name } = &base_expr {
                if name == "msg" {
                    return match member_name.as_str() {
                        "sender" => ParsedExpr::TaintSource {
                            source: TaintSource::MsgSender,
                        },
                        "value" => ParsedExpr::TaintSource {
                            source: TaintSource::MsgValue,
                        },
                        _ => ParsedExpr::MemberAccess {
                            base: Box::new(base_expr),
                            member: member_name,
                        },
                    };
                } else if name == "block" {
                    return match member_name.as_str() {
                        "timestamp" => ParsedExpr::TaintSource {
                            source: TaintSource::BlockTimestamp,
                        },
                        "number" => ParsedExpr::TaintSource {
                            source: TaintSource::BlockNumber,
                        },
                        _ => ParsedExpr::MemberAccess {
                            base: Box::new(base_expr),
                            member: member_name,
                        },
                    };
                } else if name == "tx" && member_name == "origin" {
                    return ParsedExpr::TaintSource {
                        source: TaintSource::TxOrigin,
                    };
                }
            }

            ParsedExpr::MemberAccess {
                base: Box::new(base_expr),
                member: member_name,
            }
        }

        Expression::FunctionCall(_, callee, args) => {
            if let Expression::Type(_, _) = callee.as_ref() {
                if let Some(inner) = args.first() {
                    return parse_expression(inner);
                }
            }
            ParsedExpr::FunctionCall {
                callee: Box::new(parse_expression(callee)),
                args: args.iter().map(parse_expression).collect(),
            }
        },

        Expression::NamedFunctionCall(_, callee, named_args) => ParsedExpr::FunctionCall {
            callee: Box::new(parse_expression(callee)),
            args: named_args
                .iter()
                .map(|arg| parse_expression(&arg.expr))
                .collect(),
        },

        Expression::Power(_, l, r) => ParsedExpr::BinaryOp {
            op: BinaryOperator::Other,
            left: Box::new(parse_expression(l)),
            right: Box::new(parse_expression(r)),
        },

        Expression::Parenthesis(_, inner) => parse_expression(inner),

        Expression::Add(_, l, r) => ParsedExpr::BinaryOp {
            op: BinaryOperator::Add,
            left: Box::new(parse_expression(l)),
            right: Box::new(parse_expression(r)),
        },

        Expression::Subtract(_, l, r) => ParsedExpr::BinaryOp {
            op: BinaryOperator::Sub,
            left: Box::new(parse_expression(l)),
            right: Box::new(parse_expression(r)),
        },

        Expression::Multiply(_, l, r) => ParsedExpr::BinaryOp {
            op: BinaryOperator::Mul,
            left: Box::new(parse_expression(l)),
            right: Box::new(parse_expression(r)),
        },

        Expression::Divide(_, l, r) => ParsedExpr::BinaryOp {
            op: BinaryOperator::Div,
            left: Box::new(parse_expression(l)),
            right: Box::new(parse_expression(r)),
        },

        Expression::Modulo(_, l, r) => ParsedExpr::BinaryOp {
            op: BinaryOperator::Mod,
            left: Box::new(parse_expression(l)),
            right: Box::new(parse_expression(r)),
        },

        Expression::ShiftLeft(_, l, r) => ParsedExpr::BinaryOp {
            op: BinaryOperator::Shl,
            left: Box::new(parse_expression(l)),
            right: Box::new(parse_expression(r)),
        },

        Expression::ShiftRight(_, l, r) => ParsedExpr::BinaryOp {
            op: BinaryOperator::Shr,
            left: Box::new(parse_expression(l)),
            right: Box::new(parse_expression(r)),
        },

        Expression::BitwiseOr(_, l, r) => ParsedExpr::BinaryOp {
            op: BinaryOperator::BitOr,
            left: Box::new(parse_expression(l)),
            right: Box::new(parse_expression(r)),
        },

        Expression::Less(_, l, r) => ParsedExpr::BinaryOp {
            op: BinaryOperator::Lt,
            left: Box::new(parse_expression(l)),
            right: Box::new(parse_expression(r)),
        },

        Expression::LessEqual(_, l, r) => ParsedExpr::BinaryOp {
            op: BinaryOperator::LtEq,
            left: Box::new(parse_expression(l)),
            right: Box::new(parse_expression(r)),
        },

        Expression::More(_, l, r) => ParsedExpr::BinaryOp {
            op: BinaryOperator::Gt,
            left: Box::new(parse_expression(l)),
            right: Box::new(parse_expression(r)),
        },

        Expression::MoreEqual(_, l, r) => ParsedExpr::BinaryOp {
            op: BinaryOperator::GtEq,
            left: Box::new(parse_expression(l)),
            right: Box::new(parse_expression(r)),
        },

        Expression::Assign(_, l, r) => ParsedExpr::BinaryOp {
            op: BinaryOperator::Other,
            left: Box::new(parse_expression(l)),
            right: Box::new(parse_expression(r)),
        },

        Expression::ArraySubscript(_, base, index) => ParsedExpr::IndexAccess {
            base: Box::new(parse_expression(base)),
            index: index
                .as_ref()
                .map(|i| Box::new(parse_expression(i)))
                .unwrap_or_else(|| Box::new(ParsedExpr::Other)),
        },

        Expression::NumberLiteral(_, val, _, _) => ParsedExpr::Literal {
            value: val.clone(),
        },

        Expression::StringLiteral(vals) => ParsedExpr::Literal {
            value: vals.iter().map(|s| s.string.clone()).collect(),
        },

        Expression::BoolLiteral(_, val) => ParsedExpr::Literal {
            value: val.to_string(),
        },

        _ => ParsedExpr::Other,
    }
}

fn canonical_abi_type(type_name: &str) -> String {
    let mut t = type_name.to_lowercase();
    if t.contains("flashborrower") || t.ends_with(".address") {
        return "address".to_string();
    }
    if t.starts_with("contract ") {
        return "address".to_string();
    }
    if t.contains("address") && !t.contains('[') {
        return "address".to_string();
    }
    if t.contains("bytes") {
        return "bytes".to_string();
    }
    if t.starts_with("uint") && !t.contains('[') {
        return "uint256".to_string();
    }
    if t.starts_with("int") && !t.contains('[') {
        return "int256".to_string();
    }
    // strip memory/calldata/storage suffix noise from debug formatting
    t = t
        .replace(" memory", "")
        .replace(" calldata", "")
        .replace(" storage", "");
    t
}

fn format_type(ty: &solang_parser::pt::Expression) -> String {
    let raw = match ty {
        Expression::Type(_, ty) => format!("{:?}", ty).to_lowercase(),
        Expression::Variable(id) => id.name.clone(),
        Expression::ArraySubscript(_, base, size) => {
            let base_type = format_type(base);
            if let Some(s) = size {
                format!("{}[{}]", base_type, format_type(s))
            } else {
                format!("{}[]", base_type)
            }
        }
        _ => "unknown".to_string(),
    };
    canonical_abi_type(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_selector() {
        // transfer(address,uint256) = 0xa9059cbb
        let selector = compute_selector("transfer", &[
            ("to".into(), "address".into()),
            ("amount".into(), "uint256".into()),
        ]);
        assert_eq!(selector, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_parse_simple_contract() {
        let source = r#"
            contract Test {
                function deposit(uint256 amount) public {
                    require(amount > 0);
                }
            }
        "#;
        let functions = parse_solidity(source).unwrap();
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "deposit");
        assert!(functions[0].is_entry_point);
    }
}
