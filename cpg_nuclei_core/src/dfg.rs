//! Data Flow Graph (DFG) builder for intra-procedural analysis.
//!
//! Constructs def-use chains to track data flow from sources to sinks.

use crate::parser::{BinaryOperator, ParsedExpr, ParsedFunction, ParsedStatement};
use crate::types::TaintSource;
use std::collections::{HashMap, HashSet};

/// Node identifier in the DFG.
pub type NodeId = usize;

/// A node in the data flow graph.
#[derive(Debug, Clone)]
pub enum DfgNode {
    /// Definition site (variable assignment, parameter)
    Def {
        var_name: String,
        source: Option<TaintSource>,
    },

    /// Use site (variable read)
    Use { var_name: String },

    /// Function/method call
    Call {
        callee: String,
        is_low_level: bool,
        is_transfer: bool,
        is_external: bool,
    },

    /// Binary operation
    BinaryOp { op: BinaryOperator },

    /// Sink (security-critical operation)
    Sink { kind: SinkKind },
}

/// Types of security-critical sinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SinkKind {
    LowLevelCall,
    Division,
    Modulo,
    StateWrite,
    Transfer,
    ExternalCall,
    SelfDestruct,
    Create,
}

/// Edge in the data flow graph.
#[derive(Debug, Clone)]
pub struct DfgEdge {
    pub from: NodeId,
    pub to: NodeId,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    /// Data flows from def to use
    DataFlow,
    /// Control flow edge
    Control,
    /// Argument to call
    Argument,
    /// Return value
    Return,
}

/// Data flow graph for a single function.
#[derive(Debug)]
pub struct FunctionDfg {
    pub function_name: String,
    pub nodes: Vec<DfgNode>,
    pub edges: Vec<DfgEdge>,
    /// Map from variable name to its most recent definition node
    pub var_defs: HashMap<String, NodeId>,
    /// Nodes that are taint sources
    pub sources: HashSet<NodeId>,
    /// Nodes that are sinks
    pub sinks: HashSet<NodeId>,
}

impl FunctionDfg {
    pub fn new(name: &str) -> Self {
        FunctionDfg {
            function_name: name.to_string(),
            nodes: Vec::new(),
            edges: Vec::new(),
            var_defs: HashMap::new(),
            sources: HashSet::new(),
            sinks: HashSet::new(),
        }
    }

    /// Add a node and return its ID.
    pub fn add_node(&mut self, node: DfgNode) -> NodeId {
        let id = self.nodes.len();
        self.nodes.push(node);
        id
    }

    /// Add an edge between nodes.
    pub fn add_edge(&mut self, from: NodeId, to: NodeId, kind: EdgeKind) {
        self.edges.push(DfgEdge { from, to, kind });
    }

    /// Mark a node as a taint source.
    pub fn mark_source(&mut self, node_id: NodeId) {
        self.sources.insert(node_id);
    }

    /// Mark a node as a sink.
    pub fn mark_sink(&mut self, node_id: NodeId) {
        self.sinks.insert(node_id);
    }

    /// Define a variable (creates def node, updates var_defs map).
    pub fn define_var(&mut self, name: &str, source: Option<TaintSource>) -> NodeId {
        let node_id = self.add_node(DfgNode::Def {
            var_name: name.to_string(),
            source,
        });
        self.var_defs.insert(name.to_string(), node_id);

        if source.is_some() {
            self.mark_source(node_id);
        }

        node_id
    }

    /// Use a variable (creates use node, links to def if exists).
    pub fn use_var(&mut self, name: &str) -> NodeId {
        let use_id = self.add_node(DfgNode::Use {
            var_name: name.to_string(),
        });

        // Link to definition if it exists
        if let Some(&def_id) = self.var_defs.get(name) {
            self.add_edge(def_id, use_id, EdgeKind::DataFlow);
        }

        use_id
    }
}

/// Build a DFG from a parsed function.
pub fn build_function_dfg(func: &ParsedFunction) -> FunctionDfg {
    let mut dfg = FunctionDfg::new(&func.name);

    // Mark parameters as taint sources (user-controlled inputs)
    for (param_name, _param_type) in &func.params {
        dfg.define_var(param_name, Some(TaintSource::Parameter));
    }

    // Process function body
    for stmt in &func.body {
        process_statement(&mut dfg, stmt);
    }

    dfg
}

fn process_statement(dfg: &mut FunctionDfg, stmt: &ParsedStatement) {
    match stmt {
        ParsedStatement::VariableDecl {
            name,
            initializer,
            ..
        } => {
            let mut source_nodes = Vec::new();

            // Process initializer expression
            if let Some(init) = initializer {
                source_nodes = process_expression(dfg, init);
            }

            // Define the variable
            let def_id = dfg.define_var(name, None);

            // Link initializer to definition
            for src_id in source_nodes {
                dfg.add_edge(src_id, def_id, EdgeKind::DataFlow);
            }
        }

        ParsedStatement::Assignment { lhs, rhs } => {
            // Process RHS first
            let rhs_nodes = process_expression(dfg, rhs);

            // Process LHS (get variable name)
            if let ParsedExpr::Variable { name } = lhs.as_ref() {
                let def_id = dfg.define_var(name, None);
                for src_id in rhs_nodes {
                    dfg.add_edge(src_id, def_id, EdgeKind::DataFlow);
                }
            } else if let ParsedExpr::IndexAccess { base, index } = lhs.as_ref() {
                // State write sink (array/mapping assignment)
                let sink_id = dfg.add_node(DfgNode::Sink {
                    kind: SinkKind::StateWrite,
                });
                dfg.mark_sink(sink_id);

                // Index and RHS flow into the state write
                let index_nodes = process_expression(dfg, index);
                for node in index_nodes {
                    dfg.add_edge(node, sink_id, EdgeKind::DataFlow);
                }
                for node in rhs_nodes {
                    dfg.add_edge(node, sink_id, EdgeKind::DataFlow);
                }

                // Process base too
                let base_nodes = process_expression(dfg, base);
                for node in base_nodes {
                    dfg.add_edge(node, sink_id, EdgeKind::DataFlow);
                }
            } else if let ParsedExpr::MemberAccess { .. } = lhs.as_ref() {
                // State variable member write
                let sink_id = dfg.add_node(DfgNode::Sink {
                    kind: SinkKind::StateWrite,
                });
                dfg.mark_sink(sink_id);
                for node in rhs_nodes {
                    dfg.add_edge(node, sink_id, EdgeKind::DataFlow);
                }
            }
        }

        ParsedStatement::Call { callee, args } => {
            let _callee_nodes = process_expression(dfg, callee);
            for arg in args {
                process_expression(dfg, arg);
            }
        }

        ParsedStatement::Return { value } => {
            if let Some(val) = value {
                process_expression(dfg, val);
            }
        }

        ParsedStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            process_expression(dfg, condition);
            for s in then_body {
                process_statement(dfg, s);
            }
            for s in else_body {
                process_statement(dfg, s);
            }
        }

        ParsedStatement::Loop { body } => {
            for s in body {
                process_statement(dfg, s);
            }
        }

        ParsedStatement::Block { statements } => {
            for s in statements {
                process_statement(dfg, s);
            }
        }

        ParsedStatement::Expression { expr } => {
            process_expression(dfg, expr);
        }

        ParsedStatement::Other => {}
    }
}

fn process_expression(dfg: &mut FunctionDfg, expr: &ParsedExpr) -> Vec<NodeId> {
    match expr {
        ParsedExpr::Variable { name } => {
            vec![dfg.use_var(name)]
        }

        ParsedExpr::TaintSource { source } => {
            let node_id = dfg.add_node(DfgNode::Def {
                var_name: format!("{:?}", source),
                source: Some(*source),
            });
            dfg.mark_source(node_id);
            vec![node_id]
        }

        ParsedExpr::MemberAccess { base, member } => {
            let base_nodes = process_expression(dfg, base);

            // Check for dangerous method calls
            let is_dangerous = matches!(
                member.as_str(),
                "call" | "delegatecall" | "staticcall" | "transfer" | "send"
            );

            if is_dangerous {
                let sink_kind = match member.as_str() {
                    "call" | "delegatecall" | "staticcall" => SinkKind::LowLevelCall,
                    "transfer" | "send" => SinkKind::Transfer,
                    _ => SinkKind::ExternalCall,
                };
                let sink_id = dfg.add_node(DfgNode::Sink { kind: sink_kind });
                dfg.mark_sink(sink_id);
                for node in &base_nodes {
                    dfg.add_edge(*node, sink_id, EdgeKind::DataFlow);
                }
                vec![sink_id]
            } else {
                base_nodes
            }
        }

        ParsedExpr::FunctionCall { callee, args } => {
            let mut result_nodes = Vec::new();

            // Process callee
            let callee_nodes = process_expression(dfg, callee);

            // Determine if this is a dangerous call
            let (is_low_level, is_transfer, is_external) = match callee.as_ref() {
                ParsedExpr::MemberAccess { member, .. } => {
                    let is_ll = matches!(
                        member.as_str(),
                        "call" | "delegatecall" | "staticcall"
                    );
                    let is_tr = matches!(
                        member.as_str(),
                        "transfer" | "send" | "safeTransfer" | "safeTransferFrom"
                    );
                    let is_cb = member.as_str() == "onFlashLoan";
                    (is_ll, is_tr, is_ll || is_tr || is_cb)
                }
                ParsedExpr::Variable { name } if name == "selfdestruct" => (false, false, true),
                _ => (false, false, false),
            };

            let call_id = dfg.add_node(DfgNode::Call {
                callee: format!("{:?}", callee),
                is_low_level,
                is_transfer,
                is_external,
            });

            // Process arguments
            let mut arg_nodes_all = Vec::new();
            for arg in args {
                let arg_nodes = process_expression(dfg, arg);
                for node in &arg_nodes {
                    dfg.add_edge(*node, call_id, EdgeKind::Argument);
                }
                arg_nodes_all.extend(arg_nodes);
            }

            // If dangerous, also add a sink
            let mut sink_id = None;
            if is_low_level {
                let sid = dfg.add_node(DfgNode::Sink {
                    kind: SinkKind::LowLevelCall,
                });
                dfg.mark_sink(sid);
                dfg.add_edge(call_id, sid, EdgeKind::DataFlow);
                for node in &callee_nodes {
                    dfg.add_edge(*node, sid, EdgeKind::DataFlow);
                }
                sink_id = Some(sid);
            } else if is_transfer {
                let sid = dfg.add_node(DfgNode::Sink {
                    kind: SinkKind::Transfer,
                });
                dfg.mark_sink(sid);
                dfg.add_edge(call_id, sid, EdgeKind::DataFlow);
                sink_id = Some(sid);
            } else if let ParsedExpr::MemberAccess { member, .. } = callee.as_ref() {
                if member.as_str() == "onFlashLoan" {
                    let sid = dfg.add_node(DfgNode::Sink {
                        kind: SinkKind::ExternalCall,
                    });
                    dfg.mark_sink(sid);
                    dfg.add_edge(call_id, sid, EdgeKind::DataFlow);
                    sink_id = Some(sid);
                }
            } else if let ParsedExpr::Variable { name } = callee.as_ref() {
                if name == "selfdestruct" {
                    let sid = dfg.add_node(DfgNode::Sink {
                        kind: SinkKind::SelfDestruct,
                    });
                    dfg.mark_sink(sid);
                    dfg.add_edge(call_id, sid, EdgeKind::DataFlow);
                    sink_id = Some(sid);
                }
            }

            if let Some(sid) = sink_id {
                for node in arg_nodes_all {
                    dfg.add_edge(node, sid, EdgeKind::DataFlow);
                }
            }

            result_nodes.push(call_id);
            result_nodes
        }

        ParsedExpr::BinaryOp { op, left, right } => {
            let left_nodes = process_expression(dfg, left);
            let right_nodes = process_expression(dfg, right);

            let op_id = dfg.add_node(DfgNode::BinaryOp { op: *op });

            for node in &left_nodes {
                dfg.add_edge(*node, op_id, EdgeKind::DataFlow);
            }
            for node in &right_nodes {
                dfg.add_edge(*node, op_id, EdgeKind::DataFlow);
            }

            // Division/modulo with tainted denominator is a sink
            if matches!(op, BinaryOperator::Div | BinaryOperator::Mod) {
                let sink_kind = if *op == BinaryOperator::Div {
                    SinkKind::Division
                } else {
                    SinkKind::Modulo
                };
                let sink_id = dfg.add_node(DfgNode::Sink { kind: sink_kind });
                dfg.mark_sink(sink_id);
                // Right operand (denominator) flowing to division is the risk
                for node in &right_nodes {
                    dfg.add_edge(*node, sink_id, EdgeKind::DataFlow);
                }
            }

            vec![op_id]
        }

        ParsedExpr::IndexAccess { base, index } => {
            let mut nodes = process_expression(dfg, base);
            nodes.extend(process_expression(dfg, index));
            nodes
        }

        ParsedExpr::UnaryOp { operand, .. } => process_expression(dfg, operand),

        ParsedExpr::Literal { .. } => vec![],

        ParsedExpr::Other => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_solidity;

    #[test]
    fn test_dfg_parameter_sources() {
        let source = r#"
            contract Test {
                function deposit(uint256 amount) public {
                    uint256 x = amount;
                }
            }
        "#;
        let functions = parse_solidity(source).unwrap();
        let dfg = build_function_dfg(&functions[0]);

        assert!(!dfg.sources.is_empty(), "Parameters should be taint sources");
    }

    #[test]
    fn test_dfg_division_sink() {
        let source = r#"
            contract Test {
                function divide(uint256 a, uint256 b) public returns (uint256) {
                    return a / b;
                }
            }
        "#;
        let functions = parse_solidity(source).unwrap();
        let dfg = build_function_dfg(&functions[0]);

        assert!(!dfg.sinks.is_empty(), "Division should create a sink");
    }
}
