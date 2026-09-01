//! Core data types for static analysis results.

use serde::{Deserialize, Serialize};

/// A function identified as having tainted data paths to security-critical sinks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintTarget {
    /// 4-byte function selector (Keccak256 of signature, first 4 bytes)
    pub function_selector: [u8; 4],

    /// Human-readable function name with parameters
    pub function_name: String,

    /// Taint severity score (0.0-10.0), maps to base_energy in router
    pub taint_severity: f32,

    /// Types of sinks reached by tainted data
    pub sink_types: Vec<SinkType>,

    /// Glider-aligned vulnerability label (e.g. "TaintedDivision")
    pub vulnerability_class: String,
}

/// Map sink types to a Glider-aligned vulnerability class name.
pub fn classify_vulnerability(sink_types: &[SinkType]) -> String {
    if sink_types.contains(&SinkType::SelfDestruct) {
        "SelfDestructWithTaint".to_string()
    } else if sink_types.contains(&SinkType::ExternalCallback) {
        "ExternalCallbackReentrancy".to_string()
    } else if sink_types.contains(&SinkType::LowLevelCall) {
        "UncheckedLowLevelCall".to_string()
    } else if sink_types.contains(&SinkType::Transfer) {
        "TaintedTransfer".to_string()
    } else if sink_types.contains(&SinkType::ArithmeticDiv) {
        "TaintedDivision".to_string()
    } else if sink_types.contains(&SinkType::ContractCreation) {
        "TaintedContractCreation".to_string()
    } else if sink_types.contains(&SinkType::StateUpdate) {
        "TaintedStateUpdate".to_string()
    } else {
        "UnclassifiedTaint".to_string()
    }
}

/// Categories of security-critical operations (sinks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SinkType {
    /// Low-level calls: .call(), .delegatecall(), .staticcall()
    LowLevelCall,

    /// Division or modulo by potentially-tainted value
    ArithmeticDiv,

    /// Storage write from tainted source (state variable assignment)
    StateUpdate,

    /// ETH or token transfer operations
    Transfer,

    /// External callback (reentrancy vector)
    ExternalCallback,

    /// selfdestruct with tainted address
    SelfDestruct,

    /// create/create2 with tainted bytecode or salt
    ContractCreation,
}

impl SinkType {
    /// Base severity score for this sink type
    pub fn base_severity(&self) -> f32 {
        match self {
            SinkType::LowLevelCall => 5.0,
            SinkType::ArithmeticDiv => 3.0,
            SinkType::StateUpdate => 2.0,
            SinkType::Transfer => 5.0,
            SinkType::ExternalCallback => 5.0,
            SinkType::SelfDestruct => 10.0,
            SinkType::ContractCreation => 4.0,
        }
    }
}

/// Result of analyzing a contract for tainted data flows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticAnalysisResult {
    /// Name of the analyzed contract
    pub contract_name: String,

    /// Functions with tainted paths to sinks
    pub targets: Vec<TaintTarget>,

    /// Number of entry points after pruning (with taint paths)
    pub pruned_entry_count: usize,

    /// Total number of public/external functions analyzed
    pub total_entry_count: usize,
}

impl StaticAnalysisResult {
    /// Returns the pruning ratio (0.0 = all pruned, 1.0 = none pruned)
    pub fn pruning_ratio(&self) -> f32 {
        if self.total_entry_count == 0 {
            return 1.0;
        }
        self.targets.len() as f32 / self.total_entry_count as f32
    }
}

/// Taint source categories (where tainted data originates).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaintSource {
    /// Function parameter (user-controlled input)
    Parameter,

    /// msg.sender - transaction sender address
    MsgSender,

    /// msg.value - ETH sent with transaction
    MsgValue,

    /// block.timestamp - miner-influenced
    BlockTimestamp,

    /// Return value from external call
    ExternalReturn,

    /// tx.origin - original transaction sender
    TxOrigin,

    /// block.number
    BlockNumber,

    /// calldata (raw)
    Calldata,
}

/// Glider-aligned type aliases for 1:1 translation.
pub type GliderFunction = crate::parser::ParsedFunction;
pub type GliderInstruction = crate::parser::ParsedStatement;
pub type GliderCall = crate::dfg::DfgNode;
pub type GliderVarValue = TaintSource;

impl TaintSource {
    /// Whether this source is considered high-risk
    pub fn is_high_risk(&self) -> bool {
        matches!(
            self,
            TaintSource::Parameter
                | TaintSource::MsgValue
                | TaintSource::ExternalReturn
                | TaintSource::TxOrigin
                | TaintSource::Calldata
        )
    }
}
