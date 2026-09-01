//! Nuclei YAML exporter for verified CPG data-flow slices.

pub mod nuclei_exporter;

pub use nuclei_exporter::NucleiExporter;

use crate::cpg_schema::DataFlowSlice;
use crate::joern_cpg_bridge::SatPath;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportFormat {
    Nuclei,
}

#[derive(Debug, Clone)]
pub struct ExportContext<'a> {
    pub sat: &'a SatPath,
    pub slice: &'a DataFlowSlice,
    pub defect_class: &'a str,
    pub spec_id: Option<&'a str>,
}

pub trait ExportAdapter {
    fn render(&self, ctx: &ExportContext) -> String;
}

pub fn dispatch(fmt: ExportFormat, ctx: &ExportContext) -> String {
    match fmt {
        ExportFormat::Nuclei => NucleiExporter.render(ctx),
    }
}
