use crate::scans::scan_engine_page::clamd_socket_ownership::ClamdSocketOwnership;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanEnginePageOutput {
    EvidenceRefreshRequested,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClamdSocketView {
    SocketInspecting,
    SocketInspected(ClamdSocketOwnership),
}
