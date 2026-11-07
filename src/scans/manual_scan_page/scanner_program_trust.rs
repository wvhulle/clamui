use crate::host_services::{
    clamav_programs::trusted_program_lookup::ProgramLocation,
    clamav_scanner::scanner_command_builder::ScannerProgramPaths,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScannerProgramTrust {
    ProgramsTrusted,
    ReplaceableProgramRefused,
}

pub fn scanner_program_trust(scanner_programs: &ScannerProgramPaths) -> ScannerProgramTrust {
    let program_refused = [
        &scanner_programs.clamdscan_program,
        &scanner_programs.clamscan_program,
    ]
    .into_iter()
    .any(|program_location| {
        matches!(
            program_location,
            ProgramLocation::OnlyReplaceableCandidates { .. }
        )
    });
    if program_refused {
        ScannerProgramTrust::ReplaceableProgramRefused
    } else {
        ScannerProgramTrust::ProgramsTrusted
    }
}
