use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod commands;

/// MERCURY -- product-specific proof, inquiry, and pilot tooling on top of Chio.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format: human-readable or JSON.
    #[arg(long, global = true, default_value = "false")]
    json: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Build a `Proof Package v1` from a verified Chio evidence package.
    Proof {
        #[command(subcommand)]
        command: ProofCommands,
    },

    /// Build an `Inquiry Package v1` from a verified proof package.
    Inquiry {
        #[command(subcommand)]
        command: InquiryCommands,
    },

    /// Export the design-partner pilot corpus for the gold MERCURY workflow.
    Pilot {
        #[command(subcommand)]
        command: PilotCommands,
    },

    /// Export supervised-live evidence for the same workflow from a typed capture file.
    SupervisedLive {
        #[command(subcommand)]
        command: SupervisedLiveCommands,
    },

    /// Export one bounded downstream review-consumer package on top of MERCURY evidence.
    DownstreamReview {
        #[command(subcommand)]
        command: DownstreamReviewCommands,
    },

    /// Export one bounded governance-workbench workflow package on top of MERCURY evidence.
    GovernanceWorkbench {
        #[command(subcommand)]
        command: GovernanceWorkbenchCommands,
    },

    /// Export one bounded assurance-suite reviewer and investigation package family.
    AssuranceSuite {
        #[command(subcommand)]
        command: AssuranceSuiteCommands,
    },

    /// Export one bounded embedded OEM package and manifest-based partner bundle.
    EmbeddedOem {
        #[command(subcommand)]
        command: EmbeddedOemCommands,
    },

    /// Export one bounded trust-network package for shared witness and proof-profile exchange.
    TrustNetwork {
        #[command(subcommand)]
        command: TrustNetworkCommands,
    },

    /// Export one bounded release-readiness package for reviewer, partner, and operator adoption.
    ReleaseReadiness {
        #[command(subcommand)]
        command: ReleaseReadinessCommands,
    },

    /// Export one bounded controlled-adoption package for renewal and reference readiness.
    ControlledAdoption {
        #[command(subcommand)]
        command: ControlledAdoptionCommands,
    },

    /// Export one bounded reference-distribution package for landed-account expansion.
    ReferenceDistribution {
        #[command(subcommand)]
        command: ReferenceDistributionCommands,
    },

    /// Export one bounded broader-distribution package for selective account qualification.
    BroaderDistribution {
        #[command(subcommand)]
        command: BroaderDistributionCommands,
    },

    /// Export one bounded selective-account-activation package for controlled delivery.
    SelectiveAccountActivation {
        #[command(subcommand)]
        command: SelectiveAccountActivationCommands,
    },

    /// Export one bounded delivery-continuity package for outcome evidence and renewal gating.
    DeliveryContinuity {
        #[command(subcommand)]
        command: DeliveryContinuityCommands,
    },

    /// Export one bounded renewal-qualification package for outcome review and expansion gating.
    RenewalQualification {
        #[command(subcommand)]
        command: RenewalQualificationCommands,
    },

    /// Export one bounded second-account-expansion package for portfolio review and reuse governance.
    SecondAccountExpansion {
        #[command(subcommand)]
        command: SecondAccountExpansionCommands,
    },

    /// Export one bounded portfolio-program package for multi-account review and guardrails.
    PortfolioProgram {
        #[command(subcommand)]
        command: PortfolioProgramCommands,
    },

    /// Export one bounded second-portfolio-program package for adjacent program reuse review.
    SecondPortfolioProgram {
        #[command(subcommand)]
        command: SecondPortfolioProgramCommands,
    },

    /// Export one bounded third-program package for repeated portfolio reuse review.
    ThirdProgram {
        #[command(subcommand)]
        command: ThirdProgramCommands,
    },

    /// Export one bounded program-family package for shared review over adjacent programs.
    ProgramFamily {
        #[command(subcommand)]
        command: ProgramFamilyCommands,
    },

    /// Export one bounded portfolio-revenue-boundary package for commercial handoff review.
    PortfolioRevenueBoundary {
        #[command(subcommand)]
        command: PortfolioRevenueBoundaryCommands,
    },

    /// Verify a `Proof Package v1` or `Inquiry Package v1`.
    Verify {
        /// Input JSON file containing a MERCURY package.
        #[arg(long)]
        input: PathBuf,

        /// Include the verification steps in human-readable output.
        #[arg(long, default_value_t = false)]
        explain: bool,
    },
}

#[derive(Subcommand)]
enum ProofCommands {
    /// Export a `Proof Package v1` wrapper over a verified Chio evidence package.
    Export {
        /// Input directory containing an Chio evidence package.
        #[arg(long)]
        input: PathBuf,

        /// Output JSON file for the MERCURY proof package.
        #[arg(long)]
        output: PathBuf,

        /// One or more MERCURY bundle-manifest JSON files to attach.
        #[arg(long = "bundle-manifest", required = true)]
        bundle_manifest: Vec<PathBuf>,
    },
}

#[derive(Subcommand)]
enum InquiryCommands {
    /// Export an `Inquiry Package v1` derived from a proof package.
    Export {
        /// Input JSON file containing a MERCURY proof package.
        #[arg(long)]
        input: PathBuf,

        /// Output JSON file for the MERCURY inquiry package.
        #[arg(long)]
        output: PathBuf,

        /// Audience label for the reviewed export.
        #[arg(long)]
        audience: String,

        /// Optional redaction profile label.
        #[arg(long)]
        redaction_profile: Option<String>,

        /// Whether the reviewed export remains verifier-equivalent.
        #[arg(long, default_value_t = false)]
        verifier_equivalent: bool,
    },
}

#[derive(Subcommand)]
enum PilotCommands {
    /// Export the primary and rollback pilot corpus with proof artifacts.
    Export {
        /// Output directory for the generated pilot corpus.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum SupervisedLiveCommands {
    /// Export a live or mirrored supervised-live capture with proof artifacts.
    Export {
        /// Input JSON file containing a supervised-live capture contract.
        #[arg(long)]
        input: PathBuf,

        /// Output directory for the generated supervised-live corpus.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the canonical supervised-live qualification and reviewer package.
    Qualify {
        /// Output directory for the generated qualification package.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum DownstreamReviewCommands {
    /// Export the selected downstream review-consumer package and delivery drop.
    Export {
        /// Output directory for the generated downstream review package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the downstream validation corpus, report, and decision artifact.
    Validate {
        /// Output directory for the generated downstream validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum GovernanceWorkbenchCommands {
    /// Export the selected governance-workbench workflow package and review surfaces.
    Export {
        /// Output directory for the generated governance-workbench package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the governance validation corpus, report, and decision artifact.
    Validate {
        /// Output directory for the generated governance validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum AssuranceSuiteCommands {
    /// Export the assurance-suite reviewer-population packages and investigation surfaces.
    Export {
        /// Output directory for the generated assurance-suite package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the assurance validation corpus, report, and decision artifact.
    Validate {
        /// Output directory for the generated assurance validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum EmbeddedOemCommands {
    /// Export the selected embedded OEM package and partner SDK bundle.
    Export {
        /// Output directory for the generated embedded OEM package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the embedded OEM validation corpus, report, and decision artifact.
    Validate {
        /// Output directory for the generated embedded OEM validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum TrustNetworkCommands {
    /// Export the selected trust-network package and shared reviewer exchange bundle.
    Export {
        /// Output directory for the generated trust-network package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the trust-network validation corpus, report, and decision artifact.
    Validate {
        /// Output directory for the generated trust-network validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum ReleaseReadinessCommands {
    /// Export the selected release-readiness package and partner-delivery bundle.
    Export {
        /// Output directory for the generated release-readiness package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the release-readiness validation corpus, report, and decision artifact.
    Validate {
        /// Output directory for the generated release-readiness validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum ControlledAdoptionCommands {
    /// Export the selected controlled-adoption package and renewal evidence bundle.
    Export {
        /// Output directory for the generated controlled-adoption package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the controlled-adoption validation corpus, report, and decision artifact.
    Validate {
        /// Output directory for the generated controlled-adoption validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum ReferenceDistributionCommands {
    /// Export the selected reference-distribution package and landed-account expansion bundle.
    Export {
        /// Output directory for the generated reference-distribution package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the reference-distribution validation corpus, report, and decision artifact.
    Validate {
        /// Output directory for the generated reference-distribution validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum BroaderDistributionCommands {
    /// Export the selected broader-distribution package and governed qualification bundle.
    Export {
        /// Output directory for the generated broader-distribution package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the broader-distribution validation corpus, report, and decision artifact.
    Validate {
        /// Output directory for the generated broader-distribution validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum SelectiveAccountActivationCommands {
    /// Export the selected selective-account-activation package and controlled delivery bundle.
    Export {
        /// Output directory for the generated selective-account-activation package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the selective-account-activation validation corpus, report, and decision artifact.
    Validate {
        /// Output directory for the generated selective-account-activation validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum DeliveryContinuityCommands {
    /// Export the selected delivery-continuity package and outcome-evidence bundle.
    Export {
        /// Output directory for the generated delivery-continuity package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the delivery-continuity validation corpus, report, and decision artifact.
    Validate {
        /// Output directory for the generated delivery-continuity validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum RenewalQualificationCommands {
    /// Export the selected renewal-qualification package and outcome-review bundle.
    Export {
        /// Output directory for the generated renewal-qualification package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the renewal-qualification validation corpus, report, and decision artifact.
    Validate {
        /// Output directory for the generated renewal-qualification validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum SecondAccountExpansionCommands {
    /// Export the selected second-account-expansion package and portfolio-review bundle.
    Export {
        /// Output directory for the generated second-account-expansion package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the second-account-expansion validation corpus, report, and decision artifact.
    Validate {
        /// Output directory for the generated second-account-expansion validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum PortfolioProgramCommands {
    /// Export the selected portfolio-program package and program-review bundle.
    Export {
        /// Output directory for the generated portfolio-program package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the portfolio-program validation corpus, report, and decision artifact.
    Validate {
        /// Output directory for the generated portfolio-program validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum SecondPortfolioProgramCommands {
    /// Export the selected second-portfolio-program package and portfolio-reuse bundle.
    Export {
        /// Output directory for the generated second-portfolio-program package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the second-portfolio-program validation corpus, report, and decision artifact.
    Validate {
        /// Output directory for the generated second-portfolio-program validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum ThirdProgramCommands {
    /// Export the selected third-program package and multi-program reuse bundle.
    Export {
        /// Output directory for the generated third-program package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the third-program validation corpus, report, and decision artifact.
    Validate {
        /// Output directory for the generated third-program validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum ProgramFamilyCommands {
    /// Export the selected program-family package and shared-review bundle.
    Export {
        /// Output directory for the generated program-family package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the program-family validation corpus, report, and decision artifact.
    Validate {
        /// Output directory for the generated program-family validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum PortfolioRevenueBoundaryCommands {
    /// Export the selected portfolio-revenue-boundary package and commercial-review bundle.
    Export {
        /// Output directory for the generated portfolio-revenue-boundary package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the portfolio-revenue-boundary validation corpus, report, and decision artifact.
    Validate {
        /// Output directory for the generated portfolio-revenue-boundary validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

fn run(cli: Cli) -> Result<(), chio_control_plane::CliError> {
    match cli.command {
        Commands::Proof { command } => match command {
            ProofCommands::Export {
                input,
                output,
                bundle_manifest,
            } => commands::cmd_mercury_proof_export(&input, &output, &bundle_manifest, cli.json),
        },
        Commands::Inquiry { command } => match command {
            InquiryCommands::Export {
                input,
                output,
                audience,
                redaction_profile,
                verifier_equivalent,
            } => commands::cmd_mercury_inquiry_export(
                &input,
                &output,
                &audience,
                redaction_profile.as_deref(),
                verifier_equivalent,
                cli.json,
            ),
        },
        Commands::Pilot { command } => match command {
            PilotCommands::Export { output } => {
                commands::cmd_mercury_pilot_export(&output, cli.json)
            }
        },
        Commands::SupervisedLive { command } => match command {
            SupervisedLiveCommands::Export { input, output } => {
                commands::cmd_mercury_supervised_live_export(&input, &output, cli.json)
            }
            SupervisedLiveCommands::Qualify { output } => {
                commands::cmd_mercury_supervised_live_qualify(&output, cli.json)
            }
        },
        Commands::DownstreamReview { command } => match command {
            DownstreamReviewCommands::Export { output } => {
                commands::cmd_mercury_downstream_review_export(&output, cli.json)
            }
            DownstreamReviewCommands::Validate { output } => {
                commands::cmd_mercury_downstream_review_validate(&output, cli.json)
            }
        },
        Commands::GovernanceWorkbench { command } => match command {
            GovernanceWorkbenchCommands::Export { output } => {
                commands::cmd_mercury_governance_workbench_export(&output, cli.json)
            }
            GovernanceWorkbenchCommands::Validate { output } => {
                commands::cmd_mercury_governance_workbench_validate(&output, cli.json)
            }
        },
        Commands::AssuranceSuite { command } => match command {
            AssuranceSuiteCommands::Export { output } => {
                commands::cmd_mercury_assurance_suite_export(&output, cli.json)
            }
            AssuranceSuiteCommands::Validate { output } => {
                commands::cmd_mercury_assurance_suite_validate(&output, cli.json)
            }
        },
        Commands::EmbeddedOem { command } => match command {
            EmbeddedOemCommands::Export { output } => {
                commands::cmd_mercury_embedded_oem_export(&output, cli.json)
            }
            EmbeddedOemCommands::Validate { output } => {
                commands::cmd_mercury_embedded_oem_validate(&output, cli.json)
            }
        },
        Commands::TrustNetwork { command } => match command {
            TrustNetworkCommands::Export { output } => {
                commands::cmd_mercury_trust_network_export(&output, cli.json)
            }
            TrustNetworkCommands::Validate { output } => {
                commands::cmd_mercury_trust_network_validate(&output, cli.json)
            }
        },
        Commands::ReleaseReadiness { command } => match command {
            ReleaseReadinessCommands::Export { output } => {
                commands::cmd_mercury_release_readiness_export(&output, cli.json)
            }
            ReleaseReadinessCommands::Validate { output } => {
                commands::cmd_mercury_release_readiness_validate(&output, cli.json)
            }
        },
        Commands::ControlledAdoption { command } => match command {
            ControlledAdoptionCommands::Export { output } => {
                commands::cmd_mercury_controlled_adoption_export(&output, cli.json)
            }
            ControlledAdoptionCommands::Validate { output } => {
                commands::cmd_mercury_controlled_adoption_validate(&output, cli.json)
            }
        },
        Commands::ReferenceDistribution { command } => match command {
            ReferenceDistributionCommands::Export { output } => {
                commands::cmd_mercury_reference_distribution_export(&output, cli.json)
            }
            ReferenceDistributionCommands::Validate { output } => {
                commands::cmd_mercury_reference_distribution_validate(&output, cli.json)
            }
        },
        Commands::BroaderDistribution { command } => match command {
            BroaderDistributionCommands::Export { output } => {
                commands::cmd_mercury_broader_distribution_export(&output, cli.json)
            }
            BroaderDistributionCommands::Validate { output } => {
                commands::cmd_mercury_broader_distribution_validate(&output, cli.json)
            }
        },
        Commands::SelectiveAccountActivation { command } => match command {
            SelectiveAccountActivationCommands::Export { output } => {
                commands::cmd_mercury_selective_account_activation_export(&output, cli.json)
            }
            SelectiveAccountActivationCommands::Validate { output } => {
                commands::cmd_mercury_selective_account_activation_validate(&output, cli.json)
            }
        },
        Commands::DeliveryContinuity { command } => match command {
            DeliveryContinuityCommands::Export { output } => {
                commands::cmd_mercury_delivery_continuity_export(&output, cli.json)
            }
            DeliveryContinuityCommands::Validate { output } => {
                commands::cmd_mercury_delivery_continuity_validate(&output, cli.json)
            }
        },
        Commands::RenewalQualification { command } => match command {
            RenewalQualificationCommands::Export { output } => {
                commands::cmd_mercury_renewal_qualification_export(&output, cli.json)
            }
            RenewalQualificationCommands::Validate { output } => {
                commands::cmd_mercury_renewal_qualification_validate(&output, cli.json)
            }
        },
        Commands::SecondAccountExpansion { command } => match command {
            SecondAccountExpansionCommands::Export { output } => {
                commands::cmd_mercury_second_account_expansion_export(&output, cli.json)
            }
            SecondAccountExpansionCommands::Validate { output } => {
                commands::cmd_mercury_second_account_expansion_validate(&output, cli.json)
            }
        },
        Commands::PortfolioProgram { command } => match command {
            PortfolioProgramCommands::Export { output } => {
                commands::cmd_mercury_portfolio_program_export(&output, cli.json)
            }
            PortfolioProgramCommands::Validate { output } => {
                commands::cmd_mercury_portfolio_program_validate(&output, cli.json)
            }
        },
        Commands::SecondPortfolioProgram { command } => match command {
            SecondPortfolioProgramCommands::Export { output } => {
                commands::cmd_mercury_second_portfolio_program_export(&output, cli.json)
            }
            SecondPortfolioProgramCommands::Validate { output } => {
                commands::cmd_mercury_second_portfolio_program_validate(&output, cli.json)
            }
        },
        Commands::ThirdProgram { command } => match command {
            ThirdProgramCommands::Export { output } => {
                commands::cmd_mercury_third_program_export(&output, cli.json)
            }
            ThirdProgramCommands::Validate { output } => {
                commands::cmd_mercury_third_program_validate(&output, cli.json)
            }
        },
        Commands::ProgramFamily { command } => match command {
            ProgramFamilyCommands::Export { output } => {
                commands::cmd_mercury_program_family_export(&output, cli.json)
            }
            ProgramFamilyCommands::Validate { output } => {
                commands::cmd_mercury_program_family_validate(&output, cli.json)
            }
        },
        Commands::PortfolioRevenueBoundary { command } => match command {
            PortfolioRevenueBoundaryCommands::Export { output } => {
                commands::cmd_mercury_portfolio_revenue_boundary_export(&output, cli.json)
            }
            PortfolioRevenueBoundaryCommands::Validate { output } => {
                commands::cmd_mercury_portfolio_revenue_boundary_validate(&output, cli.json)
            }
        },
        Commands::Verify { input, explain } => {
            commands::cmd_mercury_verify(&input, cli.json, explain)
        }
    }
}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(cli) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
