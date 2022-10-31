use super::Plonk;
#[cfg(feature = "sys")]
use crate::barretenberg_rs::composer::StandardComposer;
use crate::barretenberg_structures::Assignments;
use acvm::acir::{circuit::Circuit, native_types::Witness};
use acvm::FieldElement;
use acvm::{Language, ProofSystemCompiler};
use std::collections::BTreeMap;
#[cfg(feature = "wasm-base")]
use std::io::Write;
#[cfg(feature = "wasm-base")]
use tempfile::NamedTempFile;

#[cfg(windows)]
pub const NODE: &'static str = "node.exe";
#[cfg(windows)]
pub const NPM: &'static str = "npm.cmd";

#[cfg(not(windows))]
pub const NODE: &'static str = "node";
#[cfg(not(windows))]
pub const NPM: &'static str = "npm";

impl ProofSystemCompiler for Plonk {
    fn prove_with_meta(
        &self,
        circuit: Circuit,
        witness_values: BTreeMap<Witness, FieldElement>,
    ) -> Vec<u8> {
        let constraint_system = crate::serialise_circuit(&circuit);

        let mut composer = StandardComposer::new(constraint_system);

        // Add witnesses in the correct order
        // Note: The witnesses are sorted via their witness index
        // witness_values may not have all the witness indexes, e.g for unused witness which are not solved by the solver
        let mut sorted_witness = Assignments::new();
        let num_witnesses = circuit.num_vars();
        for i in 1..num_witnesses {
            // Get the value if it exists. If i does not, then we fill it with the zero value
            let value = match witness_values.get(&Witness(i)) {
                Some(value) => *value,
                None => FieldElement::zero(),
            };

            sorted_witness.push(value);
        }

        remove_public_inputs(
            circuit.public_inputs.0.len(),
            composer.create_proof(sorted_witness),
        )
    }

    fn verify_from_cs(
        &self,
        proof: &[u8],
        public_inputs: Vec<FieldElement>,
        circuit: Circuit,
    ) -> bool {
        let constraint_system = crate::serialise_circuit(&circuit);

        let mut composer = StandardComposer::new(constraint_system);

        composer.verify(proof, Some(Assignments::from_vec(public_inputs)))
    }

    fn np_language(&self) -> Language {
        Language::PLONKCSat { width: 3 }
    }
}

#[cfg(feature = "wasm-base")]
fn get_path_to_cli() -> String {
    let output = std::process::Command::new(NPM)
        .arg("root")
        .arg("-g")
        .stdout(std::process::Stdio::piped())
        .output()
        .expect("Failed to execute command to fetch root directory");

    let path_to_root_dir = String::from_utf8(output.stdout).unwrap();
    let path_to_root_dir = path_to_root_dir.trim().to_owned();
    let mut path_to_indexjs = path_to_root_dir;
    path_to_indexjs.push_str("/@noir-lang/noir-cli/dest/index.js");
    path_to_indexjs
}
