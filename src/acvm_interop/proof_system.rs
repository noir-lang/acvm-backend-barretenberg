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

impl ProofSystemCompiler for Plonk {
    #[cfg(feature = "sys")]
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

        composer.create_proof(sorted_witness)
    }

    #[cfg(feature = "wasm-base")]
    fn prove_with_meta(
        &self,
        circuit: Circuit,
        witness_values: BTreeMap<Witness, FieldElement>,
    ) -> Vec<u8> {
        //Serialise to disk
        let serialized = circuit.to_bytes();
        let mut circuit_file = NamedTempFile::new().unwrap();
        circuit_file.write_all(serialized.as_slice());

        let serialized = Witness::to_bytes(&witness_values);
        let mut witness_file = NamedTempFile::new().unwrap();
        witness_file.write_all(serialized.as_slice());

        //Call noirjs-cli...TODO
        // Command::new("git")
        // .arg("-c")
        // .arg("advice.detachedHead=false")
        // .arg("clone")
        // .arg("--depth")
        // .arg("1")
        // .arg("--branch")
        // .arg(&tag)
        // .arg(base.as_str())
        // .arg(&loc)
        // .status()
        // .expect("git clone command failed to start");

        circuit_file.close();
        witness_file.close();

        //dummy prover:
        vec![72, 69, 76, 76, 79]
    }

    #[cfg(feature = "sys")]
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

    #[cfg(feature = "wasm-base")]
    fn verify_from_cs(
        &self,
        proof: &[u8],
        public_inputs: Vec<FieldElement>,
        circuit: Circuit,
    ) -> bool {
        //dummy verifier
        true
    }

    fn np_language(&self) -> Language {
        Language::PLONKCSat { width: 3 }
    }
}
