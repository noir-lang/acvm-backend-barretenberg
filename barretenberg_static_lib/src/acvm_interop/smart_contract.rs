use crate::composer::StandardComposer;
use common::acvm::acir::circuit::Circuit;
use common::acvm::SmartContract;
use common::serialiser::serialise_circuit;

use super::Plonk;

impl SmartContract for Plonk {
    fn eth_contract_from_cs(&self, circuit: Circuit) -> String {
        let constraint_system = serialise_circuit(&circuit);

        let mut composer = StandardComposer::new(constraint_system);

        composer.smart_contract()
    }
}
