use crate::composer::StandardComposer;
use common::acvm::acir::circuit::Circuit;
use common::acvm::SmartContract;
use common::serializer::serialize_circuit;

use super::Plonk;

impl SmartContract for Plonk {
    fn eth_contract_from_vk(&self, _verification_key: &[u8]) -> String {
        todo!("use `eth_contract_from_cs` for now");
    }

    fn eth_contract_from_cs(&self, circuit: Circuit) -> String {
        let constraint_system = serialize_circuit(&circuit);

        let mut composer = StandardComposer::new(constraint_system);

        composer.smart_contract()
    }
}
