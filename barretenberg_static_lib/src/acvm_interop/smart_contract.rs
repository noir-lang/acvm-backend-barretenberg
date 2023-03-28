use common::acvm::acir::circuit::Circuit;
use common::acvm::SmartContract;

use super::Plonk;

impl SmartContract for Plonk {
    fn eth_contract_from_vk(&self, verification_key: &[u8]) -> String {
        // composer.smart_contract(verification_key)
        unimplemented!()
    }

    fn eth_contract_from_cs(&self, circuit: Circuit) -> String {
        unimplemented!("use `eth_contract_from_vk`");
    }
}
