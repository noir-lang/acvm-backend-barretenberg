use acvm::acir::circuit::Circuit;

use acvm::SmartContract;

use super::Plonk;

impl SmartContract for Plonk {
    fn eth_contract_from_cs(&self, circuit: Circuit) -> String {
        todo!("there is no smart contract for the js cli, we could hook up the wasm one");
    }
}
