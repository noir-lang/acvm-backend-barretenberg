use acvm::FieldElement;

use super::{Barretenberg, FIELD_BYTES};

pub(crate) trait Recursion {
    fn verify_proof_(
        &self,
        key: Vec<FieldElement>,
        proof: Vec<FieldElement>,
        num_public_inputs: u32,
        input_aggregation_object: [FieldElement; 16],
    ) -> [FieldElement; 16];
}

#[cfg(feature = "native")]
impl Recursion for Barretenberg {
    fn verify_proof_(
        &self,
        key: Vec<FieldElement>,
        proof: Vec<FieldElement>,
        num_public_inputs: u32,
        input_aggregation_object: [FieldElement; 16],
    ) -> [FieldElement; 16] {
        let mut vk_as_bytes = Vec::new();
        for vk_field in key {
            vk_as_bytes.extend(vk_field.to_be_bytes());
        }

        let mut proof_fields_as_bytes = Vec::new();
        for proof_field in proof {
            proof_fields_as_bytes.extend(proof_field.to_be_bytes());
        }

        // let public_input_as_bytes = public_input.to_be_bytes();

        let mut input_agg_obj_bytes = Vec::new();
        for input_var in input_aggregation_object {
            input_agg_obj_bytes.extend(input_var.to_be_bytes());
        }

        let mut output_agg_obj_addr: *mut u8 = std::ptr::null_mut();
        let p_output_agg_obj = &mut output_agg_obj_addr as *mut *mut u8;

        // let public_inputs = vec![1];
        let output_agg_size;
        unsafe {
            output_agg_size = barretenberg_sys::recursion::verify_proof(
                &vk_as_bytes,
                &proof_fields_as_bytes,
                num_public_inputs,
                &input_agg_obj_bytes,
                p_output_agg_obj,
            );
        }

        let output_agg_as_bytes;
        unsafe {
            output_agg_as_bytes =
                Vec::from_raw_parts(output_agg_obj_addr, output_agg_size, output_agg_size);
        }

        let output_agg_obj_byte_slices =
            output_agg_as_bytes.chunks(FIELD_BYTES).collect::<Vec<_>>();
        let mut output_aggregation_obj: [FieldElement; 16] = [FieldElement::zero(); 16];
        for (i, output_agg_bytes) in output_agg_obj_byte_slices.into_iter().enumerate() {
            output_aggregation_obj[i] = FieldElement::from_be_bytes_reduce(output_agg_bytes);
        }

        output_aggregation_obj
    }
}