use wasm_bindgen::prelude::*;

use crate::{eval, ExprRepr};

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn evaluate(code: &str) -> Result<String, String> {
    let result = eval(code).map_err(|e| e.to_string())?;
    Ok(result.repr_str())
}

#[wasm_bindgen]
pub fn evaluate_with_type(code: &str) -> Result<Vec<String>, String> {
    let result = eval(code).map_err(|e| e.to_string())?;
    Ok(vec![result.type_of().to_string(), result.repr_str()])
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn console_log(a: &str);

    #[wasm_bindgen(js_namespace = console, js_name = error)]
    pub fn console_error(a: &str);
}
