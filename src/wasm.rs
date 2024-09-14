use wasm_bindgen::prelude::*;

use crate::eval;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn run(code: &str) -> Result<JsValue, JsValue> {
    let value = eval(code).map_err(|e| e.to_string())?;
    Ok(JsValue::from_str(&value.to_string()))
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn console_log(a: &str);

    #[wasm_bindgen(js_namespace = console, js_name = error)]
    pub fn console_error(a: &str);
}
