use wasm_bindgen::prelude::*;

use crate::{parse, Error, Evaluate, Scope, Value};

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen(js_name = run)]
pub fn js_run(code: &str) -> Result<JsValue, JsValue> {
    let value = run(code).map_err(|e| e.to_string())?;
    Ok(JsValue::from_str(&value.to_string()))
}

fn run(code: &str) -> Result<Value, Error> {
    Ok(parse(code)?.eval(Scope::root())?)
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn console_log(a: &str, b: &str);

    #[wasm_bindgen(js_namespace = console, js_name = error)]
    pub fn console_error(a: &str, b: &str);
}
