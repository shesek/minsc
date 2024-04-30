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

lazy_static! {
    static ref ROOT_SCOPE: Scope<'static> = Scope::root();
}

fn run(code: &str) -> Result<Value, Error> {
    Ok(parse(code)?.eval(&ROOT_SCOPE)?)
}
