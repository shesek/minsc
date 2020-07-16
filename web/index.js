import("./pkg").then(module => {
  const { compile_js } = module;
  console.log(compile_js("pk(A) || pk(B)"));
}).catch(console.error);
